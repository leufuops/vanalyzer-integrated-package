#!/usr/bin/env python3
from __future__ import annotations

import concurrent.futures
import json
import os
import threading
import time
import traceback
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import psycopg2
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


SECRETS_DIR      = os.getenv("SECRETS_DIR", "/run/secrets")
BASE_URL         = "https://api.sev.co"
PAGE_SIZE        = 500
MAX_PAGES        = 50_000
CONNECT_TIMEOUT  = 10
READ_TIMEOUT     = 60
HTTP_RETRIES     = 3
BACKOFF_FACTOR   = 2.0
BATCH_SIZE       = 500
CVE_WORKERS      = int(os.getenv("SEVCO_CVE_WORKERS", "16"))

THREAD_LOCAL = threading.local()
PRINT_LOCK   = threading.Lock()
STATE_LOCK   = threading.Lock()


class PaginationLimitReached(Exception):
    pass


def read_secret(name: str, env_fallback: str = "", default: str = "") -> str:
    try:
        with open(os.path.join(SECRETS_DIR, name)) as fh:
            v = fh.read().strip()
            if v:
                return v
    except FileNotFoundError:
        pass
    if env_fallback:
        v = (os.getenv(env_fallback) or "").strip()
        if v:
            return v
    return default


def load_config() -> Dict[str, Any]:
    def req(secret: str, env: str) -> str:
        v = read_secret(secret, env_fallback=env)
        if not v:
            raise RuntimeError(f"Secret '{secret}' / env '{env}' not found — required")
        return v

    return {
        "sevco_api_token": req("sevco_api_token", "SEVCO_API_TOKEN"),
        "sevco_org_id":    req("sevco_org_id",    "SEVCO_ORG_ID"),
        "pg_db":           req("postgres_db",     "PGDATABASE"),
        "pg_user":         req("postgres_user",   "PGUSER"),
        "pg_password":     req("postgres_password", "PGPASSWORD"),
        "pg_host":         os.getenv("POSTGRES_HOST", "appdb"),
        "pg_port":         int(os.getenv("POSTGRES_PORT", "5432")),
        "pg_sslmode":      os.getenv("PG_SSLMODE", "disable"),
    }


def get_conn(cfg: Dict[str, Any]):
    return psycopg2.connect(
        host=cfg["pg_host"],
        port=cfg["pg_port"],
        dbname=cfg["pg_db"],
        user=cfg["pg_user"],
        password=cfg["pg_password"],
        sslmode=cfg["pg_sslmode"],
    )


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def log(level: str, msg: str) -> None:
    ts = now_utc().strftime("%Y-%m-%d %H:%M:%S")
    with PRINT_LOCK:
        print(f"[{ts}] [{level}] {msg}", flush=True)


def norm_host(hostname: Optional[str]) -> Optional[str]:
    if not hostname:
        return None
    return hostname.strip().lower().split(".")[0]


# ============================================================================
# HTTP CLIENT
# ============================================================================

class SevcoClient:
    def __init__(self, api_token: str, org_id: str):
        self._api_token = api_token
        self._org_id    = org_id
        self.base_url   = BASE_URL.rstrip("/")

    def _session(self) -> requests.Session:
        if not hasattr(THREAD_LOCAL, "sevco_session"):
            s = requests.Session()
            retry = Retry(
                total=HTTP_RETRIES,
                status_forcelist=[429, 500, 502, 503, 504],
                backoff_factor=BACKOFF_FACTOR,
                respect_retry_after_header=True,
                raise_on_status=False,
            )
            s.mount("https://", HTTPAdapter(max_retries=retry, pool_connections=50, pool_maxsize=50))
            s.headers.update({
                "Authorization":      f"Token {self._api_token}",
                "x-sevco-target-org": self._org_id,
                "Accept":             "application/json",
                "Content-Type":       "application/json",
                "User-Agent":         "vanalyzer-sevco-etl/1.0",
            })
            THREAD_LOCAL.sevco_session = s
        return THREAD_LOCAL.sevco_session

    def post(self, endpoint: str, body: Dict[str, Any]) -> Any:
        url  = f"{self.base_url}{endpoint}"
        t0   = time.time()
        resp = self._session().post(url, json=body, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT))
        log("HTTP", f"POST {url} -> {resp.status_code} ({round(time.time() - t0, 2)}s)")
        if resp.status_code == 400:
            raise PaginationLimitReached(f"400 Bad Request — pagination limit reached on {endpoint}")
        resp.raise_for_status()
        return resp.json()

    def paginate(self, endpoint: str, query: Dict[str, Any]) -> List[Any]:
        all_items: List[Any] = []
        page = 0
        seen: set = set()

        for _ in range(MAX_PAGES):
            if page in seen:
                log("WARN", f"Repeated page {page} on {endpoint}, stopping.")
                break
            seen.add(page)

            try:
                data = self.post(endpoint, {"query": deepcopy(query), "pagination": {"limit": PAGE_SIZE, "page": page}})
            except PaginationLimitReached as e:
                log("WARN", str(e))
                break

            items       = self._extract_items(data)
            all_items.extend(items)

            pag         = self._extract_pagination(data)
            total       = pag.get("total", 0)
            per_page    = pag.get("per_page") or pag.get("limit") or len(items)
            server_page = pag.get("page", page)

            log("INFO", f"  {endpoint} page={page} page_items={len(items)} accumulated={len(all_items)}" +
                (f" server_total={total}" if total else ""))

            if not items:
                break
            if isinstance(total, int) and total > 0 and len(all_items) >= total:
                break
            if isinstance(per_page, int) and per_page > 0 and len(items) < per_page:
                break

            page = int(server_page) + 1 if isinstance(server_page, int) else page + 1

        return all_items

    def devices_for_cve(self, cve_id: str) -> List[Any]:
        query = {
            "negate":     False,
            "combinator": "and",
            "rules": [{
                "entity_type": "vuln",
                "field":       "cve",
                "operator":    "equals",
                "value":       cve_id,
            }],
        }
        return self.paginate("/v3/asset/device", query)

    @staticmethod
    def _extract_items(data: Any) -> List[Any]:
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for key in ("items", "results", "data", "rows", "events"):
                val = data.get(key)
                if isinstance(val, list):
                    return val
        return []

    @staticmethod
    def _extract_pagination(data: Any) -> Dict[str, Any]:
        if isinstance(data, dict):
            p = data.get("pagination")
            if isinstance(p, dict):
                return p
            m = data.get("meta", {})
            if isinstance(m, dict):
                p = m.get("pagination")
                if isinstance(p, dict):
                    return p
        return {}


# ============================================================================
# ETL RUNS
# ============================================================================

def start_run(cfg: Dict[str, Any]) -> int:
    conn = get_conn(cfg)
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO public.sevco_etl_runs (started_at, status)
            VALUES (NOW(), 'running')
            RETURNING run_id
        """)
        run_id = cur.fetchone()[0]
    conn.commit()
    conn.close()
    log("INFO", f"ETL run started: run_id={run_id}")
    return run_id


def finish_run(cfg: Dict[str, Any], run_id: int, rows_devices: int, rows_vulns: int,
               rows_events: int, rows_vuln_devices: int,
               status: str, error: Optional[str] = None) -> None:
    conn = get_conn(cfg)
    with conn.cursor() as cur:
        cur.execute("""
            UPDATE public.sevco_etl_runs
            SET finished_at        = NOW(),
                status             = %s,
                rows_devices       = %s,
                rows_vulns         = %s,
                rows_events        = %s,
                rows_vuln_devices  = %s,
                error_message      = %s
            WHERE run_id = %s
        """, (status, rows_devices, rows_vulns, rows_events, rows_vuln_devices, error, run_id))
    conn.commit()
    conn.close()
    log("INFO", f"ETL run {run_id} finished: status={status} devices={rows_devices} "
                f"vulns={rows_vulns} events={rows_events} vuln_devices={rows_vuln_devices}")


# ============================================================================
# UPSERT DEVICES
# ============================================================================

def upsert_devices(cfg: Dict[str, Any], items: List[Any], run_id: int) -> int:
    log("INFO", f"Loading {len(items)} devices in batches of {BATCH_SIZE}...")
    count = 0
    conn  = get_conn(cfg)
    cur   = conn.cursor()
    try:
        for item in items:
            attrs    = item.get("attributes", {})
            hostname = attrs.get("hostname") or (attrs.get("hostnames") or [None])[0]
            geo      = attrs.get("geo_ip") or {}
            cur.execute("""
                INSERT INTO public.sevco_device (
                    device_id, run_id,
                    org_id, correlation_id,
                    hostname,
                    primary_ip, internal_ips, external_ips, all_ips,
                    mac_addresses, mac_manufacturers,
                    os, os_platform, os_release, os_version,
                    os_end_of_life_at,
                    manufacturer, model, serial_number,
                    encryption_status,
                    asset_category, asset_sub_category,
                    associated_usernames, controls,
                    geo_city, geo_country, geo_country_code,
                    geo_latitude, geo_longitude,
                    source_ids, source_config_ids, source_count,
                    days_active, days_since_last_activity,
                    first_observed_at, last_observed_at, last_activity_at,
                    raw, ingested_at
                ) VALUES (
                    %s,%s,%s,%s,%s,%s,%s,%s,%s,
                    %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                    %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                    %s,%s,%s,%s,%s,%s,%s,%s,%s,NOW()
                )
                ON CONFLICT (device_id) DO UPDATE SET
                    run_id                   = EXCLUDED.run_id,
                    correlation_id           = EXCLUDED.correlation_id,
                    hostname                 = EXCLUDED.hostname,
                    primary_ip               = EXCLUDED.primary_ip,
                    internal_ips             = EXCLUDED.internal_ips,
                    external_ips             = EXCLUDED.external_ips,
                    all_ips                  = EXCLUDED.all_ips,
                    mac_addresses            = EXCLUDED.mac_addresses,
                    mac_manufacturers        = EXCLUDED.mac_manufacturers,
                    os                       = EXCLUDED.os,
                    os_platform              = EXCLUDED.os_platform,
                    os_release               = EXCLUDED.os_release,
                    os_version               = EXCLUDED.os_version,
                    os_end_of_life_at        = EXCLUDED.os_end_of_life_at,
                    manufacturer             = EXCLUDED.manufacturer,
                    model                    = EXCLUDED.model,
                    serial_number            = EXCLUDED.serial_number,
                    encryption_status        = EXCLUDED.encryption_status,
                    asset_category           = EXCLUDED.asset_category,
                    asset_sub_category       = EXCLUDED.asset_sub_category,
                    associated_usernames     = EXCLUDED.associated_usernames,
                    controls                 = EXCLUDED.controls,
                    geo_city                 = EXCLUDED.geo_city,
                    geo_country              = EXCLUDED.geo_country,
                    geo_country_code         = EXCLUDED.geo_country_code,
                    geo_latitude             = EXCLUDED.geo_latitude,
                    geo_longitude            = EXCLUDED.geo_longitude,
                    source_ids               = EXCLUDED.source_ids,
                    source_config_ids        = EXCLUDED.source_config_ids,
                    source_count             = EXCLUDED.source_count,
                    days_active              = EXCLUDED.days_active,
                    days_since_last_activity = EXCLUDED.days_since_last_activity,
                    first_observed_at        = EXCLUDED.first_observed_at,
                    last_observed_at         = EXCLUDED.last_observed_at,
                    last_activity_at         = EXCLUDED.last_activity_at,
                    raw                      = EXCLUDED.raw,
                    ingested_at              = NOW()
            """, (
                item.get("id"),                                      run_id,
                item.get("org_id"),                                  item.get("correlation_id"),
                hostname,
                attrs.get("ip"),
                attrs.get("internal_ips") or [],
                attrs.get("external_ips") or [],
                attrs.get("ips") or [],
                attrs.get("mac_addresses") or [],
                attrs.get("mac_manufacturers") or [],
                attrs.get("os"),                                     attrs.get("os_platform"),
                attrs.get("os_release"),                             attrs.get("os_version"),
                attrs.get("os_end_of_life_timestamp"),
                attrs.get("manufacturer"),                           attrs.get("model"),
                attrs.get("serial_number"),
                attrs.get("encryption_status"),
                (attrs.get("asset_classification") or {}).get("category"),
                (attrs.get("asset_classification") or {}).get("sub_category"),
                attrs.get("associated_usernames") or [],
                attrs.get("controls") or [],
                geo.get("city"),                                     geo.get("country"),
                geo.get("country_code"),
                geo.get("latitude"),                                 geo.get("longitude"),
                item.get("source_ids") or [],
                item.get("source_config_ids") or [],
                item.get("source_count", 0),
                item.get("days_active"),                             item.get("days_since_last_activity"),
                item.get("first_observed_timestamp"),
                item.get("last_observed_timestamp"),
                item.get("last_activity_timestamp"),
                json.dumps(item),
            ))
            count += 1
            if count % BATCH_SIZE == 0:
                conn.commit()
                log("INFO", f"  devices committed: {count}")
        conn.commit()
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        raise
    finally:
        cur.close()
        conn.close()
    log("INFO", f"Devices loaded: {count}")
    return count


# ============================================================================
# UPSERT VULNS (exploded by source_config_id)
# ============================================================================

def upsert_vulns(cfg: Dict[str, Any], items: List[Any], run_id: int) -> int:
    log("INFO", f"Loading {len(items)} vulnerabilities (exploding by source_config_id)...")
    count = 0
    conn  = get_conn(cfg)
    cur   = conn.cursor()
    try:
        for item in items:
            attrs        = item.get("attributes", {})
            ssvc_list    = attrs.get("ssvc") or []
            ssvc         = next((s for s in ssvc_list if s.get("source") == "CISA-ADP"), None) or \
                           (ssvc_list[0] if ssvc_list else {})
            exploit_refs = attrs.get("exploit_references") or {}
            cwe_ids      = list({w.get("cwe_id") for w in (attrs.get("weaknesses") or []) if w.get("cwe_id")})
            mitre_ids    = [t.get("id") for t in (attrs.get("mitre_attack_techniques") or []) if t.get("id")]
            capec_ids    = [a.get("capec_id") for a in (attrs.get("attack_patterns") or []) if a.get("capec_id")]

            sources = item.get("sources") or []
            if not sources:
                sources = [{"config_id": None, "platform_id": None, "id": None}]

            for src in sources:
                source_config_id   = src.get("config_id")
                source_platform_id = src.get("platform_id") or src.get("source")
                source_native_id   = src.get("id")

                cur.execute("""
                    INSERT INTO public.sevco_vuln (
                        run_id,
                        vuln_id, source_config_id, source_platform_id, source_native_id,
                        org_id, correlation_id,
                        cve_id, sevco_vuln_id,
                        severity, cvss_severity,
                        cvss3_base_score, cvss3_temporal_score, composite_cvss_score,
                        epss_score, epss_percentile,
                        nvd_vuln_status,
                        description, solution,
                        port, protocol, product, product_type, vendor,
                        cisa_kev_exploit_add, vulncheck_kev_exploit_add,
                        public_exploit_found, commercial_exploit_found, weaponized_exploit_found,
                        exploits_count, max_exploit_maturity,
                        exploit_availabilities, exploit_maturities,
                        botnets, botnets_count,
                        ransomware, ransomware_families_count,
                        threat_actors_count,
                        cwe_ids, mitre_technique_ids, capec_ids,
                        ssvc_exploitation, ssvc_automatable, ssvc_technical_impact,
                        categories,
                        source_ids, source_config_ids, source_count,
                        first_found_at, last_found_at,
                        first_observed_at, last_observed_at,
                        raw, ingested_at
                    ) VALUES (
                        %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                        %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                        %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                        %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                        %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                        %s,%s,%s,NOW()
                    )
                    ON CONFLICT (vuln_id, source_config_id) DO UPDATE SET
                        run_id                    = EXCLUDED.run_id,
                        source_platform_id        = EXCLUDED.source_platform_id,
                        source_native_id          = EXCLUDED.source_native_id,
                        correlation_id            = EXCLUDED.correlation_id,
                        severity                  = EXCLUDED.severity,
                        cvss_severity             = EXCLUDED.cvss_severity,
                        cvss3_base_score          = EXCLUDED.cvss3_base_score,
                        cvss3_temporal_score      = EXCLUDED.cvss3_temporal_score,
                        composite_cvss_score      = EXCLUDED.composite_cvss_score,
                        epss_score                = EXCLUDED.epss_score,
                        epss_percentile           = EXCLUDED.epss_percentile,
                        nvd_vuln_status           = EXCLUDED.nvd_vuln_status,
                        description               = EXCLUDED.description,
                        solution                  = EXCLUDED.solution,
                        port                      = EXCLUDED.port,
                        protocol                  = EXCLUDED.protocol,
                        product                   = EXCLUDED.product,
                        product_type              = EXCLUDED.product_type,
                        vendor                    = EXCLUDED.vendor,
                        cisa_kev_exploit_add      = EXCLUDED.cisa_kev_exploit_add,
                        vulncheck_kev_exploit_add = EXCLUDED.vulncheck_kev_exploit_add,
                        public_exploit_found      = EXCLUDED.public_exploit_found,
                        commercial_exploit_found  = EXCLUDED.commercial_exploit_found,
                        weaponized_exploit_found  = EXCLUDED.weaponized_exploit_found,
                        exploits_count            = EXCLUDED.exploits_count,
                        max_exploit_maturity      = EXCLUDED.max_exploit_maturity,
                        exploit_availabilities    = EXCLUDED.exploit_availabilities,
                        exploit_maturities        = EXCLUDED.exploit_maturities,
                        botnets                   = EXCLUDED.botnets,
                        botnets_count             = EXCLUDED.botnets_count,
                        ransomware                = EXCLUDED.ransomware,
                        ransomware_families_count = EXCLUDED.ransomware_families_count,
                        threat_actors_count       = EXCLUDED.threat_actors_count,
                        cwe_ids                   = EXCLUDED.cwe_ids,
                        mitre_technique_ids       = EXCLUDED.mitre_technique_ids,
                        capec_ids                 = EXCLUDED.capec_ids,
                        ssvc_exploitation         = EXCLUDED.ssvc_exploitation,
                        ssvc_automatable          = EXCLUDED.ssvc_automatable,
                        ssvc_technical_impact     = EXCLUDED.ssvc_technical_impact,
                        categories                = EXCLUDED.categories,
                        source_ids                = EXCLUDED.source_ids,
                        source_config_ids         = EXCLUDED.source_config_ids,
                        source_count              = EXCLUDED.source_count,
                        first_found_at            = EXCLUDED.first_found_at,
                        last_found_at             = EXCLUDED.last_found_at,
                        first_observed_at         = EXCLUDED.first_observed_at,
                        last_observed_at          = EXCLUDED.last_observed_at,
                        raw                       = EXCLUDED.raw,
                        ingested_at               = NOW()
                """, (
                    run_id,
                    item.get("id"),          source_config_id,
                    source_platform_id,      source_native_id,
                    item.get("org_id"),      item.get("correlation_id"),
                    attrs.get("cve"),        attrs.get("vuln_id"),
                    attrs.get("severity"),   attrs.get("cvss_severity"),
                    attrs.get("cvss3_base_score"),
                    attrs.get("cvss3_temporal_score"),
                    attrs.get("composite_cvss_score"),
                    attrs.get("epss_score"),        attrs.get("epss_percentile"),
                    attrs.get("nvd_vuln_status"),
                    attrs.get("description"),       attrs.get("solution"),
                    attrs.get("port"),              attrs.get("protocol"),
                    attrs.get("product") or [],
                    attrs.get("product_type"),
                    attrs.get("vendor") or [],
                    attrs.get("cisa_kev_exploit_add"),
                    attrs.get("vulncheck_kev_exploit_add"),
                    attrs.get("public_exploit_found"),
                    attrs.get("commercial_exploit_found"),
                    attrs.get("weaponized_exploit_found"),
                    attrs.get("exploits_count"),    attrs.get("max_exploit_maturity"),
                    exploit_refs.get("availabilities") or [],
                    exploit_refs.get("maturities") or [],
                    attrs.get("botnets") or [],     attrs.get("botnets_count", 0),
                    attrs.get("ransomware") or [],  attrs.get("ransomware_families_count", 0),
                    attrs.get("threat_actors_count", 0),
                    cwe_ids, mitre_ids, capec_ids,
                    ssvc.get("exploitation"),       ssvc.get("automatable"),
                    ssvc.get("technical_impact"),
                    attrs.get("categories") or [],
                    item.get("source_ids") or [],
                    item.get("source_config_ids") or [],
                    item.get("source_count", 0),
                    attrs.get("first_found"),       attrs.get("last_found"),
                    item.get("first_observed_timestamp"),
                    item.get("last_observed_timestamp"),
                    json.dumps(item),
                ))
                count += 1
                if count % BATCH_SIZE == 0:
                    conn.commit()
                    log("INFO", f"  vulns committed: {count}")
        conn.commit()
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        raise
    finally:
        cur.close()
        conn.close()
    log("INFO", f"Vulnerabilities loaded: {count}")
    return count


# ============================================================================
# INSERT DEVICE EVENTS
# ============================================================================

def insert_events(cfg: Dict[str, Any], items: List[Any], run_id: int) -> int:
    log("INFO", f"Loading {len(items)} device events...")
    count = 0
    conn  = get_conn(cfg)
    cur   = conn.cursor()
    try:
        for item in items:
            cur.execute("""
                INSERT INTO public.sevco_device_event (
                    object_id, run_id,
                    asset_id, org_id,
                    event_type, attribute, value,
                    source, config_id, execution_id,
                    hostnames, ip_addresses, mac_addresses,
                    event_at, object_version, ingested_at
                ) VALUES (
                    %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW()
                )
                ON CONFLICT (object_id) DO UPDATE SET
                    run_id         = EXCLUDED.run_id,
                    event_type     = EXCLUDED.event_type,
                    attribute      = EXCLUDED.attribute,
                    value          = EXCLUDED.value,
                    source         = EXCLUDED.source,
                    config_id      = EXCLUDED.config_id,
                    execution_id   = EXCLUDED.execution_id,
                    hostnames      = EXCLUDED.hostnames,
                    ip_addresses   = EXCLUDED.ip_addresses,
                    mac_addresses  = EXCLUDED.mac_addresses,
                    event_at       = EXCLUDED.event_at,
                    object_version = EXCLUDED.object_version,
                    ingested_at    = NOW()
            """, (
                item.get("object_id"),        run_id,
                item.get("asset_id"),         item.get("org_id"),
                item.get("event_type"),       item.get("attribute"),
                item.get("value"),
                item.get("source"),           item.get("config_id"),
                item.get("execution_id"),
                item.get("hostnames") or [],
                item.get("ip_addresses") or [],
                item.get("mac_addresses") or [],
                item.get("event_timestamp"),  item.get("object_version"),
            ))
            count += 1
            if count % BATCH_SIZE == 0:
                conn.commit()
                log("INFO", f"  events committed: {count}")
        conn.commit()
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        raise
    finally:
        cur.close()
        conn.close()
    log("INFO", f"Device events loaded: {count}")
    return count


# ============================================================================
# CVE -> DEVICE MAPPING  (parallel workers)
# ============================================================================

def build_unique_cves(vuln_items: List[Any]) -> List[str]:
    cves: Set[str] = set()
    for item in vuln_items:
        cve = (item.get("attributes") or {}).get("cve")
        if cve and isinstance(cve, str) and cve.strip():
            cves.add(cve.strip())
    return sorted(cves)


def _worker_fetch_cve(args: Tuple[str, SevcoClient]) -> Tuple[str, List[Any], Optional[str]]:
    cve_id, client = args
    try:
        devices = client.devices_for_cve(cve_id)
        return cve_id, devices, None
    except Exception as e:
        return cve_id, [], str(e)


def upsert_vuln_devices(cfg: Dict[str, Any], client: SevcoClient,
                        unique_cves: List[str], run_id: int) -> int:
    log("INFO", f"Mapping {len(unique_cves)} unique CVEs to affected devices "
                f"using {CVE_WORKERS} parallel workers...")

    total_edges  = 0
    processed    = 0
    failed_cves: Dict[str, str] = {}

    cve_to_devices: Dict[str, List[Any]] = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=CVE_WORKERS) as executor:
        future_to_cve = {
            executor.submit(_worker_fetch_cve, (cve_id, client)): cve_id
            for cve_id in unique_cves
        }
        for future in concurrent.futures.as_completed(future_to_cve):
            cve_id = future_to_cve[future]
            try:
                result_cve, devices, error = future.result()
            except Exception as e:
                error   = str(e)
                devices = []

            processed += 1

            if error:
                failed_cves[cve_id] = error
                log("WARN", f"  [{processed}/{len(unique_cves)}] {cve_id}: FAILED — {error}")
                continue

            with STATE_LOCK:
                cve_to_devices[cve_id] = devices

            log("INFO", f"  [{processed}/{len(unique_cves)}] {cve_id}: {len(devices)} devices")

    log("INFO", f"All CVE queries done. Failed: {len(failed_cves)}. Inserting edges into DB...")

    conn = get_conn(cfg)
    cur  = conn.cursor()
    try:
        for cve_id, devices in cve_to_devices.items():
            for device in devices:
                device_id = device.get("id")
                if not device_id:
                    continue
                attrs    = device.get("attributes", {})
                hostname = attrs.get("hostname") or (attrs.get("hostnames") or [None])[0]

                cur.execute("""
                    INSERT INTO public.sevco_vuln_device (
                        run_id, cve_id, device_id,
                        hostname,
                        os_platform, os_version,
                        primary_ip,
                        source_ids,
                        ingested_at
                    ) VALUES (
                        %s,%s,%s,%s,%s,%s,%s,%s,NOW()
                    )
                    ON CONFLICT (cve_id, device_id) DO UPDATE SET
                        run_id      = EXCLUDED.run_id,
                        hostname    = EXCLUDED.hostname,
                        os_platform = EXCLUDED.os_platform,
                        os_version  = EXCLUDED.os_version,
                        primary_ip  = EXCLUDED.primary_ip,
                        source_ids  = EXCLUDED.source_ids,
                        ingested_at = NOW()
                """, (
                    run_id,
                    cve_id,
                    device_id,
                    hostname,
                    attrs.get("os_platform"),
                    attrs.get("os_version"),
                    attrs.get("ip"),
                    device.get("source_ids") or [],
                ))
                total_edges += 1
                if total_edges % BATCH_SIZE == 0:
                    conn.commit()
                    log("INFO", f"  vuln_device edges committed: {total_edges}")

        conn.commit()
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        raise
    finally:
        cur.close()
        conn.close()

    if failed_cves:
        log("WARN", f"Failed CVEs ({len(failed_cves)}): {', '.join(sorted(failed_cves)[:20])}" +
            (" ..." if len(failed_cves) > 20 else ""))

    log("INFO", f"CVE-device mapping complete: {total_edges} edges | {len(failed_cves)} failed CVEs")
    return total_edges


# ============================================================================
# MAIN
# ============================================================================

def main() -> int:
    log("INFO", "=" * 60)
    log("INFO", "Sevco ETL — start")
    log("INFO", "=" * 60)

    cfg = load_config()
    log("INFO", f"DB: {cfg['pg_user']}@{cfg['pg_host']}:{cfg['pg_port']}/{cfg['pg_db']}")
    log("INFO", f"CVE workers: {CVE_WORKERS}")

    run_id = start_run(cfg)

    rows_devices      = 0
    rows_vulns        = 0
    rows_events       = 0
    rows_vuln_devices = 0
    status    = "success"
    error_msg = None

    try:
        client = SevcoClient(cfg["sevco_api_token"], cfg["sevco_org_id"])

        log("INFO", "── STEP 1: devices")
        device_items = client.paginate("/v3/asset/device", {})
        rows_devices = upsert_devices(cfg, device_items, run_id)

        log("INFO", "── STEP 2: vulnerabilities")
        vuln_items = client.paginate("/v3/asset/vulnerabilities", {})
        rows_vulns = upsert_vulns(cfg, vuln_items, run_id)

        log("INFO", "── STEP 3: device events")
        rows_events = insert_events(cfg, client.paginate("/v2/asset/device/events", {}), run_id)

        log("INFO", "── STEP 4: CVE → device mapping")
        unique_cves       = build_unique_cves(vuln_items)
        rows_vuln_devices = upsert_vuln_devices(cfg, client, unique_cves, run_id)

    except Exception:
        status    = "error"
        error_msg = traceback.format_exc()
        log("ERROR", f"ETL failed:\n{error_msg}")

    finally:
        finish_run(cfg, run_id, rows_devices, rows_vulns, rows_events,
                   rows_vuln_devices, status, error_msg)

    log("INFO", "=" * 60)
    log("INFO", f"Sevco ETL — {status.upper()}")
    log("INFO", f"  devices={rows_devices}  vulns={rows_vulns}  "
                f"events={rows_events}  vuln_devices={rows_vuln_devices}")
    log("INFO", "=" * 60)

    return 0 if status == "success" else 1


if __name__ == "__main__":
    raise SystemExit(main())
