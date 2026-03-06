#!/usr/bin/env python3

import os
import json
import time
import logging
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple, Set

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

import psycopg2
from psycopg2.pool import SimpleConnectionPool
from psycopg2.extras import execute_values

LOG = logging.getLogger("mde_etl")


# ----------------------------
# Utils
# ----------------------------

def setup_logging(level: str) -> None:
    lvl = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=lvl,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    return utc_now().replace(microsecond=0).isoformat()


def read_secret(name: str, env_fallback: str = "", default: str = "") -> str:
    path = f"/run/secrets/{name}"
    try:
        with open(path) as f:
            val = f.read().strip()
            if val:
                return val
    except FileNotFoundError:
        pass
    except Exception as e:
        LOG.warning("Error reading secret %s: %s", path, e)

    if env_fallback:
        val = (os.getenv(env_fallback) or "").strip()
        if val:
            return val
    return default


def die(msg: str, code: int = 2) -> None:
    LOG.critical(msg)
    raise SystemExit(code)


def is_windows(os_platform: str) -> bool:
    return (os_platform or "").lower().startswith("windows")


def to_json_str(v: Any) -> Optional[str]:
    if v is None:
        return None
    try:
        return json.dumps(v, ensure_ascii=False, default=str)
    except Exception:
        return json.dumps(str(v), ensure_ascii=False)


def to_text(v: Any) -> Optional[str]:
    if v is None:
        return None
    if isinstance(v, (dict, list, tuple)):
        return to_json_str(v)
    s = str(v).strip()
    return s if s else None


def to_ts_str(v: Any) -> Optional[str]:
    """
    PostgreSQL ::timestamptz tolera ISO8601.
    Si viene '' o None -> None.
    """
    if v is None:
        return None
    if isinstance(v, str):
        s = v.strip()
        return s if s else None
    if isinstance(v, datetime):
        return v.isoformat()
    return to_text(v)


# ----------------------------
# PG wrapper
# ----------------------------

class Pg:
    def __init__(self, host: str, port: int, dbname: str,
                 user: str, password: str, sslmode: str = "disable",
                 pool_min: int = 1, pool_max: int = 5):
        self._dsn = (
            f"host={host} port={port} dbname={dbname} "
            f"user={user} password={password} sslmode={sslmode}"
        )
        self._pool: Optional[SimpleConnectionPool] = None
        self.pool_min = pool_min
        self.pool_max = pool_max

    def init(self) -> None:
        if self._pool:
            return
        self._pool = SimpleConnectionPool(self.pool_min, self.pool_max, self._dsn)
        LOG.info("PG pool initialized")

    @contextmanager
    def conn(self):
        if not self._pool:
            self.init()
        c = self._pool.getconn()
        try:
            yield c
            c.commit()
        except Exception:
            c.rollback()
            raise
        finally:
            self._pool.putconn(c)

    def close(self) -> None:
        if self._pool:
            self._pool.closeall()
            self._pool = None

    def exec(self, sql: str, args: Optional[tuple] = None) -> None:
        with self.conn() as c:
            with c.cursor() as cur:
                cur.execute(sql, args or ())

    def fetchone(self, sql: str, args: Optional[tuple] = None) -> Optional[tuple]:
        with self.conn() as c:
            with c.cursor() as cur:
                cur.execute(sql, args or ())
                return cur.fetchone()

    def fetchval(self, sql: str, args: Optional[tuple] = None) -> Any:
        row = self.fetchone(sql, args)
        return row[0] if row else None


def run_start(pg: Pg, source: str, key: str) -> int:
    row = pg.fetchone(
        "INSERT INTO public.mde_etl_runs (source, object_type, started_at, status) "
        "VALUES (%s, %s, now(), 'running') RETURNING run_id;",
        (source, key),
    )
    assert row
    return int(row[0])


def run_finish(pg: Pg, rid: int, status: str,
               fetched: int, upserted: int, error: str = "") -> None:
    pg.exec(
        "UPDATE public.mde_etl_runs "
        "SET finished_at=now(), status=%s, rows_fetched=%s, rows_upserted=%s, error=%s "
        "WHERE run_id=%s;",
        (status, fetched, upserted, error or None, rid),
    )


# ----------------------------
# MDE client
# ----------------------------

class MDEClient:
    def __init__(self, tenant_id: str, client_id: str, client_secret: str,
                 api_base: str = "https://api.security.microsoft.com",
                 scope: str = "https://api.securitycenter.microsoft.com/.default",
                 timeout: int = 60, retries: int = 6, backoff: float = 1.5) -> None:
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.api_base = api_base.rstrip("/")
        self.scope = scope
        self.timeout = timeout
        self._token: Optional[str] = None
        self._token_expiry: float = 0.0
        self.sess = requests.Session()
        adapter = HTTPAdapter(
            max_retries=Retry(
                total=retries, connect=retries, read=retries, status=retries,
                backoff_factor=backoff,
                status_forcelist=(429, 500, 502, 503, 504),
                allowed_methods=frozenset(["GET", "POST"]),
                raise_on_status=False,
            ),
            pool_connections=10,
            pool_maxsize=10,
        )
        self.sess.mount("https://", adapter)
        self.sess.mount("http://", adapter)

    def get_token(self, force: bool = False) -> str:
        now = time.time()
        if not force and self._token and (now + 60) < self._token_expiry:
            return self._token
        url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        r = self.sess.post(url, data={
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": self.scope,
        }, timeout=self.timeout)
        if r.status_code != 200:
            die(f"Token request failed HTTP {r.status_code}: {r.text[:2000]}")
        js = r.json()
        tok = js.get("access_token")
        if not tok:
            die(f"Token response missing access_token: {json.dumps(js)[:500]}")
        exp = int(js.get("expires_in", 3600))
        self._token = tok
        self._token_expiry = time.time() + exp
        LOG.info("Auth OK  expires_in=%ds", exp)
        return tok

    def _headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self.get_token()}"}

    def get_json(self, url: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        r = self.sess.get(url, headers=self._headers(), params=params, timeout=self.timeout)
        if r.status_code in (401, 403):
            LOG.warning("HTTP %d at %s — refreshing token and retrying", r.status_code, url)
            self.get_token(force=True)
            r = self.sess.get(url, headers=self._headers(), params=params, timeout=self.timeout)
        if r.status_code >= 400:
            die(f"GET HTTP {r.status_code} url={url} body={r.text[:2000]}")
        try:
            return r.json()
        except Exception as e:
            die(f"JSON parse error url={url}: {e}")

    def paged(self, path: str, params: Optional[Dict[str, Any]] = None,
              label: str = "") -> Iterable[Dict[str, Any]]:
        url = f"{self.api_base}{path}"
        p: Optional[Dict[str, Any]] = dict(params or {})
        page = 0
        while True:
            page += 1
            LOG.debug("GET %s page=%d params=%s", label or path, page, p)
            js = self.get_json(url, params=p)
            vals = js.get("value", [])
            if not isinstance(vals, list):
                die(f"Unexpected schema at {url}: {str(js)[:500]}")
            yield from vals
            nxt = js.get("@odata.nextLink") or js.get("odata.nextLink")
            if not nxt:
                break
            url = nxt
            p = None
            LOG.info("  %s: page %d done, continuing...", label or path, page)


# ----------------------------
# Fetchers
# ----------------------------

def fetch_machines(mde: MDEClient) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    LOG.info("Fetching /api/machines ...")
    for m in mde.paged("/api/machines", params={"$top": 10000}, label="machines"):
        mid = str(m.get("id") or "").strip()
        if mid:
            out[mid] = m
    LOG.info("machines: %d devices", len(out))
    return out


def fetch_soft_vulns(mde: MDEClient, page_size: int = 50000,
                     since_time: Optional[str] = None) -> List[Dict[str, Any]]:
    params: Dict[str, Any] = {"pageSize": page_size}
    if since_time:
        params["sinceTime"] = since_time
    LOG.info("Fetching /api/machines/SoftwareVulnerabilitiesByMachine ...")
    rows = list(mde.paged(
        "/api/machines/SoftwareVulnerabilitiesByMachine",
        params=params,
        label="SoftwareVulnerabilitiesByMachine",
    ))
    LOG.info("soft_vulns: %d rows", len(rows))
    return rows


def fetch_cve_detail(mde: MDEClient, cve_id: str) -> Optional[Dict[str, Any]]:
    url = f"{mde.api_base}/api/vulnerabilities/{cve_id}"
    try:
        return mde.get_json(url)
    except SystemExit:
        LOG.warning("CVE detail not available: %s", cve_id)
        return None


def fetch_fixing_kb_index(mde: MDEClient) -> Dict[Tuple[str, str, str, str, str], str]:
    idx: Dict[Tuple[str, str, str, str, str], str] = {}
    LOG.info("Fetching /api/vulnerabilities/machinesVulnerabilities ...")
    for r in mde.paged(
        "/api/vulnerabilities/machinesVulnerabilities",
        params={"$top": 10000},
        label="machinesVulnerabilities",
    ):
        machine_id = str(r.get("machineId") or "").strip()
        cve_id     = str(r.get("cveId") or "").strip()
        vendor     = str(r.get("productVendor") or "").strip().lower()
        name       = str(r.get("productName") or "").strip().lower()
        ver        = str(r.get("productVersion") or "").strip()
        kb         = str(r.get("fixingKbId") or "").strip()
        if machine_id and cve_id and kb:
            idx[(machine_id, cve_id, vendor, name, ver)] = kb
    LOG.info("fixing_kb_index: %d entries", len(idx))
    return idx


# ----------------------------
# Upserts
# ----------------------------

def upsert_assets(pg: Pg, machines: Dict[str, Dict[str, Any]], dry_run: bool) -> int:
    if not machines:
        return 0
    rows = []
    for m in machines.values():
        mid = str(m.get("id") or "").strip()
        if not mid:
            continue
        rows.append((
            mid,
            to_text(m.get("computerDnsName") or m.get("machineName")),
            to_text(m.get("deviceName") or m.get("computerDnsName")),
            to_text(m.get("rbacGroupName")),
            to_text(m.get("osPlatform")),
            to_text(m.get("osVersion")),
            to_text(m.get("osArchitecture")),
            to_text(m.get("osProcessor")),
            to_text(m.get("agentVersion") or m.get("version")),
            to_text(m.get("healthStatus")),
            to_text(m.get("riskScore")),
            to_text(m.get("exposureLevel")),
            to_text(m.get("deviceValue")),
            to_text(m.get("onboardingStatus")),
            m.get("isAadJoined"),
            to_ts_str(m.get("lastSeen")),
            to_json_str(m.get("machineTags") or []),
            to_json_str(m),
        ))
    if dry_run:
        LOG.info("[DRY-RUN] upsert_assets: %d rows (not written)", len(rows))
        return len(rows)

    sql = """
    INSERT INTO public.mde_asset (
      device_id, computer_dns_name, device_name, rbac_group_name,
      os_platform, os_version, os_architecture, os_processor, agent_version,
      health_status, risk_score, exposure_level, device_value,
      onboarding_status, is_aad_joined, last_seen,
      machine_tags, inventory_json,
      created_at, updated_at
    ) VALUES %s
    ON CONFLICT (device_id) DO UPDATE SET
      computer_dns_name  = EXCLUDED.computer_dns_name,
      device_name        = EXCLUDED.device_name,
      rbac_group_name    = EXCLUDED.rbac_group_name,
      os_platform        = EXCLUDED.os_platform,
      os_version         = EXCLUDED.os_version,
      os_architecture    = EXCLUDED.os_architecture,
      os_processor       = EXCLUDED.os_processor,
      agent_version      = EXCLUDED.agent_version,
      health_status      = EXCLUDED.health_status,
      risk_score         = EXCLUDED.risk_score,
      exposure_level     = EXCLUDED.exposure_level,
      device_value       = EXCLUDED.device_value,
      onboarding_status  = EXCLUDED.onboarding_status,
      is_aad_joined      = EXCLUDED.is_aad_joined,
      last_seen          = EXCLUDED.last_seen,
      machine_tags       = EXCLUDED.machine_tags,
      inventory_json     = EXCLUDED.inventory_json,
      updated_at         = now();
    """
    with pg.conn() as c:
        with c.cursor() as cur:
            execute_values(
                cur, sql, rows,
                template="""(
                  %s,%s,%s,%s,
                  %s,%s,%s,%s,%s,
                  %s,%s,%s,%s,
                  %s,%s,%s::timestamptz,
                  %s::jsonb,%s::jsonb,
                  now(),now()
                )""",
                page_size=500,
            )
    LOG.info("upsert_assets: %d rows processed", len(rows))
    return len(rows)


def upsert_cves(
    pg: Pg,
    mde: MDEClient,
    cve_ids: List[str],
    max_cve_details: int,
    dry_run: bool,
) -> Tuple[int, Dict[str, Dict[str, Any]]]:
    take = cve_ids[:max_cve_details]
    LOG.info("CVE enrichment: %d unique, taking %d", len(cve_ids), len(take))

    cve_map: Dict[str, Dict[str, Any]] = {}
    for i, cid in enumerate(take, 1):
        if i % 100 == 0:
            LOG.info("  CVE progress: %d/%d", i, len(take))
        det = fetch_cve_detail(mde, cid)
        if det:
            cve_map[cid] = det
        time.sleep(0.05)

    if not cve_map:
        LOG.warning("No CVE details obtained.")
        return (0, cve_map)

    rows = []
    for cid, d in cve_map.items():
        cvss_raw = d.get("cvssV3") or d.get("cvssScore")
        try:
            cvss = float(cvss_raw) if cvss_raw is not None else None
        except (ValueError, TypeError):
            cvss = None

        epss_raw = d.get("epss")
        try:
            epss = float(epss_raw) if epss_raw is not None else None
        except (ValueError, TypeError):
            epss = None

        rows.append((
            cid,
            to_text(d.get("name")),
            to_text(d.get("severity")),
            to_text(d.get("description")),
            cvss,
            to_text(d.get("cvssVector")),
            epss,
            to_ts_str(d.get("publishedOn")),
            to_ts_str(d.get("updatedOn")),
            d.get("publicExploit"),
            d.get("exploitVerified"),
            d.get("exploitInKit"),
            to_json_str(d.get("exploitTypes") or []),
            to_json_str(d.get("exploitUris") or []),
            to_json_str(d),
        ))

    if dry_run:
        LOG.info("[DRY-RUN] upsert_cves: %d rows (not written)", len(rows))
        return (len(rows), cve_map)

    sql = """
    INSERT INTO public.mde_cve (
      cve_id, name, severity, description,
      cvss_v3, cvss_vector, epss,
      published_on, updated_on,
      public_exploit, exploit_verified, exploit_in_kit,
      exploit_types, exploit_uris,
      cve_json,
      created_at, updated_at
    ) VALUES %s
    ON CONFLICT (cve_id) DO UPDATE SET
      name             = EXCLUDED.name,
      severity         = EXCLUDED.severity,
      description      = EXCLUDED.description,
      cvss_v3          = EXCLUDED.cvss_v3,
      cvss_vector      = EXCLUDED.cvss_vector,
      epss             = EXCLUDED.epss,
      published_on     = EXCLUDED.published_on,
      updated_on       = EXCLUDED.updated_on,
      public_exploit   = EXCLUDED.public_exploit,
      exploit_verified = EXCLUDED.exploit_verified,
      exploit_in_kit   = EXCLUDED.exploit_in_kit,
      exploit_types    = EXCLUDED.exploit_types,
      exploit_uris     = EXCLUDED.exploit_uris,
      cve_json         = EXCLUDED.cve_json,
      updated_at       = now();
    """
    with pg.conn() as c:
        with c.cursor() as cur:
            execute_values(
                cur, sql, rows,
                template="""(
                  %s,%s,%s,%s,
                  %s,%s,%s,
                  %s::timestamptz,%s::timestamptz,
                  %s,%s,%s,
                  %s::jsonb,%s::jsonb,
                  %s::jsonb,
                  now(),now()
                )""",
                page_size=200,
            )
    LOG.info("upsert_cves: %d CVEs processed", len(rows))
    return (len(rows), cve_map)


def ensure_cve_stubs(pg: Pg, cve_ids_needed: List[str], dry_run: bool) -> None:
    if not cve_ids_needed:
        return
    if dry_run:
        LOG.info("[DRY-RUN] ensure_cve_stubs: %d (not written)", len(cve_ids_needed))
        return
    with pg.conn() as c:
        with c.cursor() as cur:
            execute_values(
                cur,
                "INSERT INTO public.mde_cve (cve_id, created_at, updated_at) VALUES %s "
                "ON CONFLICT (cve_id) DO NOTHING;",
                [(cid,) for cid in cve_ids_needed],
                template="(%s, now(), now())",
                page_size=1000,
            )


def ensure_asset_stub_one(pg: Pg, r: Dict[str, Any], dry_run: bool) -> None:
    if dry_run:
        return
    did = to_text(r.get("deviceId"))
    if not did:
        return
    pg.exec(
        """
        INSERT INTO public.mde_asset (
          device_id, computer_dns_name, device_name, rbac_group_name,
          os_platform, os_version, os_architecture,
          machine_tags, inventory_json,
          created_at, updated_at
        ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s::jsonb, now(), now())
        ON CONFLICT (device_id) DO NOTHING;
        """,
        (
            did,
            to_text(r.get("computerDnsName") or r.get("deviceName")),
            to_text(r.get("deviceName")),
            to_text(r.get("rbacGroupName")),
            to_text(r.get("osPlatform")),
            to_text(r.get("osVersion")),
            to_text(r.get("osArchitecture")),
            to_json_str([]),
            to_json_str({"stub": True}),
        ),
    )


def ensure_cve_stub_one(pg: Pg, cve_id: str, dry_run: bool) -> None:
    if dry_run:
        return
    if not cve_id:
        return
    pg.exec(
        "INSERT INTO public.mde_cve (cve_id, created_at, updated_at) VALUES (%s, now(), now()) "
        "ON CONFLICT (cve_id) DO NOTHING;",
        (cve_id,),
    )


# ----------------------------
# Insert asset_vuln (CORREGIDO)
# ----------------------------

def insert_asset_vulns(
    pg: Pg,
    soft_vulns: List[Dict[str, Any]],
    run_ts: datetime,
    windows_only: bool,
    include_evidence: bool,
    fixing_kb_idx: Optional[Dict[Tuple[str, str, str, str, str], str]],
    dry_run: bool,
    batch_size: int = 500,
) -> Tuple[int, int]:
    sql = """
    INSERT INTO public.mde_asset_vuln (
      run_ts, device_id, cve_id,
      software_vendor, software_name, software_version,
      cvss_score, exploitability_level,
      first_seen, last_seen,
      security_update_available,
      recommended_security_update_id, recommended_security_update,
      fixing_kb_id,
      evidence_json, row_json,
      created_at
    ) VALUES %s
    ON CONFLICT (run_ts, device_id, cve_id, software_vendor, software_name, software_version)
    DO UPDATE SET
      cvss_score                      = EXCLUDED.cvss_score,
      exploitability_level            = EXCLUDED.exploitability_level,
      first_seen                      = EXCLUDED.first_seen,
      last_seen                       = EXCLUDED.last_seen,
      security_update_available       = EXCLUDED.security_update_available,
      recommended_security_update_id  = EXCLUDED.recommended_security_update_id,
      recommended_security_update     = EXCLUDED.recommended_security_update,
      fixing_kb_id                    = COALESCE(EXCLUDED.fixing_kb_id, public.mde_asset_vuln.fixing_kb_id),
      evidence_json                   = EXCLUDED.evidence_json,
      row_json                        = EXCLUDED.row_json;
    """
    tmpl = """(
      %s::timestamptz,%s,%s,
      %s,%s,%s,
      %s::numeric,%s,
      %s::timestamptz,%s::timestamptz,
      %s,%s,%s,
      %s,
      %s::jsonb,%s::jsonb,
      now()
    )"""

    run_ts_str = run_ts.replace(microsecond=0).isoformat()

    def flush(batch: List[tuple]) -> int:
        if not batch:
            return 0
        if dry_run:
            LOG.debug("[DRY-RUN] asset_vuln batch %d rows (not written)", len(batch))
            return len(batch)
        try:
            with pg.conn() as c:
                with c.cursor() as cur:
                    execute_values(cur, sql, batch, template=tmpl, page_size=200)
            return len(batch)
        except Exception as e:
            sample = batch[0] if batch else None
            LOG.error("asset_vuln batch failed: %s | sample=%s", e, sample, exc_info=True)
            raise

    total = 0
    upserted = 0
    skipped_os = 0
    skipped_missing_device = 0
    skipped_missing_cve = 0

    rows: List[tuple] = []

    for r in soft_vulns:
        total += 1

        device_id = to_text(r.get("deviceId"))
        cve_id = to_text(r.get("cveId"))

        if not device_id:
            skipped_missing_device += 1
            continue
        if not cve_id:
            skipped_missing_cve += 1
            continue

        if windows_only and not is_windows(to_text(r.get("osPlatform")) or ""):
            skipped_os += 1
            continue

        ensure_asset_stub_one(pg, r, dry_run)
        ensure_cve_stub_one(pg, cve_id, dry_run)

        vendor = to_text(r.get("softwareVendor")) or "unknown"
        name = to_text(r.get("softwareName")) or "unknown"
        ver = to_text(r.get("softwareVersion")) or "unknown"

        kb: Optional[str] = None
        if fixing_kb_idx is not None:
            kb = fixing_kb_idx.get((device_id, cve_id, vendor.lower(), name.lower(), ver))

        evidence_json: Optional[str] = None
        if include_evidence:
            evidence_json = to_json_str({
                "diskPaths": r.get("diskPaths"),
                "registryPaths": r.get("registryPaths"),
            })

        cvss_raw = r.get("cvssScore")
        try:
            cvss = float(cvss_raw) if cvss_raw is not None else None
        except (ValueError, TypeError):
            cvss = None

        rows.append((
            run_ts_str,
            device_id,
            cve_id,
            vendor,
            name,
            ver,
            cvss,
            to_text(r.get("exploitabilityLevel")),
            to_ts_str(r.get("firstSeenTimestamp")),
            to_ts_str(r.get("lastSeenTimestamp")),
            r.get("securityUpdateAvailable"),
            to_text(r.get("recommendedSecurityUpdateId")),
            to_text(r.get("recommendedSecurityUpdate")),
            to_text(kb),
            evidence_json,
            to_json_str(r),
        ))

        if len(rows) >= batch_size:
            upserted += flush(rows)
            rows = []

    if rows:
        upserted += flush(rows)

    LOG.info(
        "asset_vuln: total=%d | upserted=%d | skip_os=%d | missing_device=%d | missing_cve=%d",
        total, upserted, skipped_os, skipped_missing_device, skipped_missing_cve,
    )

    if not dry_run:
        cnt = pg.fetchval(
            "SELECT count(*) FROM public.mde_asset_vuln WHERE run_ts=%s::timestamptz;",
            (run_ts_str,),
        )
        LOG.info("asset_vuln rows in DB for run_ts=%s => %s", run_ts_str, cnt)

    return (total, upserted)


# ----------------------------
# Args / Main
# ----------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="MDE ETL -> PostgreSQL public.mde_*")
    p.add_argument("--tenant-id",         default=None)
    p.add_argument("--client-id",         default=None)
    p.add_argument("--client-secret",     default=None)
    p.add_argument("--pg-host",           default=None)
    p.add_argument("--pg-port",           type=int, default=None)
    p.add_argument("--pg-db",             default=None)
    p.add_argument("--pg-user",           default=None)
    p.add_argument("--pg-pass",           default=None)
    p.add_argument("--pg-sslmode",        default=None)
    p.add_argument("--api-base",          default="https://api.security.microsoft.com")
    p.add_argument("--scope",             default="https://api.securitycenter.microsoft.com/.default")
    p.add_argument("--timeout",           type=int, default=60)
    p.add_argument("--page-size",         type=int, default=50000)
    p.add_argument("--since-time",        default=None)
    p.add_argument("--all-os",            action="store_true")
    p.add_argument("--include-evidence",  action="store_true")
    p.add_argument("--no-cve-details",    action="store_true")
    p.add_argument("--max-cve-details",   type=int, default=3000)
    p.add_argument("--include-fixing-kb", action="store_true")
    p.add_argument("--batch-size",        type=int, default=500)
    p.add_argument("--dry-run",           action="store_true")
    p.add_argument("--log-level",         default="INFO",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return p.parse_args()


def main() -> int:
    args = parse_args()
    setup_logging(args.log_level)

    windows_only = not args.all_os

    tenant_id     = (args.tenant_id
                     or read_secret("mde_tenant_id",       "MDE_TENANT_ID")
                     or read_secret("azure_tenant_id",     "AZURE_TENANT_ID"))
    client_id     = (args.client_id
                     or read_secret("mde_client_id",       "MDE_CLIENT_ID")
                     or read_secret("azure_client_id",     "AZURE_CLIENT_ID"))
    client_secret = (args.client_secret
                     or read_secret("mde_client_secret",   "MDE_CLIENT_SECRET")
                     or read_secret("azure_client_secret", "AZURE_CLIENT_SECRET"))

    pg_host    = (args.pg_host
                  or (os.getenv("PGHOST",         "").strip())
                  or (os.getenv("DATABASE_HOST",  "").strip())
                  or (os.getenv("DB_HOST",        "").strip())
                  or read_secret("postgres_host", "PG_HOST", "")
                  or read_secret("db_host",       "",        "")
                  or "appdb")
    pg_port    = args.pg_port    or int(read_secret("postgres_port", "PG_PORT",    "5432") or "5432")
    pg_db      = args.pg_db      or read_secret("postgres_db",       "PG_DB",      "aap_analytics")
    pg_user    = args.pg_user    or read_secret("postgres_user",     "PG_USER",    "")
    pg_pass    = args.pg_pass    or read_secret("postgres_password", "PG_PASS",    "")
    pg_sslmode = args.pg_sslmode or read_secret("postgres_sslmode",  "PG_SSLMODE", "disable")

    if not tenant_id:
        die("Missing MDE tenant_id. Use /run/secrets/mde_tenant_id or --tenant-id")
    if not client_id:
        die("Missing MDE client_id. Use /run/secrets/mde_client_id or --client-id")
    if not client_secret:
        die("Missing MDE client_secret. Use /run/secrets/mde_client_secret or --client-secret")
    if not pg_user:
        die("Missing postgres_user. Use /run/secrets/postgres_user or --pg-user")
    if not pg_pass:
        die("Missing postgres_password. Use /run/secrets/postgres_password or --pg-pass")

    LOG.info("=== MDE ETL START ===")
    LOG.info("api_base=%s  windows_only=%s  page_size=%d  dry_run=%s",
             args.api_base, windows_only, args.page_size, args.dry_run)
    LOG.info("pg=%s:%s/%s  sslmode=%s", pg_host, pg_port, pg_db, pg_sslmode)
    if args.since_time:
        LOG.info("since_time=%s (delta export)", args.since_time)

    pg = Pg(host=pg_host, port=pg_port, dbname=pg_db,
            user=pg_user, password=pg_pass, sslmode=pg_sslmode)
    if not args.dry_run:
        pg.init()

    mde = MDEClient(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
        api_base=args.api_base,
        scope=args.scope,
        timeout=args.timeout,
    )

    run_ts = utc_now()
    rid_main = None
    if not args.dry_run:
        try:
            rid_main = run_start(pg, "mde", "full_run")
        except Exception as e:
            LOG.warning("Could not register etl_run: %s", e)

    total_fetched = 0
    total_written = 0
    error_msg = ""

    try:
        LOG.info("--- STEP 1: machines -> public.mde_asset ---")
        machines = fetch_machines(mde)
        total_fetched += len(machines)
        total_written += upsert_assets(pg, machines, args.dry_run)

        LOG.info("--- STEP 2: SoftwareVulnerabilitiesByMachine ---")
        soft_vulns = fetch_soft_vulns(mde, args.page_size, args.since_time)
        total_fetched += len(soft_vulns)

        seen_cves: Set[str] = set()
        unique_cves: List[str] = []
        for r in soft_vulns:
            cid = to_text(r.get("cveId"))
            if cid and cid not in seen_cves:
                seen_cves.add(cid)
                unique_cves.append(cid)
        LOG.info("Unique CVEs observed: %d", len(unique_cves))

        if not args.no_cve_details:
            LOG.info("--- STEP 3: CVE details -> public.mde_cve ---")
            n_cves, _cve_map = upsert_cves(pg, mde, unique_cves, args.max_cve_details, args.dry_run)
            total_fetched += n_cves
            total_written += n_cves
        else:
            LOG.info("--- STEP 3: CVE details skipped (--no-cve-details) ---")

        LOG.info("--- STEP 3b: Ensure CVE stubs for ALL observed CVEs ---")
        ensure_cve_stubs(pg, unique_cves, args.dry_run)

        fixing_kb_idx: Optional[Dict[Tuple[str, str, str, str, str], str]] = None
        if args.include_fixing_kb:
            LOG.info("--- STEP 4: fixingKb index ---")
            fixing_kb_idx = fetch_fixing_kb_index(mde)
            total_fetched += len(fixing_kb_idx)

        LOG.info("--- STEP 5: asset_vuln insert/upsert (run_ts=%s) ---", run_ts.isoformat())
        n_total, n_ins = insert_asset_vulns(
            pg=pg,
            soft_vulns=soft_vulns,
            run_ts=run_ts,
            windows_only=windows_only,
            include_evidence=args.include_evidence,
            fixing_kb_idx=fixing_kb_idx,
            dry_run=args.dry_run,
            batch_size=args.batch_size,
        )
        total_fetched += n_total
        total_written += n_ins

    except Exception as e:
        error_msg = str(e)
        LOG.error("ETL FAILED: %s", e, exc_info=True)

    if rid_main is not None:
        try:
            run_finish(pg, rid_main,
                       "ok" if not error_msg else "failed",
                       total_fetched, total_written, error_msg)
        except Exception as e2:
            LOG.warning("Could not update etl_run: %s", e2)

    if not args.dry_run:
        pg.close()

    if error_msg:
        LOG.error("=== MDE ETL FAILED ===")
        return 1

    LOG.info(
        "=== MDE ETL DONE === run_ts=%s  fetched=%d  written=%d",
        run_ts.isoformat(), total_fetched, total_written,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
