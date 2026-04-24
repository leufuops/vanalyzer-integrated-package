from __future__ import annotations

import json
import logging
import os
import random
import sys
import time
import traceback
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Generator, List, Optional, Set, Tuple

import psycopg2
import psycopg2.extras
from psycopg2.extras import execute_values
from psycopg2.pool import SimpleConnectionPool

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

LOG = logging.getLogger("tm_etl")

SECRETS_DIR = os.getenv("SECRETS_DIR", "/run/secrets")


def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stderr,
    )


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


def die(msg: str, code: int = 2) -> None:
    LOG.critical(msg)
    sys.exit(code)


def backoff_sleep(attempt: int) -> None:
    time.sleep(0.8 * (2 ** (attempt - 1)) + random.random() * 0.3)


def safe_json(resp: requests.Response) -> Dict[str, Any]:
    try:
        return resp.json()
    except Exception:
        return {"_http_status": resp.status_code, "_text": resp.text[:2000]}


def parse_ts(v: Any) -> Optional[str]:
    if not isinstance(v, str) or not v.strip():
        return None
    s = v.strip()
    try:
        s2 = s[:-1] + "+00:00" if s.endswith("Z") else s
        return datetime.fromisoformat(s2).astimezone(timezone.utc).isoformat()
    except Exception:
        return None


def to_json_str(v: Any) -> Optional[str]:
    if v is None:
        return None
    try:
        return json.dumps(v, ensure_ascii=False, default=str)
    except Exception:
        return json.dumps(str(v))


def ensure_list(v: Any) -> List[Any]:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def norm_hostname(v: Any) -> str:
    if not isinstance(v, str) or not v.strip():
        return ""
    return v.strip().lower().split(".")[0]


class Pg:
    def __init__(self, host: str, port: int, dbname: str,
                 user: str, password: str, sslmode: str = "disable") -> None:
        self._dsn = (
            f"host={host} port={port} dbname={dbname} "
            f"user={user} password={password} sslmode={sslmode}"
        )
        self._pool: Optional[SimpleConnectionPool] = None

    def init(self) -> None:
        if not self._pool:
            self._pool = SimpleConnectionPool(1, 5, self._dsn)
            LOG.info("PG pool initialized")

    @contextmanager
    def conn(self) -> Generator:
        if not self._pool:
            self.init()
        c = self._pool.getconn()  # type: ignore
        try:
            yield c
            c.commit()
        except Exception:
            c.rollback()
            raise
        finally:
            self._pool.putconn(c)  # type: ignore

    def close(self) -> None:
        if self._pool:
            self._pool.closeall()
            self._pool = None

    def fetchone(self, sql: str, args: tuple = ()) -> Optional[tuple]:
        with self.conn() as c:
            with c.cursor() as cur:
                cur.execute(sql, args)
                return cur.fetchone()

    def fetchval(self, sql: str, args: tuple = ()) -> Any:
        row = self.fetchone(sql, args)
        return row[0] if row else None

    def exec(self, sql: str, args: tuple = ()) -> None:
        with self.conn() as c:
            with c.cursor() as cur:
                cur.execute(sql, args)


class TMHTTP:
    def __init__(self, base_url: str, api_key: str, cfg: Dict[str, Any]) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key  = api_key
        self.cfg      = cfg
        self.sess     = requests.Session()
        adapter = HTTPAdapter(
            max_retries=Retry(
                total=cfg["max_retries"],
                backoff_factor=1.5,
                status_forcelist=(500, 502, 503, 504),
                allowed_methods=frozenset(["GET", "POST"]),
                raise_on_status=False,
            ),
            pool_connections=10,
            pool_maxsize=10,
        )
        self.sess.mount("https://", adapter)
        self.sess.mount("http://",  adapter)

    @property
    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Accept":        "application/json",
        }

    def get(self, path_or_url: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        url = path_or_url if path_or_url.startswith("http") else f"{self.base_url}{path_or_url}"
        retries_429 = 0
        for attempt in range(1, self.cfg["max_retries"] + 1):
            try:
                r = self.sess.get(url, headers=self._headers,
                                  params=params or {}, timeout=self.cfg["timeout"])
            except Exception as e:
                LOG.warning("GET %s attempt %d: %s", url, attempt, e)
                if attempt == self.cfg["max_retries"]:
                    return {"_exception": str(e)}
                backoff_sleep(attempt)
                continue

            if r.status_code == 429:
                wait = int(r.headers.get("Retry-After", 65))
                retries_429 += 1
                if retries_429 > 5:
                    LOG.error("GET %s: too many 429s", url)
                    return {"_http_error": 429}
                LOG.warning("GET %s: 429 - waiting %ds", url, wait)
                time.sleep(wait)
                continue

            if r.status_code == 200:
                return safe_json(r)
            if r.status_code in (401, 403):
                die(f"TrendMicro GET {url}: HTTP {r.status_code} - invalid token or missing permissions")
            if r.status_code in (500, 502, 503, 504):
                LOG.warning("GET %s HTTP %d, retry %d", url, r.status_code, attempt)
                backoff_sleep(attempt)
                continue
            LOG.error("GET %s HTTP %d: %s", url, r.status_code, r.text[:400])
            return {"_http_error": r.status_code, "_text": r.text[:400]}

        return {"_exception": "max retries"}


def run_start(pg: Pg, base_url: str) -> int:
    row = pg.fetchone(
        "INSERT INTO public.trendmicro_etl_runs (status, api_base_url) "
        "VALUES ('running', %s) RETURNING run_id",
        (base_url,),
    )
    assert row
    return int(row[0])


def run_finish(
    pg: Pg, run_id: int, status: str,
    rows_endpoints: int, rows_alerts: int, rows_oat: int,
    error_message: Optional[str] = None,
    error_detail: Optional[str] = None,
) -> None:
    pg.exec(
        "UPDATE public.trendmicro_etl_runs SET "
        "finished_at=now(), status=%s, "
        "rows_endpoints=%s, rows_alerts=%s, rows_oat=%s, "
        "error_message=%s, error_detail=%s "
        "WHERE run_id=%s",
        (status, rows_endpoints, rows_alerts, rows_oat,
         error_message, error_detail, run_id),
    )


def fetch_paginated(
    client: TMHTTP,
    path: str,
    page_size: int,
    max_items: int,
    label: str,
) -> List[Dict]:
    all_items: List[Dict] = []
    params: Dict[str, Any] = {"top": page_size}
    next_ref: Optional[str] = path
    next_params: Optional[Dict] = params
    page = 0

    while next_ref:
        page += 1
        resp = client.get(next_ref, next_params)
        if resp.get("_exception") or resp.get("_http_error"):
            LOG.warning("%s: fetch error page %d: %s", label, page, resp)
            break

        items: List[Any] = []
        if isinstance(resp, list):
            items = resp
        elif isinstance(resp, dict):
            for key in ("items", "data", "rows", "result", "list",
                        "endpoints", "alerts", "detections"):
                val = resp.get(key)
                if isinstance(val, list):
                    items = val
                    break
            if not items:
                for val in resp.values():
                    if isinstance(val, list) and val:
                        items = val
                        break

        all_items.extend(i for i in items if isinstance(i, dict))
        LOG.info("%s: page %d -> +%d (total %d)", label, page, len(items), len(all_items))

        if max_items and len(all_items) >= max_items:
            all_items = all_items[:max_items]
            LOG.warning("%s: cut at max_items=%d", label, max_items)
            break

        next_link = None
        if isinstance(resp, dict):
            for key in ("nextLink", "next_link", "next"):
                val = resp.get(key)
                if isinstance(val, str) and (val.startswith("/") or val.startswith("http")):
                    next_link = val
                    break

        if not next_link or not items:
            break
        next_ref   = next_link
        next_params = None

        time.sleep(client.cfg["sleep"])

    LOG.info("%s: %d total fetched", label, len(all_items))
    return all_items


def fetch_endpoint_detail(client: TMHTTP, agent_guid: str) -> Optional[Dict]:
    resp = client.get(f"/v3.0/endpointSecurity/endpoints/{agent_guid}")
    if resp.get("_exception") or resp.get("_http_error"):
        return None
    return resp if isinstance(resp, dict) else None


def fetch_alert_detail(client: TMHTTP, alert_id: str) -> Optional[Dict]:
    resp = client.get(f"/v3.0/workbench/alerts/{alert_id}")
    if resp.get("_exception") or resp.get("_http_error"):
        return None
    return resp if isinstance(resp, dict) else None


def upsert_endpoints(
    pg: Pg,
    endpoints: List[Dict],
    details_map: Dict[str, Dict],
    dry_run: bool,
) -> Tuple[int, int]:
    if not endpoints:
        return 0, 0

    ep_rows  = []
    ifc_rows = []

    for inv in endpoints:
        guid = inv.get("agentGuid")
        if not isinstance(guid, str) or not guid:
            continue

        det  = details_map.get(guid, {})
        os_b = det.get("os") or {}
        epp  = (det.get("eppAgent") or inv.get("eppAgent")) or {}
        edr  = (det.get("edrSensor") or inv.get("edrSensor")) or {}

        ep_rows.append((
            guid,
            inv.get("endpointName") or det.get("endpointName") or "",
            det.get("description"),
            inv.get("type") or det.get("type"),
            inv.get("osName")         or os_b.get("name"),
            inv.get("osVersion")      or os_b.get("version"),
            inv.get("osPlatform")     or os_b.get("platform"),
            inv.get("osArchitecture") or os_b.get("architecture"),
            inv.get("osKernelVersion") or os_b.get("kernelVersion"),
            det.get("cpuArchitecture"),
            inv.get("lastUsedIp") or det.get("lastUsedIp"),
            inv.get("isolationStatus") or det.get("isolationStatus"),
            det.get("serviceGatewayOrProxy"),
            det.get("securityPolicy"),
            det.get("securityPolicyOverriddenStatus"),
            inv.get("creditAllocatedLicenses") or [],
            epp.get("status"),
            epp.get("version"),
            epp.get("componentVersion"),
            epp.get("componentUpdateStatus"),
            epp.get("policyName"),
            epp.get("endpointGroup"),
            epp.get("protectionManager"),
            parse_ts(epp.get("lastConnectedDateTime")),
            parse_ts(epp.get("lastScannedDateTime")),
            epp.get("productNames") or [],
            edr.get("status"),
            edr.get("connectivity"),
            edr.get("version"),
            parse_ts(edr.get("lastConnectedDateTime")),
            edr.get("advancedRiskTelemetryStatus"),
            edr.get("componentUpdateStatus"),
            edr.get("endpointGroup"),
            to_json_str(inv),
            to_json_str(det) if det else None,
        ))

        for iface in ensure_list(det.get("interfaces")):
            if not isinstance(iface, dict):
                continue
            mac = iface.get("macAddress")
            ips = [str(ip) for ip in ensure_list(iface.get("ipAddresses")) if ip]
            if mac or ips:
                ifc_rows.append((guid, mac, ips))

    if dry_run:
        LOG.info("[DRY-RUN] upsert_endpoints: %d rows, %d ifaces", len(ep_rows), len(ifc_rows))
        return len(ep_rows), len(ifc_rows)

    ep_sql = """
    INSERT INTO public.trendmicro_endpoint (
      agent_guid, endpoint_name, description, type,
      os_name, os_version, os_platform, os_architecture, os_kernel_version,
      cpu_architecture, last_used_ip, isolation_status,
      service_gateway_or_proxy, security_policy, security_policy_overridden,
      credit_allocated_licenses,
      epp_status, epp_version, epp_component_version, epp_component_update_status,
      epp_policy_name, epp_endpoint_group, epp_protection_manager,
      epp_last_connected_at, epp_last_scanned_at, epp_product_names,
      edr_status, edr_connectivity, edr_version, edr_last_connected_at,
      edr_advanced_risk_telemetry, edr_component_update_status, edr_endpoint_group,
      raw_inventory, raw_detail
    ) VALUES %s
    ON CONFLICT (agent_guid) DO UPDATE SET
      endpoint_name                = EXCLUDED.endpoint_name,
      description                  = EXCLUDED.description,
      type                         = EXCLUDED.type,
      os_name                      = EXCLUDED.os_name,
      os_version                   = EXCLUDED.os_version,
      os_platform                  = EXCLUDED.os_platform,
      os_architecture              = EXCLUDED.os_architecture,
      os_kernel_version            = EXCLUDED.os_kernel_version,
      cpu_architecture             = EXCLUDED.cpu_architecture,
      last_used_ip                 = EXCLUDED.last_used_ip,
      isolation_status             = EXCLUDED.isolation_status,
      service_gateway_or_proxy     = EXCLUDED.service_gateway_or_proxy,
      security_policy              = EXCLUDED.security_policy,
      security_policy_overridden   = EXCLUDED.security_policy_overridden,
      credit_allocated_licenses    = EXCLUDED.credit_allocated_licenses,
      epp_status                   = EXCLUDED.epp_status,
      epp_version                  = EXCLUDED.epp_version,
      epp_component_version        = EXCLUDED.epp_component_version,
      epp_component_update_status  = EXCLUDED.epp_component_update_status,
      epp_policy_name              = EXCLUDED.epp_policy_name,
      epp_endpoint_group           = EXCLUDED.epp_endpoint_group,
      epp_protection_manager       = EXCLUDED.epp_protection_manager,
      epp_last_connected_at        = EXCLUDED.epp_last_connected_at,
      epp_last_scanned_at          = EXCLUDED.epp_last_scanned_at,
      epp_product_names            = EXCLUDED.epp_product_names,
      edr_status                   = EXCLUDED.edr_status,
      edr_connectivity             = EXCLUDED.edr_connectivity,
      edr_version                  = EXCLUDED.edr_version,
      edr_last_connected_at        = EXCLUDED.edr_last_connected_at,
      edr_advanced_risk_telemetry  = EXCLUDED.edr_advanced_risk_telemetry,
      edr_component_update_status  = EXCLUDED.edr_component_update_status,
      edr_endpoint_group           = EXCLUDED.edr_endpoint_group,
      raw_inventory                = EXCLUDED.raw_inventory,
      raw_detail                   = EXCLUDED.raw_detail,
      ingested_at                  = now()
    """

    ep_tmpl = (
        "(%s,%s,%s,%s,"
        " %s,%s,%s,%s,%s,"
        " %s,%s,%s,%s,%s,%s,"
        " %s::text[],"
        " %s,%s,%s,%s,%s,%s,%s,"
        " %s::timestamptz,%s::timestamptz,%s::text[],"
        " %s,%s,%s,%s::timestamptz,%s,%s,%s,"
        " %s::jsonb,%s::jsonb)"
    )

    with pg.conn() as c:
        with c.cursor() as cur:
            execute_values(cur, ep_sql, ep_rows, template=ep_tmpl, page_size=100)

    if ifc_rows:
        ifc_sql = """
        INSERT INTO public.trendmicro_endpoint_iface (agent_guid, mac_address, ip_addresses)
        VALUES %s
        ON CONFLICT DO NOTHING
        """
        ifc_tmpl = "(%s, %s, %s::text[])"
        with pg.conn() as c:
            with c.cursor() as cur:
                cur.execute(
                    "DELETE FROM public.trendmicro_endpoint_iface "
                    "WHERE agent_guid = ANY(%s)",
                    ([row[0] for row in ep_rows],),
                )
                execute_values(cur, ifc_sql, ifc_rows, template=ifc_tmpl, page_size=500)

    LOG.info("upsert_endpoints: %d endpoints, %d interfaces", len(ep_rows), len(ifc_rows))
    return len(ep_rows), len(ifc_rows)


def upsert_alerts(
    pg: Pg,
    alerts: List[Dict],
    details_map: Dict[str, Dict],
    dry_run: bool,
) -> Tuple[int, int]:
    if not alerts:
        return 0, 0

    alert_rows: List[tuple] = []
    host_rows:  List[tuple] = []

    for a in alerts:
        alert_id = a.get("id")
        if not isinstance(alert_id, str) or not alert_id:
            continue

        det = details_map.get(alert_id, {})
        merged = {}
        merged.update(det)
        merged.update(a)

        scope = merged.get("impactScope") or {}

        techniques: List[str] = []
        rule_names: List[str] = []
        for rule in ensure_list(merged.get("matchedRules")):
            if not isinstance(rule, dict):
                continue
            if rule.get("name"):
                rule_names.append(str(rule["name"]))
            for mf in ensure_list(rule.get("matchedFilters")):
                if not isinstance(mf, dict):
                    continue
                for t in ensure_list(mf.get("mitreTechniqueIds")):
                    if t:
                        techniques.append(str(t))

        techniques = list(dict.fromkeys(techniques))
        rule_names = list(dict.fromkeys(rule_names))

        alert_rows.append((
            alert_id,
            merged.get("incidentId"),
            merged.get("schemaVersion"),
            merged.get("status"),
            merged.get("investigationStatus"),
            merged.get("investigationResult"),
            merged.get("alertProvider"),
            merged.get("modelId"),
            merged.get("model"),
            merged.get("modelType"),
            merged.get("score"),
            merged.get("severity"),
            merged.get("description"),
            merged.get("workbenchLink"),
            parse_ts(merged.get("createdDateTime")),
            parse_ts(merged.get("updatedDateTime")),
            scope.get("desktopCount"),
            scope.get("serverCount"),
            scope.get("accountCount"),
            scope.get("containerCount"),
            techniques,
            rule_names,
            to_json_str(merged),
        ))

        for entity in ensure_list(scope.get("entities")):
            if not isinstance(entity, dict):
                continue
            etype = str(entity.get("entityType", "")).lower()
            evalue = entity.get("entityValue")

            hostname    = None
            agent_guid  = None
            ips: List[str] = []

            if etype == "host":
                if isinstance(evalue, dict):
                    hostname   = evalue.get("name")
                    agent_guid = evalue.get("guid")
                    ips = [str(ip) for ip in ensure_list(evalue.get("ips")) if ip and str(ip).strip()]
                elif isinstance(evalue, str):
                    hostname = evalue

            host_rows.append((
                alert_id,
                agent_guid,
                hostname,
                etype,
                to_json_str(evalue),
                ips,
            ))

    if dry_run:
        LOG.info("[DRY-RUN] upsert_alerts: %d alerts, %d host rows", len(alert_rows), len(host_rows))
        return len(alert_rows), len(host_rows)

    alert_sql = """
    INSERT INTO public.trendmicro_alert (
      alert_id, incident_id, schema_version,
      status, investigation_status, investigation_result,
      alert_provider, model_id, model, model_type,
      score, severity, description, workbench_link,
      created_at, updated_at,
      impact_desktop_count, impact_server_count,
      impact_account_count, impact_container_count,
      mitre_technique_ids, matched_rule_names,
      raw
    ) VALUES %s
    ON CONFLICT (alert_id) DO UPDATE SET
      incident_id            = EXCLUDED.incident_id,
      schema_version         = EXCLUDED.schema_version,
      status                 = EXCLUDED.status,
      investigation_status   = EXCLUDED.investigation_status,
      investigation_result   = EXCLUDED.investigation_result,
      alert_provider         = EXCLUDED.alert_provider,
      model_id               = EXCLUDED.model_id,
      model                  = EXCLUDED.model,
      model_type             = EXCLUDED.model_type,
      score                  = EXCLUDED.score,
      severity               = EXCLUDED.severity,
      description            = EXCLUDED.description,
      workbench_link         = EXCLUDED.workbench_link,
      created_at             = EXCLUDED.created_at,
      updated_at             = EXCLUDED.updated_at,
      impact_desktop_count   = EXCLUDED.impact_desktop_count,
      impact_server_count    = EXCLUDED.impact_server_count,
      impact_account_count   = EXCLUDED.impact_account_count,
      impact_container_count = EXCLUDED.impact_container_count,
      mitre_technique_ids    = EXCLUDED.mitre_technique_ids,
      matched_rule_names     = EXCLUDED.matched_rule_names,
      raw                    = EXCLUDED.raw,
      ingested_at            = now()
    """

    alert_tmpl = (
        "(%s,%s,%s,"
        " %s,%s,%s,%s,%s,%s,%s,"
        " %s,%s,%s,%s,"
        " %s::timestamptz,%s::timestamptz,"
        " %s,%s,%s,%s,"
        " %s::text[],%s::text[],"
        " %s::jsonb)"
    )

    with pg.conn() as c:
        with c.cursor() as cur:
            execute_values(cur, alert_sql, alert_rows, template=alert_tmpl, page_size=100)

    if host_rows:
        with pg.conn() as c:
            with c.cursor() as cur:
                cur.execute(
                    "DELETE FROM public.trendmicro_alert_host "
                    "WHERE alert_id = ANY(%s)",
                    ([r[0] for r in alert_rows],),
                )
                host_sql = """
                INSERT INTO public.trendmicro_alert_host
                  (alert_id, agent_guid, endpoint_name, entity_type, entity_value, ips)
                VALUES %s
                """
                host_tmpl = "(%s,%s,%s,%s,%s::jsonb,%s::text[])"
                execute_values(cur, host_sql, host_rows, template=host_tmpl, page_size=200)

    LOG.info("upsert_alerts: %d alerts, %d host-entity rows", len(alert_rows), len(host_rows))
    return len(alert_rows), len(host_rows)


def insert_oat_detections(
    pg: Pg,
    oat_items: List[Dict],
    dry_run: bool,
    batch_size: int = 500,
) -> int:
    if not oat_items:
        return 0

    sql = """
    INSERT INTO public.trendmicro_oat_detection (
      uuid, agent_guid, endpoint_name, endpoint_ip,
      source, entity_type, detected_at, ingested_at_api,
      filter_ids, filter_names, filter_risk_level,
      mitre_tactic_ids, mitre_technique_ids,
      process_name, process_cmd, process_user, process_file_sha256,
      object_name, object_cmd, event_name, logon_user,
      raw_detail
    ) VALUES %s
    ON CONFLICT (uuid) DO UPDATE SET
      agent_guid          = EXCLUDED.agent_guid,
      endpoint_name       = EXCLUDED.endpoint_name,
      endpoint_ip         = EXCLUDED.endpoint_ip,
      source              = EXCLUDED.source,
      entity_type         = EXCLUDED.entity_type,
      detected_at         = EXCLUDED.detected_at,
      ingested_at_api     = EXCLUDED.ingested_at_api,
      filter_ids          = EXCLUDED.filter_ids,
      filter_names        = EXCLUDED.filter_names,
      filter_risk_level   = EXCLUDED.filter_risk_level,
      mitre_tactic_ids    = EXCLUDED.mitre_tactic_ids,
      mitre_technique_ids = EXCLUDED.mitre_technique_ids,
      process_name        = EXCLUDED.process_name,
      process_cmd         = EXCLUDED.process_cmd,
      process_user        = EXCLUDED.process_user,
      process_file_sha256 = EXCLUDED.process_file_sha256,
      object_name         = EXCLUDED.object_name,
      object_cmd          = EXCLUDED.object_cmd,
      event_name          = EXCLUDED.event_name,
      logon_user          = EXCLUDED.logon_user,
      raw_detail          = EXCLUDED.raw_detail,
      ingested_at         = now()
    """

    tmpl = (
        "(%s,%s,%s,%s::text[],"
        " %s,%s,%s::timestamptz,%s::timestamptz,"
        " %s::text[],%s::text[],%s,"
        " %s::text[],%s::text[],"
        " %s,%s,%s,%s,"
        " %s,%s,%s,%s::text[],"
        " %s::jsonb)"
    )

    def flush(batch: List[tuple]) -> int:
        if not batch:
            return 0
        if dry_run:
            LOG.debug("[DRY-RUN] oat batch %d", len(batch))
            return len(batch)
        try:
            with pg.conn() as c:
                with c.cursor() as cur:
                    execute_values(cur, sql, batch, template=tmpl, page_size=200)
            return len(batch)
        except Exception as e:
            LOG.error("OAT batch failed: %s", e, exc_info=True)
            raise

    inserted = 0
    batch: List[tuple] = []

    for item in oat_items:
        uuid = item.get("uuid")
        if not isinstance(uuid, str) or not uuid:
            continue

        ep     = item.get("endpoint") or {}
        det    = item.get("detail") or {}
        filters = ensure_list(item.get("filters"))

        filter_ids:   List[str] = []
        filter_names: List[str] = []
        tactic_ids:   List[str] = []
        tech_ids:     List[str] = []
        risk_level:   Optional[str] = None

        for f in filters:
            if not isinstance(f, dict):
                continue
            if f.get("id"):
                filter_ids.append(str(f["id"]))
            if f.get("name"):
                filter_names.append(str(f["name"]))
            if f.get("riskLevel") and not risk_level:
                risk_level = str(f["riskLevel"])
            for t in ensure_list(f.get("mitreTacticIds")):
                if t:
                    tactic_ids.append(str(t))
            for t in ensure_list(f.get("mitreTechniqueIds")):
                if t:
                    tech_ids.append(str(t))

        filter_ids   = list(dict.fromkeys(filter_ids))
        filter_names = list(dict.fromkeys(filter_names))
        tactic_ids   = list(dict.fromkeys(tactic_ids))
        tech_ids     = list(dict.fromkeys(tech_ids))

        ep_ips = [str(ip) for ip in ensure_list(ep.get("ips")) if ip]
        logon  = [str(u) for u in ensure_list(det.get("logonUser")) if u]

        detected_raw   = item.get("detectedDateTime")
        ingested_raw   = item.get("ingestedDateTime")

        batch.append((
            uuid,
            ep.get("agentGuid") or det.get("endpointGuid") or det.get("endpointGUID"),
            ep.get("endpointName") or det.get("endpointHostName"),
            ep_ips,
            item.get("source"),
            item.get("entityType"),
            parse_ts(detected_raw),
            parse_ts(ingested_raw),
            filter_ids,
            filter_names,
            risk_level,
            tactic_ids,
            tech_ids,
            det.get("processName"),
            det.get("processCmd"),
            det.get("processUser"),
            det.get("processFileHashSha256"),
            det.get("objectName"),
            det.get("objectCmd"),
            det.get("eventName"),
            logon,
            to_json_str(det),
        ))

        if len(batch) >= batch_size:
            inserted += flush(batch)
            batch = []

    if batch:
        inserted += flush(batch)

    LOG.info("insert_oat_detections: %d inserted", inserted)
    return inserted


def load_config() -> Dict[str, Any]:
    def req(secret: str, env: str) -> str:
        v = read_secret(secret, env_fallback=env)
        if not v:
            die(f"Secret '{secret}' / env '{env}' not found - required")
        return v

    return {
        "tm_api_key":   req("trendmicro_api_key",  "TM_API_KEY"),
        "tm_base_url":  read_secret("trendmicro_api_url", env_fallback="TM_BASE_URL",
                                    default="https://api.xdr.trendmicro.com"),
        "pg_db":        req("postgres_db",          "PGDATABASE"),
        "pg_user":      req("postgres_user",        "PGUSER"),
        "pg_password":  req("postgres_password",    "PGPASSWORD"),
        "pg_host":      os.getenv("POSTGRES_HOST",  "appdb"),
        "pg_port":      int(os.getenv("POSTGRES_PORT", "5432")),
        "pg_sslmode":   os.getenv("PG_SSLMODE",    "disable"),
        "page_size":    int(os.getenv("TM_PAGE_SIZE",   "200")),
        "timeout":      int(os.getenv("TM_TIMEOUT",     "90")),
        "max_retries":  int(os.getenv("TM_MAX_RETRIES", "6")),
        "sleep":        float(os.getenv("TM_SLEEP",     "0.25")),
        "batch_size":   int(os.getenv("TM_BATCH_SIZE",  "500")),
        "max_endpoints": int(os.getenv("TM_MAX_ENDPOINTS", "0")),
        "max_alerts":    int(os.getenv("TM_MAX_ALERTS",    "0")),
        "max_oat":       int(os.getenv("TM_MAX_OAT",       "0")),
        "log_level":    os.getenv("TM_LOG_LEVEL", "INFO").upper(),
    }


def main() -> int:
    cfg = load_config()
    setup_logging(cfg["log_level"])

    LOG.info("=== TrendMicro Vision One ETL starting ===")
    LOG.info("API URL   : %s", cfg["tm_base_url"])
    LOG.info("DB        : %s@%s:%s/%s (ssl=%s)",
             cfg["pg_user"], cfg["pg_host"], cfg["pg_port"],
             cfg["pg_db"], cfg["pg_sslmode"])

    pg = Pg(
        host=cfg["pg_host"], port=cfg["pg_port"],
        dbname=cfg["pg_db"], user=cfg["pg_user"],
        password=cfg["pg_password"], sslmode=cfg["pg_sslmode"],
    )
    pg.init()

    client = TMHTTP(cfg["tm_base_url"], cfg["tm_api_key"], cfg)

    run_id: Optional[int] = None
    try:
        run_id = run_start(pg, cfg["tm_base_url"])
        LOG.info("ETL run started: run_id=%d", run_id)
    except Exception as e:
        LOG.warning("Could not register trendmicro_etl_runs: %s", e)

    rows_endpoints = rows_alerts = rows_oat = 0
    error_msg:    Optional[str] = None
    error_detail: Optional[str] = None
    status = "error"

    try:
        LOG.info("--- STEP 1: endpointSecurity/endpoints ---")
        endpoints = fetch_paginated(
            client, "/v3.0/endpointSecurity/endpoints",
            cfg["page_size"], cfg["max_endpoints"], "endpoints",
        )
        LOG.info("Endpoints fetched: %d", len(endpoints))

        LOG.info("--- STEP 2: endpoint details (%d) ---", len(endpoints))
        details_map: Dict[str, Dict] = {}
        for i, ep in enumerate(endpoints, 1):
            guid = ep.get("agentGuid")
            if not isinstance(guid, str) or not guid:
                continue
            det = fetch_endpoint_detail(client, guid)
            if det:
                details_map[guid] = det
            if i % 25 == 0 or i == len(endpoints):
                LOG.info("  endpoint details: %d/%d fetched", len(details_map), i)
            time.sleep(cfg["sleep"])
        LOG.info("Endpoint details fetched: %d", len(details_map))

        rows_endpoints, _ = upsert_endpoints(pg, endpoints, details_map, False)

        LOG.info("--- STEP 3: workbench/alerts ---")
        alerts = fetch_paginated(
            client, "/v3.0/workbench/alerts",
            cfg["page_size"], cfg["max_alerts"], "alerts",
        )
        LOG.info("Alerts fetched: %d", len(alerts))

        LOG.info("--- STEP 4: alert details (%d) ---", len(alerts))
        alert_details_map: Dict[str, Dict] = {}
        for i, al in enumerate(alerts, 1):
            aid = al.get("id")
            if not isinstance(aid, str) or not aid:
                continue
            det = fetch_alert_detail(client, aid)
            if det:
                alert_details_map[aid] = det
            if i % 10 == 0 or i == len(alerts):
                LOG.info("  alert details: %d/%d fetched", len(alert_details_map), i)
            time.sleep(cfg["sleep"])
        LOG.info("Alert details fetched: %d", len(alert_details_map))

        rows_alerts, _ = upsert_alerts(pg, alerts, alert_details_map, False)

        LOG.info("--- STEP 5: oat/detections ---")
        oat_items = fetch_paginated(
            client, "/v3.0/oat/detections",
            cfg["page_size"], cfg["max_oat"], "oat_detections",
        )
        LOG.info("OAT detections fetched: %d", len(oat_items))

        rows_oat = insert_oat_detections(pg, oat_items, False, cfg["batch_size"])

        if run_id:
            cnt_ep  = pg.fetchval("SELECT count(*) FROM public.trendmicro_endpoint")
            cnt_al  = pg.fetchval("SELECT count(*) FROM public.trendmicro_alert")
            cnt_oat = pg.fetchval(
                "SELECT count(*) FROM public.trendmicro_oat_detection WHERE ingested_at >= "
                "(SELECT started_at FROM public.trendmicro_etl_runs WHERE run_id=%s)",
                (run_id,),
            )
            LOG.info("DB totals -> endpoints=%s | alerts=%s | oat(run)=%s",
                     cnt_ep, cnt_al, cnt_oat)

        status = "success"

    except SystemExit:
        raise
    except Exception as e:
        error_msg    = str(e)
        error_detail = traceback.format_exc()
        status       = "error"
        LOG.error("ETL FAILED: %s", e, exc_info=True)

    finally:
        if run_id is not None:
            try:
                run_finish(
                    pg, run_id, status,
                    rows_endpoints, rows_alerts, rows_oat,
                    error_msg, error_detail,
                )
                LOG.info("Run closed: run_id=%d status=%s", run_id, status)
            except Exception as fe:
                LOG.warning("Could not update trendmicro_etl_runs: %s", fe)
        pg.close()

    if status == "error":
        LOG.error("=== TrendMicro ETL FAILED === run_id=%s", run_id)
        return 1

    LOG.info("=== TrendMicro ETL OK | run_id=%s | endpoints=%d alerts=%d oat=%d ===",
             run_id, rows_endpoints, rows_alerts, rows_oat)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
