#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import json
import time
import gzip
import argparse
import ipaddress
import hashlib
import random
from datetime import datetime, date, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests
import psycopg2
from psycopg2.extras import execute_values, Json

_json_dumps = json.dumps
_json_dump = json.dump


def _json_default(o):
    if isinstance(o, (datetime, date)):
        return o.isoformat()
    return str(o)


def dumps(obj, **kwargs):
    kwargs.setdefault("default", _json_default)
    return _json_dumps(obj, **kwargs)


def dump(obj, fp, **kwargs):
    kwargs.setdefault("default", _json_default)
    return _json_dump(obj, fp, **kwargs)


json.dumps = dumps
json.dump = dump

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _read_file(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        return None


def _read_secret(name: str) -> Optional[str]:
    return _read_file(f"/run/secrets/{name}")


def _read_secret_any(names: List[str]) -> Optional[str]:
    for n in names:
        v = _read_secret(n)
        if v:
            return v
    return None


def _env_any(names: List[str]) -> Optional[str]:
    for n in names:
        v = os.environ.get(n)
        if v and v.strip():
            return v.strip()
    return None


def _to_dt(v: Any) -> Optional[datetime]:
    if v is None:
        return None
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    if isinstance(v, (int, float)):
        x = float(v)
        # ms epoch
        if x > 10_000_000_000:
            x = x / 1000.0
        try:
            return datetime.fromtimestamp(x, tz=timezone.utc)
        except Exception:
            return None
    if isinstance(v, str):
        s = v.strip()
        if not s:
            return None
        try:
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            dt = datetime.fromisoformat(s)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            try:
                x = float(s)
                return _to_dt(x)
            except Exception:
                return None
    return None


def _safe_inet(v: Any) -> Optional[str]:
    if v is None:
        return None
    if isinstance(v, str):
        s = v.strip()
        if not s:
            return None
        try:
            ipaddress.ip_address(s)
            return s
        except Exception:
            return None
    return None


def _truncate(s: Optional[str], max_len: int) -> Optional[str]:
    if s is None:
        return None
    ss = str(s)
    if len(ss) <= max_len:
        return ss
    return ss[:max_len]


def _normalize_hostname(*candidates: Any) -> Optional[str]:
    for c in candidates:
        if not c:
            continue
        s = str(c).strip()
        if not s:
            continue
        s = s.split()[0].strip()
        if not s:
            continue
        s = s.lower()
        if "." in s:
            s = s.split(".", 1)[0]
        return s or None
    return None


def _normalize_severity(v: Any) -> Optional[str]:
    if v is None:
        return None
    if isinstance(v, str):
        s = v.strip().lower()
        if s in {"low", "medium", "high", "critical", "info", "informational"}:
            return "informational" if s == "info" else s
        return s or None
    if isinstance(v, (int, float)):
        n = int(v)
        m = {0: "informational", 1: "low", 2: "medium", 3: "high", 4: "critical"}
        return m.get(n, str(n))
    return str(v).strip().lower() or None


def _normalize_state(v: Any) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip().upper()
    return s or None


def _as_bool(v: Any) -> Optional[bool]:
    if v is None:
        return None
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if s in {"1", "true", "t", "yes", "y", "on"}:
        return True
    if s in {"0", "false", "f", "no", "n", "off"}:
        return False
    return None


def _safe_vpr(v: Any) -> Optional[float]:
    """
    VPR puede venir como número o dict.
    Guardamos numeric(4,1).
    """
    if v is None:
        return None
    try:
        if isinstance(v, dict):
            for k in ("score", "vpr_score", "vprScore", "value", "raw", "rating"):
                if k in v and v[k] is not None:
                    return _safe_vpr(v[k])
            return None
        x = float(v)
        x = round(x, 1)
        if x < 0:
            x = 0.0
        if x > 999.9:
            x = 999.9
        return x
    except Exception:
        return None


def _finding_id(asset_uuid: str, plugin_id: int, cve_id: str) -> str:
    base = f"{asset_uuid}:{plugin_id}:{cve_id}".encode("utf-8", errors="ignore")
    return hashlib.sha1(base).hexdigest()


def _dedupe_str_list(items: Any) -> List[str]:
    out: List[str] = []
    seen = set()
    if items is None:
        return out
    if not isinstance(items, (list, tuple)):
        items = [items]
    for x in items:
        if x is None:
            continue
        s = str(x).strip()
        if not s:
            continue
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


def _safe_int(v: Any) -> Optional[int]:
    if v is None:
        return None
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, float):
        try:
            return int(v)
        except Exception:
            return None
    s = str(v).strip()
    if not s:
        return None
    try:
        # a veces viene "443/tcp"
        if "/" in s:
            s = s.split("/", 1)[0].strip()
        return int(float(s))
    except Exception:
        return None


def _as_text(v: Any) -> Optional[str]:
    if v is None:
        return None
    if isinstance(v, str):
        return v
    try:
        return json.dumps(v, ensure_ascii=False, default=_json_default)
    except Exception:
        try:
            return str(v)
        except Exception:
            return None


NETWORK_OS_KEYWORDS = {
    "ios", "nx-os", "pan-os", "fortios", "juniper",
    "router", "switch", "firewall",
    "aruba", "mikrotik", "ubiquiti",
    "palo alto", "fortinet", "cisco", "checkpoint",
}


def _is_network_device(os_name: Optional[str]) -> bool:
    if not os_name:
        return False
    s = os_name.lower()
    return any(k in s for k in NETWORK_OS_KEYWORDS)


def _asset_is_excluded(asset_obj: Dict[str, Any], hostname: Optional[str], ipv4: Optional[str], os_name: Optional[str]) -> bool:
    if not isinstance(asset_obj, dict):
        return hostname is None

    # Capa 1: inactivos/eliminados/terminados
    for k in ("inactive", "is_inactive", "isInactive",
              "deleted", "is_deleted", "isDeleted",
              "terminated", "is_terminated", "isTerminated"):
        if k in asset_obj:
            b = _as_bool(asset_obj.get(k))
            if b is True:
                return True

    state = asset_obj.get("state") or asset_obj.get("status") or asset_obj.get("lifecycle_state") or asset_obj.get("lifecycleState")
    if state is not None:
        ss = str(state).strip().upper()
        if ss in {"INACTIVE", "DELETED", "TERMINATED", "DISABLED"}:
            return True

    # Capa 1: no licenciado
    for k in ("licensed", "is_licensed", "isLicensed", "has_license", "hasLicense"):
        if k in asset_obj:
            b = _as_bool(asset_obj.get(k))
            if b is False:
                return True

    for k in ("license_status", "licenseStatus", "license", "licence", "licence_status"):
        if k in asset_obj and asset_obj.get(k) is not None:
            s = str(asset_obj.get(k)).strip().lower()
            if "unlic" in s or s in {"none", "no", "false"}:
                return True

    # Capa 3: equipos de red
    if _is_network_device(os_name):
        return True

    # Capa 2: discovered/discover-only
    discovered_flag = False
    for k in ("discovered", "is_discovered", "isDiscovered", "discovery", "discover_only", "discoverOnly"):
        if k in asset_obj:
            b = _as_bool(asset_obj.get(k))
            if b is True:
                discovered_flag = True

    src = asset_obj.get("source") or asset_obj.get("source_type") or asset_obj.get("sourceType")
    if src is not None:
        s = str(src).strip().lower()
        if "discover" in s:
            discovered_flag = True

    sources = asset_obj.get("sources")
    if isinstance(sources, (list, tuple)):
        for x in sources:
            if x is None:
                continue
            if "discover" in str(x).strip().lower():
                discovered_flag = True
                break

    if discovered_flag and not hostname:
        return True

    # Capa 4: identidad mínima obligatoria
    if not hostname:
        return True

    return False


def _read_db_config(args) -> Dict[str, str]:
    host = (
        args.db_host
        or _env_any(["DATABASE_HOST", "DB_HOST", "PGHOST"])
        or _read_secret_any(["postgres_host", "db_host"])
        or "appdb"
    )
    port = (
        args.db_port
        or _env_any(["DATABASE_PORT", "DB_PORT", "PGPORT"])
        or _read_secret_any(["postgres_port", "db_port"])
        or "5432"
    )
    user = (
        args.db_user
        or _env_any(["DATABASE_USER", "DB_USER", "PGUSER"])
        or _read_secret_any(["postgres_user"])
        or "vanalyzer"
    )
    password = (
        args.db_password
        or _env_any(["DATABASE_PASSWORD", "DB_PASSWORD", "PGPASSWORD"])
        or _read_secret_any(["postgres_password"])
    )
    database = (
        args.db_name
        or _env_any(["DATABASE_NAME", "DB_NAME", "PGDATABASE"])
        or _read_secret_any(["postgres_db"])
        or "vanalyzer"
    )
    if not password:
        raise RuntimeError("DB password not found (env DATABASE_PASSWORD/DB_PASSWORD/PGPASSWORD or /run/secrets/postgres_password)")
    return {"host": host, "port": str(port), "user": user, "password": password, "dbname": database}


def _connect(db_cfg: Dict[str, str], autocommit: bool = False):
    conn = psycopg2.connect(
        host=db_cfg["host"],
        port=db_cfg["port"],
        user=db_cfg["user"],
        password=db_cfg["password"],
        dbname=db_cfg["dbname"],
        connect_timeout=30,
        keepalives=1,
        keepalives_idle=60,
        keepalives_interval=30,
        keepalives_count=5,
        options="-c statement_timeout=300000",
    )
    conn.autocommit = autocommit
    return conn


def _assert_tables(conn):
    required = [
        "tenable_assets_current",
        "tenable_findings_current",
        "tenable_findings_history",
        "tenable_plugin_cve_map",
        "tenable_ingest_runs",
    ]
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema='public' AND table_name LIKE 'tenable_%'
            """
        )
        have = {r[0] for r in cur.fetchall()}
    missing = [t for t in required if t not in have]
    if missing:
        raise RuntimeError(f"Missing required tables in public schema: {missing}")


def _assert_ports_table(conn):
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT 1
            FROM information_schema.tables
            WHERE table_schema='public' AND table_name='tenable_finding_ports'
            """
        )
        ok = cur.fetchone() is not None
    if not ok:
        raise RuntimeError(
            "Tabla public.tenable_finding_ports no existe. "
            "Créala primero (como ya estaban haciendo) y vuelve a correr el ETL."
        )


def _generated_columns(conn, table: str, schema: str = "public") -> set:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema=%s AND table_name=%s AND is_generated='ALWAYS'
            """,
            (schema, table),
        )
        return {r[0] for r in cur.fetchall()}


def _read_tenable_creds(args) -> Tuple[str, str, str]:
    base_url = args.tenable_base_url or _env_any(["TENABLE_BASE_URL"]) or "https://cloud.tenable.com"
    access_key = args.access_key or _env_any(["TENABLE_ACCESS_KEY", "ACCESS_KEY"]) or _read_secret_any(["tenable_access_key", "access_key"])
    secret_key = args.secret_key or _env_any(["TENABLE_SECRET_KEY", "SECRET_KEY"]) or _read_secret_any(["tenable_secret_key", "secret_key"])
    if not access_key or not secret_key:
        raise RuntimeError("Tenable keys not found. Need ACCESS_KEY/SECRET_KEY or TENABLE_ACCESS_KEY/TENABLE_SECRET_KEY (args/env/secrets).")
    return base_url.rstrip("/"), access_key, secret_key


class TenableClient:
    def __init__(self, base_url: str, access_key: str, secret_key: str, timeout: int = 60,
                 max_retries: int = 8, backoff_base: float = 1.2, backoff_cap: float = 60.0):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "X-ApiKeys": f"accessKey={access_key};secretKey={secret_key}",
            }
        )
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        self.backoff_cap = backoff_cap

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def _sleep_backoff(self, attempt: int, retry_after: Optional[str] = None):
        if retry_after:
            try:
                ra = float(retry_after)
                time.sleep(min(max(0.0, ra), self.backoff_cap))
                return
            except Exception:
                pass
        t = min(self.backoff_cap, (self.backoff_base ** attempt))
        t = t + random.uniform(0.0, min(1.0, t * 0.2))
        time.sleep(t)

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        url = self._url(path)
        last_exc = None
        for attempt in range(0, self.max_retries + 1):
            try:
                r = self.session.request(method, url, timeout=self.timeout, **kwargs)
                if r.status_code in (429, 500, 502, 503, 504):
                    if attempt >= self.max_retries:
                        r.raise_for_status()
                    self._sleep_backoff(attempt + 1, r.headers.get("Retry-After"))
                    continue
                r.raise_for_status()
                return r
            except (requests.Timeout, requests.ConnectionError) as e:
                last_exc = e
                if attempt >= self.max_retries:
                    raise
                self._sleep_backoff(attempt + 1, None)
            except requests.HTTPError:
                raise
        if last_exc:
            raise last_exc
        raise RuntimeError("Unexpected request failure")

    def start_export(self, states: List[str], severities: List[str]) -> str:
        payload = {"filters": {"state": states, "severity": severities}}
        r = self._request("POST", "/vulns/export", json=payload)
        data = r.json()
        export_uuid = data.get("export_uuid") or data.get("uuid") or data.get("exportUUID")
        if not export_uuid:
            raise RuntimeError(f"Unexpected Tenable export response: {data}")
        return str(export_uuid)

    def export_status(self, export_uuid: str) -> Dict[str, Any]:
        r = self._request("GET", f"/vulns/export/{export_uuid}/status")
        return r.json()

    def download_chunk(self, export_uuid: str, chunk_id: int) -> Any:
        r = self._request("GET", f"/vulns/export/{export_uuid}/chunks/{chunk_id}")
        raw = r.content
        if raw[:2] == b"\x1f\x8b":
            raw = gzip.decompress(raw)
        try:
            return json.loads(raw.decode("utf-8", errors="replace"))
        except Exception:
            return json.loads(raw)

    def wait_finished(self, export_uuid: str, poll_seconds: float = 2.0, max_wait_seconds: int = 3600) -> List[int]:
        start = time.time()
        last_status = None
        while True:
            st = self.export_status(export_uuid)
            last_status = st
            status = str(st.get("status") or "").upper()
            if status == "FINISHED":
                chunks = st.get("chunks_available") or st.get("chunks") or st.get("chunksAvailable") or []
                if isinstance(chunks, dict):
                    chunks = list(chunks.keys())
                if isinstance(chunks, list) and chunks and isinstance(chunks[0], dict) and "id" in chunks[0]:
                    chunks = [int(x["id"]) for x in chunks]
                chunks = [int(x) for x in chunks]
                if not chunks:
                    raise RuntimeError(f"Export FINISHED but chunks_available empty. Status: {st}")
                return chunks
            if status in {"CANCELLED", "ERROR", "FAILED"}:
                raise RuntimeError(f"Export failed: {st}")
            if time.time() - start > max_wait_seconds:
                raise RuntimeError(f"Export timeout. Last status: {last_status}")
            time.sleep(poll_seconds)


_MAX_PLUGIN_OUTPUT_FULL = int(os.environ.get("TENABLE_PORT_OUTPUT_MAX", "60000"))


def _extract_port_tuple(item: Dict[str, Any]) -> Tuple[str, Optional[int], str]:
    raw_port = item.get("port")
    raw_proto = item.get("protocol")
    raw_svc = (
        item.get("svc_name")
        or item.get("service_name")
        or item.get("serviceName")
        or item.get("service")
        or item.get("svc")
        or item.get("svcName")
    )

    if isinstance(raw_port, dict):
        raw_proto = raw_proto or raw_port.get("protocol") or raw_port.get("transport")
        raw_svc = raw_svc or raw_port.get("service") or raw_port.get("service_name")
        raw_port = raw_port.get("port") or raw_port.get("number")

    if isinstance(raw_proto, dict):
        raw_proto = raw_proto.get("name") or raw_proto.get("protocol") or raw_proto.get("transport")

    port_i = _safe_int(raw_port)
    proto_s = str(raw_proto).strip().lower() if raw_proto is not None and str(raw_proto).strip() else ""
    svc_s = str(raw_svc).strip().lower() if raw_svc is not None and str(raw_svc).strip() else ""
    return proto_s, port_i, svc_s


def _extract_from_item(item: Dict[str, Any]) -> Tuple[
    Optional[Dict[str, Any]],
    List[Dict[str, Any]],
    List[Dict[str, Any]],
    List[Dict[str, Any]],
]:
    asset_obj = item.get("asset") if isinstance(item.get("asset"), dict) else {}
    plugin_obj = item.get("plugin") if isinstance(item.get("plugin"), dict) else {}

    asset_uuid = asset_obj.get("uuid") or item.get("asset_uuid") or item.get("assetUUID") or item.get("uuid")
    asset_uuid = str(asset_uuid) if asset_uuid else None

    hostname_raw = asset_obj.get("hostname") or item.get("hostname")
    fqdn = asset_obj.get("fqdn") or item.get("fqdn")
    netbios = asset_obj.get("netbios_name") or asset_obj.get("netbios") or item.get("netbios_name")
    hostname = _normalize_hostname(hostname_raw, fqdn, netbios)

    ipv4 = _safe_inet(asset_obj.get("ipv4") or item.get("ipv4"))

    os_name = asset_obj.get("operating_system") or item.get("operating_system") or item.get("os") or asset_obj.get("os_name")
    if isinstance(os_name, list):
        os_name = os_name[0] if os_name else None
    os_name = str(os_name).strip() if os_name is not None and str(os_name).strip() else None

    last_seen = _to_dt(
        item.get("last_seen")
        or item.get("lastSeen")
        or item.get("last_found")
        or item.get("lastFound")
        or asset_obj.get("last_seen")
        or asset_obj.get("lastSeen")
    )
    if last_seen is None:
        last_seen = _now_utc()

    plugin_id = plugin_obj.get("id") or item.get("plugin_id") or item.get("pluginID")
    try:
        plugin_id = int(plugin_id) if plugin_id is not None else None
    except Exception:
        plugin_id = None

    cves = plugin_obj.get("cve") or item.get("cve") or item.get("cves") or item.get("plugin.cve")
    cve_list = _dedupe_str_list(cves)

    map_rows: List[Dict[str, Any]] = []
    if plugin_id is not None and cve_list:
        for cve_id in cve_list:
            map_rows.append({"plugin_id": plugin_id, "cve_id": cve_id})

    if _asset_is_excluded(asset_obj, hostname=hostname, ipv4=ipv4, os_name=os_name):
        return None, [], map_rows, []

    asset_row = None
    if asset_uuid:
        payload = {"asset": asset_obj, "source": "vulns/export"}
        asset_row = {
            "asset_uuid": asset_uuid,
            "hostname": hostname,
            "ipv4": ipv4,
            "os_name": os_name,
            "last_seen": last_seen,
            "data": payload,
        }

    severity = _normalize_severity(
        item.get("severity")
        or item.get("severity_name")
        or item.get("severityName")
        or item.get("severity_id")
        or item.get("severityId")
    )
    state = _normalize_state(item.get("state") or item.get("vuln_state") or item.get("vulnState"))

    first_found = _to_dt(item.get("first_seen") or item.get("firstSeen") or item.get("first_found") or item.get("firstFound"))
    if first_found is None:
        first_found = last_seen

    vpr_score = _safe_vpr(
        item.get("vpr")
        or item.get("vpr_score")
        or item.get("vprScore")
        or plugin_obj.get("vpr")
        or plugin_obj.get("vpr_score")
        or plugin_obj.get("vprScore")
    )

    plugin_output = item.get("plugin_output") or item.get("pluginOutput") or item.get("output") or item.get("evidence")
    plugin_output = _truncate(plugin_output, 1500)

    plugin_output_full = (
        item.get("plugin_output")
        or item.get("pluginOutput")
        or item.get("output")
        or item.get("evidence")
    )
    plugin_output_full = _as_text(plugin_output_full)
    plugin_output_full = _truncate(plugin_output_full, _MAX_PLUGIN_OUTPUT_FULL)

    protocol, port, service_name = _extract_port_tuple(item)

    findings_rows: List[Dict[str, Any]] = []
    ports_rows: List[Dict[str, Any]] = []

    if asset_uuid and plugin_id is not None and cve_list:
        for cve_id in cve_list:
            fid = _finding_id(asset_uuid, plugin_id, cve_id)
            findings_rows.append(
                {
                    "finding_id": fid,
                    "asset_uuid": asset_uuid,
                    "plugin_id": plugin_id,
                    "cve_id": cve_id,
                    "severity": severity,
                    "vpr_score": vpr_score,
                    "state": state,
                    "first_found": first_found,
                    "plugin_output": plugin_output,
                }
            )

            if state in {"OPEN", "REOPENED"} and port is not None:
                ports_rows.append(
                    {
                        "finding_id": fid,
                        "asset_uuid": asset_uuid,
                        "plugin_id": plugin_id,
                        "cve_id": cve_id,
                        "protocol": protocol or "",
                        "port": int(port),
                        "service_name": service_name or "",
                        "plugin_output_full": plugin_output_full,
                        "data": {
                            "source": "vulns/export",
                            "severity": severity,
                            "state": state,
                            "first_found": first_found.isoformat() if isinstance(first_found, datetime) else None,
                            "last_seen": last_seen.isoformat() if isinstance(last_seen, datetime) else None,
                            "raw": {
                                "protocol": item.get("protocol"),
                                "port": item.get("port"),
                                "svc_name": item.get("svc_name") or item.get("service_name") or item.get("service"),
                            },
                        },
                    }
                )

    return asset_row, findings_rows, map_rows, ports_rows


def _upsert_assets_current(conn, rows: List[Dict[str, Any]]) -> int:
    if not rows:
        return 0
    values = []
    for r in rows:
        values.append(
            (
                r["asset_uuid"],
                r.get("hostname"),
                r.get("ipv4"),
                r.get("os_name"),
                r.get("last_seen"),
                Json(r.get("data") or {}, dumps=json.dumps),
            )
        )

    q = """
    INSERT INTO public.tenable_assets_current
      (asset_uuid, hostname, ipv4, os_name, last_seen, data)
    VALUES %s
    ON CONFLICT (asset_uuid) DO UPDATE SET
      hostname = EXCLUDED.hostname,
      ipv4     = EXCLUDED.ipv4,
      os_name  = EXCLUDED.os_name,
      last_seen = GREATEST(public.tenable_assets_current.last_seen, EXCLUDED.last_seen),
      data     = EXCLUDED.data
    """
    with conn.cursor() as cur:
        execute_values(cur, q, values, page_size=2000)
    return len(rows)


def _insert_plugin_cve_map(conn, rows: List[Dict[str, Any]]) -> int:
    if not rows:
        return 0
    values = [(int(r["plugin_id"]), str(r["cve_id"])) for r in rows if r.get("plugin_id") is not None and r.get("cve_id")]
    if not values:
        return 0
    q = """
    INSERT INTO public.tenable_plugin_cve_map
      (plugin_id, cve_id)
    VALUES %s
    ON CONFLICT (plugin_id, cve_id) DO NOTHING
    """
    with conn.cursor() as cur:
        execute_values(cur, q, values, page_size=5000)
    return len(values)


def _upsert_findings_current(conn, rows: List[Dict[str, Any]]) -> int:
    if not rows:
        return 0
    values = []
    for r in rows:
        values.append(
            (
                r["finding_id"],
                r["asset_uuid"],
                int(r["plugin_id"]),
                str(r["cve_id"]),
                r.get("severity"),
                r.get("vpr_score"),
                r.get("state"),
                r.get("first_found"),
                r.get("plugin_output"),
            )
        )

    q = """
    INSERT INTO public.tenable_findings_current
      (finding_id, asset_uuid, plugin_id, cve_id, severity, vpr_score, state, first_found, plugin_output)
    VALUES %s
    ON CONFLICT (finding_id) DO UPDATE SET
      severity      = EXCLUDED.severity,
      vpr_score     = EXCLUDED.vpr_score,
      state         = EXCLUDED.state,
      first_found   = COALESCE(public.tenable_findings_current.first_found, EXCLUDED.first_found),
      plugin_output = EXCLUDED.plugin_output,
      ingested_at   = now()
    """
    with conn.cursor() as cur:
        execute_values(cur, q, values, page_size=2000)
    return len(rows)


def _upsert_finding_ports(conn, rows: List[Dict[str, Any]]) -> int:
    """
    Upsert robusto SIN depender de ON CONFLICT (evita problemas si el índice unique es por expresión/partial).
    Estrategia:
      1) tmp_ports
      2) UPDATE matching rows
      3) INSERT missing rows (con NOT EXISTS)
    Nota: NO insertamos updated_at (la DB lo maneja con DEFAULT y en UPDATE lo seteamos a now()).
    """
    if not rows:
        return 0

    seen = set()
    values = []
    for r in rows:
        fid = str(r.get("finding_id") or "").strip()
        au = str(r.get("asset_uuid") or "").strip()
        if not fid or not au:
            continue

        protocol = (r.get("protocol") or "").strip().lower()
        service_name = (r.get("service_name") or "").strip().lower()
        port = _safe_int(r.get("port"))
        if port is None:
            continue

        key = (fid, protocol, int(port), service_name)
        if key in seen:
            continue
        seen.add(key)

        values.append(
            (
                fid,
                au,
                int(r.get("plugin_id") or 0),
                str(r.get("cve_id")) if r.get("cve_id") else None,
                protocol,
                int(port),
                service_name,
                _as_text(r.get("plugin_output_full")),
                Json(r.get("data") or {}, dumps=json.dumps),
            )
        )

    if not values:
        return 0

    with conn.cursor() as cur:
        cur.execute(
            """
            CREATE TEMP TABLE tmp_ports (
              finding_id         text,
              asset_uuid         uuid,
              plugin_id          integer,
              cve_id             text,
              protocol           text,
              port               integer,
              service_name       text,
              plugin_output_full text,
              data               jsonb
            ) ON COMMIT DROP;
            """
        )
        execute_values(
            cur,
            """
            INSERT INTO tmp_ports
              (finding_id, asset_uuid, plugin_id, cve_id, protocol, port, service_name, plugin_output_full, data)
            VALUES %s
            """,
            values,
            page_size=3000,
        )

        # UPDATE existentes
        cur.execute(
            """
            UPDATE public.tenable_finding_ports p
            SET
              cve_id             = t.cve_id,
              plugin_output_full = t.plugin_output_full,
              data               = t.data,
              updated_at         = now()
            FROM tmp_ports t
            WHERE p.finding_id = t.finding_id
              AND p.port = t.port
              AND COALESCE(p.protocol,'') = COALESCE(t.protocol,'')
              AND COALESCE(p.service_name,'') = COALESCE(t.service_name,'')
            """
        )
        updated = cur.rowcount if cur.rowcount is not None else 0

        # INSERT faltantes
        cur.execute(
            """
            INSERT INTO public.tenable_finding_ports
              (finding_id, asset_uuid, plugin_id, cve_id, protocol, port, service_name, plugin_output_full, data)
            SELECT
              t.finding_id, t.asset_uuid, t.plugin_id, t.cve_id,
              COALESCE(t.protocol,''), t.port, COALESCE(t.service_name,''),
              t.plugin_output_full, t.data
            FROM tmp_ports t
            WHERE NOT EXISTS (
              SELECT 1
              FROM public.tenable_finding_ports p
              WHERE p.finding_id = t.finding_id
                AND p.port = t.port
                AND COALESCE(p.protocol,'') = COALESCE(t.protocol,'')
                AND COALESCE(p.service_name,'') = COALESCE(t.service_name,'')
            )
            ON CONFLICT DO NOTHING
            """
        )
        inserted = cur.rowcount if cur.rowcount is not None else 0

    return int(updated) + int(inserted)


def _sync_findings_current_to_history(conn, keep_finding_ids: List[str], assets_count: int, items_seen: int) -> int:
    with conn.cursor() as cur:
        if assets_count <= 0 or items_seen <= 0:
            cur.execute("SELECT count(*) FROM public.tenable_findings_current")
            existing = int(cur.fetchone()[0])
            if existing > 0:
                raise RuntimeError(f"Guard anti-wipe: assets_count={assets_count}, items_seen={items_seen} pero había findings_current existentes. No se sincroniza.")
            return 0

        cur.execute("CREATE TEMP TABLE tmp_finding_ids (finding_id text PRIMARY KEY) ON COMMIT DROP;")
        if keep_finding_ids:
            execute_values(
                cur,
                "INSERT INTO tmp_finding_ids (finding_id) VALUES %s ON CONFLICT DO NOTHING",
                [(x,) for x in keep_finding_ids],
                page_size=5000,
            )

        gen = _generated_columns(conn, "tenable_findings_history", "public")
        cols = ["asset_uuid", "cve_id", "severity", "first_found", "fixed_at"]
        cols = [c for c in cols if c not in gen]
        if cols != ["asset_uuid", "cve_id", "severity", "first_found", "fixed_at"]:
            raise RuntimeError(f"Unexpected generated columns in history affecting required insert columns: generated={gen}")

        cur.execute(
            """
            WITH moved AS (
              DELETE FROM public.tenable_findings_current fc
              WHERE NOT EXISTS (SELECT 1 FROM tmp_finding_ids t WHERE t.finding_id = fc.finding_id)
              RETURNING fc.asset_uuid, fc.cve_id, fc.severity, fc.first_found
            )
            INSERT INTO public.tenable_findings_history (asset_uuid, cve_id, severity, first_found, fixed_at)
            SELECT asset_uuid, cve_id, severity, first_found, now()
            FROM moved
            """
        )
        return cur.rowcount if cur.rowcount is not None else 0


def _insert_fixed_history_from_export(conn, fixed_rows: List[Dict[str, Any]]) -> int:
    if not fixed_rows:
        return 0

    seen = set()
    values = []
    for r in fixed_rows:
        au = r.get("asset_uuid")
        cve = r.get("cve_id")
        ff = r.get("first_found")
        sev = r.get("severity")
        if not au or not cve or not ff:
            continue
        key = (str(au), str(cve), ff.isoformat() if isinstance(ff, datetime) else str(ff))
        if key in seen:
            continue
        seen.add(key)
        values.append((str(au), str(cve), sev, ff))

    if not values:
        return 0

    _ = _generated_columns(conn, "tenable_findings_history", "public")

    with conn.cursor() as cur:
        cur.execute("CREATE TEMP TABLE tmp_fixed (asset_uuid uuid, cve_id text, severity text, first_found timestamptz) ON COMMIT DROP;")
        execute_values(
            cur,
            "INSERT INTO tmp_fixed (asset_uuid, cve_id, severity, first_found) VALUES %s",
            values,
            page_size=5000,
        )

        cur.execute(
            """
            INSERT INTO public.tenable_findings_history (asset_uuid, cve_id, severity, first_found, fixed_at)
            SELECT f.asset_uuid, f.cve_id, f.severity, f.first_found, now()
            FROM tmp_fixed f
            WHERE NOT EXISTS (
              SELECT 1
              FROM public.tenable_findings_history h
              WHERE h.asset_uuid = f.asset_uuid
                AND h.cve_id = f.cve_id
                AND h.first_found = f.first_found
            )
            """
        )
        return cur.rowcount if cur.rowcount is not None else 0


def _insert_ingest_run(db_cfg: Dict[str, str], start_time: datetime, end_time: datetime, status: str, assets_count: int, findings_count: int):
    conn = None
    try:
        conn = _connect(db_cfg, autocommit=True)
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO public.tenable_ingest_runs (start_time, end_time, status, assets_count, findings_count)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (start_time, end_time, status, int(assets_count), int(findings_count)),
            )
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------
def run_pipeline(args) -> int:
    started_at = _now_utc()
    finished_at = started_at

    db_cfg = _read_db_config(args)
    conn = _connect(db_cfg, autocommit=False)

    export_uuid = None
    assets_map: Dict[str, Dict[str, Any]] = {}
    current_map: Dict[str, Dict[str, Any]] = {}
    map_map: Dict[Tuple[int, str], Dict[str, Any]] = {}

    fixed_candidates: List[Dict[str, Any]] = []
    ports_candidates: List[Dict[str, Any]] = []
    items_seen = 0

    try:
        _assert_tables(conn)
        _assert_ports_table(conn)

        base_url, access_key, secret_key = _read_tenable_creds(args)
        client = TenableClient(
            base_url, access_key, secret_key,
            timeout=args.http_timeout,
            max_retries=args.http_retries,
            backoff_base=args.backoff_base,
            backoff_cap=args.backoff_cap,
        )

        export_uuid = client.start_export(args.states, args.severities)
        chunks = client.wait_finished(export_uuid, poll_seconds=args.poll_seconds, max_wait_seconds=args.max_wait_seconds)

        if args.max_chunks and args.max_chunks > 0:
            sys.stderr.write(f"[WARN] max_chunks={args.max_chunks} fue solicitado pero será IGNORADO para traer TODO.\n")

        downloaded = set()
        for chunk_id in chunks:
            payload = client.download_chunk(export_uuid, chunk_id)
            downloaded.add(int(chunk_id))

            items = payload
            if isinstance(payload, dict):
                items = payload.get("vulnerabilities") or payload.get("items") or payload.get("results") or payload.get("data") or []
            if not isinstance(items, list):
                continue

            for it in items:
                if not isinstance(it, dict):
                    continue
                items_seen += 1

                arow, frows, mrows, prow = _extract_from_item(it)

                if arow and arow.get("asset_uuid"):
                    assets_map[arow["asset_uuid"]] = arow

                for mr in mrows:
                    try:
                        k = (int(mr["plugin_id"]), str(mr["cve_id"]))
                        map_map[k] = mr
                    except Exception:
                        pass

                for fr in frows:
                    st = _normalize_state(fr.get("state"))
                    if st in {"OPEN", "REOPENED"}:
                        current_map[fr["finding_id"]] = fr
                    elif st == "FIXED":
                        fixed_candidates.append(fr)

                if prow:
                    ports_candidates.extend(prow)

        if len(downloaded) != len(set(chunks)):
            missing = sorted(set(chunks) - downloaded)
            raise RuntimeError(f"Chunk download incomplete. expected={len(set(chunks))} got={len(downloaded)} missing={missing[:20]}")

        assets_list = list(assets_map.values())
        findings_current_list = list(current_map.values())
        plugin_cve_list = list(map_map.values())

        _upsert_assets_current(conn, assets_list)
        _insert_plugin_cve_map(conn, plugin_cve_list)

        keep_ids = [r["finding_id"] for r in findings_current_list]
        moved = _sync_findings_current_to_history(conn, keep_ids, assets_count=len(assets_list), items_seen=items_seen)

        # primero current para cumplir FK (si tu tabla de puertos la tiene)
        _upsert_findings_current(conn, findings_current_list)

        # luego puertos (SIN updated_at en INSERT)
        ports_upserted = _upsert_finding_ports(conn, ports_candidates)

        fixed_inserted = _insert_fixed_history_from_export(conn, fixed_candidates)

        conn.commit()

        finished_at = _now_utc()
        _insert_ingest_run(
            db_cfg=db_cfg,
            start_time=started_at,
            end_time=finished_at,
            status="SUCCESS",
            assets_count=len(assets_list),
            findings_count=len(findings_current_list),
        )

        sys.stdout.write(
            f"[OK] export_uuid={export_uuid} chunks={len(set(chunks))} downloaded={len(downloaded)} "
            f"items_seen={items_seen} assets={len(assets_list)} findings_current={len(findings_current_list)} "
            f"ports_upserted={ports_upserted} moved_to_history={moved} fixed_inserted={fixed_inserted}\n"
        )
        return 0

    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass

        finished_at = _now_utc()
        try:
            _insert_ingest_run(
                db_cfg=db_cfg,
                start_time=started_at,
                end_time=finished_at,
                status="ERROR",
                assets_count=0,
                findings_count=0,
            )
        except Exception:
            pass

        sys.stderr.write(f"[ERROR] {e}\n")
        return 2

    finally:
        try:
            conn.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Args
# ---------------------------------------------------------------------------
def _parse_args():
    p = argparse.ArgumentParser(add_help=True)

    # Tenable
    p.add_argument("--tenable-base-url", default=os.environ.get("TENABLE_BASE_URL", "https://cloud.tenable.com"))
    p.add_argument("--access-key", default=os.environ.get("TENABLE_ACCESS_KEY") or os.environ.get("ACCESS_KEY"))
    p.add_argument("--secret-key", default=os.environ.get("TENABLE_SECRET_KEY") or os.environ.get("SECRET_KEY"))

    # Incluye FIXED en export
    p.add_argument("--states", default=os.environ.get("TENABLE_STATES", "OPEN,REOPENED,FIXED"))
    p.add_argument("--severities", default=os.environ.get("TENABLE_SEVERITIES", "low,medium,high,critical"))

    p.add_argument("--poll-seconds", type=float, default=float(os.environ.get("TENABLE_POLL_SECONDS", "2.0")))
    p.add_argument("--max-wait-seconds", type=int, default=int(os.environ.get("TENABLE_MAX_WAIT_SECONDS", "3600")))
    p.add_argument("--http-timeout", type=int, default=int(os.environ.get("TENABLE_HTTP_TIMEOUT", "60")))

    # se ignora (solo warn)
    p.add_argument("--max-chunks", type=int, default=int(os.environ.get("TENABLE_MAX_CHUNKS", "0")))

    # Retries (429/5xx)
    p.add_argument("--http-retries", type=int, default=int(os.environ.get("TENABLE_HTTP_RETRIES", "8")))
    p.add_argument("--backoff-base", type=float, default=float(os.environ.get("TENABLE_BACKOFF_BASE", "1.6")))
    p.add_argument("--backoff-cap", type=float, default=float(os.environ.get("TENABLE_BACKOFF_CAP", "60")))

    # DB
    p.add_argument("--db-host", default=os.environ.get("PGHOST") or os.environ.get("DB_HOST") or os.environ.get("DATABASE_HOST"))
    p.add_argument("--db-port", default=os.environ.get("PGPORT") or os.environ.get("DB_PORT") or os.environ.get("DATABASE_PORT"))
    p.add_argument("--db-user", default=os.environ.get("PGUSER") or os.environ.get("DB_USER") or os.environ.get("DATABASE_USER"))
    p.add_argument("--db-password", default=os.environ.get("PGPASSWORD") or os.environ.get("DB_PASSWORD") or os.environ.get("DATABASE_PASSWORD"))
    p.add_argument("--db-name", default=os.environ.get("PGDATABASE") or os.environ.get("DB_NAME") or os.environ.get("DATABASE_NAME"))

    args = p.parse_args()
    args.states = [s.strip().upper() for s in str(args.states).split(",") if s.strip()]
    args.severities = [s.strip().lower() for s in str(args.severities).split(",") if s.strip()]
    return args


def main():
    args = _parse_args()
    rc = run_pipeline(args)
    sys.exit(rc)


if __name__ == "__main__":
    main()
