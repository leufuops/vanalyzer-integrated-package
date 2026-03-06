#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import csv as csv_mod
import io
import json
import os
import random
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor, execute_values
    HAS_PSYCOPG2 = True
except ImportError:
    psycopg2 = None  # type: ignore
    HAS_PSYCOPG2 = False

# ---------------------------------------------------------------------------
# Types & constants
# ---------------------------------------------------------------------------
JsonObj  = Dict[str, Any]
CVE_RE   = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
IP4_RE   = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$")
IP6_RE   = re.compile(r"^[0-9a-fA-F:]+(/\d{1,3})?$")
MAC_RE   = re.compile(r"^([0-9A-F]{2}[:\-]){5}[0-9A-F]{2}$")

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
def log(msg: str) -> None:
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)

def log_warn(msg: str) -> None:
    log(f"[WARN] {msg}")

def log_err(msg: str) -> None:
    log(f"[ERROR] {msg}")

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Type helpers
# ---------------------------------------------------------------------------
def _s(val: Any) -> Optional[str]:
    if val is None:
        return None
    s = str(val).strip()
    return s or None


def _clean(val: Any) -> Optional[str]:
    """Strip surrounding brackets/quotes and whitespace."""
    s = _s(val)
    if s is None:
        return None
    s = re.sub(r'^[\[\]{}"\' ]+|[\[\]{}"\' ]+$', '', s).strip()
    return s or None


def _i(val: Any) -> Optional[int]:
    if val is None:
        return None
    try:
        return int(val)
    except (ValueError, TypeError):
        return None


def _f(val: Any) -> Optional[float]:
    if val is None:
        return None
    try:
        return round(float(val), 4)
    except (ValueError, TypeError):
        return None


def _b(val: Any) -> Optional[bool]:
    if val is None:
        return None
    if isinstance(val, bool):
        return val
    if isinstance(val, int):
        return bool(val)
    if isinstance(val, str):
        return val.strip().lower() in ("1", "true", "yes", "on")
    return None


def parse_dt(val: Any) -> Optional[datetime]:
    if val is None:
        return None
    if isinstance(val, datetime):
        return val if val.tzinfo else val.replace(tzinfo=timezone.utc)
    if isinstance(val, (int, float)):
        try:
            ts = float(val)
            if ts > 1e11:
                ts /= 1000.0
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        except (ValueError, OSError):
            return None
    if isinstance(val, str):
        s = val.strip()
        if not s:
            return None
        try:
            ts = float(s)
            if ts > 1e11:
                ts /= 1000.0
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        except (ValueError, OSError):
            pass
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
        ):
            try:
                dt = datetime.strptime(s, fmt)
                return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    return None


# ---------------------------------------------------------------------------
# Array/network helpers
# ---------------------------------------------------------------------------
def _ip_list(val: Any) -> List[str]:
    candidates: List[str] = []
    if val is None:
        return []
    if isinstance(val, str):
        candidates = [v.strip() for v in re.split(r"[,;\s]+", val) if v.strip()]
    elif isinstance(val, list):
        for item in val:
            if item is None:
                continue
            if isinstance(item, str) and item.strip():
                candidates += [v.strip() for v in re.split(r"[,;\s]+", item) if v.strip()]
            elif isinstance(item, dict):
                for k in ("ip_addr", "ip", "address", "ipAddress", "ipv4"):
                    v = item.get(k)
                    if v and str(v).strip():
                        candidates.append(str(v).strip())
                        break
    valid: List[str] = []
    seen: set = set()
    for ip in candidates:
        ip = ip.strip("[]\"'")
        if ip and (IP4_RE.match(ip) or IP6_RE.match(ip)) and ip not in seen:
            valid.append(ip)
            seen.add(ip)
    return valid


def _mac_list(val: Any) -> List[str]:
    raw: List[str] = []
    if val is None:
        return []
    if isinstance(val, str):
        raw = [val]
    elif isinstance(val, list):
        raw = [str(m) for m in val if m]
    result: List[str] = []
    for m in raw:
        m = m.strip().upper()
        if MAC_RE.match(m):
            result.append(m.replace("-", ":"))
    return result


def _tags(val: Any) -> List[str]:
    if isinstance(val, list):
        return [str(t).strip() for t in val if t is not None and str(t).strip()]
    if isinstance(val, str):
        return [v.strip() for v in val.split(",") if v.strip()]
    return []


def _pg_inet_array(ips: List[str]) -> Optional[str]:
    return ("{" + ",".join(ips) + "}") if ips else None


def _pg_text_array(items: List[str]) -> Optional[str]:
    if not items:
        return None
    escaped = ['"' + i.replace('"', '\\"') + '"' for i in items]
    return "{" + ",".join(escaped) + "}"


def _json(val: Any) -> str:
    if val is None:
        return "{}"
    if isinstance(val, str):
        try:
            json.loads(val)
            return val
        except Exception:
            return "{}"
    try:
        return json.dumps(val, default=str)
    except Exception:
        return "{}"


def severity_from_cvss(score: Optional[float]) -> Optional[str]:
    if score is None:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


def best_severity(a: Optional[str], b: Optional[str]) -> Optional[str]:
    def rank(s: Optional[str]) -> int:
        return SEVERITY_ORDER.get((s or "").lower(), -1)
    return a if rank(a) >= rank(b) else b


def extract_cves(pkg: JsonObj) -> List[str]:
    found: set = set()
    for field in ("cve_list", "cves", "cve_ids", "cveList", "vulnerabilities"):
        val = pkg.get(field)
        if isinstance(val, list):
            for item in val:
                s = str(item.get("cve_id", "") if isinstance(item, dict) else item)
                for m in CVE_RE.finditer(s):
                    found.add(m.group(0).upper())
        elif isinstance(val, str):
            for m in CVE_RE.finditer(val):
                found.add(m.group(0).upper())
    for field in ("notes", "description", "summary", "impact", "title"):
        s = pkg.get(field)
        if isinstance(s, str):
            for m in CVE_RE.finditer(s):
                found.add(m.group(0).upper())
    return sorted(found)


def extract_reference_urls(pkg: JsonObj) -> List[str]:
    urls: List[str] = []
    for field in ("references", "reference_urls", "urls", "links"):
        val = pkg.get(field)
        if isinstance(val, list):
            for item in val:
                if isinstance(item, str) and item.startswith("http"):
                    urls.append(item)
                elif isinstance(item, dict):
                    for k in ("url", "href", "link"):
                        v = item.get(k)
                        if isinstance(v, str) and v.startswith("http"):
                            urls.append(v)
                            break
    return list(dict.fromkeys(urls))  # deduplicate preserving order


# ---------------------------------------------------------------------------
# Secrets / config
# ---------------------------------------------------------------------------
def read_secret(path: str, required: bool = False, default: str = "") -> str:
    try:
        with open(path, "r", encoding="utf-8") as f:
            v = f.read().strip()
            if v:
                return v
    except FileNotFoundError:
        pass
    except Exception as e:
        if required:
            raise RuntimeError(f"Error reading secret {path}: {e}") from e
    if required and not default:
        raise RuntimeError(f"Required secret not found: {path}")
    return default


def first_secret(paths: List[str], required: bool = False) -> str:
    for p in paths:
        try:
            with open(p, "r", encoding="utf-8") as f:
                v = f.read().strip()
                if v:
                    return v
        except FileNotFoundError:
            continue
    if required:
        raise RuntimeError(f"None of the required secrets found: {paths}")
    return ""


def env_str(name: str, default: str) -> str:
    v = os.getenv(name)
    return str(v).strip() if v and str(v).strip() else default

def env_int(name: str, default: int) -> int:
    v = os.getenv(name)
    try:
        return int(v.strip()) if v and v.strip() else default
    except ValueError:
        return default

def env_float(name: str, default: float) -> float:
    v = os.getenv(name)
    try:
        return float(v.strip()) if v and v.strip() else default
    except ValueError:
        return default

def env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if not v:
        return default
    return v.strip().lower() in ("1", "true", "yes", "y", "on")

def env_opt_float(name: str) -> Optional[float]:
    v = os.getenv(name)
    try:
        return float(v.strip()) if v and v.strip() else None
    except ValueError:
        return None

def mask(s: str, keep: int = 4) -> str:
    return ("*" * max(0, len(s) - keep)) + s[-keep:] if s else ""


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
class Config:
    def __init__(self) -> None:
        self.api_key: str = first_secret(
            ["/run/secrets/automox_api_key", "/run/secrets/automox_apikey"],
            required=True,
        )
        self.org_id: str = first_secret(
            ["/run/secrets/automox_org_id", "/run/secrets/automox_orgid"],
            required=True,
        )
        self.base_url: str   = env_str("AUTOMOX_BASE_URL", "https://console.automox.com/api").rstrip("/")
        self.auth_mode: str  = env_str("AUTOMOX_AUTH_MODE", "bearer").lower()
        self.limit: int      = max(1, min(500, env_int("AUTOMOX_LIMIT", 500)))
        self.max_packages: int = max(0, env_int("AUTOMOX_MAX_PACKAGES", 0))
        self.timeout_s: int  = env_int("AUTOMOX_TIMEOUT_S", 60)
        self.retries: int    = env_int("AUTOMOX_RETRIES", 6)
        self.sleep_s: float  = env_float("AUTOMOX_SLEEP_S", 0.05)
        self.verify_ssl: bool = env_bool("AUTOMOX_VERIFY_SSL", True)
        self.min_cvss: Optional[float] = env_opt_float("AUTOMOX_MIN_CVSS")
        self.dry_run: bool   = env_bool("AUTOMOX_DRY_RUN", False)
        self.fetch_inventory: bool = env_bool("AUTOMOX_FETCH_INVENTORY", True)

        self.pg_db   = read_secret("/run/secrets/postgres_db",       required=True)
        self.pg_user = read_secret("/run/secrets/postgres_user",     required=True)
        self.pg_pass = read_secret("/run/secrets/postgres_password", required=False)
        self.pg_host = (
            os.getenv("PGHOST", "").strip()
            or os.getenv("DATABASE_HOST", "").strip()
            or read_secret("/run/secrets/postgres_host")
            or "appdb"
        )
        self.pg_port = os.getenv("PGPORT", "5432").strip() or "5432"


# ---------------------------------------------------------------------------
# DB client
# ---------------------------------------------------------------------------
class DBClient:
    def __init__(self, cfg: Config) -> None:
        self.db   = cfg.pg_db
        self.user = cfg.pg_user
        self.pw   = cfg.pg_pass
        self.host = cfg.pg_host
        self.port = cfg.pg_port
        self.conn = None

    def connect(self) -> None:
        if not HAS_PSYCOPG2:
            log("psycopg2 not available – using psql fallback")
            return
        kw: Dict[str, Any] = dict(dbname=self.db, user=self.user, cursor_factory=RealDictCursor)
        if self.pw:
            kw["password"] = self.pw
        if self.host:
            kw["host"] = self.host
            kw["port"] = self.port
        try:
            self.conn = psycopg2.connect(**kw)
            self.conn.autocommit = True
        except Exception as e:
            raise RuntimeError(f"DB connect failed: {e}") from e

    def close(self) -> None:
        if self.conn:
            try:
                self.conn.close()
            except Exception:
                pass

    def execute(self, sql: str, params: Optional[Tuple] = None) -> None:
        if not HAS_PSYCOPG2 or self.conn is None:
            self._psql_exec(sql, params)
            return
        with self.conn.cursor() as cur:
            cur.execute(sql, params or ())

    def fetchone(self, sql: str, params: Optional[Tuple] = None) -> Optional[Dict[str, Any]]:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def query(self, sql: str, params: Optional[Tuple] = None) -> List[Dict[str, Any]]:
        if not HAS_PSYCOPG2 or self.conn is None:
            return self._psql_query(sql, params)
        with self.conn.cursor() as cur:
            cur.execute(sql, params or ())
            if cur.description is None:
                return []
            return [dict(r) for r in cur.fetchall()]

    # psql fallback --------------------------------------------------------
    def _render(self, sql: str, params: Optional[Tuple]) -> str:
        if not params:
            return sql
        rendered = sql
        for p in params:
            if p is None:
                lit = "NULL"
            elif isinstance(p, bool):
                lit = "TRUE" if p else "FALSE"
            elif isinstance(p, (int, float)):
                lit = str(p)
            elif isinstance(p, datetime):
                lit = "'" + p.isoformat().replace("'", "''") + "'"
            else:
                lit = "'" + str(p).replace("'", "''") + "'"
            rendered = rendered.replace("%s", lit, 1)
        return rendered

    def _env(self) -> Dict[str, str]:
        e = os.environ.copy()
        if self.pw:
            e["PGPASSWORD"] = self.pw
        return e

    def _cmd(self) -> List[str]:
        cmd = ["psql", "-U", self.user, "-d", self.db, "-X", "-v", "ON_ERROR_STOP=1"]
        if self.host:
            cmd += ["-h", self.host, "-p", self.port]
        return cmd

    def _psql_exec(self, sql: str, params: Optional[Tuple] = None) -> None:
        p = subprocess.run(self._cmd() + ["-c", self._render(sql, params)],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           env=self._env(), check=False)
        if p.returncode != 0:
            raise RuntimeError(p.stderr.decode(errors="ignore"))

    def _psql_query(self, sql: str, params: Optional[Tuple] = None) -> List[Dict[str, Any]]:
        copy_sql = f"COPY ({self._render(sql, params)}) TO STDOUT WITH CSV HEADER;"
        p = subprocess.run(self._cmd() + ["-qAt", "-c", copy_sql],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           env=self._env(), check=False)
        if p.returncode != 0:
            raise RuntimeError(p.stderr.decode(errors="ignore"))
        out = p.stdout.decode("utf-8", errors="replace")
        return [dict(row) for row in csv_mod.DictReader(io.StringIO(out))] if out.strip() else []


# ---------------------------------------------------------------------------
# Automox HTTP client
# ---------------------------------------------------------------------------
class AutomoxClient:
    def __init__(self, cfg: Config) -> None:
        self.cfg  = cfg
        self.sess = requests.Session()
        self.sess.headers.update({
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "vanalyzer-automox-etl/5.0",
        })
        if cfg.auth_mode == "bearer":
            self.sess.headers["Authorization"] = f"Bearer {cfg.api_key}"

    def _base_params(self) -> Dict[str, Any]:
        p: Dict[str, Any] = {"o": self.cfg.org_id}
        if self.cfg.auth_mode == "query":
            p["api_key"] = self.cfg.api_key
        return p

    def get(self, path: str, params: Optional[Dict[str, Any]] = None,
            allow_404: bool = False) -> Tuple[Any, int]:
        url    = f"{self.cfg.base_url}/{path.lstrip('/')}"
        merged = {**self._base_params(), **(params or {})}

        for attempt in range(self.cfg.retries + 1):
            try:
                if self.cfg.sleep_s > 0:
                    time.sleep(self.cfg.sleep_s)
                r = self.sess.get(url, params=merged,
                                  timeout=self.cfg.timeout_s,
                                  verify=self.cfg.verify_ssl)

                # respect rate-limit headers
                remaining = _i(r.headers.get("x-ratelimit-remaining"))
                if remaining is not None and remaining < 5:
                    reset_ts = _i(r.headers.get("x-ratelimit-reset"))
                    if reset_ts:
                        wait = max(0.0, reset_ts - time.time()) + 0.5
                        time.sleep(wait)

                if r.status_code == 404 and allow_404:
                    return None, 404
                if r.status_code == 429:
                    wait = float(r.headers.get("retry-after") or (2.0 + attempt))
                    time.sleep(wait + random.uniform(0, wait * 0.25))
                    continue
                if 500 <= r.status_code <= 599:
                    backoff = min(30.0, 1.5 ** attempt)
                    time.sleep(backoff + random.uniform(0, backoff * 0.25))
                    continue
                if r.status_code >= 400:
                    raise RuntimeError(f"HTTP {r.status_code} GET {url}")
                if not r.content or not r.text.strip():
                    return None, r.status_code
                return r.json(), r.status_code

            except requests.RequestException as e:
                if attempt >= self.cfg.retries:
                    raise RuntimeError(f"GET {url} failed: {e}") from e
                time.sleep(min(30.0, 1.5 ** attempt))

        raise RuntimeError(f"GET {url} exhausted retries")


# ---------------------------------------------------------------------------
# Pagination helpers
# ---------------------------------------------------------------------------
def _items(payload: Any) -> List[JsonObj]:
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    if isinstance(payload, dict):
        for k in ("results", "data", "servers", "devices"):
            v = payload.get(k)
            if isinstance(v, list):
                return [x for x in v if isinstance(x, dict)]
    return []


def detect_resource(client: AutomoxClient) -> str:
    for res in ("servers", "devices"):
        try:
            _, code = client.get(res, params={"page": 0, "limit": 1}, allow_404=True)
            if code != 404:
                log(f"API resource detected: /{res}")
                return res
        except Exception:
            continue
    return "servers"


def iter_devices(client: AutomoxClient, resource: str) -> Iterable[JsonObj]:
    page = 0
    while True:
        payload, _ = client.get(resource, params={"page": page, "limit": client.cfg.limit})
        batch = _items(payload)
        if not batch:
            break
        for item in batch:
            yield item
        if len(batch) < client.cfg.limit:
            break
        page += 1


def fetch_detail(client: AutomoxClient, resource: str, device_id: int) -> Optional[JsonObj]:
    payload, code = client.get(f"{resource}/{device_id}", allow_404=True)
    return payload if isinstance(payload, dict) and code != 404 else None


def fetch_inventory(client: AutomoxClient, org_uuid: str, device_uuid: str) -> Optional[JsonObj]:
    """Fetch extended software inventory via device-details endpoint."""
    if not org_uuid or not device_uuid:
        return None
    path = f"device-details/orgs/{org_uuid}/devices/{device_uuid}/inventory"
    try:
        payload, code = client.get(path, allow_404=True)
        return payload if isinstance(payload, dict) and code != 404 else None
    except Exception:
        return None


def iter_packages(client: AutomoxClient, resource: str, device_id: int,
                  max_packages: int) -> Iterable[JsonObj]:
    page = 0
    total = 0
    while True:
        want = client.cfg.limit
        if max_packages > 0:
            want = min(client.cfg.limit, max_packages - total)
            if want <= 0:
                break
        payload, code = client.get(
            f"{resource}/{device_id}/packages",
            params={"page": page, "limit": want},
            allow_404=True,
        )
        if code == 404:
            return
        batch = _items(payload)
        if not batch:
            break
        for item in batch:
            yield item
            total += 1
            if max_packages > 0 and total >= max_packages:
                return
        if len(batch) < want:
            break
        page += 1


# ---------------------------------------------------------------------------
# Row builders
# ---------------------------------------------------------------------------
def build_asset_row(run_id: int, d_list: JsonObj,
                    d_detail: Optional[JsonObj],
                    d_inv: Optional[JsonObj]) -> Tuple:
    """Build a row for automox_assets_inventory (exact column order)."""
    # merge: detail > list, inventory enriches OS fields
    d = d_detail if d_detail else d_list
    inv = d_inv or {}

    # --- Identifiers ---
    source_asset_id = int(d.get("id") or d_list["id"])
    source_uuid     = _clean(d.get("uuid") or d.get("device_uuid") or d.get("server_uuid"))
    asset_ref       = _clean(d.get("asset_ref") or d.get("name") or d.get("hostname"))

    # --- Hostname / FQDN ---
    hostname      = _clean(d.get("name") or d.get("hostname") or d.get("display_name"))
    hostname_norm = hostname.lower().strip() if hostname else None
    fqdn          = _clean(
        d.get("fqdn") or d.get("fully_qualified_name")
        or inv.get("fqdn") or (hostname + "." + d.get("domain", "") if hostname and d.get("domain") else None)
    )
    fqdn_norm     = fqdn.lower().strip() if fqdn else hostname_norm
    domain        = _clean(d.get("domain") or d.get("workgroup"))
    serial_number = _clean(d.get("serial_number") or d.get("serial") or inv.get("serial_number"))

    # --- Network ---
    all_ips = _ip_list(
        d.get("ip_addrs") or d.get("ip_addresses") or d.get("ip_addrs_private")
    )
    last_ip = _s(d.get("last_ip_address") or d.get("ip_address"))
    if last_ip and last_ip not in all_ips:
        all_ips = [last_ip] + all_ips
    ip_primary   = all_ips[0] if all_ips else None
    ip_addrs_pg  = _pg_inet_array(all_ips)

    mac_list     = _mac_list(d.get("mac_addrs") or d.get("mac_address") or inv.get("mac_addrs"))
    mac_addrs_pg = _pg_text_array(mac_list)

    subnet = _clean(d.get("subnet") or d.get("subnet_mask") or inv.get("subnet"))
    site   = _clean(
        d.get("server_group_name") or d.get("group_name")
        or d.get("site_name") or d.get("zone_name")
    )

    # --- OS  (dig deep: status dict > top level > inventory) ---
    status_raw = d.get("status")
    st = status_raw if isinstance(status_raw, dict) else {}

    os_family  = _clean(
        st.get("os_family") or d.get("os_family") or d.get("os_type")
        or inv.get("os_family") or inv.get("platform")
    )
    os_name    = _clean(
        st.get("os_name") or st.get("operating_system")
        or d.get("os_name") or d.get("operating_system") or d.get("os")
        or inv.get("os_name") or inv.get("operating_system")
    )
    os_version = _clean(
        st.get("os_version") or d.get("os_version") or d.get("os_version_str")
        or inv.get("os_version")
    )
    os_build   = _clean(
        d.get("os_build") or d.get("build_number") or d.get("os_build_id")
        or inv.get("os_build") or inv.get("build_number")
    )
    kernel_ver = _clean(
        st.get("kernel_version") or d.get("kernel_version") or d.get("kernel")
        or inv.get("kernel_version")
    )

    # fallback: if os_name still missing, try to compose from os_family + os_version
    if not os_name and os_family:
        os_name = (os_family + (" " + os_version if os_version else "")).strip() or None

    # --- Hardware ---
    manufacturer = _clean(d.get("manufacturer") or d.get("vendor") or inv.get("manufacturer"))
    model        = _clean(d.get("model") or inv.get("model"))
    cpu_cores    = _i(d.get("cpu_count") or d.get("cpu_cores") or inv.get("cpu_count"))
    ram_mb       = _i(d.get("ram") or d.get("ram_mb") or d.get("total_memory_mb") or inv.get("ram_mb"))
    disk_gb      = _i(d.get("disk_space") or d.get("disk_total_gb") or inv.get("disk_space"))

    # --- Status ---
    connected = _b(
        st.get("connected") or d.get("connected")
        or (isinstance(status_raw, str) and status_raw.lower() == "connected")
    )
    needs_reboot = _b(
        st.get("needs_reboot") or d.get("needs_reboot") or d.get("reboot_required")
    )

    last_seen = parse_dt(
        d.get("last_connected_time") or d.get("last_seen_time")
        or d.get("last_update_time") or d.get("last_connected")
    )
    last_scan = parse_dt(
        d.get("last_scan_time") or d.get("last_processed")
        or d.get("last_scanned") or d.get("last_refresh_time")
    )

    pending_patches = _i(d.get("pending_patch_count") or d.get("pending_patches") or d.get("patch_count"))
    pending_updates = _i(d.get("pending_update_count") or d.get("outstanding_patches"))

    # --- Tags ---
    tags    = _tags(d.get("tags"))
    tags_pg = _pg_text_array(tags)

    # --- Raw JSON ---
    raw_inventory = _json(d_list)
    raw_detail    = _json(d_detail)

    return (
        run_id, "automox", source_asset_id,
        source_uuid, asset_ref,
        hostname, hostname_norm,
        fqdn, fqdn_norm,
        domain, serial_number,
        ip_primary, ip_addrs_pg, mac_addrs_pg,
        subnet, site,
        os_family, os_name, os_version, os_build, kernel_ver,
        manufacturer, model, cpu_cores, ram_mb, disk_gb,
        connected, last_seen, last_scan, needs_reboot,
        pending_updates, pending_patches,
        tags_pg,
        raw_inventory, raw_detail,
    )


def build_package_row(run_id: int, device_id: int, pkg: JsonObj) -> Tuple:
    """Build a row for automox_pending_software (exact column order)."""
    source_update_row_id = _i(pkg.get("update_row_id") or pkg.get("row_id"))
    package_id   = _i(pkg.get("id") or pkg.get("package_id"))
    software_id  = _i(pkg.get("software_id") or pkg.get("software_uuid"))
    software_name = _clean(pkg.get("display_name") or pkg.get("name") or pkg.get("software_name")) or "Unknown"
    vendor        = _clean(pkg.get("repo") or pkg.get("vendor") or pkg.get("publisher"))
    package_type  = _clean(pkg.get("package_type") or pkg.get("type") or pkg.get("category"))
    current_ver   = _clean(pkg.get("version") or pkg.get("installed_version") or pkg.get("current_version"))
    available_ver = _clean(pkg.get("package_version") or pkg.get("available_version") or pkg.get("new_version"))
    if available_ver and available_ver == current_ver:
        available_ver = None

    kb_id    = _clean(pkg.get("kb_id") or pkg.get("kb") or pkg.get("knowledgebase_id"))
    patch_id = _clean(pkg.get("patch_id") or pkg.get("update_id") or pkg.get("bulletin_id"))

    is_pending  = True
    is_ignored  = bool(_b(pkg.get("ignored")) or False)
    is_deferred = bool(_b(pkg.get("deferred")) or False)
    deferred_until = parse_dt(pkg.get("deferred_until") or pkg.get("defer_until"))

    severity = _clean(pkg.get("severity") or pkg.get("severity_type") or pkg.get("patch_classification"))
    cvss     = _f(pkg.get("cvss_score") or pkg.get("cvss"))
    if not severity and cvss is not None:
        severity = severity_from_cvss(cvss)
    # normalize severity casing
    if severity:
        severity = severity.lower()

    reboot_req = _b(pkg.get("requires_reboot") or pkg.get("reboot_required"))

    cves    = extract_cves(pkg)
    cves_pg = _pg_text_array(cves)

    raw_update = _json(pkg)

    return (
        run_id, "automox", device_id,
        source_update_row_id, package_id, software_id,
        software_name, vendor, package_type,
        current_ver, available_ver,
        kb_id, patch_id,
        is_pending, is_ignored, is_deferred, deferred_until,
        severity, cvss, reboot_req,
        cves_pg,
        raw_update,
    )


def build_cve_rows(run_id: int, device_id: int, pending_id: Optional[int],
                   pkg: JsonObj, cves: List[str],
                   min_cvss: Optional[float]) -> List[Tuple]:
    """Build rows for automox_asset_cves (exact column order)."""
    rows: List[Tuple] = []

    pkg_severity  = _clean(pkg.get("severity") or pkg.get("severity_type"))
    pkg_cvss      = _f(pkg.get("cvss_score") or pkg.get("cvss"))
    pkg_sw_name   = _clean(pkg.get("display_name") or pkg.get("name")) or "Unknown"
    pkg_sw_ver    = _clean(pkg.get("version") or pkg.get("installed_version"))
    pkg_avail_ver = _clean(pkg.get("package_version") or pkg.get("available_version"))
    pkg_reboot    = _b(pkg.get("requires_reboot") or pkg.get("reboot_required"))
    pkg_refs      = extract_reference_urls(pkg)

    # build per-CVE detail map from vulnerabilities[] if present
    vuln_map: Dict[str, JsonObj] = {}
    for v in (pkg.get("vulnerabilities") or []):
        if isinstance(v, dict):
            cid = (v.get("cve_id") or v.get("cve") or v.get("cveId") or "").upper().strip()
            if CVE_RE.match(cid):
                vuln_map[cid] = v

    for cve in cves:
        detail = vuln_map.get(cve, {})

        cvss_score  = _f(detail.get("cvss_score") or detail.get("cvss")) or pkg_cvss
        severity    = _clean(detail.get("severity") or detail.get("severity_type"))
        if not severity:
            severity = pkg_severity
        if not severity and cvss_score is not None:
            severity = severity_from_cvss(cvss_score)
        if severity:
            severity = severity.lower()

        if min_cvss is not None and cvss_score is not None and cvss_score < min_cvss:
            continue

        cvss_vector = _clean(
            detail.get("cvss_vector") or detail.get("vector_string")
            or detail.get("cvssVector")
        )
        epss        = _f(detail.get("epss_score") or detail.get("epss"))
        exploited   = _b(
            detail.get("exploited") or detail.get("known_exploited")
            or detail.get("actively_exploited")
        )
        patch_avail  = pkg_avail_ver is not None
        fixed_in     = _clean(
            detail.get("fixed_in_version") or detail.get("fixed_version")
            or detail.get("remediation_version")
        ) or pkg_avail_ver

        affected_sw_name = _clean(
            detail.get("affected_software") or detail.get("affected_product")
            or detail.get("software_name")
        ) or pkg_sw_name
        affected_sw_ver  = _clean(
            detail.get("affected_version") or detail.get("affected_software_version")
        ) or pkg_sw_ver

        evidence = _clean(
            detail.get("evidence") or detail.get("notes") or detail.get("description")
            or detail.get("title") or detail.get("summary")
        )
        if not evidence:
            # compose a minimal evidence string from what we know
            parts = [f"Package: {pkg_sw_name}"]
            if pkg_sw_ver:
                parts.append(f"v{pkg_sw_ver}")
            if pkg_avail_ver:
                parts.append(f"(fix: v{pkg_avail_ver})")
            evidence = " ".join(parts)

        ref_urls = extract_reference_urls(detail) or pkg_refs
        ref_urls_pg = _pg_text_array(ref_urls)

        raw_cve      = _json(detail if detail else {})
        raw_relation = _json({"package_id": _i(pkg.get("id")), "package_name": pkg_sw_name,
                               "source": "automox"})

        rows.append((
            run_id, "automox", device_id, pending_id,
            cve, severity, cvss_score, cvss_vector,
            epss, exploited, patch_avail, fixed_in,
            affected_sw_name, affected_sw_ver,
            evidence, ref_urls_pg,
            raw_cve, raw_relation,
        ))
    return rows


# ---------------------------------------------------------------------------
# SQL constants  –  exact schema match
# ---------------------------------------------------------------------------
ASSET_SQL = """
    INSERT INTO public.automox_assets_inventory (
        run_id, source_system, source_asset_id,
        source_uuid, asset_ref,
        hostname, hostname_norm,
        fqdn, fqdn_norm,
        domain, serial_number,
        ip_primary, ip_addrs, mac_addrs,
        subnet, site,
        os_family, os_name, os_version, os_build, kernel_version,
        manufacturer, model, cpu_cores, ram_mb, disk_total_gb,
        connected, last_seen_at, last_scan_at, needs_reboot,
        pending_updates_count, pending_patches_count,
        tags,
        raw_inventory, raw_detail
    ) VALUES %s
    ON CONFLICT (run_id, source_system, source_asset_id) DO UPDATE SET
        source_uuid           = EXCLUDED.source_uuid,
        asset_ref             = EXCLUDED.asset_ref,
        hostname              = EXCLUDED.hostname,
        hostname_norm         = EXCLUDED.hostname_norm,
        fqdn                  = EXCLUDED.fqdn,
        fqdn_norm             = EXCLUDED.fqdn_norm,
        ip_primary            = EXCLUDED.ip_primary,
        ip_addrs              = EXCLUDED.ip_addrs,
        mac_addrs             = EXCLUDED.mac_addrs,
        os_family             = EXCLUDED.os_family,
        os_name               = EXCLUDED.os_name,
        os_version            = EXCLUDED.os_version,
        os_build              = EXCLUDED.os_build,
        kernel_version        = EXCLUDED.kernel_version,
        connected             = EXCLUDED.connected,
        last_seen_at          = EXCLUDED.last_seen_at,
        last_scan_at          = EXCLUDED.last_scan_at,
        needs_reboot          = EXCLUDED.needs_reboot,
        pending_patches_count = EXCLUDED.pending_patches_count,
        pending_updates_count = EXCLUDED.pending_updates_count,
        raw_inventory         = EXCLUDED.raw_inventory,
        raw_detail            = EXCLUDED.raw_detail,
        ingested_at           = now()
"""

ASSET_TPL = (
    "(%s, %s, %s,"          # run_id, source_system, source_asset_id
    " %s, %s,"              # source_uuid, asset_ref
    " %s, %s,"              # hostname, hostname_norm
    " %s, %s,"              # fqdn, fqdn_norm
    " %s, %s,"              # domain, serial_number
    " %s::inet, %s::inet[], %s,"  # ip_primary, ip_addrs, mac_addrs
    " %s, %s,"              # subnet, site
    " %s, %s, %s, %s, %s," # os_family, os_name, os_version, os_build, kernel_version
    " %s, %s, %s, %s, %s," # manufacturer, model, cpu_cores, ram_mb, disk_total_gb
    " %s, %s, %s, %s,"     # connected, last_seen_at, last_scan_at, needs_reboot
    " %s, %s,"              # pending_updates_count, pending_patches_count
    " %s,"                  # tags
    " %s, %s)"              # raw_inventory, raw_detail
)

PKG_SQL = """
    INSERT INTO public.automox_pending_software (
        run_id, source_system, source_asset_id,
        source_update_row_id, package_id, software_id,
        software_name, vendor, package_type,
        current_version, available_version,
        kb_id, patch_id,
        is_pending, is_ignored, is_deferred, deferred_until,
        severity, cvss_score, reboot_required,
        cve_ids,
        raw_update
    ) VALUES (
        %s, %s, %s,
        %s, %s, %s,
        %s, %s, %s,
        %s, %s,
        %s, %s,
        %s, %s, %s, %s,
        %s, %s, %s,
        %s,
        %s
    )
    RETURNING pending_id
"""

CVE_SQL = """
    INSERT INTO public.automox_asset_cves (
        run_id, source_system, source_asset_id, pending_id,
        cve_id, severity, cvss_score, cvss_vector,
        epss_score, exploited, patch_available, fixed_in_version,
        affected_software_name, affected_software_version,
        evidence, reference_urls,
        raw_cve, raw_relation
    ) VALUES (
        %s, %s, %s, %s,
        %s, %s, %s, %s,
        %s, %s, %s, %s,
        %s, %s,
        %s, %s,
        %s, %s
    )
    ON CONFLICT (run_id, source_system, source_asset_id, cve_id) DO UPDATE SET
        cvss_score            = COALESCE(EXCLUDED.cvss_score,            public.automox_asset_cves.cvss_score),
        severity              = COALESCE(EXCLUDED.severity,              public.automox_asset_cves.severity),
        cvss_vector           = COALESCE(EXCLUDED.cvss_vector,           public.automox_asset_cves.cvss_vector),
        epss_score            = COALESCE(EXCLUDED.epss_score,            public.automox_asset_cves.epss_score),
        exploited             = COALESCE(EXCLUDED.exploited,             public.automox_asset_cves.exploited),
        patch_available       = EXCLUDED.patch_available,
        fixed_in_version      = COALESCE(EXCLUDED.fixed_in_version,      public.automox_asset_cves.fixed_in_version),
        affected_software_name= COALESCE(EXCLUDED.affected_software_name,public.automox_asset_cves.affected_software_name),
        evidence              = COALESCE(EXCLUDED.evidence,              public.automox_asset_cves.evidence),
        reference_urls        = COALESCE(EXCLUDED.reference_urls,        public.automox_asset_cves.reference_urls),
        raw_cve               = EXCLUDED.raw_cve,
        ingested_at           = now()
"""


# ---------------------------------------------------------------------------
# ETL run management
# ---------------------------------------------------------------------------
def purge_previous(db: DBClient, org_id: str) -> None:
    row = db.fetchone(
        "SELECT COUNT(*) AS cnt FROM public.automox_etl_runs WHERE source_system = %s AND org_id = %s",
        ("automox", org_id),
    )
    count = int(row["cnt"]) if row else 0
    if count:
        log(f"Purging {count} previous run(s) for org_id={org_id} (cascade)...")
        db.execute(
            "DELETE FROM public.automox_etl_runs WHERE source_system = %s AND org_id = %s",
            ("automox", org_id),
        )
        log("Purge complete.")
    else:
        log("No previous runs to purge.")


def create_run(db: DBClient, org_id: str, cfg: Config) -> int:
    params_json = json.dumps({
        "base_url": cfg.base_url, "limit": cfg.limit,
        "max_packages": cfg.max_packages, "min_cvss": cfg.min_cvss,
    })
    db.execute(
        """INSERT INTO public.automox_etl_runs
           (source_system, org_id, started_at, status, request_params)
           VALUES (%s, %s, %s, %s, %s)""",
        ("automox", org_id, utc_now(), "running", params_json),
    )
    row = db.fetchone(
        "SELECT currval(pg_get_serial_sequence('public.automox_etl_runs','run_id')) AS run_id"
    )
    if not row:
        raise RuntimeError("Could not retrieve run_id after INSERT")
    return int(row["run_id"])


def close_run(db: DBClient, run_id: int, status: str,
              rows_assets: int, rows_pending: int, rows_cves: int,
              meta: Optional[Dict] = None,
              error: Optional[str] = None,
              detail: Optional[str] = None) -> None:
    meta_json = json.dumps(meta or {})
    db.execute(
        """UPDATE public.automox_etl_runs SET
               finished_at    = %s,
               status         = %s,
               rows_assets    = %s,
               rows_pending_sw= %s,
               rows_cves      = %s,
               response_meta  = %s,
               error_message  = %s,
               error_detail   = %s
           WHERE run_id = %s""",
        (utc_now(), status, rows_assets, rows_pending, rows_cves,
         meta_json, error, detail, run_id),
    )


# ---------------------------------------------------------------------------
# Insert helpers
# ---------------------------------------------------------------------------
def insert_asset(db: DBClient, row: Tuple, dry_run: bool) -> None:
    if dry_run:
        return
    if HAS_PSYCOPG2 and db.conn is not None:
        with db.conn.cursor() as cur:
            execute_values(cur, ASSET_SQL, [row], template=ASSET_TPL)
    else:
        db.execute(ASSET_SQL.replace("VALUES %s", f"VALUES {ASSET_TPL}"), row)


def insert_package(db: DBClient, row: Tuple, dry_run: bool) -> Optional[int]:
    if dry_run:
        return None
    if HAS_PSYCOPG2 and db.conn is not None:
        with db.conn.cursor() as cur:
            cur.execute(PKG_SQL, row)
            result = cur.fetchone()
            if result is None:
                return None
            return result["pending_id"] if isinstance(result, dict) else result[0]
    else:
        db.execute(PKG_SQL.replace("RETURNING pending_id", ""), row)
        id_row = db.fetchone("SELECT lastval() AS id")
        return int(id_row["id"]) if id_row else None


def insert_cve(db: DBClient, row: Tuple, dry_run: bool) -> None:
    if dry_run:
        return
    db.execute(CVE_SQL, row)


# ---------------------------------------------------------------------------
# Main ETL loop
# ---------------------------------------------------------------------------
def run_etl(cfg: Config) -> int:
    db = DBClient(cfg)
    db.connect()

    client   = AutomoxClient(cfg)
    resource = detect_resource(client)

    log("=" * 60)
    log("Automox ETL v5.0")
    log(f"  org_id       = {cfg.org_id}")
    log(f"  api_key      = {mask(cfg.api_key)}")
    log(f"  resource     = /{resource}")
    log(f"  page_limit   = {cfg.limit}")
    log(f"  max_packages = {cfg.max_packages or 'unlimited'}")
    log(f"  min_cvss     = {cfg.min_cvss if cfg.min_cvss is not None else 'none'}")
    log(f"  dry_run      = {cfg.dry_run}")
    log(f"  pg           = {cfg.pg_host}:{cfg.pg_port}/{cfg.pg_db}")
    log("=" * 60)

    if cfg.dry_run:
        run_id = 0
        log("[DRY-RUN] No DB writes.")
    else:
        purge_previous(db, cfg.org_id)
        run_id = create_run(db, cfg.org_id, cfg)
        log(f"ETL run_id = {run_id}")

    rows_assets  = 0
    rows_pending = 0
    rows_cves    = 0
    errors: List[str] = []
    run_meta: Dict[str, Any] = {"pages_read": 0, "devices_seen": 0}

    # fetch org info once to get org_uuid for inventory endpoint
    org_uuid: Optional[str] = None
    try:
        orgs_payload, _ = client.get("orgs")
        orgs = _items(orgs_payload)
        for org in orgs:
            if str(org.get("id")) == str(cfg.org_id):
                org_uuid = _clean(org.get("uuid") or org.get("org_uuid"))
                break
        if not org_uuid and orgs:
            org_uuid = _clean(orgs[0].get("uuid"))
    except Exception as e:
        log_warn(f"Could not fetch org UUID: {e}")

    try:
        dev_num = 0
        for d_list in iter_devices(client, resource):
            device_id = _i(d_list.get("id"))
            if device_id is None:
                continue

            dev_num += 1
            run_meta["devices_seen"] = dev_num
            log(f"[{dev_num}] id={device_id}  name={d_list.get('name', '?')}")

            # --- Fetch detail ---
            d_detail: Optional[JsonObj] = None
            try:
                d_detail = fetch_detail(client, resource, device_id)
            except Exception as e:
                log_warn(f"  detail fetch failed: {e}")
                errors.append(f"detail:{device_id}:{e}")

            # --- Fetch extended inventory (OS, hardware, serial) ---
            d_inv: Optional[JsonObj] = None
            if cfg.fetch_inventory and org_uuid:
                device_uuid = _clean(
                    (d_detail or d_list).get("uuid")
                    or (d_detail or d_list).get("device_uuid")
                )
                if device_uuid:
                    try:
                        d_inv = fetch_inventory(client, org_uuid, device_uuid)
                    except Exception as e:
                        log_warn(f"  inventory fetch failed: {e}")

            # --- Insert asset ---
            try:
                asset_row = build_asset_row(run_id, d_list, d_detail, d_inv)
                insert_asset(db, asset_row, cfg.dry_run)
                rows_assets += 1
            except Exception as e:
                log_err(f"  asset insert failed: {e}")
                errors.append(f"asset:{device_id}:{e}")
                continue

            # --- Packages & CVEs ---
            pkg_num = 0
            try:
                for pkg in iter_packages(client, resource, device_id, cfg.max_packages):
                    pkg_num += 1
                    cves = extract_cves(pkg)

                    pending_id: Optional[int] = None
                    try:
                        pkg_row    = build_package_row(run_id, device_id, pkg)
                        pending_id = insert_package(db, pkg_row, cfg.dry_run)
                        rows_pending += 1
                    except Exception as e:
                        log_warn(f"  pkg#{pkg_num} insert failed: {e}")
                        errors.append(f"pkg:{device_id}:#{pkg_num}:{e}")

                    for cve_row in build_cve_rows(
                        run_id, device_id, pending_id, pkg, cves, cfg.min_cvss
                    ):
                        try:
                            insert_cve(db, cve_row, cfg.dry_run)
                            rows_cves += 1
                        except Exception as e:
                            cve_id = cve_row[4] if len(cve_row) > 4 else "?"
                            log_warn(f"  cve {cve_id} insert failed: {e}")
                            errors.append(f"cve:{device_id}:{cve_id}:{e}")

            except Exception as e:
                log_warn(f"  packages fetch failed: {e}")
                errors.append(f"pkgs:{device_id}:{e}")

            log(f"  → pkgs={pkg_num}  total assets={rows_assets}  total pkgs={rows_pending}  total cves={rows_cves}")

    except Exception as fatal:
        log_err(f"FATAL: {fatal}")
        if not cfg.dry_run:
            close_run(db, run_id, "error", rows_assets, rows_pending, rows_cves,
                      meta=run_meta, error=str(fatal),
                      detail="\n".join(errors[-20:]))
        db.close()
        return 1

    status = "success" if not errors else "partial"
    run_meta["error_count"] = len(errors)

    log("=" * 60)
    log(f"DONE  run_id={run_id}  status={status}")
    log(f"  assets={rows_assets}  packages={rows_pending}  cves={rows_cves}  errors={len(errors)}")
    log("=" * 60)

    if errors:
        log("First errors:")
        for e in errors[:10]:
            log(f"  {e}")

    if not cfg.dry_run:
        close_run(db, run_id, status, rows_assets, rows_pending, rows_cves,
                  meta=run_meta,
                  error="\n".join(errors[:5]) if errors else None,
                  detail="\n".join(errors) if errors else None)

    db.close()
    return 0


# ---------------------------------------------------------------------------
def main() -> int:
    try:
        cfg = Config()
    except RuntimeError as e:
        log_err(str(e))
        return 2
    return run_etl(cfg)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        log(f"[FATAL] {e}")
        raise
