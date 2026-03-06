#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv as csv_mod
import io
import os
import re
import sys
import time
import json
import argparse
import hashlib
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
except Exception:
    psycopg2 = None

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

DEFAULT_TICKETS_TABLE_CANDIDATES = [
    "public.snow_problem_vuln_tickets",
    "public.snow_problem_vuln_ticket",
]

STATE_CATEGORY_OPEN     = "open"
STATE_CATEGORY_RESOLVED = "resolved"
DEFAULT_SN_TABLE          = "problem"
IMPORT_SET_TABLE          = "u_vuln_sync"

INCIDENT_COL_ENDPOINT_HASH = "endpoint_hash"
INCIDENT_COL_ASSET         = "asset"
INCIDENT_COL_CVE           = "cve"
INCIDENT_COL_EVENT_TYPE    = "event_type"
INCIDENT_COL_H_UPDATED_AT  = "h_updated_at"
INCIDENT_COL_EVENT_EPOCH   = "mitigated_event_detected_at"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def log(msg: str) -> None:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


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
        raise RuntimeError(f"Missing required secret: {path}")
    return default


def first_existing_secret(paths: List[str], required: bool = False, default: str = "") -> str:
    for p in paths:
        try:
            with open(p, "r", encoding="utf-8") as f:
                v = f.read().strip()
                if v:
                    return v
        except FileNotFoundError:
            continue
        except Exception as e:
            if required:
                raise RuntimeError(f"Error reading secret {p}: {e}") from e
    if required and not default:
        raise RuntimeError(f"None of the required secrets found: {paths}")
    return default


def norm_asset(s: str) -> str:
    return (s or "").strip().lower()


def norm_hash(s: str) -> str:
    return (s or "").strip().lower()


def norm_cve(s: str) -> str:
    return (s or "").strip().upper()


def extract_cves(cve_field: str) -> List[str]:
    if not cve_field:
        return []
    found = sorted({m.group(0).upper() for m in CVE_RE.finditer(cve_field)})
    if found:
        return found
    raw = cve_field.strip().upper()
    if raw.startswith("CVE-"):
        return [raw]
    return []


def correlation_key(endpoint_hash: str, asset: str, cve: str) -> str:
    base = f"{norm_hash(endpoint_hash)}|{norm_asset(asset)}|{norm_cve(cve)}"
    return hashlib.sha1(base.encode("utf-8")).hexdigest()


def dt_to_sn_human(dt: Optional[datetime]) -> str:
    if not dt:
        return "n/a"
    s = dt.strftime("%B %d, %Y, %I:%M %p")
    s = s.replace(" 0", " ")
    s = s.replace(", 0", ", ")
    return s


def epoch_ms_to_human(val: Any) -> str:
    if val is None:
        return "n/a"
    try:
        ts = int(str(val).strip())
        if ts > 1e12:
            ts = ts / 1000.0
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        return dt_to_sn_human(dt)
    except (ValueError, TypeError, OSError):
        return str(val)


def map_sensitivity_to_urgency(sensitivity: str) -> str:
    s = (sensitivity or "").strip().lower()
    if s in {"critical", "high"}:
        return "1"
    elif s in {"medium"}:
        return "2"
    elif s in {"low"}:
        return "3"
    elif s in {"informational", "info"}:
        return "3"
    else:
        return "2"


class DBClient:
    def __init__(self, db: str, user: str, password: str = "", host: str = "", port: str = "5432"):
        self.db       = db
        self.user     = user
        self.password = password
        self.host     = host
        self.port     = port
        self.conn     = None

    def connect(self) -> None:
        if psycopg2 is None:
            log("psycopg2 not available; using psql fallback.")
            return
        kwargs: Dict[str, Any] = dict(dbname=self.db, user=self.user, cursor_factory=RealDictCursor)
        if self.password:
            kwargs["password"] = self.password
        if self.host:
            kwargs["host"] = self.host
            kwargs["port"] = self.port
        try:
            self.conn = psycopg2.connect(**kwargs)
            self.conn.autocommit = True
            return
        except Exception as e:
            if not self.host:
                try:
                    kwargs["host"] = "localhost"
                    kwargs["port"] = self.port
                    self.conn = psycopg2.connect(**kwargs)
                    self.conn.autocommit = True
                    return
                except Exception:
                    pass
            raise RuntimeError(f"Could not connect to Postgres: {e}") from e

    def close(self) -> None:
        if self.conn:
            try:
                self.conn.close()
            except Exception:
                pass

    def query(self, sql: str, params: Optional[Tuple[Any, ...]] = None) -> List[Dict[str, Any]]:
        if psycopg2 is None or self.conn is None:
            return self._psql_query(sql, params)
        with self.conn.cursor() as cur:
            cur.execute(sql, params or ())
            if cur.description is None:
                return []
            return [dict(r) for r in cur.fetchall()]

    def execute(self, sql: str, params: Optional[Tuple[Any, ...]] = None) -> None:
        if psycopg2 is None or self.conn is None:
            self._psql_exec(sql, params)
            return
        with self.conn.cursor() as cur:
            cur.execute(sql, params or ())

    def _render_sql(self, sql: str, params: Optional[Tuple[Any, ...]]) -> str:
        rendered = sql
        if params:
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

    def _psql_query(self, sql: str, params: Optional[Tuple[Any, ...]] = None) -> List[Dict[str, Any]]:
        rendered = self._render_sql(sql, params)
        copy_sql = f"COPY ({rendered}) TO STDOUT WITH CSV HEADER;"
        env = os.environ.copy()
        if self.password:
            env["PGPASSWORD"] = self.password
        cmd = ["psql", "-U", self.user, "-d", self.db, "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-c", copy_sql]
        if self.host:
            cmd += ["-h", self.host, "-p", self.port]
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, check=False)
        if p.returncode != 0:
            raise RuntimeError(f"psql query error:\n{p.stderr.decode(errors='ignore')}")
        out = p.stdout.decode("utf-8", errors="replace")
        if not out.strip():
            return []
        reader = csv_mod.DictReader(io.StringIO(out))
        return [dict(row) for row in reader]

    def _psql_exec(self, sql: str, params: Optional[Tuple[Any, ...]] = None) -> None:
        rendered = self._render_sql(sql, params)
        env = os.environ.copy()
        if self.password:
            env["PGPASSWORD"] = self.password
        cmd = ["psql", "-U", self.user, "-d", self.db, "-X", "-v", "ON_ERROR_STOP=1", "-c", rendered]
        if self.host:
            cmd += ["-h", self.host, "-p", self.port]
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, check=False)
        if p.returncode != 0:
            raise RuntimeError(f"psql exec error:\n{p.stderr.decode(errors='ignore')}")


class ServiceNowClient:
    def __init__(self, base_url: str, user: str, password: str, verify_ssl: bool = True, timeout: int = 30):
        self.base_url = base_url.rstrip("/")
        self.verify   = verify_ssl
        self.timeout  = timeout
        self.user_sys_id = ""

        if not user or not password:
            raise RuntimeError("Missing ServiceNow credentials.")

        self.s = requests.Session()
        self.s.auth = (user, password)
        self.s.headers.update({"Accept": "application/json", "Content-Type": "application/json"})
        self.sn_user = user
        log(f"ServiceNow auth: Basic Auth (user: {user})")

    def _req(self, method: str, path: str, params: Optional[dict] = None, payload: Optional[dict] = None) -> dict:
        url      = f"{self.base_url}{path}"
        last_err = None
        for attempt in range(1, 6):
            try:
                r = self.s.request(method=method, url=url, params=params, json=payload, timeout=self.timeout, verify=self.verify)
                if r.status_code == 401:
                    raise RuntimeError("ServiceNow returned 401 Unauthorized.")
                if r.status_code in (429, 500, 502, 503, 504):
                    last_err = f"HTTP {r.status_code}: {r.text[:200]}"
                    time.sleep(min(2 ** attempt, 12))
                    continue
                r.raise_for_status()
                return r.json()
            except RuntimeError:
                raise
            except requests.exceptions.RequestException as e:
                last_err = str(e)
                time.sleep(min(2 ** attempt, 12))
        raise RuntimeError(f"ServiceNow request failed {method} {path}: {last_err}")

    def resolve_user_sys_id(self) -> str:
        data = self._req("GET", "/api/now/table/sys_user", params={
            "sysparm_query": f"user_name={self.sn_user}",
            "sysparm_fields": "sys_id,name",
            "sysparm_limit": "1",
        })
        results = data.get("result") or []
        if not results:
            raise RuntimeError(f"Could not find sys_id for user '{self.sn_user}'")
        self.user_sys_id = results[0]["sys_id"]
        log(f"User sys_id resolved: {self.user_sys_id} ({results[0].get('name','')})")
        return self.user_sys_id

    def create_record(self, table: str, fields: dict) -> dict:
        data = self._req("POST", f"/api/now/table/{table}", payload=fields)
        return data.get("result") or {}

    def get_record(self, table: str, sys_id: str, fields: str = "") -> dict:
        params: Dict[str, str] = {}
        if fields:
            params["sysparm_fields"] = fields
        data = self._req("GET", f"/api/now/table/{table}/{sys_id}", params=params)
        return data.get("result") or {}

    def close_via_import(self, sn_number: str, close_notes: str) -> Tuple[bool, str]:
        payload = {
            "u_number": sn_number,
            "u_state": "106",
            "u_resolution_code": "fix_applied",
            "u_assigned_to": self.user_sys_id,
            "u_cause_notes": "Known vulnerability in third-party software. Mitigated by vendor patch.",
            "u_fix_notes": close_notes,
            "u_close_notes": close_notes,
        }

        url = f"{self.base_url}/api/now/import/{IMPORT_SET_TABLE}"
        last_err = None

        for attempt in range(1, 4):
            try:
                r = self.s.post(url, json=payload, timeout=self.timeout, verify=self.verify)
                if r.status_code == 201:
                    body   = r.json()
                    result = body.get("result", [{}])
                    res = result[0] if isinstance(result, list) and result else (result if isinstance(result, dict) else {})

                    status = (res.get("status") or "").lower()

                    if status == "updated":
                        return True, "updated"
                    elif status == "error":
                        err_msg = res.get("error_message", "unknown")
                        last_err = f"Import error: {err_msg}"
                        break
                    else:
                        return True, status
                elif r.status_code in (429, 500, 502, 503, 504):
                    last_err = f"HTTP {r.status_code}"
                    time.sleep(min(2 ** attempt, 12))
                    continue
                else:
                    last_err = f"HTTP {r.status_code}: {r.text[:200]}"
                    break
            except Exception as e:
                last_err = str(e)
                time.sleep(min(2 ** attempt, 8))

        return False, last_err or "unknown error"


@dataclass
class ActiveVuln:
    endpoint_id: Optional[int]
    asset: str
    endpoint_hash: str
    product_name: str
    product_raw_entry_name: str
    sensitivity_level_name: str
    cve_raw: str
    vulid: Optional[int]
    patchid: Optional[int]
    patch_name: str
    patch_release_date: str
    patch_release_timestamp: Optional[datetime]
    created_at: Optional[datetime]
    updated_at: Optional[datetime]
    link: str
    vulnerability_summary: str
    vulnerability_v3_base_score: Optional[float]
    vulnerability_v3_exploitability_level: Optional[float]
    typecve: str
    version: str
    subversion: str


def build_short_description(cve: str, v: ActiveVuln) -> str:
    cvss     = v.vulnerability_v3_base_score
    cvss_str = f"{cvss:.1f}" if isinstance(cvss, (int, float)) else (str(cvss) if cvss is not None else "n/a")
    prod     = (v.product_name or "n/a").strip()
    ver      = (v.version or "").strip()
    ver_str  = f" {ver}" if ver else ""
    return f"Detected vulnerability: {cve} on {v.asset} (CVSS {cvss_str}) – {prod}{ver_str}"


def build_description(cve: str, v: ActiveVuln) -> str:
    created_at = dt_to_sn_human(v.created_at) if v.created_at else "n/a"
    if v.patch_release_timestamp:
        patch_release_human = dt_to_sn_human(v.patch_release_timestamp)
    else:
        patch_release_human = epoch_ms_to_human(v.patch_release_date)
    cvss     = v.vulnerability_v3_base_score
    cvss_str = f"{cvss:.1f}" if isinstance(cvss, (int, float)) else (str(cvss) if cvss is not None else "n/a")
    expl     = v.vulnerability_v3_exploitability_level
    expl_str = f"{expl:.1f}" if isinstance(expl, (int, float)) else (str(expl) if expl is not None else "n/a")
    summary = (v.vulnerability_summary or "").strip()
    patchid = v.patchid if v.patchid is not None else 0
    patch_name = (v.patch_name or "n/a").strip()
    return "\n".join([
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        "VULNERABILITY DETECTED",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"Source: Vicarius",
        "",
        f"Asset: {v.asset}",
        f"Sensitivity: {(v.sensitivity_level_name or 'n/a').strip()}",
        "",
        f"CVE: {cve}",
        f"Type: {(v.typecve or 'n/a').strip()}",
        f"Internal Vuln ID: {v.vulid if v.vulid is not None else 'n/a'}",
        "",
        f"Product: {(v.product_name or 'n/a').strip()}",
        f"Version: {(v.version or 'n/a').strip()}",
        f"Subversion: {(v.subversion or 'n/a').strip()}",
        f"Raw Entry: {(v.product_raw_entry_name or 'n/a').strip()}",
        "",
        f"CVSS v3 Base Score: {cvss_str}",
        f"Exploitability Level: {expl_str}",
        "",
        f"Patch ID: {patchid}",
        f"Patch Name: {patch_name}",
        f"Release Date: {patch_release_human}",
        "",
        f"First Detected: {created_at}",
        "",
        f"Link: {(v.link or 'n/a').strip()}",
        "",
        summary if summary else "No description available",
        "",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
    ])


def detect_existing_table(db: DBClient, candidates: List[str]) -> str:
    for t in candidates:
        row = db.query("SELECT to_regclass(%s)::text AS t", (t,))
        if row and row[0].get("t") and row[0]["t"] not in (None, "null", ""):
            return t
    raise RuntimeError(f"No tickets table found: {candidates}")


def validate_incident_columns(db: DBClient) -> None:
    required      = {INCIDENT_COL_ENDPOINT_HASH, INCIDENT_COL_ASSET, INCIDENT_COL_CVE, INCIDENT_COL_EVENT_TYPE}
    timestamp_cols = {INCIDENT_COL_H_UPDATED_AT, INCIDENT_COL_EVENT_EPOCH}
    rows     = db.query("SELECT column_name FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'incident'")
    existing = {r.get("column_name", "") for r in rows}
    missing = required - existing
    if missing:
        raise RuntimeError(f"public.incident is missing required columns: {sorted(missing)}")
    if not (timestamp_cols & existing):
        raise RuntimeError(f"public.incident must have at least one timestamp column: {sorted(timestamp_cols)}")


def fetch_active_vulns(db: DBClient, limit: int, min_cvss: Optional[float]) -> List[ActiveVuln]:
    where:  List[str] = []
    params: List[Any] = []
    if min_cvss is not None:
        where.append("COALESCE(vulnerability_v3_base_score, 0) >= %s")
        params.append(min_cvss)
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
    limit_sql = f"LIMIT {int(limit)}" if limit and limit > 0 else ""
    sql = f"""
      SELECT endpoint_id, COALESCE(asset,'') AS asset, COALESCE(endpoint_hash,'') AS endpoint_hash,
        COALESCE(product_name,'') AS product_name, COALESCE(product_raw_entry_name,'') AS product_raw_entry_name,
        COALESCE(sensitivity_level_name,'') AS sensitivity_level_name, COALESCE(cve,'') AS cve_raw,
        vulid, patchid, COALESCE(patch_name,'') AS patch_name, COALESCE(patch_release_date,'') AS patch_release_date,
        patch_release_timestamp, created_at, updated_at, COALESCE(link,'') AS link,
        COALESCE(vulnerability_summary,'') AS vulnerability_summary, vulnerability_v3_base_score,
        vulnerability_v3_exploitability_level, COALESCE(typecve,'') AS typecve,
        COALESCE(version,'') AS version, COALESCE(subversion,'') AS subversion
      FROM public.activevulnerabilities {where_sql}
      ORDER BY updated_at DESC NULLS LAST {limit_sql}
    """
    rows = db.query(sql, tuple(params))
    out: List[ActiveVuln] = []
    for r in rows:
        out.append(ActiveVuln(
            endpoint_id=r.get("endpoint_id"), asset=r.get("asset") or "", endpoint_hash=r.get("endpoint_hash") or "",
            product_name=r.get("product_name") or "", product_raw_entry_name=r.get("product_raw_entry_name") or "",
            sensitivity_level_name=r.get("sensitivity_level_name") or "", cve_raw=r.get("cve_raw") or "",
            vulid=r.get("vulid"), patchid=r.get("patchid"), patch_name=r.get("patch_name") or "",
            patch_release_date=r.get("patch_release_date") or "", patch_release_timestamp=r.get("patch_release_timestamp"),
            created_at=r.get("created_at"), updated_at=r.get("updated_at"), link=r.get("link") or "",
            vulnerability_summary=r.get("vulnerability_summary") or "",
            vulnerability_v3_base_score=r.get("vulnerability_v3_base_score"),
            vulnerability_v3_exploitability_level=r.get("vulnerability_v3_exploitability_level"),
            typecve=r.get("typecve") or "", version=r.get("version") or "", subversion=r.get("subversion") or "",
        ))
    return out


def load_existing_keys(db: DBClient, tickets_table: str) -> Dict[str, Dict[str, Any]]:
    sql  = f"SELECT correlation_key, sn_sys_id, sn_number, sn_url, sn_state_category, is_active, endpoint_hash, asset, cve FROM {tickets_table}"
    rows = db.query(sql)
    m: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        k = (r.get("correlation_key") or "").strip()
        if k:
            m[k] = r
    return m


def upsert_ticket_record_created(
    db: DBClient, tickets_table: str, corr_key: str, v: ActiveVuln, cve: str,
    sn_sys_id: str, sn_number: str, sn_url: str, sn_state: str,
) -> None:
    first_detected = v.created_at or utc_now()
    last_detected  = v.updated_at or v.created_at or utc_now()
    ticket_created = utc_now()
    sql = f"""
      INSERT INTO {tickets_table} (
        correlation_key, asset, cve, endpoint_hash, endpoint_id,
        product_name, product_raw_entry_name, version, sensitivity_level_name,
        cvss_v3_base_score, vulnerability_v3_exploitability_level,
        vulnerability_summary, reference_link,
        sn_table, sn_sys_id, sn_number, sn_url,
        sn_state, sn_state_category, is_active,
        first_detected_at, last_detected_at, ticket_created_at,
        mitigated_detected_at, ticket_resolved_at, closed_reason
      ) VALUES (
        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NULL, NULL, NULL
      )
      ON CONFLICT (correlation_key) DO UPDATE SET last_detected_at = EXCLUDED.last_detected_at
    """
    db.execute(sql, (
        corr_key, v.asset, cve, v.endpoint_hash, v.endpoint_id,
        v.product_name, v.product_raw_entry_name, v.version, v.sensitivity_level_name,
        v.vulnerability_v3_base_score, v.vulnerability_v3_exploitability_level,
        v.vulnerability_summary, v.link,
        DEFAULT_SN_TABLE, sn_sys_id, sn_number, sn_url,
        sn_state, STATE_CATEGORY_OPEN, True,
        first_detected, last_detected, ticket_created,
    ))


def update_last_detected(db: DBClient, tickets_table: str, corr_key: str, v: ActiveVuln) -> None:
    last_detected = v.updated_at or utc_now()
    db.execute(f"UPDATE {tickets_table} SET last_detected_at = %s WHERE correlation_key = %s", (last_detected, corr_key))


def fetch_open_tickets(db: DBClient, tickets_table: str) -> List[Dict[str, Any]]:
    sql = f"""
      SELECT correlation_key, sn_sys_id, sn_number, sn_url, endpoint_hash, asset, cve
      FROM {tickets_table}
      WHERE COALESCE(is_active, true) = true
        AND COALESCE(sn_state_category, %s) = %s
        AND ticket_resolved_at IS NULL
      ORDER BY ticket_created_at DESC NULLS LAST
    """
    return db.query(sql, (STATE_CATEGORY_OPEN, STATE_CATEGORY_OPEN))


def find_mitigated_matches(db: DBClient, open_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not open_rows:
        return []
    values_sql_parts: List[str] = []
    params: List[Any] = []
    for r in open_rows:
        eh  = norm_hash(r.get("endpoint_hash") or "")
        c   = norm_cve(r.get("cve") or "")
        ck  = (r.get("correlation_key") or "").strip()
        num = (r.get("sn_number") or "").strip()
        if not (eh and c and ck and num):
            continue
        values_sql_parts.append("(%s, %s, %s, %s)")
        params.extend([ck, num, eh, c])
    if not values_sql_parts:
        return []
    values_sql = ",\n      ".join(values_sql_parts)
    sql = f"""
    WITH open_cases(correlation_key, sn_number, eh, c) AS (
      VALUES {values_sql}
    ),
    mitigated AS (
      SELECT lower({INCIDENT_COL_ENDPOINT_HASH}) AS eh, upper({INCIDENT_COL_CVE}) AS c,
        max(COALESCE({INCIDENT_COL_H_UPDATED_AT}, to_timestamp({INCIDENT_COL_EVENT_EPOCH} / 1000.0))) AS mitigated_at
      FROM public.incident
      WHERE {INCIDENT_COL_EVENT_TYPE} ILIKE '%%MitigatedVulnerability%%'
        AND {INCIDENT_COL_ENDPOINT_HASH} IS NOT NULL AND {INCIDENT_COL_CVE} IS NOT NULL
      GROUP BY 1, 2
    )
    SELECT o.correlation_key, o.sn_number, m.mitigated_at
    FROM open_cases o
    JOIN mitigated m ON m.eh = o.eh AND m.c = o.c
    WHERE m.mitigated_at IS NOT NULL
    """
    return db.query(sql, tuple(params))


def mark_closed_in_db(db: DBClient, tickets_table: str, correlation_key: str, mitigated_at: datetime, sn_state: str) -> None:
    sql = f"""
      UPDATE {tickets_table}
      SET mitigated_detected_at = %s, ticket_resolved_at = %s, sn_state = %s,
          sn_state_category = %s, is_active = false, closed_reason = 'MitigatedVulnerability'
      WHERE correlation_key = %s
    """
    db.execute(sql, (mitigated_at, utc_now(), sn_state, STATE_CATEGORY_RESOLVED, correlation_key))


def main() -> int:
    ap = argparse.ArgumentParser(description="Sync vulnerabilities to ServiceNow Problems")
    ap.add_argument("--limit",        type=int,   default=0)
    ap.add_argument("--min-cvss",     type=float, default=None)
    ap.add_argument("--create-limit", type=int,   default=0)
    ap.add_argument("--dry-run",      action="store_true")
    ap.add_argument("--verify-ssl",   choices=["true", "false"], default="true")
    ap.add_argument("--tickets-table", default="")
    args       = ap.parse_args()
    verify_ssl = args.verify_ssl.lower() == "true"

    pg_db   = read_secret("/run/secrets/postgres_db", required=True)
    pg_user = read_secret("/run/secrets/postgres_user", required=True)
    pg_pass = read_secret("/run/secrets/postgres_password", required=False, default="")
    pg_host = (
        os.getenv("PGHOST", "").strip() or os.getenv("DATABASE_HOST", "").strip() or os.getenv("DB_HOST", "").strip()
        or read_secret("/run/secrets/postgres_host", required=False, default="")
        or read_secret("/run/secrets/db_host", required=False, default="") or "appdb"
    )
    pg_port = os.getenv("PGPORT", "5432").strip() or "5432"

    db = DBClient(pg_db, pg_user, pg_pass, host=pg_host, port=pg_port)
    db.connect()

    tickets_table = args.tickets_table.strip()
    if not tickets_table:
        tickets_table = detect_existing_table(db, DEFAULT_TICKETS_TABLE_CANDIDATES)

    for t in ["public.activevulnerabilities", "public.incident", tickets_table]:
        ok = db.query("SELECT to_regclass(%s)::text AS t", (t,))
        if not ok or not ok[0].get("t") or ok[0]["t"] in (None, "null", ""):
            raise RuntimeError(f"Required table does not exist: {t}")

    validate_incident_columns(db)
    log(f"DB: {pg_db} | Tickets table: {tickets_table}")

    sn_url  = first_existing_secret(["/run/secrets/servicenow_instance_url", "/run/secrets/snow_instance_url", "/run/secrets/servicenow_url"], required=True)
    sn_user = first_existing_secret(["/run/secrets/servicenow_user", "/run/secrets/snow_user"], required=True)
    sn_pass = first_existing_secret(["/run/secrets/servicenow_password", "/run/secrets/snow_password"], required=True)

    sn = ServiceNowClient(base_url=sn_url, user=sn_user, password=sn_pass, verify_ssl=verify_ssl)
    sn.resolve_user_sys_id()

    existing = load_existing_keys(db, tickets_table)
    log(f"Tickets already registered in DB: {len(existing)}")

    vulns = fetch_active_vulns(db, limit=args.limit, min_cvss=args.min_cvss)
    log(f"Active vulns read: {len(vulns)} (limit={'unlimited' if args.limit <= 0 else args.limit})")

    created = 0
    skipped = 0
    for v in vulns:
        if args.create_limit > 0 and created >= args.create_limit:
            break
        cves = extract_cves(v.cve_raw)
        if not cves:
            continue
        for cve in cves:
            if args.create_limit > 0 and created >= args.create_limit:
                break
            if not v.endpoint_hash or not v.asset:
                continue
            ck = correlation_key(v.endpoint_hash, v.asset, cve)
            if ck in existing:
                skipped += 1
                try:
                    update_last_detected(db, tickets_table, ck, v)
                except Exception as e:
                    log(f"[WARN] Could not update last_detected_at for {ck}: {e}")
                continue

            short_desc = build_short_description(cve, v)
            desc       = build_description(cve, v)
            urgency    = map_sensitivity_to_urgency(v.sensitivity_level_name)
            payload    = {"short_description": short_desc, "description": desc, "urgency": urgency}

            log(f"[CREATE] {v.asset} | {cve} | sensitivity={v.sensitivity_level_name or 'n/a'} | urgency={urgency} | correlation_key={ck}")

            if args.dry_run:
                created += 1
                continue

            res = sn.create_record(DEFAULT_SN_TABLE, payload)
            sys_id = (res.get("sys_id") or "").strip()
            number = (res.get("number") or "").strip()
            if not sys_id:
                log(f"[ERROR] ServiceNow did not return sys_id for {v.asset} | {cve}. Skipping.")
                continue

            sn_state   = str(res.get("state") or "101")
            ticket_url = f"{sn.base_url}/nav_to.do?uri={DEFAULT_SN_TABLE}.do?sys_id={sys_id}"

            upsert_ticket_record_created(db=db, tickets_table=tickets_table, corr_key=ck, v=v, cve=cve,
                                         sn_sys_id=sys_id, sn_number=number, sn_url=ticket_url, sn_state=sn_state)
            existing[ck] = {"correlation_key": ck, "sn_sys_id": sys_id, "sn_number": number, "sn_url": ticket_url}
            created += 1
            log(f"[OK] Created SN Problem: {number} sys_id={sys_id} | state={sn_state}")

    log(f"Tickets created this run: {created} | Already existed (skipped): {skipped} | dry_run={args.dry_run}")

    open_rows = fetch_open_tickets(db, tickets_table)
    log(f"Open tickets to evaluate for mitigation: {len(open_rows)}")

    matches = find_mitigated_matches(db, open_rows)
    log(f"Mitigated matches found in incident table: {len(matches)}")

    if not matches:
        log("No tickets to close. Done.")
        db.close()
        return 0

    if not args.dry_run:
        first_m  = matches[0]
        test_num = (first_m.get("sn_number") or "").strip()
        if test_num:
            log(f"[TEST] Testing Import Set closure on {test_num}...")
            ok, info = sn.close_via_import(test_num, "Vulnerability mitigated (automated).")
            log(f"[TEST] Import result: ok={ok} info={info}")

            if ok:
                first_ck = (first_m.get("correlation_key") or "").strip()
                first_ma = first_m.get("mitigated_at")
                if isinstance(first_ma, str):
                    try:
                        first_ma = datetime.fromisoformat(first_ma.replace("Z", "+00:00"))
                    except Exception:
                        first_ma = utc_now()
                elif not isinstance(first_ma, datetime):
                    first_ma = utc_now()
                mark_closed_in_db(db, tickets_table, first_ck, first_ma, "106")
                log(f"[TEST] SUCCESS - {test_num} closed in SN and DB")
                matches = matches[1:]
            else:
                log(f"[TEST] FAILED - {info}")
                log("[TEST] Aborting. Check Transform Map configuration.")
                db.close()
                return 1

    closed = 0
    failed = 0
    for m in matches:
        ck           = (m.get("correlation_key") or "").strip()
        sn_number    = (m.get("sn_number") or "").strip()
        mitigated_at = m.get("mitigated_at")

        if not ck or not sn_number or mitigated_at is None:
            continue

        if isinstance(mitigated_at, str):
            try:
                mitigated_at_dt: datetime = datetime.fromisoformat(mitigated_at.replace("Z", "+00:00"))
            except Exception:
                mitigated_at_dt = utc_now()
        elif isinstance(mitigated_at, datetime):
            mitigated_at_dt = mitigated_at
        else:
            mitigated_at_dt = utc_now()

        note = f"Vulnerability mitigated (MitigatedVulnerability) at {dt_to_sn_human(mitigated_at_dt)}."

        if args.dry_run:
            closed += 1
            continue

        ok, info = sn.close_via_import(sn_number, note)
        if ok:
            mark_closed_in_db(db, tickets_table, ck, mitigated_at_dt, "106")
            closed += 1
            if closed % 100 == 0:
                log(f"[PROGRESS] Closed {closed} tickets so far...")
        else:
            failed += 1
            if failed <= 10:
                log(f"[ERROR] Could not close {sn_number}: {info}")

    log(f"Tickets closed: {closed} | Failed to close: {failed} | dry_run={args.dry_run}")
    db.close()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as e:
        log(f"[FATAL] {e}")
        raise
