#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import signal
import logging
import traceback
from typing import Any, Dict, List, Optional, Tuple, Iterable
from datetime import datetime, timezone

import requests

try:
    import psycopg2
    import psycopg2.extras
except Exception as e:
    print("[FATAL] Falta psycopg2 en el contenedor:", repr(e), file=sys.stderr)
    sys.exit(2)

# ============================================================
# LOGGING
# ============================================================

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper().strip()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("falcon_spotlight_etl")

STOP = False


def _handle_sigint(sig, frame):
    global STOP
    STOP = True
    log.warning("Interrumpido por usuario (CTRL+C / SIGTERM). Terminando con seguridad...")


signal.signal(signal.SIGINT, _handle_sigint)
signal.signal(signal.SIGTERM, _handle_sigint)

# ============================================================
# TABLES
# ============================================================

T_HOSTS   = "falcon_spotlight_dim_hosts"
T_VULNS   = "falcon_spotlight_dim_vulnerabilities"
T_REMED   = "falcon_spotlight_dim_remediations"
T_EVAL    = "falcon_spotlight_dim_evaluation_logic"
T_FACT    = "falcon_spotlight_fact_vulnerability_instances"
T_REL_EVAL = "falcon_spotlight_rel_evaluation_logic"
T_REL_APPS = "falcon_spotlight_rel_apps"

# ============================================================
# HELPERS: secrets/env
# ============================================================

def read_secret(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        return None


def get_env_or_secret(env_key: str, secret_path: str, default: Optional[str] = None) -> Optional[str]:
    v = os.environ.get(env_key)
    if v is not None and str(v).strip() != "":
        return str(v).strip()
    s = read_secret(secret_path)
    if s is not None and s != "":
        return s
    return default


# ============================================================
# HELPERS: time parse
# ============================================================

def parse_ts(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        if s.endswith("Z"):
            s2 = s[:-1] + "+00:00"
        else:
            s2 = s
        dt = datetime.fromisoformat(s2)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


# ============================================================
# HELPERS: no-brackets flatten (KV) + CSV joins
# ============================================================

def safe_str(x: Any) -> str:
    if x is None:
        return ""
    if isinstance(x, (int, float, bool)):
        return str(x)
    if isinstance(x, datetime):
        return x.astimezone(timezone.utc).isoformat()
    return str(x)


def _sanitize_value(s: str) -> str:
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    s = s.replace("\t", " ")
    s = s.replace("\n", "\\n")
    return s.strip()


def flatten_kv(obj: Any, prefix: str = "", out: Optional[List[str]] = None, max_items: int = 12000) -> str:
    """
    Aplana dict/list sin corchetes:
      - dict: a.b.c=value
      - list: a_0=value; a_1=value
    """
    if out is None:
        out = []

    if len(out) >= max_items:
        return "; ".join(out[:max_items])

    if obj is None:
        if prefix:
            out.append(f"{prefix}=")
        return "; ".join(out)

    if isinstance(obj, dict):
        for k, v in obj.items():
            k2 = str(k)
            key = f"{prefix}.{k2}" if prefix else k2
            flatten_kv(v, key, out, max_items=max_items)
        return "; ".join(out)

    if isinstance(obj, list):
        for i, v in enumerate(obj):
            key = f"{prefix}_{i}" if prefix else str(i)
            flatten_kv(v, key, out, max_items=max_items)
        return "; ".join(out)

    val = _sanitize_value(safe_str(obj))
    if prefix:
        out.append(f"{prefix}={val}")
    else:
        out.append(val)
    return "; ".join(out)


def join_csv(values: Iterable[Any], dedup: bool = True, sep: str = ", ") -> str:
    out: List[str] = []
    seen = set()
    for v in values:
        s = safe_str(v).strip()
        if s == "":
            continue
        if dedup:
            if s in seen:
                continue
            seen.add(s)
        out.append(s)
    return sep.join(out)


def get_nested(d: Dict[str, Any], path: str, default=None):
    cur: Any = d
    for part in path.split("."):
        if not isinstance(cur, dict):
            return default
        if part not in cur:
            return default
        cur = cur.get(part)
    return cur


# ============================================================
# FALCON API
# ============================================================

def falcon_get_token(base_url: str, client_id: str, client_secret: str, timeout: int = 30) -> str:
    url = base_url.rstrip("/") + "/oauth2/token"
    r = requests.post(url, data={"client_id": client_id, "client_secret": client_secret}, timeout=timeout)
    r.raise_for_status()
    j = r.json()
    tok = j.get("access_token")
    if not tok:
        raise RuntimeError(f"oauth2/token no retornó access_token: {j}")
    return tok


def spotlight_fetch_page(
    base_url: str,
    token: str,
    filter_str: str,
    sort: str,
    limit: int,
    after: Optional[str],
    facets: List[str],
    timeout: int = 60,
) -> Dict[str, Any]:
    url = base_url.rstrip("/") + "/spotlight/combined/vulnerabilities/v1"

    params: List[Tuple[str, str]] = [
        ("filter", filter_str),
        ("sort", sort),
        ("limit", str(limit)),
    ]
    for f in facets:
        params.append(("facet", f))
    if after:
        params.append(("after", after))

    headers = {"Authorization": f"Bearer {token}"}
    r = requests.get(url, headers=headers, params=params, timeout=timeout)
    if r.status_code >= 400:
        try:
            body = r.json()
        except Exception:
            body = r.text
        raise RuntimeError(f"HTTP {r.status_code} {url}: {body}")
    return r.json()


# ============================================================
# DB HELPERS
# ============================================================

class DB:
    def __init__(self):
        self.host = os.environ.get("DATABASE_HOST") or os.environ.get("DB_HOST") or "appdb"
        self.port = int(os.environ.get("DATABASE_PORT") or os.environ.get("DB_PORT") or "5432")
        self.user = get_env_or_secret("DATABASE_USER", "/run/secrets/postgres_user", "vanalyzer") or "vanalyzer"
        self.password = get_env_or_secret("DATABASE_PASSWORD", "/run/secrets/postgres_password", "vanalyzer") or "vanalyzer"
        self.dbname = get_env_or_secret("DATABASE_NAME", "/run/secrets/postgres_db", "vanalyzer") or "vanalyzer"

        self._conn = None
        self._col_cache: Dict[str, List[str]] = {}
        self._pk_cache: Dict[str, List[str]] = {}

    def connect(self):
        if self._conn:
            return self._conn
        self._conn = psycopg2.connect(
            host=self.host,
            port=self.port,
            user=self.user,
            password=self.password,
            dbname=self.dbname,
        )
        self._conn.autocommit = False
        return self._conn

    def close(self):
        try:
            if self._conn:
                self._conn.close()
        except Exception:
            pass
        self._conn = None

    def get_columns(self, table: str) -> List[str]:
        if table in self._col_cache:
            return self._col_cache[table]
        q = """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema='public' AND table_name=%s
        ORDER BY ordinal_position
        """
        with self.connect().cursor() as cur:
            cur.execute(q, (table,))
            cols = [r[0] for r in cur.fetchall()]
        if not cols:
            raise RuntimeError(f"Table not found or no columns: {table}")
        self._col_cache[table] = cols
        return cols

    def get_primary_key(self, table: str) -> List[str]:
        if table in self._pk_cache:
            return self._pk_cache[table]
        q = """
        SELECT kcu.column_name
        FROM information_schema.table_constraints tc
        JOIN information_schema.key_column_usage kcu
          ON tc.constraint_name = kcu.constraint_name
         AND tc.table_schema   = kcu.table_schema
        WHERE tc.table_schema='public'
          AND tc.table_name=%s
          AND tc.constraint_type='PRIMARY KEY'
        ORDER BY kcu.ordinal_position
        """
        with self.connect().cursor() as cur:
            cur.execute(q, (table,))
            pk = [r[0] for r in cur.fetchall()]
        if not pk:
            raise RuntimeError(f"Table has no PRIMARY KEY: {table}")
        self._pk_cache[table] = pk
        return pk

    @staticmethod
    def _to_dt(v: Any) -> Optional[datetime]:
        if v is None:
            return None
        if isinstance(v, datetime):
            if v.tzinfo is None:
                return v.replace(tzinfo=timezone.utc)
            return v.astimezone(timezone.utc)
        if isinstance(v, str):
            s = v.strip()
            if not s:
                return None
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            try:
                dt = datetime.fromisoformat(s)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
            except Exception:
                return None
        return None

    @classmethod
    def _rank_row(cls, r: Dict[str, Any]) -> Optional[datetime]:
        # preferimos "updated_*" sobre "created_*"
        for k in ("updated_at", "updated_timestamp", "created_timestamp", "created_at"):
            if k in r:
                dt = cls._to_dt(r.get(k))
                if dt:
                    return dt
        return None

    @staticmethod
    def _is_empty_value(v: Any) -> bool:
        if v is None:
            return True
        if isinstance(v, str) and v.strip() == "":
            return True
        if isinstance(v, (list, tuple, set, dict)) and len(v) == 0:
            return True
        return False

    @classmethod
    def _merge_rows_keep_data(cls, old: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
        """
        - No pierde datos: si en new viene vacío, conserva old.
        - Si en new viene valor, pisa old.
        - Para timestamps, conserva el mayor.
        """
        merged = dict(old)

        # merge general (no vacíos ganan)
        for k, v in new.items():
            if cls._is_empty_value(v):
                continue
            merged[k] = v

        # merge timestamps (max)
        for k in ("updated_at", "updated_timestamp", "created_timestamp", "created_at"):
            dt_old = cls._to_dt(old.get(k))
            dt_new = cls._to_dt(new.get(k))
            if dt_old and dt_new:
                merged[k] = dt_new if dt_new >= dt_old else dt_old
            elif dt_new and not dt_old:
                merged[k] = dt_new
            elif dt_old and not dt_new:
                merged[k] = dt_old

        return merged

    @classmethod
    def _dedupe_by_pk(cls, rows: List[Dict[str, Any]], pk_cols: List[str]) -> List[Dict[str, Any]]:
        """
        Dedup obligatorio para evitar:
          ON CONFLICT DO UPDATE ... cannot affect row a second time
        """
        dedup: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
        for r in rows:
            key = tuple(r.get(pk) for pk in pk_cols)
            # si PK incompleta, no sirve
            if any(cls._is_empty_value(x) for x in key):
                continue

            if key not in dedup:
                dedup[key] = r
            else:
                # merge + preferencia por row más nueva (sin perder data)
                merged = cls._merge_rows_keep_data(dedup[key], r)
                # si uno tiene rank mayor, igual ya queda por timestamp max en merge
                dedup[key] = merged

        return list(dedup.values())

    def upsert_rows(self, table: str, rows: List[Dict[str, Any]], pk_cols: Optional[List[str]] = None, batch_size: int = 5000):
        if not rows:
            return

        cols = self.get_columns(table)
        if pk_cols is None:
            pk_cols = self.get_primary_key(table)

        # 1) filtra keys a columnas reales + asegura PKs
        filtered: List[Dict[str, Any]] = []
        for r in rows:
            rr = {k: v for k, v in r.items() if k in cols}
            for pk in pk_cols:
                if pk not in rr:
                    rr[pk] = r.get(pk)
            filtered.append(rr)

        # 2) DEDUPE por PK (CRÍTICO)
        filtered = self._dedupe_by_pk(filtered, pk_cols)
        if not filtered:
            return

        insert_cols = sorted({k for r in filtered for k in r.keys()})
        if not insert_cols:
            return

        upd_cols = [c for c in insert_cols if c not in pk_cols]
        set_sql = ", ".join([f"{c}=EXCLUDED.{c}" for c in upd_cols]) if upd_cols else ""
        conflict_sql = ", ".join(pk_cols)

        if set_sql:
            sql = f"INSERT INTO public.{table} ({', '.join(insert_cols)}) VALUES %s " \
                  f"ON CONFLICT ({conflict_sql}) DO UPDATE SET {set_sql};"
        else:
            sql = f"INSERT INTO public.{table} ({', '.join(insert_cols)}) VALUES %s " \
                  f"ON CONFLICT ({conflict_sql}) DO NOTHING;"

        conn = self.connect()
        with conn.cursor() as cur:
            rows2 = filtered
            for i in range(0, len(rows2), batch_size):
                chunk = rows2[i:i + batch_size]
                values = []
                for r in chunk:
                    rowvals = []
                    for c in insert_cols:
                        rowvals.append(r.get(c))
                    values.append(tuple(rowvals))
                psycopg2.extras.execute_values(cur, sql, values, page_size=min(batch_size, 5000))


# ============================================================
# TRANSFORMS
# ============================================================

def build_dim_host_row(resource: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    aid = resource.get("aid") or ""
    if not aid:
        return None

    hi = resource.get("host_info") or {}

    row: Dict[str, Any] = {
        "aid": aid,
        "hostname": hi.get("hostname"),
        "local_ip": hi.get("local_ip"),
        "external_ip": hi.get("external_ip"),
        "machine_domain": hi.get("machine_domain"),
        "os_version": hi.get("os_version"),
        "os_build": hi.get("os_build"),
        "system_serial_number": hi.get("system_serial_number"),
        "last_seen": parse_ts(hi.get("last_seen")),
        "updated_at": parse_ts(resource.get("updated_timestamp")) or datetime.now(timezone.utc),

        # extras típicos de RAW host_info (si existen columnas)
        "platform": hi.get("platform"),
        "product_type_desc": hi.get("product_type_desc"),
        "service_provider": hi.get("service_provider"),
        "service_provider_account_id": hi.get("service_provider_account_id"),
        "system_manufacturer": hi.get("system_manufacturer"),
        "internet_exposure": hi.get("internet_exposure"),
        "asset_criticality": hi.get("asset_criticality"),
        "managed_by": hi.get("managed_by"),
        "ou": hi.get("ou"),
        "site_name": hi.get("site_name"),
        "host_instance_id": hi.get("instance_id"),
        "tags_csv": join_csv((hi.get("tags") or []), dedup=True),

        # RAW sin corchetes
        "raw_host_kv_text": flatten_kv(hi, prefix="host_info"),
        "raw_host_info_text": flatten_kv(hi, prefix="host_info"),
    }

    # si algún día agregas "device" a facets/endpoint y viene acá
    if "device" in resource and isinstance(resource["device"], dict):
        row["raw_device_kv_text"] = flatten_kv(resource["device"], prefix="device")
        row["raw_device_text"] = flatten_kv(resource["device"], prefix="device")
        row["device_id"] = resource["device"].get("device_id") or resource["device"].get("id")

    return row


def build_dim_vuln_row(resource: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    cve = resource.get("cve") or {}
    cve_id = cve.get("id") or resource.get("vulnerability_id") or ""
    if not cve_id:
        return None

    row: Dict[str, Any] = {
        "cve_id": cve_id,
        "severity": cve.get("severity"),
        "cvss_score": cve.get("base_score"),
        "exprt_score": cve.get("exprt_score"),
        "exploit_status": cve.get("exploit_status"),
        "cisa_kev": get_nested(cve, "cisa_info.is_cisa_kev", None),
        "description": cve.get("description"),
        "updated_at": parse_ts(resource.get("updated_timestamp")) or datetime.now(timezone.utc),

        # extras
        "vector": cve.get("vector"),
        "published_date": parse_ts(cve.get("published_date")),
        "spotlight_published_date": parse_ts(cve.get("spotlight_published_date")),
        "cwes_csv": join_csv((cve.get("cwes") or []), dedup=True),
        "references_csv": join_csv((cve.get("references") or []), dedup=True),
        "vendor_advisory_csv": join_csv((cve.get("vendor_advisory") or []), dedup=True),
        "types_csv": join_csv((cve.get("types") or []), dedup=True),
        "exploitability_score": cve.get("exploitability_score"),
        "impact_score": cve.get("impact_score"),
        "exprt_rating": cve.get("exprt_rating"),
        "remediation_level": cve.get("remediation_level"),

        # RAW sin corchetes
        "raw_cve_kv_text": flatten_kv(cve, prefix="cve"),
        "raw_cve_text": flatten_kv(cve, prefix="cve"),
    }
    return row


def build_dim_remediation_rows(resource: Dict[str, Any]) -> List[Dict[str, Any]]:
    rem = resource.get("remediation") or {}
    ents = rem.get("entities") or []
    out: List[Dict[str, Any]] = []

    for e in ents:
        if not isinstance(e, dict):
            continue
        rid = e.get("id") or ""
        if not rid:
            continue

        row: Dict[str, Any] = {
            "remediation_id": rid,
            "title": e.get("title"),
            "vendor_url": e.get("vendor_url"),
            "description": e.get("description") or e.get("action"),
            "action_priority": e.get("action_priority") or e.get("recommendation_type"),
            "updated_at": parse_ts(resource.get("updated_timestamp")) or datetime.now(timezone.utc),

            # extras
            "action": e.get("action"),
            "recommendation_type": e.get("recommendation_type"),
            "reference": e.get("reference"),
            "status": e.get("status"),

            # RAW sin corchetes
            "raw_remediation_kv_text": flatten_kv(e, prefix="remediation_entity"),
            "raw_remediation_text": flatten_kv(e, prefix="remediation_entity"),
        }
        out.append(row)
    return out


def build_fact_instance_row(resource: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    instance_id = resource.get("id") or ""
    if not instance_id:
        return None

    aid = resource.get("aid") or ""
    cid = resource.get("cid") or ""
    cve_id = resource.get("vulnerability_id") or (resource.get("cve") or {}).get("id")

    dp = resource.get("data_providers") or []
    providers = []
    for x in dp:
        if isinstance(x, dict):
            p = x.get("provider")
            if p:
                providers.append(p)

    remediation_ids: List[str] = []
    apps = resource.get("apps") or []
    for a in apps:
        if not isinstance(a, dict):
            continue
        ids = get_nested(a, "remediation.ids", []) or []
        if isinstance(ids, list):
            for rid in ids:
                if rid:
                    remediation_ids.append(rid)

    row: Dict[str, Any] = {
        "instance_id": instance_id,
        "aid": aid,
        "cve_id": cve_id,
        "status": resource.get("status"),
        "created_timestamp": parse_ts(resource.get("created_timestamp")),
        "updated_timestamp": parse_ts(resource.get("updated_timestamp")),
        "closed_timestamp": parse_ts(resource.get("closed_timestamp")),
        "confidence": resource.get("confidence"),

        # extras
        "cid": cid,
        "vulnerability_id": resource.get("vulnerability_id"),
        "vulnerability_metadata_id": resource.get("vulnerability_metadata_id"),
        "suppression_is_suppressed": get_nested(resource, "suppression_info.is_suppressed", None),
        "data_providers_csv": join_csv(providers, dedup=True),
        "remediation_ids_csv": join_csv(remediation_ids, dedup=True),
        "remediation_ids_count": len({x for x in remediation_ids if x}),

        # RAW sin corchetes (todo el resource)
        "raw_instance_kv_text": flatten_kv(resource, prefix="resource"),
        "raw_instance_text": flatten_kv(resource, prefix="resource"),
    }
    return row


def build_rel_apps_rows(resource: Dict[str, Any]) -> List[Dict[str, Any]]:
    instance_id = resource.get("id") or ""
    if not instance_id:
        return []

    apps = resource.get("apps") or []
    out: List[Dict[str, Any]] = []
    seq = 1

    for a in apps:
        if not isinstance(a, dict):
            continue

        ids = get_nested(a, "remediation.ids", []) or []
        if not isinstance(ids, list):
            ids = []
        recommended_id = get_nested(a, "remediation_info.recommended_id", None)

        el = a.get("evaluation_logic") or {}
        el_id = el.get("id") if isinstance(el, dict) else None

        row: Dict[str, Any] = {
            "instance_id": instance_id,
            "seq": seq,
            "sub_status": a.get("sub_status"),
            "vendor_normalized": a.get("vendor_normalized"),
            "product_name_normalized": a.get("product_name_normalized"),
            "product_name_version": a.get("product_name_version"),
            "remediation_ids_csv": join_csv(ids, dedup=True),
            "recommended_remediation_id": recommended_id,
            "evaluation_logic_id": el_id,
            "raw_app_kv_text": flatten_kv(a, prefix="app"),
        }
        out.append(row)
        seq += 1

    return out


def build_dim_eval_logic_rows(resource: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    apps = resource.get("apps") or []
    for a in apps:
        if not isinstance(a, dict):
            continue
        el = a.get("evaluation_logic")
        if not isinstance(el, dict):
            continue
        el_id = el.get("id")
        if not el_id:
            continue

        row: Dict[str, Any] = {
            "evaluation_logic_id": el_id,
            "created_at": parse_ts(el.get("created_timestamp")),
            "updated_at": parse_ts(el.get("updated_timestamp")) or datetime.now(timezone.utc),
            "raw_evaluation_logic_kv_text": flatten_kv(el, prefix="evaluation_logic"),
            "raw_evaluation_logic_text": flatten_kv(el, prefix="evaluation_logic"),
        }
        out.append(row)
    return out


def _extract_file_path_from_logic(logic_obj: Dict[str, Any]) -> Optional[str]:
    items = logic_obj.get("items") or []
    if isinstance(items, list):
        for it in items:
            if isinstance(it, dict) and it.get("filepath"):
                return it.get("filepath")
    return None


def _extract_app_name_version(app: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    name = app.get("product_name_normalized") or app.get("vendor_normalized")
    ver = app.get("product_name_version")
    return name, ver


def build_rel_eval_logic_rows(resource: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    instance_id = resource.get("id") or ""
    if not instance_id:
        return out

    apps = resource.get("apps") or []
    seq = 1

    for app in apps:
        if not isinstance(app, dict):
            continue
        el = app.get("evaluation_logic")
        if not isinstance(el, dict):
            continue

        evidence_id = el.get("id")
        aid = el.get("aid") or resource.get("aid")
        cid = el.get("cid") or resource.get("cid")
        data_provider = el.get("data_provider")

        created_ts = parse_ts(el.get("created_timestamp"))
        updated_ts = parse_ts(el.get("updated_timestamp"))

        entities = get_nested(el, "host_info.entities_matched", []) or []
        asset_ids = []
        if isinstance(entities, list):
            for x in entities:
                if isinstance(x, dict) and x.get("asset_id"):
                    asset_ids.append(x["asset_id"])

        simp = el.get("simplified_logic") or []
        simp_lines: List[str] = []
        if isinstance(simp, list):
            for block in simp:
                if not isinstance(block, dict):
                    continue
                title = safe_str(block.get("title")).strip()
                checks = safe_str(block.get("checks")).strip()
                match_required = safe_str(block.get("match_required")).strip()
                found = join_csv(block.get("found") or [], dedup=False, sep=" | ")
                data = join_csv(block.get("data") or [], dedup=False, sep=" | ")
                parts = []
                if title: parts.append(f"title={title}")
                if checks: parts.append(f"checks={checks}")
                if match_required: parts.append(f"match_required={match_required}")
                if found: parts.append(f"found={found}")
                if data: parts.append(f"data={data}")
                if parts:
                    simp_lines.append("; ".join(parts))
        simplified_logic_text = " || ".join(simp_lines)

        app_name, app_version = _extract_app_name_version(app)

        base: Dict[str, Any] = {
            "instance_id": instance_id,
            "logic_type": app.get("sub_status"),
            "app_name": app_name,
            "app_version": app_version,
            "evidence_id": evidence_id,
            "aid": aid,
            "cid": cid,
            "data_provider": data_provider,
            "created_timestamp": created_ts,
            "updated_timestamp": updated_ts,
            "entities_matched_csv": join_csv(asset_ids, dedup=True),
            "simplified_logic_text": simplified_logic_text,

            # raw completo (sin brackets) para no perder nada
            "evidence_details_text": flatten_kv(el, prefix="evaluation_logic"),
        }

        logic_list = el.get("logic") or []
        if isinstance(logic_list, list) and len(logic_list) > 0:
            for chk in logic_list:
                if not isinstance(chk, dict):
                    continue
                row = dict(base)
                row["seq"] = seq
                seq += 1
                row["file_path"] = _extract_file_path_from_logic(chk)
                row["logic_titles_csv"] = safe_str(chk.get("title")).strip()
                row["logic_items_csv"] = flatten_kv(chk, prefix="evaluation_logic.logic")
                out.append(row)
        else:
            row = dict(base)
            row["seq"] = seq
            seq += 1
            row["logic_items_csv"] = ""
            out.append(row)

    return out


# ============================================================
# PIPELINE
# ============================================================

def run_pipeline():
    db = DB()
    conn = db.connect()

    base_url = get_env_or_secret("FALCON_BASE_URL", "/run/secrets/falcon_base_url", "https://api.us-2.crowdstrike.com")
    client_id = get_env_or_secret("FALCON_CLIENT_ID", "/run/secrets/falcon_client_id", None)
    client_secret = get_env_or_secret("FALCON_CLIENT_SECRET", "/run/secrets/falcon_client_secret", None)

    if not client_id or not client_secret:
        raise SystemExit("[FATAL] FALCON_CLIENT_ID / FALCON_CLIENT_SECRET no definidos (env o /run/secrets).")

    log.info("[+] DB host=%s port=%s db=%s user=%s", db.host, db.port, db.dbname, db.user)
    log.info("[+] Falcon base_url=%s", base_url)

    since = os.environ.get("SPOTLIGHT_SINCE", "1970-01-01T00:00:00Z").strip()
    limit = int(os.environ.get("SPOTLIGHT_LIMIT", "5000"))
    sort = os.environ.get("SPOTLIGHT_SORT", "updated_timestamp|asc").strip()
    filter_str = f"created_timestamp:>'{since}'"
    facets = ["host_info", "cve", "remediation", "evaluation_logic"]

    log.info("[+] Spotlight filter=%s", filter_str)
    log.info("[+] Spotlight sort=%s limit=%s facets=%s", sort, limit, ",".join(facets))

    token = falcon_get_token(base_url, client_id, client_secret)
    after = None

    total_seen = 0
    page = 0

    while not STOP:
        page += 1

        attempt = 0
        while True:
            attempt += 1
            try:
                data = spotlight_fetch_page(
                    base_url=base_url,
                    token=token,
                    filter_str=filter_str,
                    sort=sort,
                    limit=limit,
                    after=after,
                    facets=facets,
                )
                break
            except Exception as e:
                if attempt >= 5:
                    raise
                sleep_s = 2 ** (attempt - 1)
                log.warning("spotlight page attempt %s failed: %s. sleep=%ss", attempt, e, sleep_s)
                time.sleep(sleep_s)

        resources = data.get("resources") or []
        meta = data.get("meta") or {}
        pagination = meta.get("pagination") or {}
        after_next = pagination.get("after")

        log.info("Page %s: fetched %s resources", page, len(resources))

        if not resources:
            log.info("No resources. DONE.")
            break

        dim_hosts_rows: List[Dict[str, Any]] = []
        dim_vuln_rows: List[Dict[str, Any]] = []
        dim_rem_rows: List[Dict[str, Any]] = []
        dim_eval_rows: List[Dict[str, Any]] = []
        fact_rows: List[Dict[str, Any]] = []
        rel_apps_rows: List[Dict[str, Any]] = []
        rel_eval_rows: List[Dict[str, Any]] = []

        for r in resources:
            if STOP:
                break
            if not isinstance(r, dict):
                continue

            x = build_dim_host_row(r)
            if x: dim_hosts_rows.append(x)

            x = build_dim_vuln_row(r)
            if x: dim_vuln_rows.append(x)

            dim_rem_rows.extend(build_dim_remediation_rows(r))
            dim_eval_rows.extend(build_dim_eval_logic_rows(r))

            x = build_fact_instance_row(r)
            if x: fact_rows.append(x)

            rel_apps_rows.extend(build_rel_apps_rows(r))
            rel_eval_rows.extend(build_rel_eval_logic_rows(r))

        try:
            with conn.cursor() as cur:
                cur.execute("BEGIN;")

            db.upsert_rows(T_HOSTS, dim_hosts_rows, pk_cols=["aid"], batch_size=5000)
            db.upsert_rows(T_VULNS, dim_vuln_rows, pk_cols=["cve_id"], batch_size=5000)
            db.upsert_rows(T_REMED, dim_rem_rows, pk_cols=["remediation_id"], batch_size=5000)
            db.upsert_rows(T_EVAL,  dim_eval_rows, pk_cols=["evaluation_logic_id"], batch_size=5000)

            db.upsert_rows(T_FACT, fact_rows, pk_cols=["instance_id"], batch_size=5000)

            # rels (dependen de fact)
            db.upsert_rows(T_REL_APPS, rel_apps_rows, pk_cols=["instance_id", "seq"], batch_size=5000)
            db.upsert_rows(T_REL_EVAL, rel_eval_rows, pk_cols=["instance_id", "seq"], batch_size=5000)

            conn.commit()
        except Exception:
            conn.rollback()
            raise

        total_seen += len(resources)
        log.info("Committed page batch. total_seen=%s", total_seen)

        if not after_next:
            log.info("No pagination.after. DONE. total_resources_seen=%s", total_seen)
            break

        after = after_next

    log.info("DONE. total_resources_seen=%s", total_seen)


def main():
    try:
        run_pipeline()
    except SystemExit:
        raise
    except Exception as e:
        log.error("[FATAL] %s", e)
        log.error(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()
