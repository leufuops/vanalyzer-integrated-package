from __future__ import annotations

import importlib
import importlib.util
import json
import logging
import math
import os
import random
import subprocess
import sys
import tempfile
import time
import traceback
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Generator, List, Optional, Set, Tuple

import psycopg2
from psycopg2.extras import execute_values
from psycopg2.pool import SimpleConnectionPool

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ---------------------------------------------------------------------------
# Runtime-managed optional deps
# ---------------------------------------------------------------------------
np = None
pd = None
HAS_PANDAS = False
PARQUET_ENGINE: Optional[str] = None

LOG = logging.getLogger("r7_etl")

SECRETS_DIR = os.getenv("SECRETS_DIR", "/run/secrets")

VULN_EXPORT_MUTATION = """
mutation CreateVulnerabilityExport {
  createVulnerabilityExport(input:{}) {
    id
  }
}
""".strip()

EXPORT_STATUS_QUERY = """
query GetExport {
  export(id: "%s") {
    id
    status
    dataset
    timestamp
    result {
      prefix
      urls
    }
  }
}
""".strip()


# ---------------------------------------------------------------------------
# Logging / secrets / dependency bootstrap
# ---------------------------------------------------------------------------
def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stderr,
    )


def read_secret(name: str, env_fallback: str = "", default: str = "") -> str:
    try:
        with open(os.path.join(SECRETS_DIR, name), encoding="utf-8") as fh:
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


def module_exists(module_name: str) -> bool:
    try:
        return importlib.util.find_spec(module_name) is not None
    except Exception:
        return False


def pip_install(package_name: str) -> None:
    LOG.warning("Package '%s' not found. Installing it now...", package_name)

    cmd = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--no-cache-dir",
        package_name,
    ]

    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )

    if proc.returncode != 0:
        raise RuntimeError(
            f"Failed to install package '{package_name}'. Output:\n{proc.stdout}"
        )

    LOG.info("Package '%s' installed successfully", package_name)


def ensure_data_libs() -> None:
    """
    Ensures numpy and pandas are importable at runtime.
    """
    global np, pd, HAS_PANDAS

    if not module_exists("numpy"):
        pip_install("numpy")
    if not module_exists("pandas"):
        pip_install("pandas")

    np = importlib.import_module("numpy")
    pd = importlib.import_module("pandas")
    HAS_PANDAS = True
    LOG.info("Data libraries available: numpy=%s pandas=%s", np.__version__, pd.__version__)


def ensure_parquet_engine() -> str:
    """
    Ensures that at least one parquet engine is available.
    Tries pyarrow first, then fastparquet.
    """
    global PARQUET_ENGINE

    if PARQUET_ENGINE:
        return PARQUET_ENGINE

    if module_exists("pyarrow"):
        PARQUET_ENGINE = "pyarrow"
        LOG.info("Parquet engine available: pyarrow")
        return PARQUET_ENGINE

    if module_exists("fastparquet"):
        PARQUET_ENGINE = "fastparquet"
        LOG.info("Parquet engine available: fastparquet")
        return PARQUET_ENGINE

    LOG.warning("No parquet engine detected. Trying to install pyarrow...")
    try:
        pip_install("pyarrow")
        if module_exists("pyarrow"):
            PARQUET_ENGINE = "pyarrow"
            LOG.info("Parquet engine ready after install: pyarrow")
            return PARQUET_ENGINE
    except Exception as e:
        LOG.warning("Auto-install pyarrow failed: %s", e)

    LOG.warning("Trying fallback install: fastparquet...")
    try:
        pip_install("fastparquet")
        if module_exists("fastparquet"):
            PARQUET_ENGINE = "fastparquet"
            LOG.info("Parquet engine ready after install: fastparquet")
            return PARQUET_ENGINE
    except Exception as e:
        LOG.warning("Auto-install fastparquet failed: %s", e)

    raise RuntimeError(
        "No parquet engine available. Tried existing install + auto-install of "
        "pyarrow and fastparquet, but none worked."
    )


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------
def safe_float(v: Any) -> Optional[float]:
    if v is None:
        return None
    try:
        f = float(v)
        return None if (math.isnan(f) or math.isinf(f)) else f
    except Exception:
        return None


def safe_int(v: Any) -> Optional[int]:
    if v is None:
        return None
    try:
        return int(v)
    except Exception:
        return None


def parse_ts(v: Any) -> Optional[str]:
    if not isinstance(v, str) or not v.strip():
        return None
    s = v.strip()
    if s.upper() in ("NAT", "NONE", "NULL", "NAN", ""):
        return None
    try:
        s2 = s[:-1] + "+00:00" if s.endswith("Z") else s
        return datetime.fromisoformat(s2).astimezone(timezone.utc).isoformat()
    except Exception:
        try:
            return datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S").replace(
                tzinfo=timezone.utc
            ).isoformat()
        except Exception:
            return None


def to_json_str(v: Any) -> Optional[str]:
    if v is None:
        return None
    try:
        return json.dumps(v, ensure_ascii=False, default=str)
    except Exception:
        return json.dumps(str(v))


def clean_str_list(v: Any) -> List[str]:
    if v is None:
        return []
    if HAS_PANDAS:
        try:
            if isinstance(v, np.ndarray):
                v = v.tolist()
        except Exception:
            pass
    if not isinstance(v, (list, tuple)):
        return []
    return [str(x).strip() for x in v if x is not None and str(x).strip()]


def normalize_parquet_value(v: Any) -> Any:
    if v is None:
        return None

    if HAS_PANDAS:
        try:
            if isinstance(v, np.ndarray):
                return [normalize_parquet_value(x) for x in v.tolist()]
        except Exception:
            pass

        try:
            if isinstance(v, np.generic):
                vv = v.item()
                if isinstance(vv, float) and (math.isnan(vv) or math.isinf(vv)):
                    return None
                return vv
        except Exception:
            pass

        try:
            if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                return None
        except Exception:
            pass

        try:
            if pd.isna(v):
                return None
        except Exception:
            pass

    if isinstance(v, (list, dict)):
        return v

    return v


def extract_cves(raw: Any) -> List[str]:
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except Exception:
            raw = [raw]

    if HAS_PANDAS:
        try:
            if isinstance(raw, np.ndarray):
                raw = raw.tolist()
        except Exception:
            pass

    if not isinstance(raw, (list, tuple)):
        return []

    return sorted(
        {
            str(x).upper()
            for x in raw
            if isinstance(x, str) and str(x).upper().startswith("CVE-")
        }
    )


# ---------------------------------------------------------------------------
# Rapid7 export result helpers
# ---------------------------------------------------------------------------
def extract_export_entries(exp_obj: Dict[str, Any]) -> List[Dict[str, Any]]:
    result = exp_obj.get("result")
    if result is None:
        return []
    if isinstance(result, dict):
        return [result]
    if isinstance(result, list):
        return [e for e in result if isinstance(e, dict)]
    return []


def collect_export_urls(exp_obj: Dict[str, Any]) -> List[Tuple[str, str]]:
    all_urls: List[Tuple[str, str]] = []
    for entry in extract_export_entries(exp_obj):
        prefix = str(entry.get("prefix") or "unknown")
        for url in (entry.get("urls") or []):
            if url:
                all_urls.append((prefix, str(url)))
    return all_urls


# ---------------------------------------------------------------------------
# PostgreSQL wrapper
# ---------------------------------------------------------------------------
class Pg:
    def __init__(
        self,
        host: str,
        port: int,
        dbname: str,
        user: str,
        password: str,
        sslmode: str = "disable",
    ) -> None:
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
        c = self._pool.getconn()
        try:
            if getattr(c, "closed", 1):
                self._pool.putconn(c, close=True)
                c = self._pool.getconn()
            else:
                try:
                    with c.cursor() as cur:
                        cur.execute("SELECT 1")
                except Exception:
                    self._pool.putconn(c, close=True)
                    c = self._pool.getconn()

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


# ---------------------------------------------------------------------------
# Rapid7 HTTP client
# ---------------------------------------------------------------------------
class R7HTTP:
    def __init__(self, api_key: str, base_url: str, cfg: Dict[str, Any]) -> None:
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.cfg = cfg
        self.sess = requests.Session()

        adapter = HTTPAdapter(
            max_retries=Retry(
                total=cfg["max_retries"],
                backoff_factor=1.5,
                status_forcelist=(429, 500, 502, 503, 504),
                allowed_methods=frozenset(["GET", "POST"]),
                raise_on_status=False,
            ),
            pool_connections=5,
            pool_maxsize=5,
        )
        self.sess.mount("https://", adapter)
        self.sess.mount("http://", adapter)
        self.sess.headers.update(
            {
                "X-Api-Key": api_key,
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        )

    def graphql(self, query: str) -> Dict[str, Any]:
        url = f"{self.base_url}/export/graphql"

        for attempt in range(1, self.cfg["max_retries"] + 1):
            try:
                r = self.sess.post(
                    url,
                    json={"query": query},
                    timeout=self.cfg["timeout"],
                )
            except Exception as e:
                LOG.warning("GraphQL attempt %d: %s", attempt, e)
                if attempt == self.cfg["max_retries"]:
                    raise RuntimeError(f"GraphQL max retries exceeded: {e}")
                time.sleep(0.8 * (2 ** (attempt - 1)) + random.random() * 0.3)
                continue

            if r.status_code == 429:
                wait = int(r.headers.get("Retry-After", 60))
                LOG.warning("GraphQL 429 - waiting %ds", wait)
                time.sleep(wait)
                continue

            if r.status_code >= 400:
                raise RuntimeError(f"GraphQL HTTP {r.status_code}: {r.text[:500]}")

            try:
                payload = r.json()
            except Exception:
                raise RuntimeError(f"GraphQL response not JSON: {r.text[:500]}")

            if payload.get("errors"):
                raise RuntimeError(f"GraphQL errors: {payload['errors']}")

            return payload.get("data") or {}

        raise RuntimeError("GraphQL: max retries exhausted")

    def download_file(self, url: str, dest: str) -> None:
        with self.sess.get(url, stream=True, timeout=self.cfg["timeout"]) as r:
            if r.status_code >= 400:
                raise RuntimeError(f"Download HTTP {r.status_code}: {url}")
            with open(dest, "wb") as fh:
                for chunk in r.iter_content(chunk_size=1024 * 1024):
                    if chunk:
                        fh.write(chunk)


# ---------------------------------------------------------------------------
# ETL run bookkeeping
# ---------------------------------------------------------------------------
def run_start(pg: Pg, base_url: str, region: str) -> int:
    row = pg.fetchone(
        "INSERT INTO public.rapid7_etl_runs (status, api_base_url, region) "
        "VALUES ('running', %s, %s) RETURNING run_id",
        (base_url, region),
    )
    assert row
    return int(row[0])


def run_finish(
    pg: Pg,
    run_id: int,
    status: str,
    rows_assets: int,
    rows_vulns: int,
    rows_remediations: int,
    error_message: Optional[str] = None,
    error_detail: Optional[str] = None,
) -> None:
    pg.exec(
        "UPDATE public.rapid7_etl_runs SET "
        "finished_at=now(), status=%s, "
        "rows_assets=%s, rows_vulns=%s, rows_remediations=%s, "
        "error_message=%s, error_detail=%s "
        "WHERE run_id=%s",
        (
            status,
            rows_assets,
            rows_vulns,
            rows_remediations,
            error_message,
            error_detail,
            run_id,
        ),
    )


# ---------------------------------------------------------------------------
# Rapid7 export flow
# ---------------------------------------------------------------------------
def create_vuln_export(client: R7HTTP) -> str:
    LOG.info("Creating Rapid7 vulnerability export...")
    data = client.graphql(VULN_EXPORT_MUTATION)
    export_id = (data.get("createVulnerabilityExport") or {}).get("id")
    if not export_id:
        raise RuntimeError(f"No export ID returned: {data}")
    LOG.info("Export created: id=%s", export_id)
    return str(export_id)


def wait_for_export(
    client: R7HTTP,
    export_id: str,
    poll_interval: int,
    max_attempts: int,
) -> Dict[str, Any]:
    query = EXPORT_STATUS_QUERY % export_id
    last_status = None
    succeeded_without_urls = 0

    for attempt in range(1, max_attempts + 1):
        data = client.graphql(query)
        exp_obj = data.get("export") or {}
        status = str(exp_obj.get("status") or "UNKNOWN")

        if status != last_status:
            LOG.info("Export %s status: %s", export_id, status)
            last_status = status

        if status in ("FAILED", "ERROR", "CANCELLED"):
            raise RuntimeError(f"Export {export_id} ended with status {status}")

        result = exp_obj.get("result")
        entries = extract_export_entries(exp_obj)
        urls = collect_export_urls(exp_obj)

        LOG.info(
            "Export poll %d/%d: status=%s result_type=%s entries=%d urls=%d",
            attempt,
            max_attempts,
            status,
            type(result).__name__,
            len(entries),
            len(urls),
        )

        if urls:
            LOG.info("Export ready: %d URLs found across %d entries", len(urls), len(entries))
            return exp_obj

        if status in ("SUCCEEDED", "COMPLETE", "COMPLETED", "SUCCESS"):
            succeeded_without_urls += 1
            LOG.warning(
                "Export is %s but no URLs in result yet (attempt %d). result keys=%s",
                status,
                succeeded_without_urls,
                list(result.keys()) if isinstance(result, dict) else type(result).__name__,
            )
            if succeeded_without_urls >= 5:
                raise RuntimeError(
                    f"Export {export_id} reached {status} but result contains "
                    f"no download URLs after {succeeded_without_urls} additional polls. "
                    f"result payload: {repr(result)[:500]}"
                )

        time.sleep(poll_interval)

    raise RuntimeError(f"Timeout waiting for export {export_id} after {max_attempts} polls")


def download_parquets(
    client: R7HTTP,
    exp_obj: Dict[str, Any],
    temp_dir: str,
) -> List[Tuple[str, str]]:
    all_urls = collect_export_urls(exp_obj)

    if not all_urls:
        raise RuntimeError("No download URLs in export result")

    paths: List[Tuple[str, str]] = []
    for i, (prefix, url) in enumerate(all_urls, 1):
        safe_prefix = prefix.replace("/", "_")
        dest = os.path.join(temp_dir, f"rapid7_{safe_prefix}_{i}.parquet")
        LOG.info("Downloading parquet %d/%d prefix=%s...", i, len(all_urls), prefix)
        client.download_file(url, dest)
        paths.append((prefix, dest))
        LOG.info("Downloaded: %s", dest)

    return paths


# ---------------------------------------------------------------------------
# Parquet parsing
# ---------------------------------------------------------------------------
def classify_parquet(df: Any, prefix: str = "") -> str:
    if not HAS_PANDAS:
        return "unknown"

    cols = {str(c).lower() for c in df.columns}
    hint = prefix.lower()

    if "asset_vulnerability" in hint:
        return "asset_vulnerability"
    if "vulnerability_remediation" in hint:
        return "vulnerability_remediation"
    if hint == "asset":
        return "asset"

    if "hostname" in cols and "assetid" in cols and "vulnid" not in cols:
        return "asset"
    if "assetid" in cols and "vulnid" in cols:
        return "asset_vulnerability"
    if "assetid" in cols and "cve_id" in cols:
        return "vulnerability_remediation"

    return "unknown"


def read_parquet(path: str, prefix_hint: str = "") -> Tuple[str, List[Dict]]:
    if not HAS_PANDAS:
        raise RuntimeError("pandas is required: pip install pandas")

    engine = ensure_parquet_engine()
    df = pd.read_parquet(path, engine=engine)
    ptype = classify_parquet(df, prefix_hint)

    records = [
        {str(k): normalize_parquet_value(v) for k, v in row.items()}
        for row in df.to_dict(orient="records")
    ]
    return ptype, records


# ---------------------------------------------------------------------------
# Asset shaping
# ---------------------------------------------------------------------------
def build_assets_from_parquet(asset_rows: List[Dict], vuln_rows: List[Dict]) -> List[Dict]:
    asset_map: Dict[str, Dict] = {}

    for row in asset_rows:
        asset_id = str(row.get("assetId") or "").strip()
        if not asset_id:
            continue

        host_name = str(row.get("hostName") or "").strip()

        asset_map[asset_id] = {
            "asset_id": asset_id,
            "org_id": row.get("orgId"),
            "agent_id": row.get("agentId"),
            "aws_instance_id": row.get("awsInstanceId"),
            "azure_resource_id": row.get("azureResourceId"),
            "gcp_object_id": row.get("gcpObjectId"),
            "mac": row.get("mac"),
            "ip": str(row.get("ip") or "").strip() or None,
            "host_name": host_name or None,
            "os_architecture": row.get("osArchitecture"),
            "os_family": row.get("osFamily"),
            "os_product": row.get("osProduct"),
            "os_vendor": row.get("osVendor"),
            "os_version": row.get("osVersion"),
            "os_type": row.get("osType"),
            "os_description": row.get("osDescription"),
            "risk_score": safe_float(row.get("riskScore")),
            "sites": clean_str_list(row.get("sites")),
            "asset_groups": clean_str_list(row.get("assetGroups")),
            "tags": clean_str_list(row.get("tags")),
            "vulnerabilities": [],
        }

    for row in vuln_rows:
        asset_id = str(row.get("assetId") or "").strip()
        vuln_id = str(row.get("vulnId") or "").strip()

        if not asset_id or not vuln_id:
            continue

        if asset_id not in asset_map:
            asset_map[asset_id] = {
                "asset_id": asset_id,
                "org_id": None,
                "agent_id": None,
                "aws_instance_id": None,
                "azure_resource_id": None,
                "gcp_object_id": None,
                "mac": None,
                "ip": None,
                "host_name": None,
                "os_architecture": None,
                "os_family": None,
                "os_product": None,
                "os_vendor": None,
                "os_version": None,
                "os_type": None,
                "os_description": None,
                "risk_score": None,
                "sites": [],
                "asset_groups": [],
                "tags": [],
                "vulnerabilities": [],
            }

        asset_map[asset_id]["vulnerabilities"].append(row)

    return list(asset_map.values())


# ---------------------------------------------------------------------------
# DB inserts - assets
# ---------------------------------------------------------------------------
def upsert_assets(pg: Pg, assets: List[Dict], run_id: int, dry_run: bool) -> int:
    if not assets:
        return 0

    rows = []
    for a in assets:
        all_cves: Set[str] = set()
        for v in a.get("vulnerabilities", []):
            all_cves.update(extract_cves(v.get("cves")))

        rows.append(
            (
                a["asset_id"],
                run_id,
                a.get("org_id"),
                a.get("agent_id"),
                a.get("aws_instance_id"),
                a.get("azure_resource_id"),
                a.get("gcp_object_id"),
                a.get("mac"),
                a.get("ip"),
                a.get("host_name"),
                a.get("os_architecture"),
                a.get("os_family"),
                a.get("os_product"),
                a.get("os_vendor"),
                a.get("os_version"),
                a.get("os_type"),
                a.get("os_description"),
                safe_float(a.get("risk_score")),
                a.get("sites") or [],
                a.get("asset_groups") or [],
                a.get("tags") or [],
                len(a.get("vulnerabilities", [])),
                len(
                    {
                        str(v.get("vulnId") or "")
                        for v in a.get("vulnerabilities", [])
                        if v.get("vulnId")
                    }
                ),
                len(all_cves),
                sorted(all_cves),
            )
        )

    if dry_run:
        LOG.info("[DRY-RUN] upsert_assets: %d rows", len(rows))
        return len(rows)

    sql = """
    INSERT INTO public.rapid7_asset (
      asset_id, last_run_id,
      org_id, agent_id, aws_instance_id, azure_resource_id, gcp_object_id,
      mac, ip, host_name,
      os_architecture, os_family, os_product, os_vendor, os_version,
      os_type, os_description, risk_score,
      sites, asset_groups, tags,
      vuln_finding_count, unique_vuln_id_count, unique_cve_count, cves
    ) VALUES %s
    ON CONFLICT (asset_id) DO UPDATE SET
      last_run_id          = EXCLUDED.last_run_id,
      org_id               = EXCLUDED.org_id,
      agent_id             = EXCLUDED.agent_id,
      aws_instance_id      = EXCLUDED.aws_instance_id,
      azure_resource_id    = EXCLUDED.azure_resource_id,
      gcp_object_id        = EXCLUDED.gcp_object_id,
      mac                  = EXCLUDED.mac,
      ip                   = EXCLUDED.ip,
      host_name            = EXCLUDED.host_name,
      os_architecture      = EXCLUDED.os_architecture,
      os_family            = EXCLUDED.os_family,
      os_product           = EXCLUDED.os_product,
      os_vendor            = EXCLUDED.os_vendor,
      os_version           = EXCLUDED.os_version,
      os_type              = EXCLUDED.os_type,
      os_description       = EXCLUDED.os_description,
      risk_score           = EXCLUDED.risk_score,
      sites                = EXCLUDED.sites,
      asset_groups         = EXCLUDED.asset_groups,
      tags                 = EXCLUDED.tags,
      vuln_finding_count   = EXCLUDED.vuln_finding_count,
      unique_vuln_id_count = EXCLUDED.unique_vuln_id_count,
      unique_cve_count     = EXCLUDED.unique_cve_count,
      cves                 = EXCLUDED.cves,
      ingested_at          = now()
    """

    tmpl = (
        "(%s,%s,"
        " %s,%s,%s,%s,%s,"
        " %s,%s,%s,"
        " %s,%s,%s,%s,%s,%s,%s,%s::numeric,"
        " %s::text[],%s::text[],%s::text[],"
        " %s,%s,%s,%s::text[])"
    )

    with pg.conn() as c:
        with c.cursor() as cur:
            execute_values(cur, sql, rows, template=tmpl, page_size=100)

    LOG.info("upsert_assets: %d assets processed", len(rows))
    return len(rows)


# ---------------------------------------------------------------------------
# DB inserts - vuln findings (dedup/merge before insert)
# ---------------------------------------------------------------------------
def _norm_conflict_int(v: Any, default: int = -1) -> int:
    iv = safe_int(v)
    return default if iv is None else iv


def _norm_conflict_str(v: Any) -> str:
    return str(v or "").strip()


def _merge_text_keep_best(current: Optional[str], new_value: Optional[str]) -> Optional[str]:
    cur = str(current or "").strip()
    new = str(new_value or "").strip()

    if not cur and not new:
        return None
    if not cur:
        return new
    if not new:
        return cur

    return new if len(new) > len(cur) else cur


def _merge_bool(current: Any, new_value: Any) -> bool:
    return bool(current) or bool(new_value)


def _merge_int_max(current: Any, new_value: Any) -> Optional[int]:
    a = safe_int(current)
    b = safe_int(new_value)
    if a is None:
        return b
    if b is None:
        return a
    return max(a, b)


def _merge_float_max(current: Any, new_value: Any) -> Optional[float]:
    a = safe_float(current)
    b = safe_float(new_value)
    if a is None:
        return b
    if b is None:
        return a
    return max(a, b)


def _merge_ts_min(current: Any, new_value: Any) -> Optional[str]:
    a = parse_ts(current)
    b = parse_ts(new_value)
    if not a:
        return b
    if not b:
        return a
    return a if a <= b else b


def _merge_ts_max(current: Any, new_value: Any) -> Optional[str]:
    a = parse_ts(current)
    b = parse_ts(new_value)
    if not a:
        return b
    if not b:
        return a
    return a if a >= b else b


def _dedupe_key_for_vuln_finding(
    asset_id: str,
    run_id: int,
    vuln_id: str,
    port: Any,
    protocol: Any,
    nic: Any,
) -> Tuple[str, int, str, int, str, str]:
    return (
        str(asset_id).strip(),
        int(run_id),
        str(vuln_id).strip(),
        _norm_conflict_int(port, -1),
        _norm_conflict_str(protocol),
        _norm_conflict_str(nic),
    )


def _build_vuln_payload(asset_id: str, run_id: int, v: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "asset_id": asset_id,
        "run_id": run_id,
        "vuln_id": str(v.get("vulnId") or v.get("vuln_id") or "").strip(),
        "port": safe_int(v.get("port")),
        "protocol": str(v.get("protocol") or "").strip() or None,
        "nic": str(v.get("nic") or "").strip() or None,

        "severity": v.get("severity") or v.get("cvss_v3_severity"),
        "severity_rank": safe_int(v.get("severityRank") or v.get("severity_rank")),
        "severity_score": safe_int(v.get("severityScore") or v.get("severity_score")),

        "risk_score": safe_float(v.get("riskScore") or v.get("risk_score")),
        "risk_score_v2": safe_float(v.get("riskScoreV2_0") or v.get("risk_score_v2_0")),
        "cvss_score": safe_float(v.get("cvssScore") or v.get("cvss_score")),

        "cvss_v3_score": safe_float(v.get("cvssV3Score") or v.get("cvss_v3_score")),
        "cvss_v3_severity": v.get("cvssV3Severity") or v.get("cvss_v3_severity"),
        "cvss_v3_severity_rank": safe_int(v.get("cvssV3SeverityRank") or v.get("cvss_v3_severity_rank")),

        "cvss_v3_attack_vector": v.get("cvssV3AttackVector") or v.get("cvss_v3_attack_vector"),
        "cvss_v3_attack_complexity": v.get("cvssV3AttackComplexity") or v.get("cvss_v3_attack_complexity"),
        "cvss_v3_privileges_required": v.get("cvssV3PrivilegesRequired") or v.get("cvss_v3_privileges_required"),
        "cvss_v3_user_interaction": v.get("cvssV3UserInteraction") or v.get("cvss_v3_user_interaction"),
        "cvss_v3_scope": v.get("cvssV3Scope") or v.get("cvss_v3_scope"),
        "cvss_v3_confidentiality": v.get("cvssV3Confidentiality") or v.get("cvss_v3_confidentiality"),
        "cvss_v3_integrity": v.get("cvssV3Integrity") or v.get("cvss_v3_integrity"),
        "cvss_v3_availability": v.get("cvssV3Availability") or v.get("cvss_v3_availability"),

        "epss_score": safe_float(v.get("epssscore") or v.get("epssScore") or v.get("epss_score")),
        "epss_percentile": safe_float(v.get("epsspercentile") or v.get("epssPercentile") or v.get("epss_percentile")),

        "has_exploits": bool(v.get("hasExploits") or v.get("has_exploits")),
        "threat_feed_exists": bool(v.get("threatFeedExists") or v.get("threat_feed_exists")),
        "pci_compliant": bool(v.get("pciCompliant") or v.get("pci_compliant")),
        "pci_severity": safe_int(v.get("pciSeverity") or v.get("pci_severity")),

        "skill_level": v.get("skillLevel") or v.get("skill_level"),
        "skill_level_rank": safe_int(v.get("skillLevelRank") or v.get("skill_level_rank")),

        "title": str(v.get("title") or "").strip() or None,
        "description": str(v.get("description") or "").strip() or None,

        "first_found_at": parse_ts(v.get("firstFoundTimestamp") or v.get("first_found_timestamp")),
        "date_published": parse_ts(v.get("datePublished") or v.get("date_published")),
        "date_added": parse_ts(v.get("dateAdded") or v.get("date_added")),
        "date_modified": parse_ts(v.get("dateModified") or v.get("date_modified")),

        "cves": extract_cves(v.get("cves")),
        "tags": clean_str_list(v.get("tags")),
    }


def _merge_vuln_payload(existing: Dict[str, Any], incoming: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(existing)

    merged["severity"] = _merge_text_keep_best(merged.get("severity"), incoming.get("severity"))
    merged["cvss_v3_severity"] = _merge_text_keep_best(
        merged.get("cvss_v3_severity"),
        incoming.get("cvss_v3_severity"),
    )
    merged["skill_level"] = _merge_text_keep_best(merged.get("skill_level"), incoming.get("skill_level"))
    merged["title"] = _merge_text_keep_best(merged.get("title"), incoming.get("title"))
    merged["description"] = _merge_text_keep_best(merged.get("description"), incoming.get("description"))

    merged["protocol"] = _merge_text_keep_best(merged.get("protocol"), incoming.get("protocol"))
    merged["nic"] = _merge_text_keep_best(merged.get("nic"), incoming.get("nic"))

    merged["severity_rank"] = _merge_int_max(merged.get("severity_rank"), incoming.get("severity_rank"))
    merged["severity_score"] = _merge_int_max(merged.get("severity_score"), incoming.get("severity_score"))
    merged["cvss_v3_severity_rank"] = _merge_int_max(
        merged.get("cvss_v3_severity_rank"),
        incoming.get("cvss_v3_severity_rank"),
    )
    merged["pci_severity"] = _merge_int_max(merged.get("pci_severity"), incoming.get("pci_severity"))
    merged["skill_level_rank"] = _merge_int_max(merged.get("skill_level_rank"), incoming.get("skill_level_rank"))

    merged["risk_score"] = _merge_float_max(merged.get("risk_score"), incoming.get("risk_score"))
    merged["risk_score_v2"] = _merge_float_max(merged.get("risk_score_v2"), incoming.get("risk_score_v2"))
    merged["cvss_score"] = _merge_float_max(merged.get("cvss_score"), incoming.get("cvss_score"))
    merged["cvss_v3_score"] = _merge_float_max(merged.get("cvss_v3_score"), incoming.get("cvss_v3_score"))
    merged["epss_score"] = _merge_float_max(merged.get("epss_score"), incoming.get("epss_score"))
    merged["epss_percentile"] = _merge_float_max(merged.get("epss_percentile"), incoming.get("epss_percentile"))

    merged["has_exploits"] = _merge_bool(merged.get("has_exploits"), incoming.get("has_exploits"))
    merged["threat_feed_exists"] = _merge_bool(
        merged.get("threat_feed_exists"),
        incoming.get("threat_feed_exists"),
    )
    merged["pci_compliant"] = _merge_bool(merged.get("pci_compliant"), incoming.get("pci_compliant"))

    merged["first_found_at"] = _merge_ts_min(merged.get("first_found_at"), incoming.get("first_found_at"))
    merged["date_published"] = _merge_ts_max(merged.get("date_published"), incoming.get("date_published"))
    merged["date_added"] = _merge_ts_max(merged.get("date_added"), incoming.get("date_added"))
    merged["date_modified"] = _merge_ts_max(merged.get("date_modified"), incoming.get("date_modified"))

    merged["cves"] = sorted(set((merged.get("cves") or [])) | set((incoming.get("cves") or [])))
    merged["tags"] = sorted(set((merged.get("tags") or [])) | set((incoming.get("tags") or [])))

    merged["asset_id"] = incoming.get("asset_id") or merged.get("asset_id")
    merged["run_id"] = incoming.get("run_id") or merged.get("run_id")
    merged["vuln_id"] = incoming.get("vuln_id") or merged.get("vuln_id")
    merged["port"] = merged.get("port") if merged.get("port") is not None else incoming.get("port")

    for field in (
        "cvss_v3_attack_vector",
        "cvss_v3_attack_complexity",
        "cvss_v3_privileges_required",
        "cvss_v3_user_interaction",
        "cvss_v3_scope",
        "cvss_v3_confidentiality",
        "cvss_v3_integrity",
        "cvss_v3_availability",
    ):
        merged[field] = _merge_text_keep_best(merged.get(field), incoming.get(field))

    return merged


def _payload_to_tuple(p: Dict[str, Any]) -> tuple:
    return (
        p["asset_id"],
        p["run_id"],
        p["vuln_id"],
        p["port"],
        p["protocol"],
        p["nic"],
        p["severity"],
        p["severity_rank"],
        p["severity_score"],
        p["risk_score"],
        p["risk_score_v2"],
        p["cvss_score"],
        p["cvss_v3_score"],
        p["cvss_v3_severity"],
        p["cvss_v3_severity_rank"],
        p["cvss_v3_attack_vector"],
        p["cvss_v3_attack_complexity"],
        p["cvss_v3_privileges_required"],
        p["cvss_v3_user_interaction"],
        p["cvss_v3_scope"],
        p["cvss_v3_confidentiality"],
        p["cvss_v3_integrity"],
        p["cvss_v3_availability"],
        p["epss_score"],
        p["epss_percentile"],
        p["has_exploits"],
        p["threat_feed_exists"],
        p["pci_compliant"],
        p["pci_severity"],
        p["skill_level"],
        p["skill_level_rank"],
        p["title"],
        p["description"],
        p["first_found_at"],
        p["date_published"],
        p["date_added"],
        p["date_modified"],
        p["cves"],
        p["tags"],
    )


def insert_vuln_findings(
    pg: Pg,
    assets: List[Dict],
    run_id: int,
    dry_run: bool,
    batch_size: int = 500,
) -> int:
    sql = """
    INSERT INTO public.rapid7_vuln_finding (
      asset_id, run_id, vuln_id,
      port, protocol, nic,
      severity, severity_rank, severity_score,
      risk_score, risk_score_v2,
      cvss_score,
      cvss_v3_score, cvss_v3_severity, cvss_v3_severity_rank,
      cvss_v3_attack_vector, cvss_v3_attack_complexity,
      cvss_v3_privileges_required, cvss_v3_user_interaction,
      cvss_v3_scope, cvss_v3_confidentiality,
      cvss_v3_integrity, cvss_v3_availability,
      epss_score, epss_percentile,
      has_exploits, threat_feed_exists,
      pci_compliant, pci_severity,
      skill_level, skill_level_rank,
      title, description,
      first_found_at, date_published, date_added, date_modified,
      cves, tags
    ) VALUES %s
    ON CONFLICT (asset_id, run_id, vuln_id,
                 COALESCE(port,-1), COALESCE(protocol,''), COALESCE(nic,''))
    DO UPDATE SET
      severity              = EXCLUDED.severity,
      severity_rank         = EXCLUDED.severity_rank,
      severity_score        = EXCLUDED.severity_score,
      risk_score            = EXCLUDED.risk_score,
      risk_score_v2         = EXCLUDED.risk_score_v2,
      cvss_score            = EXCLUDED.cvss_score,
      cvss_v3_score         = EXCLUDED.cvss_v3_score,
      cvss_v3_severity      = EXCLUDED.cvss_v3_severity,
      cvss_v3_severity_rank = EXCLUDED.cvss_v3_severity_rank,
      epss_score            = EXCLUDED.epss_score,
      epss_percentile       = EXCLUDED.epss_percentile,
      has_exploits          = EXCLUDED.has_exploits,
      threat_feed_exists    = EXCLUDED.threat_feed_exists,
      pci_compliant         = EXCLUDED.pci_compliant,
      pci_severity          = EXCLUDED.pci_severity,
      skill_level           = EXCLUDED.skill_level,
      skill_level_rank      = EXCLUDED.skill_level_rank,
      title                 = EXCLUDED.title,
      description           = EXCLUDED.description,
      first_found_at        = EXCLUDED.first_found_at,
      date_published        = EXCLUDED.date_published,
      date_added            = EXCLUDED.date_added,
      date_modified         = EXCLUDED.date_modified,
      cves                  = EXCLUDED.cves,
      tags                  = EXCLUDED.tags,
      ingested_at           = now()
    """

    tmpl = (
        "(%s,%s,%s,"
        " %s,%s,%s,"
        " %s,%s,%s,"
        " %s::numeric,%s::numeric,"
        " %s::numeric,"
        " %s::numeric,%s,%s,"
        " %s,%s,%s,%s,%s,%s,%s,%s,"
        " %s::numeric,%s::numeric,"
        " %s,%s,%s,%s,"
        " %s,%s,"
        " %s,%s,"
        " %s::timestamptz,%s::timestamptz,%s::timestamptz,%s::timestamptz,"
        " %s::text[],%s::text[])"
    )

    def flush(batch: List[tuple]) -> int:
        if not batch:
            return 0

        if dry_run:
            LOG.debug("[DRY-RUN] vuln batch %d", len(batch))
            return len(batch)

        try:
            with pg.conn() as c:
                with c.cursor() as cur:
                    execute_values(cur, sql, batch, template=tmpl, page_size=200)
            return len(batch)
        except Exception as e:
            LOG.error("Vuln batch failed: %s", e, exc_info=True)
            raise

    inserted = 0
    skipped = 0

    merged_by_key: Dict[Tuple[str, int, str, int, str, str], Dict[str, Any]] = {}

    for a in assets:
        asset_id = a["asset_id"]

        for v in a.get("vulnerabilities", []):
            vuln_id = str(v.get("vulnId") or v.get("vuln_id") or "").strip()
            if not vuln_id:
                skipped += 1
                continue

            payload = _build_vuln_payload(asset_id, run_id, v)

            key = _dedupe_key_for_vuln_finding(
                asset_id=payload["asset_id"],
                run_id=payload["run_id"],
                vuln_id=payload["vuln_id"],
                port=payload["port"],
                protocol=payload["protocol"],
                nic=payload["nic"],
            )

            if key in merged_by_key:
                merged_by_key[key] = _merge_vuln_payload(merged_by_key[key], payload)
            else:
                merged_by_key[key] = payload

    rows = [_payload_to_tuple(p) for p in merged_by_key.values()]

    batch: List[tuple] = []
    for row in rows:
        batch.append(row)
        if len(batch) >= batch_size:
            inserted += flush(batch)
            batch = []

    if batch:
        inserted += flush(batch)

    LOG.info(
        "insert_vuln_findings: inserted=%d skipped=%d deduped_from=%d deduped_to=%d",
        inserted,
        skipped,
        sum(len(a.get("vulnerabilities", [])) for a in assets),
        len(rows),
    )
    return inserted


# ---------------------------------------------------------------------------
# DB inserts - remediation
# ---------------------------------------------------------------------------
def insert_remediations(
    pg: Pg,
    rem_rows: List[Dict],
    run_id: int,
    dry_run: bool,
    batch_size: int = 500,
) -> int:
    if not rem_rows:
        return 0

    sql = """
    INSERT INTO public.rapid7_remediation (
      asset_id, run_id, vuln_id, cve_id,
      title, description, proof,
      first_found_at, last_detected_at, last_removed_at, reintroduced_at
    ) VALUES %s
    ON CONFLICT (asset_id, run_id, vuln_id, COALESCE(cve_id,''))
    DO UPDATE SET
      last_detected_at = EXCLUDED.last_detected_at,
      last_removed_at  = EXCLUDED.last_removed_at,
      reintroduced_at  = EXCLUDED.reintroduced_at,
      ingested_at      = now()
    """

    tmpl = (
        "(%s,%s,%s,%s,"
        " %s,%s,%s,"
        " %s::timestamptz,%s::timestamptz,%s::timestamptz,%s::timestamptz)"
    )

    def flush(batch: List[tuple]) -> int:
        if not batch:
            return 0
        if dry_run:
            return len(batch)
        try:
            with pg.conn() as c:
                with c.cursor() as cur:
                    execute_values(cur, sql, batch, template=tmpl, page_size=200)
            return len(batch)
        except Exception as e:
            LOG.error("Remediation batch failed: %s", e, exc_info=True)
            raise

    inserted = 0
    batch: List[tuple] = []

    for r in rem_rows:
        asset_id = str(r.get("assetId") or r.get("asset_id") or "").strip()
        vuln_id = str(r.get("vulnId") or r.get("vuln_id") or "").strip()

        if not asset_id or not vuln_id:
            continue

        cve_id = str(r.get("cveId") or r.get("cve_id") or "").strip() or None
        batch.append(
            (
                asset_id,
                run_id,
                vuln_id,
                cve_id,
                str(r.get("title") or "").strip() or None,
                str(r.get("description") or "").strip() or None,
                str(r.get("proof") or "").strip() or None,
                parse_ts(r.get("firstFoundTimestamp") or r.get("first_found_timestamp")),
                parse_ts(r.get("lastDetected") or r.get("last_detected")),
                parse_ts(r.get("lastRemoved") or r.get("last_removed")),
                parse_ts(r.get("reintroducedTimestamp") or r.get("reintroduced_timestamp")),
            )
        )

        if len(batch) >= batch_size:
            inserted += flush(batch)
            batch = []

    if batch:
        inserted += flush(batch)

    LOG.info("insert_remediations: %d rows", inserted)
    return inserted


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
def load_config() -> Dict[str, Any]:
    def req(secret: str, env: str) -> str:
        v = read_secret(secret, env_fallback=env)
        if not v:
            raise RuntimeError(f"Secret '{secret}' / env '{env}' not found - required")
        return v

    region = read_secret("rapid7_region", env_fallback="R7_REGION", default="us3")
    base_url = read_secret(
        "rapid7_api_url",
        env_fallback="R7_BASE_URL",
        default=f"https://{region}.api.insight.rapid7.com",
    )

    return {
        "r7_api_key": req("rapid7_api_key", "R7_API_KEY"),
        "r7_base_url": base_url.rstrip("/"),
        "r7_region": region,
        "pg_db": req("postgres_db", "PGDATABASE"),
        "pg_user": req("postgres_user", "PGUSER"),
        "pg_password": req("postgres_password", "PGPASSWORD"),
        "pg_host": os.getenv("POSTGRES_HOST", "appdb"),
        "pg_port": int(os.getenv("POSTGRES_PORT", "5432")),
        "pg_sslmode": os.getenv("PG_SSLMODE", "disable"),
        "timeout": int(os.getenv("R7_TIMEOUT", "180")),
        "max_retries": int(os.getenv("R7_MAX_RETRIES", "5")),
        "poll_interval": int(os.getenv("R7_POLL_INTERVAL", "10")),
        "max_poll": int(os.getenv("R7_MAX_POLL", "60")),
        "batch_size": int(os.getenv("R7_BATCH_SIZE", "500")),
        "log_level": os.getenv("R7_LOG_LEVEL", "INFO").upper(),
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> int:
    cfg = load_config()
    setup_logging(cfg["log_level"])

    LOG.info("=== Rapid7 InsightVM ETL starting ===")
    LOG.info("API URL   : %s", cfg["r7_base_url"])
    LOG.info("Region    : %s", cfg["r7_region"])
    LOG.info(
        "DB        : %s@%s:%s/%s (ssl=%s)",
        cfg["pg_user"],
        cfg["pg_host"],
        cfg["pg_port"],
        cfg["pg_db"],
        cfg["pg_sslmode"],
    )

    ensure_data_libs()
    ensure_parquet_engine()

    pg = Pg(
        host=cfg["pg_host"],
        port=cfg["pg_port"],
        dbname=cfg["pg_db"],
        user=cfg["pg_user"],
        password=cfg["pg_password"],
        sslmode=cfg["pg_sslmode"],
    )
    pg.init()

    client = R7HTTP(cfg["r7_api_key"], cfg["r7_base_url"], cfg)

    run_id: Optional[int] = None
    try:
        run_id = run_start(pg, cfg["r7_base_url"], cfg["r7_region"])
        LOG.info("ETL run started: run_id=%d", run_id)
    except Exception as e:
        LOG.warning("Could not register rapid7_etl_runs: %s", e)

    rows_assets = 0
    rows_vulns = 0
    rows_remediations = 0
    error_msg: Optional[str] = None
    error_detail: Optional[str] = None
    status = "error"

    try:
        LOG.info("--- STEP 1: Create vulnerability export ---")
        export_id = create_vuln_export(client)

        LOG.info("--- STEP 2: Wait for export to be ready ---")
        exp_obj = wait_for_export(
            client,
            export_id,
            cfg["poll_interval"],
            cfg["max_poll"],
        )

        LOG.info("--- STEP 3: Download parquet files ---")
        with tempfile.TemporaryDirectory(prefix="r7_etl_") as tmp:
            paths = download_parquets(client, exp_obj, tmp)

            LOG.info("--- STEP 4: Parse parquet files (%d) ---", len(paths))
            asset_rows: List[Dict] = []
            vuln_rows: List[Dict] = []
            rem_rows: List[Dict] = []

            for prefix, path in paths:
                ptype, records = read_parquet(path, prefix_hint=prefix)
                LOG.info(
                    "  %s prefix=%s -> type=%s rows=%d",
                    os.path.basename(path),
                    prefix,
                    ptype,
                    len(records),
                )

                if ptype == "asset":
                    asset_rows.extend(records)
                elif ptype == "asset_vulnerability":
                    vuln_rows.extend(records)
                elif ptype == "vulnerability_remediation":
                    rem_rows.extend(records)
                else:
                    cols = set(records[0].keys()) if records else set()
                    if "hostName" in cols or "hostname" in cols:
                        asset_rows.extend(records)
                    elif "vulnId" in cols or "vulnid" in cols:
                        vuln_rows.extend(records)

            LOG.info(
                "Parsed: %d asset rows, %d vuln rows, %d rem rows",
                len(asset_rows),
                len(vuln_rows),
                len(rem_rows),
            )

            LOG.info("--- STEP 5: Build asset structures ---")
            assets = build_assets_from_parquet(asset_rows, vuln_rows)
            LOG.info("Assets built: %d", len(assets))

            LOG.info("--- STEP 6: Upsert rapid7_asset ---")
            rows_assets = upsert_assets(pg, assets, run_id or 0, False)

            LOG.info("--- STEP 7: Insert rapid7_vuln_finding (batch=%d) ---", cfg["batch_size"])
            rows_vulns = insert_vuln_findings(
                pg,
                assets,
                run_id or 0,
                False,
                cfg["batch_size"],
            )

            LOG.info("--- STEP 8: Insert rapid7_remediation ---")
            rows_remediations = insert_remediations(
                pg,
                rem_rows,
                run_id or 0,
                False,
                cfg["batch_size"],
            )

        if run_id:
            cnt_a = pg.fetchval("SELECT count(*) FROM public.rapid7_asset")
            cnt_v = pg.fetchval(
                "SELECT count(*) FROM public.rapid7_vuln_finding WHERE run_id=%s",
                (run_id,),
            )
            LOG.info("DB totals -> assets=%s | vuln_findings(run)=%s", cnt_a, cnt_v)

        status = "success"

    except SystemExit:
        raise
    except Exception as e:
        error_msg = str(e)
        error_detail = traceback.format_exc()
        status = "error"
        LOG.error("ETL FAILED: %s", e, exc_info=True)

    finally:
        if run_id is not None:
            try:
                run_finish(
                    pg,
                    run_id,
                    status,
                    rows_assets,
                    rows_vulns,
                    rows_remediations,
                    error_msg,
                    error_detail,
                )
                LOG.info("Run closed: run_id=%d status=%s", run_id, status)
            except Exception as fe:
                LOG.warning("Could not update rapid7_etl_runs: %s", fe)
        pg.close()

    if status == "error":
        LOG.error("=== Rapid7 ETL FAILED === run_id=%s", run_id)
        return 1

    LOG.info(
        "=== Rapid7 ETL OK | run_id=%s | assets=%d vulns=%d remediations=%d ===",
        run_id,
        rows_assets,
        rows_vulns,
        rows_remediations,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
