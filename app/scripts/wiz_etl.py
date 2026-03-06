#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wiz_etl.py — ETL Wiz -> PostgreSQL (vanalyzer-stack)
=====================================================
Tablas destino (esquema reducido):
  public.wiz_etl_runs
  public.wiz_assets          PK = asset_id (sin run_id, sin tags, sin image_native_type)
  public.wiz_cves            sin cvssv2/v3, weighted_severity, cisa_kev_*, is_client_side,
                             fix_date_before, affected_by_settings
  public.wiz_software_vulnerable

Comportamiento de insercion:
  wiz_assets  : ON CONFLICT (asset_id) DO UPDATE — 1 fila por VM, se actualiza
  wiz_cves    : ON CONFLICT (cve_id)  DO UPDATE — 1 fila por CVE, se actualiza
  wiz_software_vulnerable: ON CONFLICT por (run_id, asset_id, cve_id, software_name,
                           location_path) DO UPDATE — no duplica, solo actualiza campos

Docker secrets:
  wiz_client_id | wiz_client_secret | wiz_api_endpoint_url
  postgres_db   | postgres_user     | postgres_password

ENV opcionales:
  WIZ_AUTH_URL, WIZ_AUTH_AUDIENCE, WIZ_PAGE_SIZE, WIZ_TIMEOUT,
  WIZ_MAX_RETRIES, WIZ_MAX_FINDINGS, WIZ_FILTER_DAILY,
  WIZ_FILTER_SEVERITY, WIZ_FILTER_STATUS, WIZ_FILTER_PROJECT_IDS,
  WIZ_FILTER_HAS_FIX, WIZ_FILTER_HAS_EXPLOIT,
  WIZ_GRAPH_PROJECT_ID, WIZ_GRAPH_FIRST, WIZ_GRAPH_TYPES,
  POSTGRES_HOST, POSTGRES_PORT
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import random
import sys
import time
import traceback
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Generator, Iterable, List, Optional, Set, Tuple

import psycopg2
import psycopg2.extras
from psycopg2.extras import execute_values
from psycopg2.pool import SimpleConnectionPool

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ---------------------------------------------------------------------------
LOG = logging.getLogger("wiz_etl")


def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stderr,
    )


# ---------------------------------------------------------------------------
# Secrets
# ---------------------------------------------------------------------------
SECRETS_DIR = os.getenv("SECRETS_DIR", "/run/secrets")


def read_secret(name: str, env_fallback: str = "", default: str = "") -> str:
    try:
        with open(os.path.join(SECRETS_DIR, name), "r") as fh:
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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def die(msg: str, code: int = 2) -> None:
    LOG.critical(msg)
    sys.exit(code)


def backoff_sleep(attempt: int) -> None:
    time.sleep(0.8 * (2 ** (attempt - 1)) + random.random() * 0.25)


def safe_json(resp: requests.Response) -> Dict[str, Any]:
    try:
        return resp.json()
    except Exception:
        return {"_http_status": resp.status_code, "_text": resp.text[:2000]}


def parse_ts(v: Any) -> Optional[str]:
    if v is None:
        return None
    if isinstance(v, datetime):
        return v.isoformat()
    if isinstance(v, str):
        s = v.strip()
        if not s:
            return None
        try:
            s2 = s[:-1] + "+00:00" if s.endswith("Z") else s
            return datetime.fromisoformat(s2).astimezone(timezone.utc).isoformat()
        except Exception:
            return None
    return None


def to_json_str(v: Any) -> Optional[str]:
    if v is None:
        return None
    try:
        return json.dumps(v, ensure_ascii=False, default=str)
    except Exception:
        return json.dumps(str(v))


# ---------------------------------------------------------------------------
# PostgreSQL pool (patron MDE)
# ---------------------------------------------------------------------------
class Pg:
    def __init__(self, host: str, port: int, dbname: str,
                 user: str, password: str, sslmode: str = "disable") -> None:
        self._dsn = (f"host={host} port={port} dbname={dbname} "
                     f"user={user} password={password} sslmode={sslmode}")
        self._pool: Optional[SimpleConnectionPool] = None

    def init(self) -> None:
        if not self._pool:
            self._pool = SimpleConnectionPool(1, 5, self._dsn)
            LOG.info("PG pool inicializado")

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


# ---------------------------------------------------------------------------
# ETL runs
# ---------------------------------------------------------------------------
def run_start(pg: Pg, filters: Dict, endpoint: str, page_size: int) -> int:
    row = pg.fetchone(
        "INSERT INTO public.wiz_etl_runs "
        "  (status, api_endpoint_url, page_size, filters_applied) "
        "VALUES ('running',%s,%s,%s) RETURNING run_id",
        (endpoint, page_size, json.dumps(filters)),
    )
    assert row
    return int(row[0])


def run_finish(pg: Pg, run_id: int, status: str,
               rows_assets: int, rows_cves: int, rows_findings: int,
               rows_graph: int, pages_findings: int, pages_graph: int,
               reported_total: Optional[int],
               error_message: Optional[str] = None,
               error_detail: Optional[str] = None) -> None:
    pg.exec(
        "UPDATE public.wiz_etl_runs SET "
        "  finished_at=now(), status=%s, "
        "  rows_assets=%s, rows_cves=%s, rows_findings=%s, rows_graph_entities=%s, "
        "  pages_findings=%s, pages_graph=%s, reported_total_findings=%s, "
        "  error_message=%s, error_detail=%s "
        "WHERE run_id=%s",
        (status, rows_assets, rows_cves, rows_findings, rows_graph,
         pages_findings, pages_graph, reported_total,
         error_message, error_detail, run_id),
    )


# ---------------------------------------------------------------------------
# GraphQL queries
# ---------------------------------------------------------------------------
QUERY_VULNS = r"""
query VulnerabilityFindingsTable(
  $filterBy: VulnerabilityFindingFilters,
  $first: Int,
  $after: String,
  $orderBy: VulnerabilityFindingOrder = {direction: DESC, field: CREATED_AT}
) {
  vulnerabilityFindings(
    filterBy: $filterBy first: $first after: $after orderBy: $orderBy
  ) {
    nodes {
      id name detailedName isHighProfileThreat description
      severity vendorSeverity nvdSeverity
      status fixedVersion detectionMethod
      hasExploit hasCisaKevExploit
      firstDetectedAt lastDetectedAt resolvedAt
      score validatedInRuntime hasTriggerableRemediation
      epssSeverity epssPercentile epssProbability
      fixDate publishedDate
      categories isOperatingSystemEndOfLife recommendedVersion
      locationPath hasInitialAccessPotential
      codeLibraryLanguage
      technology { name }
      cnaScore vendorScore
      ignoreRules { id }
      layerMetadata { id details isBaseLayer }
      vulnerableAsset {
        ... on VulnerableAssetBase {
          id type name cloudPlatform subscriptionName subscriptionExternalId
          subscriptionId hasLimitedInternetExposure hasWideInternetExposure
          isAccessibleFromVPN isAccessibleFromOtherVnets
          isAccessibleFromOtherSubscriptions nativeType
        }
        ... on VulnerableAssetVirtualMachine {
          id type name cloudPlatform subscriptionName subscriptionExternalId
          subscriptionId operatingSystem imageName imageId
          hasLimitedInternetExposure hasWideInternetExposure
          isAccessibleFromVPN isAccessibleFromOtherVnets
          isAccessibleFromOtherSubscriptions
          computeInstanceGroup { name }
          nativeType
        }
        ... on VulnerableAssetContainerImage {
          id type name cloudPlatform subscriptionName subscriptionExternalId
          subscriptionId hasLimitedInternetExposure hasWideInternetExposure
          isAccessibleFromVPN isAccessibleFromOtherVnets
          isAccessibleFromOtherSubscriptions nativeType
        }
        ... on VulnerableAssetContainer {
          id type name cloudPlatform subscriptionName subscriptionExternalId
          subscriptionId hasLimitedInternetExposure hasWideInternetExposure
          isAccessibleFromVPN isAccessibleFromOtherVnets
          isAccessibleFromOtherSubscriptions nativeType
        }
        ... on VulnerableAssetEndpoint {
          id type name cloudPlatform subscriptionName subscriptionExternalId
          subscriptionId hasLimitedInternetExposure hasWideInternetExposure
          isAccessibleFromVPN isAccessibleFromOtherVnets
          isAccessibleFromOtherSubscriptions nativeType
        }
        ... on VulnerableAssetCommon {
          id type name cloudPlatform subscriptionName subscriptionExternalId
          subscriptionId nativeType
        }
      }
    }
    pageInfo { hasNextPage endCursor }
  }
}
""".strip()

QUERY_GRAPHSEARCH = r"""
query GraphSearch(
  $query: GraphEntityQueryInput,
  $projectId: String!,
  $first: Int,
  $after: String,
  $quick: Boolean = true
) {
  graphSearch(
    query: $query projectId: $projectId
    first: $first after: $after quick: $quick
  ) {
    nodes { entities { id name type properties } }
    pageInfo { endCursor hasNextPage }
  }
}
""".strip()


# ---------------------------------------------------------------------------
# Wiz HTTP client
# ---------------------------------------------------------------------------
class WizHTTP:
    def __init__(self, cfg: Dict[str, Any]) -> None:
        self.cfg = cfg
        self._token: Optional[str] = None
        self._token_exp: float = 0.0
        self.sess = requests.Session()
        adapter = HTTPAdapter(
            max_retries=Retry(
                total=cfg["max_retries"], backoff_factor=1.5,
                status_forcelist=(429, 500, 502, 503, 504),
                allowed_methods=frozenset(["GET", "POST"]),
                raise_on_status=False,
            ),
            pool_connections=10, pool_maxsize=10,
        )
        self.sess.mount("https://", adapter)
        self.sess.mount("http://",  adapter)

    def _token_valid(self) -> bool:
        return self._token is not None and time.time() < (self._token_exp - 60)

    def get_token(self, force: bool = False) -> str:
        if not force and self._token_valid():
            return self._token  # type: ignore
        data: Dict[str, str] = {
            "grant_type":    "client_credentials",
            "client_id":     self.cfg["wiz_client_id"],
            "client_secret": self.cfg["wiz_client_secret"],
        }
        if self.cfg["wiz_auth_audience"]:
            data["audience"] = self.cfg["wiz_auth_audience"]
        r = self.sess.post(
            self.cfg["wiz_auth_url"], data=data, timeout=self.cfg["timeout"],
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if r.status_code != 200:
            die(f"Token HTTP {r.status_code}: {r.text[:500]}")
        j = r.json()
        tok = j.get("access_token")
        if not tok:
            die(f"Token sin access_token: {j}")
        exp_in = j.get("expires_in")
        self._token = tok
        self._token_exp = time.time() + (exp_in if isinstance(exp_in, int) else 3600)
        LOG.info("Token Wiz OK (expira en %ss)", exp_in)
        return tok

    def graphql(self, query: str, variables: Optional[Dict] = None) -> Dict[str, Any]:
        payload = {"query": query, "variables": variables or {}}
        for attempt in range(1, self.cfg["max_retries"] + 1):
            headers = {"Authorization": f"Bearer {self.get_token()}",
                       "Content-Type": "application/json"}
            try:
                r = self.sess.post(self.cfg["wiz_api_endpoint"],
                                   headers=headers, json=payload,
                                   timeout=self.cfg["timeout"])
            except Exception as e:
                if attempt == self.cfg["max_retries"]:
                    return {"_exception": str(e)}
                backoff_sleep(attempt)
                continue
            if r.status_code in (401, 403):
                self.get_token(force=True)
                backoff_sleep(attempt)
                continue
            if r.status_code in (429, 500, 502, 503, 504):
                backoff_sleep(attempt)
                continue
            return safe_json(r)
        return {"_exception": "max retries"}


# ---------------------------------------------------------------------------
# Filtros
# ---------------------------------------------------------------------------
def build_filter_by(cfg: Dict[str, Any]) -> Dict[str, Any]:
    fb: Dict[str, Any] = {}
    if cfg["filter_daily"]:
        fb["updatedAt"] = {"inLast": {"amount": 1, "unit": "DurationFilterValueUnitDays"}}
    if cfg["filter_project_ids"]:
        fb["projectId"] = cfg["filter_project_ids"]
    if cfg["filter_severity"]:
        fb["severity"] = cfg["filter_severity"]
    if cfg["filter_status"]:
        fb["status"] = cfg["filter_status"]
    if cfg["filter_has_fix"] in ("True", "False"):
        fb["hasFix"] = cfg["filter_has_fix"]
    if cfg["filter_has_exploit"] in ("True", "False"):
        fb["hasExploit"] = cfg["filter_has_exploit"]
    return fb


# ---------------------------------------------------------------------------
# Fetchers
# ---------------------------------------------------------------------------
def fetch_findings(client: WizHTTP, cfg: Dict) -> Tuple[List[Dict], Optional[int], int]:
    variables: Dict[str, Any] = {
        "filterBy": build_filter_by(cfg),
        "first": cfg["page_size"],
        "after": None,
        "orderBy": {"field": "CREATED_AT", "direction": "DESC"},
    }
    all_nodes: List[Dict] = []
    total_count: Optional[int] = None
    pages = 0

    while True:
        pages += 1
        resp = client.graphql(QUERY_VULNS, variables)
        if resp.get("_exception"):
            die(f"GraphQL exception: {resp['_exception']}")
        if resp.get("errors"):
            die(f"GraphQL error: {resp['errors'][0].get('message', str(resp['errors'][0]))}")

        vf = (resp.get("data") or {}).get("vulnerabilityFindings") or {}
        if total_count is None and isinstance(vf.get("totalCount"), int):
            total_count = vf["totalCount"]

        nodes = vf.get("nodes") or []
        all_nodes.extend(n for n in nodes if isinstance(n, dict))
        pi = vf.get("pageInfo") or {}

        LOG.info("vulnerabilityFindings: pag %d -> +%d (acum %d/%s)",
                 pages, len(nodes), len(all_nodes), total_count or "?")

        if cfg["max_findings"] and len(all_nodes) >= cfg["max_findings"]:
            all_nodes = all_nodes[:cfg["max_findings"]]
            LOG.warning("Corte por max_findings=%d", cfg["max_findings"])
            break
        if not pi.get("hasNextPage") or not pi.get("endCursor"):
            break
        variables["after"] = pi["endCursor"]

    return all_nodes, total_count, pages




# ---------------------------------------------------------------------------
# Stubs de FK
# ---------------------------------------------------------------------------
def ensure_asset_stub(pg: Pg, asset_id: str, name: str,
                      atype: str, dry_run: bool) -> None:
    if dry_run:
        return
    pg.exec(
        "INSERT INTO public.wiz_assets (asset_id, asset_name, asset_type) "
        "VALUES (%s,%s,%s) ON CONFLICT (asset_id) DO NOTHING",
        (asset_id, name or "unknown", atype or "unknown"),
    )


def ensure_cve_stub(pg: Pg, cve_id: str, dry_run: bool) -> None:
    if dry_run:
        return
    pg.exec(
        "INSERT INTO public.wiz_cves (cve_id, last_seen_at) "
        "VALUES (%s, now()) ON CONFLICT (cve_id) DO NOTHING",
        (cve_id,),
    )


def ensure_cve_stubs_bulk(pg: Pg, cve_ids: Iterable[str], dry_run: bool) -> None:
    ids = list(set(cve_ids))
    if not ids or dry_run:
        return
    with pg.conn() as c:
        with c.cursor() as cur:
            execute_values(
                cur,
                "INSERT INTO public.wiz_cves (cve_id, last_seen_at) VALUES %s "
                "ON CONFLICT (cve_id) DO NOTHING",
                [(cid,) for cid in ids],
                template="(%s, now())",
                page_size=1000,
            )
    LOG.info("CVE stubs garantizados: %d", len(ids))


# ---------------------------------------------------------------------------
# UPSERT wiz_assets  (PK = asset_id, sin run_id, sin tags, sin image_native_type)
# Un registro por VM. Si ya existe, actualiza todo EXCEPTO first_seen_at.
# ---------------------------------------------------------------------------
def upsert_assets(pg: Pg, assets_map: Dict[str, Dict], dry_run: bool) -> int:
    if not assets_map:
        return 0

    rows = []
    for asset_id, a in assets_map.items():
        cig = a.get("computeInstanceGroup")
        rows.append((
            asset_id,
            a.get("name") or "",
            a.get("type") or "",
            a.get("nativeType"),
            a.get("cloudPlatform"),
            a.get("subscriptionId"),
            a.get("subscriptionExternalId"),
            a.get("subscriptionName"),
            a.get("hasLimitedInternetExposure"),
            a.get("hasWideInternetExposure"),
            a.get("isAccessibleFromVPN"),
            a.get("isAccessibleFromOtherVnets"),
            a.get("isAccessibleFromOtherSubscriptions"),
            a.get("operatingSystem"),
            a.get("imageName"),
            a.get("imageId"),
            cig.get("name") if isinstance(cig, dict) else None,
        ))

    if dry_run:
        LOG.info("[DRY-RUN] upsert_assets: %d filas", len(rows))
        return len(rows)

    sql = """
    INSERT INTO public.wiz_assets (
      asset_id, asset_name, asset_type, native_type,
      cloud_platform, subscription_id, subscription_external_id, subscription_name,
      has_limited_internet_exposure, has_wide_internet_exposure,
      is_accessible_from_vpn, is_accessible_from_other_vnets,
      is_accessible_from_other_subs,
      operating_system, image_name, image_id,
      compute_instance_group
    ) VALUES %s
    ON CONFLICT (asset_id) DO UPDATE SET
      asset_name                    = EXCLUDED.asset_name,
      asset_type                    = EXCLUDED.asset_type,
      native_type                   = EXCLUDED.native_type,
      cloud_platform                = EXCLUDED.cloud_platform,
      subscription_id               = EXCLUDED.subscription_id,
      subscription_external_id      = EXCLUDED.subscription_external_id,
      subscription_name             = EXCLUDED.subscription_name,
      has_limited_internet_exposure = EXCLUDED.has_limited_internet_exposure,
      has_wide_internet_exposure    = EXCLUDED.has_wide_internet_exposure,
      is_accessible_from_vpn        = EXCLUDED.is_accessible_from_vpn,
      is_accessible_from_other_vnets= EXCLUDED.is_accessible_from_other_vnets,
      is_accessible_from_other_subs = EXCLUDED.is_accessible_from_other_subs,
      operating_system              = EXCLUDED.operating_system,
      image_name                    = EXCLUDED.image_name,
      image_id                      = EXCLUDED.image_id,
      compute_instance_group        = EXCLUDED.compute_instance_group,
      ingested_at                   = now()
    """
    # first_seen_at NO se toca en el UPDATE — conserva cuándo se vio por primera vez

    tmpl = "(%s,%s,%s,%s, %s,%s,%s,%s, %s,%s,%s,%s,%s, %s,%s,%s,%s)"

    with pg.conn() as c:
        with c.cursor() as cur:
            execute_values(cur, sql, rows, template=tmpl, page_size=500)

    LOG.info("upsert_assets: %d activos unicos", len(rows))
    return len(rows)


# ---------------------------------------------------------------------------
# UPSERT wiz_cves  (dimension, sin cvssv2/v3/weighted_severity/cisa_kev/...)
# ---------------------------------------------------------------------------
def upsert_cves(pg: Pg, findings: List[Dict], dry_run: bool) -> int:
    cves_map: Dict[str, Dict] = {}
    for f in findings:
        cve_id = f.get("name")
        if isinstance(cve_id, str) and cve_id.upper().startswith("CVE-"):
            cves_map.setdefault(cve_id, f)

    if not cves_map:
        LOG.warning("No se encontraron CVE IDs validos en los findings.")
        return 0

    rows = []
    for cve_id, f in cves_map.items():
        rows.append((
            cve_id,
            f.get("description"),
            f.get("isHighProfileThreat"),
            f.get("categories") or [],   # text[]
            f.get("severity"),
            f.get("vendorSeverity"),
            f.get("nvdSeverity"),
            f.get("score"),              # numeric
            f.get("cnaScore"),           # numeric
            f.get("vendorScore"),        # numeric
            f.get("epssSeverity"),
            f.get("epssPercentile"),     # numeric
            f.get("epssProbability"),    # numeric
            f.get("hasExploit"),
            f.get("hasCisaKevExploit"),
            f.get("hasInitialAccessPotential"),
            parse_ts(f.get("publishedDate")),   # timestamptz
            parse_ts(f.get("fixDate")),          # timestamptz
            f.get("isOperatingSystemEndOfLife"),
            to_json_str(f.get("ignoreRules")),  # jsonb
        ))

    if dry_run:
        LOG.info("[DRY-RUN] upsert_cves: %d filas", len(rows))
        return len(rows)

    sql = """
    INSERT INTO public.wiz_cves (
      cve_id, description, is_high_profile_threat, categories,
      severity, vendor_severity, nvd_severity,
      score, cna_score, vendor_score,
      epss_severity, epss_percentile, epss_probability,
      has_exploit, has_cisa_kev_exploit,
      has_initial_access_potential,
      published_date, fix_date,
      is_operating_system_end_of_life,
      ignore_rules,
      last_seen_at
    ) VALUES %s
    ON CONFLICT (cve_id) DO UPDATE SET
      description                     = EXCLUDED.description,
      is_high_profile_threat          = EXCLUDED.is_high_profile_threat,
      categories                      = EXCLUDED.categories,
      severity                        = EXCLUDED.severity,
      vendor_severity                 = EXCLUDED.vendor_severity,
      nvd_severity                    = EXCLUDED.nvd_severity,
      score                           = EXCLUDED.score,
      cna_score                       = EXCLUDED.cna_score,
      vendor_score                    = EXCLUDED.vendor_score,
      epss_severity                   = EXCLUDED.epss_severity,
      epss_percentile                 = EXCLUDED.epss_percentile,
      epss_probability                = EXCLUDED.epss_probability,
      has_exploit                     = EXCLUDED.has_exploit,
      has_cisa_kev_exploit            = EXCLUDED.has_cisa_kev_exploit,
      has_initial_access_potential    = EXCLUDED.has_initial_access_potential,
      published_date                  = EXCLUDED.published_date,
      fix_date                        = EXCLUDED.fix_date,
      is_operating_system_end_of_life = EXCLUDED.is_operating_system_end_of_life,
      ignore_rules                    = EXCLUDED.ignore_rules,
      last_seen_at                    = now()
    """

    tmpl = """(
      %s, %s, %s, %s::text[],
      %s, %s, %s,
      %s::numeric, %s::numeric, %s::numeric,
      %s, %s::numeric, %s::numeric,
      %s, %s, %s,
      %s::timestamptz, %s::timestamptz,
      %s,
      %s::jsonb,
      now()
    )"""

    with pg.conn() as c:
        with c.cursor() as cur:
            execute_values(cur, sql, rows, template=tmpl, page_size=500)

    LOG.info("upsert_cves: %d CVEs procesados", len(rows))
    return len(rows)


# ---------------------------------------------------------------------------
# INSERT wiz_software_vulnerable  (batched, sin duplicados)
# ON CONFLICT (run_id, asset_id, COALESCE(cve_id,''), software_name,
#              COALESCE(location_path,'')) DO UPDATE
# ---------------------------------------------------------------------------
def insert_findings_batched(
    pg: Pg, run_id: int, findings: List[Dict],
    valid_asset_ids: Set[str], dry_run: bool, batch_size: int = 500,
) -> Tuple[int, int]:

    sql = """
    INSERT INTO public.wiz_software_vulnerable (
      run_id, finding_id, asset_id, cve_id,
      software_name, detection_method, location_path,
      code_library_language, technology,
      fixed_version, recommended_version, has_triggerable_remediation,
      status, validated_in_runtime,
      layer_id, layer_details, is_base_layer,
      first_detected_at, last_detected_at, resolved_at
    ) VALUES %s
    ON CONFLICT (run_id, asset_id, COALESCE(cve_id,''), software_name, COALESCE(location_path,''))
    DO UPDATE SET
      detection_method            = EXCLUDED.detection_method,
      code_library_language       = EXCLUDED.code_library_language,
      technology                  = EXCLUDED.technology,
      fixed_version               = EXCLUDED.fixed_version,
      recommended_version         = EXCLUDED.recommended_version,
      has_triggerable_remediation = EXCLUDED.has_triggerable_remediation,
      status                      = EXCLUDED.status,
      validated_in_runtime        = EXCLUDED.validated_in_runtime,
      layer_id                    = EXCLUDED.layer_id,
      layer_details               = EXCLUDED.layer_details,
      is_base_layer               = EXCLUDED.is_base_layer,
      first_detected_at           = EXCLUDED.first_detected_at,
      last_detected_at            = EXCLUDED.last_detected_at,
      resolved_at                 = EXCLUDED.resolved_at
    """

    tmpl = """(
      %s,%s,%s,%s,
      %s,%s,%s,
      %s,%s,
      %s,%s,%s,
      %s,%s,
      %s,%s,%s,
      %s::timestamptz,%s::timestamptz,%s::timestamptz
    )"""

    def flush(batch: List[tuple]) -> int:
        if not batch:
            return 0
        if dry_run:
            LOG.debug("[DRY-RUN] batch %d findings (no escritas)", len(batch))
            return len(batch)
        try:
            with pg.conn() as c:
                with c.cursor() as cur:
                    execute_values(cur, sql, batch, template=tmpl, page_size=200)
            return len(batch)
        except Exception as e:
            LOG.error("Batch findings fallo: %s | muestra=%s", e, batch[0], exc_info=True)
            raise

    total = skipped_no_id = skipped_no_asset = inserted = 0
    batch: List[tuple] = []

    for f in findings:
        total += 1

        finding_id = f.get("id")
        if not isinstance(finding_id, str) or not finding_id:
            skipped_no_id += 1
            continue

        va = f.get("vulnerableAsset") or {}
        asset_id = va.get("id") if isinstance(va, dict) else None
        if not isinstance(asset_id, str) or not asset_id:
            skipped_no_asset += 1
            continue

        # Stub de asset si no estaba en el mapa (borde)
        # Respetar el mismo filtro de tipos: solo VM y servidores
        if asset_id not in valid_asset_ids:
            atype = (va.get("type") or "").upper()
            if atype not in {"VIRTUAL_MACHINE", "ENDPOINT", "VIRTUAL_MACHINE_IMAGE"}:
                continue  # skip findings de contenedores/serverless
            ensure_asset_stub(pg, asset_id,
                              va.get("name") or "unknown",
                              va.get("type") or "unknown",
                              dry_run)
            valid_asset_ids.add(asset_id)

        # cve_id — None para PURL findings sin CVE asignado
        cve_id = f.get("name")
        if isinstance(cve_id, str) and not cve_id.upper().startswith("CVE-"):
            cve_id = None

        if isinstance(cve_id, str):
            ensure_cve_stub(pg, cve_id, dry_run)

        software_name = f.get("detailedName") or f.get("name") or "unknown"
        layer = f.get("layerMetadata") or {}
        tech  = f.get("technology") or {}

        batch.append((
            run_id, finding_id, asset_id, cve_id,
            software_name, f.get("detectionMethod"), f.get("locationPath"),
            f.get("codeLibraryLanguage"),
            tech.get("name") if isinstance(tech, dict) else None,
            f.get("fixedVersion"), f.get("recommendedVersion"),
            f.get("hasTriggerableRemediation"),
            f.get("status"), f.get("validatedInRuntime"),
            layer.get("id")          if isinstance(layer, dict) else None,
            layer.get("details")     if isinstance(layer, dict) else None,
            layer.get("isBaseLayer") if isinstance(layer, dict) else None,
            parse_ts(f.get("firstDetectedAt")),
            parse_ts(f.get("lastDetectedAt")),
            parse_ts(f.get("resolvedAt")),
        ))

        if len(batch) >= batch_size:
            inserted += flush(batch)
            batch = []

    if batch:
        inserted += flush(batch)

    LOG.info("findings: total=%d | insertados=%d | skip_no_id=%d | skip_no_asset=%d",
             total, inserted, skipped_no_id, skipped_no_asset)
    return total, inserted



# ---------------------------------------------------------------------------
# Config / argparse
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Wiz ETL -> PostgreSQL")
    p.add_argument("--pg-host",      default=None)
    p.add_argument("--pg-port",      type=int, default=None)
    p.add_argument("--pg-sslmode",   default="disable")
    p.add_argument("--page-size",    type=int, default=None)
    p.add_argument("--batch-size",   type=int, default=500)
    p.add_argument("--max-findings", type=int, default=None)
    p.add_argument("--graph-types",  default=None)
    p.add_argument("--dry-run",      action="store_true")
    p.add_argument("--log-level",    default="INFO",
                   choices=["DEBUG","INFO","WARNING","ERROR"])
    return p.parse_args()


def load_config(args: argparse.Namespace) -> Dict[str, Any]:
    def req(name: str, env: str) -> str:
        v = read_secret(name, env_fallback=env)
        if not v:
            die(f"Secret '{name}' / env '{env}' no encontrado.")
        return v

    return {
        "wiz_client_id":      req("wiz_client_id",      "WIZ_CLIENT_ID"),
        "wiz_client_secret":  req("wiz_client_secret",  "WIZ_CLIENT_SECRET"),
        "wiz_api_endpoint":   req("wiz_api_endpoint_url","WIZ_API_ENDPOINT_URL"),
        "pg_db":              req("postgres_db",         "PGDATABASE"),
        "pg_user":            req("postgres_user",       "PGUSER"),
        "pg_password":        req("postgres_password",   "PGPASSWORD"),
        "wiz_auth_url":       os.getenv("WIZ_AUTH_URL","https://auth.app.wiz.io/oauth/token").strip(),
        "wiz_auth_audience":  os.getenv("WIZ_AUTH_AUDIENCE","wiz-api").strip(),
        "page_size":          args.page_size or int(os.getenv("WIZ_PAGE_SIZE","200") or "200"),
        "timeout":            int(os.getenv("WIZ_TIMEOUT","60") or "60"),
        "max_retries":        int(os.getenv("WIZ_MAX_RETRIES","8") or "8"),
        "max_findings":       (args.max_findings if args.max_findings is not None
                               else int(os.getenv("WIZ_MAX_FINDINGS","0") or "0")),
        "filter_daily":       os.getenv("WIZ_FILTER_DAILY","0") == "1",
        "filter_severity":    [x.strip() for x in os.getenv("WIZ_FILTER_SEVERITY","").split(",") if x.strip()],
        "filter_status":      [x.strip() for x in os.getenv("WIZ_FILTER_STATUS","").split(",") if x.strip()],
        "filter_project_ids": [x.strip() for x in os.getenv("WIZ_FILTER_PROJECT_IDS","").split(",") if x.strip()],
        "filter_has_fix":     os.getenv("WIZ_FILTER_HAS_FIX","").strip(),
        "filter_has_exploit": os.getenv("WIZ_FILTER_HAS_EXPLOIT","").strip(),
        "graph_project_id":   os.getenv("WIZ_GRAPH_PROJECT_ID","*").strip() or "*",
        "graph_first":        int(os.getenv("WIZ_GRAPH_FIRST","500") or "500"),
        "graph_types":        [t.strip() for t in
                               (args.graph_types or os.getenv("WIZ_GRAPH_TYPES","VIRTUAL_MACHINE")
                               ).split(",") if t.strip()],
        "pg_host":    args.pg_host  or os.getenv("POSTGRES_HOST","appdb"),
        "pg_port":    args.pg_port  or int(os.getenv("POSTGRES_PORT","5432")),
        "pg_sslmode": args.pg_sslmode,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> int:
    args = parse_args()
    setup_logging(args.log_level)
    cfg  = load_config(args)

    LOG.info("=== Wiz ETL iniciando ===")
    LOG.info("API endpoint : %s", cfg["wiz_api_endpoint"])
    LOG.info("DB           : %s@%s:%s/%s (ssl=%s)",
             cfg["pg_user"], cfg["pg_host"], cfg["pg_port"],
             cfg["pg_db"], cfg["pg_sslmode"])
    LOG.info("dry_run      : %s | batch_size: %d", args.dry_run, args.batch_size)

    pg = Pg(host=cfg["pg_host"], port=cfg["pg_port"],
            dbname=cfg["pg_db"], user=cfg["pg_user"],
            password=cfg["pg_password"], sslmode=cfg["pg_sslmode"])
    if not args.dry_run:
        pg.init()

    client  = WizHTTP(cfg)
    filters = build_filter_by(cfg)

    run_id: Optional[int] = None
    if not args.dry_run:
        try:
            run_id = run_start(pg, filters, cfg["wiz_api_endpoint"], cfg["page_size"])
            LOG.info("Run iniciado: run_id=%d", run_id)
        except Exception as e:
            LOG.warning("No pude registrar etl_run: %s", e)

    rows_assets = rows_cves = rows_findings = rows_graph = 0
    pages_findings = pages_graph = 0
    reported_total: Optional[int] = None
    error_msg: Optional[str] = None
    error_detail: Optional[str] = None
    status = "error"

    try:
        # PASO 1: Findings
        LOG.info("--- PASO 1: vulnerabilityFindings ---")
        findings, reported_total, pages_findings = fetch_findings(client, cfg)
        LOG.info("Findings recibidos: %d (API reporto: %s)", len(findings), reported_total)

        # PASO 2: graphSearch eliminado (tabla wiz_graph_entities no existe)

        # PASO 3: Mapa de assets unicos — solo VMs y servidores
        # Se excluyen CONTAINER_IMAGE, CONTAINER, SERVERLESS, PAAS, etc.
        ALLOWED_ASSET_TYPES = {"VIRTUAL_MACHINE", "ENDPOINT", "VIRTUAL_MACHINE_IMAGE"}
        assets_map: Dict[str, Dict] = {}
        skipped_types: Dict[str, int] = {}
        for f in findings:
            va = f.get("vulnerableAsset")
            if not isinstance(va, dict):
                continue
            aid   = va.get("id")
            atype = (va.get("type") or "").upper()
            if not isinstance(aid, str) or not aid:
                continue
            if atype not in ALLOWED_ASSET_TYPES:
                skipped_types[atype] = skipped_types.get(atype, 0) + 1
                continue
            assets_map.setdefault(aid, va)
        LOG.info("Assets unicos (VM/ENDPOINT/VM_IMAGE): %d", len(assets_map))
        if skipped_types:
            LOG.info("Assets excluidos por tipo: %s", skipped_types)

        # PASO 4: Upsert assets (1 fila por VM, sin duplicados)
        LOG.info("--- PASO 3: upsert wiz_assets ---")
        rows_assets = upsert_assets(pg, assets_map, args.dry_run)

        # PASO 5: Upsert CVEs dimension
        LOG.info("--- PASO 4: upsert wiz_cves ---")
        rows_cves = upsert_cves(pg, findings, args.dry_run)

        # Stubs bulk para CVEs referenciados en findings
        all_cve_ids = [
            f.get("name") for f in findings
            if isinstance(f.get("name"), str) and f["name"].upper().startswith("CVE-")
        ]
        ensure_cve_stubs_bulk(pg, all_cve_ids, args.dry_run)

        # PASO 6: Findings en batches (sin duplicados por ON CONFLICT)
        LOG.info("--- PASO 5: insert wiz_software_vulnerable (batch=%d) ---", args.batch_size)
        valid_ids: Set[str] = set(assets_map.keys())
        _, rows_findings = insert_findings_batched(
            pg, run_id or 0, findings, valid_ids, args.dry_run, args.batch_size)

        if not args.dry_run and run_id:
            cnt = pg.fetchval(
                "SELECT count(*) FROM public.wiz_software_vulnerable WHERE run_id=%s",
                (run_id,))
            LOG.info("wiz_software_vulnerable BD run_id=%d -> %s filas", run_id, cnt)



        status = "success"

    except SystemExit:
        raise
    except Exception as e:
        error_msg    = str(e)
        error_detail = traceback.format_exc()
        status       = "error"
        LOG.error("ETL FALLO: %s", e, exc_info=True)

    finally:
        if run_id is not None:
            try:
                run_finish(pg, run_id, status,
                           rows_assets, rows_cves, rows_findings, rows_graph,
                           pages_findings, pages_graph, reported_total,
                           error_msg, error_detail)
                LOG.info("Run cerrado: run_id=%d status=%s", run_id, status)
            except Exception as fe:
                LOG.warning("No pude actualizar wiz_etl_runs: %s", fe)
        if not args.dry_run:
            pg.close()

    if status == "error":
        LOG.error("=== Wiz ETL FALLO === run_id=%s", run_id)
        return 1

    LOG.info("=== Wiz ETL OK | run_id=%s | assets=%d cves=%d findings=%d graph=%d ===",
             run_id, rows_assets, rows_cves, rows_findings, rows_graph)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
