from __future__ import annotations

import html
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

LOG = logging.getLogger("s1_etl")

SECRETS_DIR = os.getenv("SECRETS_DIR", "/run/secrets")

QUERY_XSPM_VULNS = """
query GetVulnerabilities($first: Int, $after: String) {
  vulnerabilities(first: $first, after: $after) {
    pageInfo {
      hasNextPage
      endCursor
    }
    edges {
      node {
        id
        name
        detectedAt
        severity
        status
        software {
          name
          version
          type
          vendor
          fixVersion
        }
        cve {
          id
          publishedDate
          score
          nvdBaseScore
          riskScore
          epssScore
          exploitedInTheWild
          exploitMaturity
          remediationLevel
          reportConfidence
        }
        asset {
          id
          name
          type
          category
          subcategory
          osType
          privileged
          cloudInfo {
            region
            accountName
            accountId
            resourceId
            providerName
          }
        }
        scope {
          account { id name }
          site    { id name }
          group   { id name }
        }
      }
    }
  }
}
""".strip()


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


def parse_date(v: Any) -> Optional[str]:
    if not isinstance(v, str):
        return None
    s = v.strip()
    return s if s else None


def clean_text(v: Any) -> Optional[str]:
    if not isinstance(v, str):
        return None
    return html.unescape(v.strip()) or None


def to_json_str(v: Any) -> Optional[str]:
    if v is None:
        return None
    try:
        return json.dumps(v, ensure_ascii=False, default=str)
    except Exception:
        return json.dumps(str(v))


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


class S1HTTP:
    def __init__(self, base_url: str, api_token: str, cfg: Dict[str, Any]) -> None:
        self.base_url  = base_url.rstrip("/")
        self.api_token = api_token
        self.cfg       = cfg
        self.sess      = requests.Session()
        adapter = HTTPAdapter(
            max_retries=Retry(
                total=cfg["max_retries"],
                backoff_factor=1.5,
                status_forcelist=(429, 500, 502, 503, 504),
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
            "Authorization": f"ApiToken {self.api_token}",
            "Content-Type":  "application/json",
        }

    def get(self, path: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        url = f"{self.base_url}{path}"
        for attempt in range(1, self.cfg["max_retries"] + 1):
            try:
                r = self.sess.get(url, headers=self._headers,
                                  params=params or {}, timeout=self.cfg["timeout"])
            except Exception as e:
                LOG.warning("GET %s attempt %d: %s", path, attempt, e)
                if attempt == self.cfg["max_retries"]:
                    return {"_exception": str(e)}
                backoff_sleep(attempt)
                continue
            if r.status_code == 200:
                return safe_json(r)
            if r.status_code in (401, 403):
                die(f"S1 GET {path}: HTTP {r.status_code} - invalid token or missing permissions")
            if r.status_code in (429, 500, 502, 503, 504):
                LOG.warning("GET %s HTTP %d, retry %d", path, r.status_code, attempt)
                backoff_sleep(attempt)
                continue
            LOG.error("GET %s HTTP %d: %s", path, r.status_code, r.text[:500])
            return {"_http_error": r.status_code, "_text": r.text[:500]}
        return {"_exception": "max retries"}

    def graphql(self, query: str, variables: Optional[Dict] = None) -> Dict[str, Any]:
        url     = f"{self.base_url}/web/api/v2.1/xspm/findings/vulnerabilities/graphql"
        payload = {"query": query, "variables": variables or {}}
        for attempt in range(1, self.cfg["max_retries"] + 1):
            try:
                r = self.sess.post(url, headers=self._headers,
                                   json=payload, timeout=self.cfg["timeout"])
            except Exception as e:
                LOG.warning("GraphQL attempt %d: %s", attempt, e)
                if attempt == self.cfg["max_retries"]:
                    return {"_exception": str(e)}
                backoff_sleep(attempt)
                continue
            if r.status_code == 200:
                return safe_json(r)
            if r.status_code in (401, 403):
                die(f"S1 GraphQL HTTP {r.status_code} - invalid token or missing permissions")
            if r.status_code in (429, 500, 502, 503, 504):
                LOG.warning("GraphQL HTTP %d, retry %d", r.status_code, attempt)
                backoff_sleep(attempt)
                continue
            LOG.error("GraphQL HTTP %d: %s", r.status_code, r.text[:500])
            return {"_http_error": r.status_code, "_text": r.text[:500]}
        return {"_exception": "max retries"}


def run_start(pg: Pg, base_url: str) -> int:
    row = pg.fetchone(
        "INSERT INTO public.sentinelone_etl_runs (status, api_base_url) "
        "VALUES ('running', %s) RETURNING run_id",
        (base_url,),
    )
    assert row
    return int(row[0])


def run_finish(
    pg: Pg, run_id: int, status: str,
    rows_agents: int, rows_apps: int, rows_vulns: int, rows_cves: int,
    error_message: Optional[str] = None,
    error_detail: Optional[str] = None,
) -> None:
    pg.exec(
        "UPDATE public.sentinelone_etl_runs SET "
        "finished_at=now(), status=%s, "
        "rows_agents=%s, rows_apps=%s, rows_vulns=%s, rows_cves=%s, "
        "error_message=%s, error_detail=%s "
        "WHERE run_id=%s",
        (status, rows_agents, rows_apps, rows_vulns, rows_cves,
         error_message, error_detail, run_id),
    )


def fetch_agents(client: S1HTTP, cfg: Dict[str, Any]) -> List[Dict]:
    path      = "/web/api/v2.1/agents"
    all_items: List[Dict] = []
    cursor: Optional[str] = None
    page = 0
    while True:
        page += 1
        params: Dict[str, Any] = {
            "limit": cfg["page_limit"], "sortBy": "id", "sortOrder": "asc",
        }
        if cursor:
            params["cursor"] = cursor
        resp = client.get(path, params)
        if resp.get("_exception") or resp.get("_http_error"):
            die(f"fetch_agents error: {resp}")
        data_block = resp.get("data") or {}
        items      = data_block if isinstance(data_block, list) else []
        pagination = resp.get("pagination") or {}
        if not items and isinstance(data_block, dict):
            items      = data_block.get("data") or []
            pagination = data_block.get("pagination") or pagination
        all_items.extend(items)
        LOG.info("agents: page %d -> +%d (total %d)", page, len(items), len(all_items))
        next_cursor = pagination.get("nextCursor")
        if not next_cursor or not items:
            break
        cursor = next_cursor
    LOG.info("agents: %d total fetched", len(all_items))
    return all_items


def fetch_installed_apps(client: S1HTTP, cfg: Dict[str, Any]) -> List[Dict]:
    if cfg.get("skip_apps"):
        LOG.info("skip_apps=True - skipping installed_applications")
        return []
    path      = "/web/api/v2.1/installed-applications"
    all_items: List[Dict] = []
    cursor: Optional[str] = None
    page = 0
    while True:
        page += 1
        params: Dict[str, Any] = {
            "limit": cfg["page_limit"], "sortBy": "id", "sortOrder": "asc",
        }
        if cursor:
            params["cursor"] = cursor
        resp = client.get(path, params)
        if resp.get("_exception") or resp.get("_http_error"):
            LOG.warning("fetch_installed_apps error page %d: %s", page, resp)
            break
        data_block = resp.get("data") or {}
        items      = data_block if isinstance(data_block, list) else []
        pagination = resp.get("pagination") or {}
        if not items and isinstance(data_block, dict):
            items      = data_block.get("data") or []
            pagination = data_block.get("pagination") or pagination
        all_items.extend(items)
        LOG.info("installed_apps: page %d -> +%d (total %d)", page, len(items), len(all_items))
        next_cursor = pagination.get("nextCursor")
        if not next_cursor or not items:
            break
        cursor = next_cursor
    LOG.info("installed_apps: %d total fetched", len(all_items))
    return all_items


def fetch_xspm_vulns(client: S1HTTP, cfg: Dict[str, Any]) -> Tuple[List[Dict], int]:
    all_nodes: List[Dict] = []
    after: Optional[str] = None
    page = 0
    while True:
        page += 1
        variables: Dict[str, Any] = {"first": cfg["vuln_page_size"]}
        if after:
            variables["after"] = after
        resp = client.graphql(QUERY_XSPM_VULNS, variables)
        if resp.get("_exception"):
            die(f"xSPM GraphQL exception: {resp['_exception']}")
        if resp.get("errors"):
            err = resp["errors"][0] if resp["errors"] else {}
            die(f"xSPM GraphQL error: {err.get('message', str(err))}")
        gql_data   = resp.get("data") or resp
        vuln_block = gql_data.get("vulnerabilities") or {}
        edges = vuln_block.get("edges") or []
        nodes = [e["node"] for e in edges if isinstance(e, dict) and "node" in e]
        if not nodes:
            nodes = vuln_block.get("nodes") or []
        all_nodes.extend(n for n in nodes if isinstance(n, dict))
        page_info = vuln_block.get("pageInfo") or {}
        LOG.info("xSPM vulns: page %d -> +%d (total %d)", page, len(nodes), len(all_nodes))
        if cfg["max_vulns"] and len(all_nodes) >= cfg["max_vulns"]:
            all_nodes = all_nodes[:cfg["max_vulns"]]
            LOG.warning("Cut by S1_MAX_VULNS=%d", cfg["max_vulns"])
            break
        if not page_info.get("hasNextPage") or not page_info.get("endCursor"):
            break
        after = page_info["endCursor"]
    LOG.info("xSPM vulns: %d total fetched in %d pages", len(all_nodes), page)
    return all_nodes, page


def extract_cloud_from_agent(agent: Dict) -> Dict[str, Optional[str]]:
    cloud_providers = agent.get("cloudProviders") or {}
    if not cloud_providers:
        return {}
    provider_name, info = next(iter(cloud_providers.items()))
    if not isinstance(info, dict):
        return {"cloud_provider": provider_name}
    return {
        "cloud_provider":      provider_name,
        "cloud_account":       info.get("cloudAccount"),
        "cloud_instance_id":   info.get("cloudInstanceId"),
        "cloud_instance_size": info.get("cloudInstanceSize"),
        "cloud_location":      info.get("cloudLocation"),
        "cloud_image":         info.get("cloudImage"),
    }


def upsert_agents(pg: Pg, agents: List[Dict], dry_run: bool) -> int:
    if not agents:
        return 0
    rows = []
    for a in agents:
        cloud = extract_cloud_from_agent(a)
        rows.append((
            a.get("id"),
            a.get("uuid"),
            a.get("computerName") or "",
            a.get("accountId"),
            a.get("accountName"),
            a.get("siteId"),
            a.get("siteName"),
            a.get("groupId"),
            a.get("groupName"),
            a.get("osName"),
            a.get("osType"),
            a.get("osRevision"),
            a.get("osArch"),
            a.get("machineType"),
            a.get("modelName"),
            a.get("coreCount"),
            a.get("cpuCount"),
            a.get("totalMemory"),
            a.get("lastIpToMgmt"),
            a.get("externalIp"),
            a.get("domain"),
            a.get("agentVersion"),
            a.get("installerType"),
            a.get("mitigationMode"),
            a.get("networkStatus"),
            a.get("isActive"),
            a.get("isDecommissioned"),
            a.get("isUpToDate"),
            a.get("appsVulnerabilityStatus"),
            a.get("activeThreats"),
            a.get("infected"),
            cloud.get("cloud_provider"),
            cloud.get("cloud_account"),
            cloud.get("cloud_instance_id"),
            cloud.get("cloud_instance_size"),
            cloud.get("cloud_location"),
            cloud.get("cloud_image"),
            parse_ts(a.get("registeredAt")),
            parse_ts(a.get("lastActiveDate")),
            parse_ts(a.get("lastSuccessfulScanDate")),
            parse_ts(a.get("createdAt")),
            parse_ts(a.get("updatedAt")),
            to_json_str(a),
        ))
    if dry_run:
        LOG.info("[DRY-RUN] upsert_agents: %d rows", len(rows))
        return len(rows)
    sql = """
    INSERT INTO public.sentinelone_agent (
      agent_id, uuid, computer_name,
      account_id, account_name, site_id, site_name, group_id, group_name,
      os_name, os_type, os_revision, os_arch,
      machine_type, model_name, core_count, cpu_count, total_memory_mb,
      last_ip_to_mgmt, external_ip, domain,
      agent_version, installer_type, mitigation_mode, network_status,
      is_active, is_decommissioned, is_up_to_date,
      apps_vulnerability_status, active_threats, infected,
      cloud_provider, cloud_account, cloud_instance_id,
      cloud_instance_size, cloud_location, cloud_image,
      registered_at, last_active_date, last_successful_scan_date,
      created_at, updated_at, raw
    ) VALUES %s
    ON CONFLICT (agent_id) DO UPDATE SET
      uuid                      = EXCLUDED.uuid,
      computer_name             = EXCLUDED.computer_name,
      account_id                = EXCLUDED.account_id,
      account_name              = EXCLUDED.account_name,
      site_id                   = EXCLUDED.site_id,
      site_name                 = EXCLUDED.site_name,
      group_id                  = EXCLUDED.group_id,
      group_name                = EXCLUDED.group_name,
      os_name                   = EXCLUDED.os_name,
      os_type                   = EXCLUDED.os_type,
      os_revision               = EXCLUDED.os_revision,
      os_arch                   = EXCLUDED.os_arch,
      machine_type              = EXCLUDED.machine_type,
      model_name                = EXCLUDED.model_name,
      core_count                = EXCLUDED.core_count,
      cpu_count                 = EXCLUDED.cpu_count,
      total_memory_mb           = EXCLUDED.total_memory_mb,
      last_ip_to_mgmt           = EXCLUDED.last_ip_to_mgmt,
      external_ip               = EXCLUDED.external_ip,
      domain                    = EXCLUDED.domain,
      agent_version             = EXCLUDED.agent_version,
      installer_type            = EXCLUDED.installer_type,
      mitigation_mode           = EXCLUDED.mitigation_mode,
      network_status            = EXCLUDED.network_status,
      is_active                 = EXCLUDED.is_active,
      is_decommissioned         = EXCLUDED.is_decommissioned,
      is_up_to_date             = EXCLUDED.is_up_to_date,
      apps_vulnerability_status = EXCLUDED.apps_vulnerability_status,
      active_threats            = EXCLUDED.active_threats,
      infected                  = EXCLUDED.infected,
      cloud_provider            = EXCLUDED.cloud_provider,
      cloud_account             = EXCLUDED.cloud_account,
      cloud_instance_id         = EXCLUDED.cloud_instance_id,
      cloud_instance_size       = EXCLUDED.cloud_instance_size,
      cloud_location            = EXCLUDED.cloud_location,
      cloud_image               = EXCLUDED.cloud_image,
      registered_at             = EXCLUDED.registered_at,
      last_active_date          = EXCLUDED.last_active_date,
      last_successful_scan_date = EXCLUDED.last_successful_scan_date,
      created_at                = EXCLUDED.created_at,
      updated_at                = EXCLUDED.updated_at,
      raw                       = EXCLUDED.raw,
      ingested_at               = now()
    """
    tmpl = (
        "(%s,%s,%s, %s,%s,%s,%s,%s,%s,"
        " %s,%s,%s,%s, %s,%s,%s,%s,%s,"
        " %s,%s,%s, %s,%s,%s,%s, %s,%s,%s,"
        " %s,%s,%s, %s,%s,%s,%s,%s,%s,"
        " %s::timestamptz,%s::timestamptz,%s::timestamptz,%s::timestamptz,%s::timestamptz,"
        " %s::jsonb)"
    )
    with pg.conn() as c:
        with c.cursor() as cur:
            execute_values(cur, sql, rows, template=tmpl, page_size=200)
    LOG.info("upsert_agents: %d agents processed", len(rows))
    return len(rows)


def upsert_installed_apps(
    pg: Pg, apps: List[Dict], known_agent_ids: Set[str], dry_run: bool,
) -> int:
    if not apps:
        return 0
    by_agent: Dict[str, List[Dict]] = {}
    skipped = 0
    for app in apps:
        aid = app.get("agentId")
        if not isinstance(aid, str) or not aid or aid not in known_agent_ids:
            skipped += 1
            continue
        by_agent.setdefault(aid, []).append(app)
    if skipped:
        LOG.info("installed_apps: %d apps with unknown agent (skipped)", skipped)
    if dry_run:
        total = sum(len(v) for v in by_agent.values())
        LOG.info("[DRY-RUN] upsert_installed_apps: %d agents, %d apps", len(by_agent), total)
        return total
    insert_sql = """
    INSERT INTO public.sentinelone_installed_app (
      app_id, agent_id, agent_uuid,
      name, version, publisher, os_type, app_type,
      risk_level, signed, size_bytes,
      installed_at, created_at, updated_at
    ) VALUES %s
    ON CONFLICT (app_id) DO UPDATE SET
      agent_id     = EXCLUDED.agent_id,
      agent_uuid   = EXCLUDED.agent_uuid,
      name         = EXCLUDED.name,
      version      = EXCLUDED.version,
      publisher    = EXCLUDED.publisher,
      os_type      = EXCLUDED.os_type,
      app_type     = EXCLUDED.app_type,
      risk_level   = EXCLUDED.risk_level,
      signed       = EXCLUDED.signed,
      size_bytes   = EXCLUDED.size_bytes,
      installed_at = EXCLUDED.installed_at,
      created_at   = EXCLUDED.created_at,
      updated_at   = EXCLUDED.updated_at,
      ingested_at  = now()
    """
    tmpl = (
        "(%s,%s,%s, %s,%s,%s,%s,%s,"
        " %s,%s,%s,"
        " %s::timestamptz,%s::timestamptz,%s::timestamptz)"
    )
    total_inserted = 0
    with pg.conn() as c:
        with c.cursor() as cur:
            for agent_id, agent_apps in by_agent.items():
                cur.execute(
                    "DELETE FROM public.sentinelone_installed_app WHERE agent_id = %s",
                    (agent_id,),
                )
                rows = [
                    (
                        app.get("id"), agent_id, app.get("agentUuid"),
                        app.get("name"), app.get("version"),
                        clean_text(app.get("publisher")),
                        app.get("osType"), app.get("type"),
                        app.get("riskLevel"), app.get("signed"), app.get("size"),
                        parse_ts(app.get("installedAt")),
                        parse_ts(app.get("createdAt")),
                        parse_ts(app.get("updatedAt")),
                    )
                    for app in agent_apps
                ]
                if rows:
                    execute_values(cur, insert_sql, rows, template=tmpl, page_size=500)
                    total_inserted += len(rows)
    LOG.info("upsert_installed_apps: %d apps processed (%d agents)",
             total_inserted, len(by_agent))
    return total_inserted


def upsert_cves(pg: Pg, vulns: List[Dict], dry_run: bool) -> int:
    cves_map: Dict[str, Dict] = {}
    for v in vulns:
        cve    = v.get("cve") or {}
        cve_id = cve.get("id")
        if isinstance(cve_id, str) and cve_id.upper().startswith("CVE-"):
            cves_map.setdefault(cve_id, cve)
    if not cves_map:
        LOG.warning("upsert_cves: no valid CVE IDs found")
        return 0
    rows = [
        (
            cve_id,
            parse_date(cve.get("publishedDate")),
            cve.get("score"),
            cve.get("nvdBaseScore"),
            cve.get("riskScore"),
            cve.get("epssScore"),
            cve.get("exploitedInTheWild"),
            cve.get("exploitMaturity"),
            cve.get("remediationLevel"),
            cve.get("reportConfidence"),
        )
        for cve_id, cve in cves_map.items()
    ]
    if dry_run:
        LOG.info("[DRY-RUN] upsert_cves: %d CVEs", len(rows))
        return len(rows)
    sql = """
    INSERT INTO public.sentinelone_cve (
      cve_id, published_date,
      s1_score, nvd_base_score, risk_score, epss_score,
      exploited_in_the_wild, exploit_maturity, remediation_level, report_confidence,
      last_seen_at
    ) VALUES %s
    ON CONFLICT (cve_id) DO UPDATE SET
      published_date        = EXCLUDED.published_date,
      s1_score              = EXCLUDED.s1_score,
      nvd_base_score        = EXCLUDED.nvd_base_score,
      risk_score            = EXCLUDED.risk_score,
      epss_score            = EXCLUDED.epss_score,
      exploited_in_the_wild = EXCLUDED.exploited_in_the_wild,
      exploit_maturity      = EXCLUDED.exploit_maturity,
      remediation_level     = EXCLUDED.remediation_level,
      report_confidence     = EXCLUDED.report_confidence,
      last_seen_at          = now()
    """
    tmpl = (
        "(%s, %s::date,"
        " %s::numeric, %s::numeric, %s::numeric, %s::numeric,"
        " %s, %s, %s, %s, now())"
    )
    with pg.conn() as c:
        with c.cursor() as cur:
            execute_values(cur, sql, rows, template=tmpl, page_size=500)
    LOG.info("upsert_cves: %d unique CVEs processed", len(rows))
    return len(rows)


def ensure_cve_stub(pg: Pg, cve_id: str, dry_run: bool) -> None:
    if dry_run:
        return
    pg.exec(
        "INSERT INTO public.sentinelone_cve (cve_id, last_seen_at) "
        "VALUES (%s, now()) ON CONFLICT (cve_id) DO NOTHING",
        (cve_id,),
    )


def insert_vuln_findings(
    pg: Pg,
    run_id: int,
    vulns: List[Dict],
    known_agents_by_name: Dict[str, str],
    dry_run: bool,
    batch_size: int = 500,
) -> Tuple[int, int]:
    sql = """
    INSERT INTO public.sentinelone_vuln_finding (
      finding_id, run_id,
      cve_id, agent_id,
      xspm_asset_id, asset_name, asset_type, asset_category,
      asset_subcategory, asset_os_type, asset_privileged,
      cloud_provider, cloud_region, cloud_account_id,
      name, severity, status, detected_at,
      software_name, software_version, software_type,
      software_vendor, software_fix_version,
      account_id, account_name, site_id, site_name
    ) VALUES %s
    ON CONFLICT (finding_id) DO UPDATE SET
      run_id               = EXCLUDED.run_id,
      cve_id               = EXCLUDED.cve_id,
      agent_id             = EXCLUDED.agent_id,
      xspm_asset_id        = EXCLUDED.xspm_asset_id,
      asset_name           = EXCLUDED.asset_name,
      asset_type           = EXCLUDED.asset_type,
      asset_category       = EXCLUDED.asset_category,
      asset_subcategory    = EXCLUDED.asset_subcategory,
      asset_os_type        = EXCLUDED.asset_os_type,
      asset_privileged     = EXCLUDED.asset_privileged,
      cloud_provider       = EXCLUDED.cloud_provider,
      cloud_region         = EXCLUDED.cloud_region,
      cloud_account_id     = EXCLUDED.cloud_account_id,
      name                 = EXCLUDED.name,
      severity             = EXCLUDED.severity,
      status               = EXCLUDED.status,
      detected_at          = EXCLUDED.detected_at,
      software_name        = EXCLUDED.software_name,
      software_version     = EXCLUDED.software_version,
      software_type        = EXCLUDED.software_type,
      software_vendor      = EXCLUDED.software_vendor,
      software_fix_version = EXCLUDED.software_fix_version,
      account_id           = EXCLUDED.account_id,
      account_name         = EXCLUDED.account_name,
      site_id              = EXCLUDED.site_id,
      site_name            = EXCLUDED.site_name,
      ingested_at          = now()
    """
    tmpl = (
        "(%s,%s,"
        " %s,%s,"
        " %s,%s,%s,%s,"
        " %s,%s,%s,"
        " %s,%s,%s,"
        " %s,%s,%s,%s::timestamptz,"
        " %s,%s,%s,%s,%s,"
        " %s,%s,%s,%s)"
    )

    def flush(batch: List[tuple]) -> int:
        if not batch:
            return 0
        if dry_run:
            LOG.debug("[DRY-RUN] batch %d findings", len(batch))
            return len(batch)
        try:
            with pg.conn() as c:
                with c.cursor() as cur:
                    execute_values(cur, sql, batch, template=tmpl, page_size=200)
            return len(batch)
        except Exception as e:
            LOG.error("Batch vuln_findings failed: %s", e, exc_info=True)
            raise

    total = skipped_no_id = skipped_no_cve = inserted = 0
    batch: List[tuple] = []

    for v in vulns:
        total += 1
        finding_id = v.get("id")
        if not isinstance(finding_id, str) or not finding_id:
            skipped_no_id += 1
            continue

        cve_block = v.get("cve") or {}
        cve_id    = cve_block.get("id")
        if not isinstance(cve_id, str) or not cve_id.upper().startswith("CVE-"):
            skipped_no_cve += 1
            cve_id = None
        else:
            ensure_cve_stub(pg, cve_id, dry_run)

        asset      = v.get("asset") or {}
        cloud_info = asset.get("cloudInfo") or {}
        sw         = v.get("software") or {}
        scope      = v.get("scope") or {}
        account    = scope.get("account") or {}
        site       = scope.get("site") or {}
        asset_name = asset.get("name") or ""
        agent_id   = known_agents_by_name.get(asset_name.lower().strip())

        batch.append((
            finding_id, run_id,
            cve_id, agent_id,
            asset.get("id"), asset_name, asset.get("type"), asset.get("category"),
            asset.get("subcategory"), asset.get("osType"), asset.get("privileged"),
            cloud_info.get("providerName"), cloud_info.get("region"), cloud_info.get("accountId"),
            v.get("name"), v.get("severity"), v.get("status"),
            parse_ts(v.get("detectedAt")),
            sw.get("name"), sw.get("version"), sw.get("type"),
            clean_text(sw.get("vendor")), sw.get("fixVersion"),
            account.get("id"), account.get("name"),
            site.get("id"), site.get("name"),
        ))

        if len(batch) >= batch_size:
            inserted += flush(batch)
            batch = []

    if batch:
        inserted += flush(batch)

    LOG.info("vuln_findings: total=%d | inserted=%d | skip_no_id=%d | skip_no_cve=%d",
             total, inserted, skipped_no_id, skipped_no_cve)
    return total, inserted


def load_config() -> Dict[str, Any]:
    def req(secret: str, env: str) -> str:
        v = read_secret(secret, env_fallback=env)
        if not v:
            die(f"Secret '{secret}' / env '{env}' not found - required")
        return v

    return {
        "s1_api_url":     req("sentinelone_api_url",  "S1_API_URL").rstrip("/"),
        "s1_api_token":   req("sentinelone_api_token", "S1_API_TOKEN"),
        "pg_db":          req("postgres_db",           "PGDATABASE"),
        "pg_user":        req("postgres_user",         "PGUSER"),
        "pg_password":    req("postgres_password",     "PGPASSWORD"),
        "pg_host":        os.getenv("POSTGRES_HOST",      "appdb"),
        "pg_port":        int(os.getenv("POSTGRES_PORT",  "5432")),
        "pg_sslmode":     os.getenv("PG_SSLMODE",         "disable"),
        "page_limit":     int(os.getenv("S1_PAGE_LIMIT",    "1000")),
        "vuln_page_size": int(os.getenv("S1_VULN_PAGE_SIZE", "500")),
        "batch_size":     int(os.getenv("S1_BATCH_SIZE",     "500")),
        "timeout":        int(os.getenv("S1_TIMEOUT",        "60")),
        "max_retries":    int(os.getenv("S1_MAX_RETRIES",    "6")),
        "max_vulns":      int(os.getenv("S1_MAX_VULNS",      "0")),
        "skip_apps":      os.getenv("S1_SKIP_APPS", "0") == "1",
        "log_level":      os.getenv("S1_LOG_LEVEL", "INFO").upper(),
    }


def main() -> int:
    cfg = load_config()
    setup_logging(cfg["log_level"])

    LOG.info("=== SentinelOne ETL starting ===")
    LOG.info("API URL   : %s", cfg["s1_api_url"])
    LOG.info("DB        : %s@%s:%s/%s (ssl=%s)",
             cfg["pg_user"], cfg["pg_host"], cfg["pg_port"],
             cfg["pg_db"], cfg["pg_sslmode"])
    LOG.info("batch_size: %d | skip_apps: %s", cfg["batch_size"], cfg["skip_apps"])

    pg = Pg(
        host=cfg["pg_host"], port=cfg["pg_port"],
        dbname=cfg["pg_db"], user=cfg["pg_user"],
        password=cfg["pg_password"], sslmode=cfg["pg_sslmode"],
    )
    pg.init()

    client = S1HTTP(cfg["s1_api_url"], cfg["s1_api_token"], cfg)

    run_id: Optional[int] = None
    try:
        run_id = run_start(pg, cfg["s1_api_url"])
        LOG.info("ETL run started: run_id=%d", run_id)
    except Exception as e:
        LOG.warning("Could not register sentinelone_etl_runs: %s", e)

    rows_agents = rows_apps = rows_vulns = rows_cves = 0
    error_msg:    Optional[str] = None
    error_detail: Optional[str] = None
    status = "error"

    try:
        LOG.info("--- STEP 1: agents ---")
        agents = fetch_agents(client, cfg)
        LOG.info("Agents fetched: %d", len(agents))
        rows_agents = upsert_agents(pg, agents, False)

        known_agents_by_name: Dict[str, str] = {}
        known_agent_ids: Set[str] = set()
        for a in agents:
            aid  = a.get("id", "")
            name = (a.get("computerName") or "").lower().strip()
            if aid:
                known_agent_ids.add(aid)
            if aid and name:
                known_agents_by_name[name] = aid

        LOG.info("--- STEP 2: installed_applications ---")
        apps = fetch_installed_apps(client, cfg)
        LOG.info("Apps fetched: %d", len(apps))
        rows_apps = upsert_installed_apps(pg, apps, known_agent_ids, False)

        LOG.info("--- STEP 3: xSPM vulnerability findings ---")
        vulns, vuln_pages = fetch_xspm_vulns(client, cfg)
        LOG.info("xSPM findings fetched: %d (pages: %d)", len(vulns), vuln_pages)

        LOG.info("--- STEP 4: upsert sentinelone_cve ---")
        rows_cves = upsert_cves(pg, vulns, False)

        LOG.info("--- STEP 5: insert sentinelone_vuln_finding (batch=%d) ---", cfg["batch_size"])
        _, rows_vulns = insert_vuln_findings(
            pg, run_id or 0, vulns,
            known_agents_by_name, False, cfg["batch_size"],
        )

        if run_id:
            cnt_vf = pg.fetchval(
                "SELECT count(*) FROM public.sentinelone_vuln_finding WHERE run_id=%s",
                (run_id,),
            )
            cnt_ag = pg.fetchval("SELECT count(*) FROM public.sentinelone_agent")
            cnt_cv = pg.fetchval("SELECT count(*) FROM public.sentinelone_cve")
            LOG.info("DB totals -> agents=%s | cves=%s | vuln_findings(run)=%s",
                     cnt_ag, cnt_cv, cnt_vf)

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
                    rows_agents, rows_apps, rows_vulns, rows_cves,
                    error_msg, error_detail,
                )
                LOG.info("Run closed: run_id=%d status=%s", run_id, status)
            except Exception as fe:
                LOG.warning("Could not update sentinelone_etl_runs: %s", fe)
        pg.close()

    if status == "error":
        LOG.error("=== SentinelOne ETL FAILED === run_id=%s", run_id)
        return 1

    LOG.info("=== SentinelOne ETL OK | run_id=%s | agents=%d apps=%d cves=%d vulns=%d ===",
             run_id, rows_agents, rows_apps, rows_cves, rows_vulns)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
