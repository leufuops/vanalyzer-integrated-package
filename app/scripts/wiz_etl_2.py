#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import json
import logging
import os
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

LOG = logging.getLogger("wiz_cloud_etl")

DEFAULT_RESOURCE_TYPES = [
    "KUBERNETES_CLUSTER",
    "KUBERNETES_NODE",
    "POD",
    "CONTAINER",
    "CONTAINER_IMAGE",
    "SERVERLESS",
    "LOAD_BALANCER",
    "DATABASE",
    "SUBNET",
]

EXCLUDED_ASSET_TYPES = {"VIRTUAL_MACHINE", "ENDPOINT", "VIRTUAL_MACHINE_IMAGE"}


def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stderr,
    )


SECRETS_DIR = os.getenv("SECRETS_DIR", "/run/secrets")


def read_secret(name: str, env_fallback: str = "") -> str:
    try:
        with open(os.path.join(SECRETS_DIR, name), "r") as fh:
            v = fh.read().strip()
            if v:
                return v
    except FileNotFoundError:
        pass
    return (os.getenv(env_fallback) or "").strip()


def die(msg: str, code: int = 2) -> None:
    LOG.critical(msg)
    sys.exit(code)


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


def to_json(v: Any) -> Optional[str]:
    if v is None:
        return None
    try:
        return json.dumps(v, ensure_ascii=False, default=str)
    except Exception:
        return json.dumps(str(v))


class RateLimiter:
    def __init__(self, max_rps: float) -> None:
        self._interval = 0.0 if max_rps <= 0 else 1.0 / max_rps
        self._last = 0.0

    def wait(self) -> None:
        if self._interval <= 0:
            return
        now = time.time()
        delay = (self._last + self._interval) - now
        if delay > 0:
            time.sleep(delay)
        self._last = time.time()


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


def run_start(pg: Pg, endpoint: str, page_size: int) -> int:
    row = pg.fetchone(
        "INSERT INTO public.wiz_cloud_etl_runs (status, api_endpoint_url, page_size) "
        "VALUES ('running',%s,%s) RETURNING run_id",
        (endpoint, page_size),
    )
    assert row
    return int(row[0])


def run_finish(
    pg: Pg, run_id: int, status: str,
    rows_assets: int, rows_vuln: int, rows_cfg: int, rows_issues: int,
    pages_cloud: int, pages_vuln: int, pages_cfg: int, pages_issues: int,
    error_message: Optional[str] = None,
    error_detail: Optional[str] = None,
) -> None:
    pg.exec(
        "UPDATE public.wiz_cloud_etl_runs SET "
        "  finished_at=now(), status=%s, "
        "  rows_assets=%s, rows_vuln_findings=%s, "
        "  rows_cfg_findings=%s, rows_issues=%s, "
        "  pages_cloud_resources=%s, pages_vuln_findings=%s, "
        "  pages_cfg_findings=%s, pages_issues=%s, "
        "  error_message=%s, error_detail=%s "
        "WHERE run_id=%s",
        (status,
         rows_assets, rows_vuln, rows_cfg, rows_issues,
         pages_cloud, pages_vuln, pages_cfg, pages_issues,
         error_message, error_detail, run_id),
    )


QUERY_CLOUD_RESOURCES = r"""
query CloudResourcesPage(
  $filterBy: CloudResourceFilters,
  $first: Int,
  $after: String
) {
  cloudResources(filterBy: $filterBy, first: $first, after: $after) {
    nodes {
      id
      name
      type
      subscriptionExternalId
      subscriptionName
    }
    pageInfo { hasNextPage endCursor }
  }
}
""".strip()

QUERY_VULN_FINDINGS = r"""
query VulnerabilityFindingsPage(
  $filterBy: VulnerabilityFindingFilters,
  $first: Int,
  $after: String
) {
  vulnerabilityFindings(filterBy: $filterBy, first: $first, after: $after) {
    nodes {
      id portalUrl name detailedName
      CVEDescription CVSSSeverity vendorSeverity
      score exploitabilityScore impactScore
      hasExploit hasCisaKevExploit
      status firstDetectedAt lastDetectedAt
      fixedVersion detectionMethod locationPath
      vulnerableAsset {
        ... on VulnerableAssetBase {
          id type name providerUniqueId
        }
        ... on VulnerableAssetContainerImage {
          id type name providerUniqueId imageId
        }
        ... on VulnerableAssetContainer {
          id type name providerUniqueId
          ImageExternalId PodNamespace PodName NodeName
        }
      }
    }
    pageInfo { hasNextPage endCursor }
  }
}
""".strip()

QUERY_CFG_FINDINGS = r"""
query ConfigurationFindingsPage(
  $filterBy: ConfigurationFindingFilters,
  $first: Int,
  $after: String
) {
  configurationFindings(filterBy: $filterBy, first: $first, after: $after) {
    nodes {
      id firstSeenAt severity result status remediation
      resource { id name type providerId nativeType region }
      rule      { id graphId name }
    }
    pageInfo { hasNextPage endCursor }
  }
}
""".strip()

QUERY_ISSUES = r"""
query IssuesV2Page(
  $filterBy: IssueFilters,
  $first: Int,
  $after: String
) {
  issuesV2(filterBy: $filterBy, first: $first, after: $after) {
    nodes {
      id createdAt updatedAt status severity type
      sourceRule { id name }
      entitySnapshot {
        id type nativeType name status
        providerId region
        subscriptionExternalId subscriptionName externalId
      }
      serviceTickets { externalId name url }
    }
    pageInfo { hasNextPage endCursor }
  }
}
""".strip()


class WizHTTP:
    def __init__(self, cfg: Dict[str, Any]) -> None:
        self.cfg = cfg
        self._token: Optional[str] = None
        self._token_exp: float = 0.0
        self.rl = RateLimiter(cfg.get("max_rps", 2.5))
        self.sess = requests.Session()
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

    def _token_valid(self) -> bool:
        return self._token is not None and time.time() < (self._token_exp - 60)

    def get_token(self, force: bool = False) -> str:
        if not force and self._token_valid():
            return self._token  # type: ignore
        self.rl.wait()
        r = self.sess.post(
            self.cfg["wiz_auth_url"],
            data={
                "grant_type":    "client_credentials",
                "client_id":     self.cfg["wiz_client_id"],
                "client_secret": self.cfg["wiz_client_secret"],
                "audience":      self.cfg["wiz_auth_audience"],
            },
            timeout=60,
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

    def graphql(self, query: str, variables: Optional[Dict] = None,
                retry_internal: bool = True) -> Dict[str, Any]:
        payload = {"query": query, "variables": variables or {}}
        backoff = 1.0
        for attempt in range(1, self.cfg["max_retries"] + 1):
            try:
                self.rl.wait()
                r = self.sess.post(
                    self.cfg["wiz_api_endpoint"],
                    headers={
                        "Authorization": f"Bearer {self.get_token()}",
                        "Content-Type":  "application/json",
                        "Accept":        "application/json",
                    },
                    json=payload,
                    timeout=self.cfg["timeout"],
                )
            except Exception:
                if attempt == self.cfg["max_retries"]:
                    raise
                time.sleep(backoff)
                backoff = min(backoff * 2, 30)
                continue

            if r.status_code in (401, 403):
                self.get_token(force=True)
                time.sleep(backoff)
                backoff = min(backoff * 2, 30)
                continue

            if r.status_code in (429, 503):
                time.sleep(backoff)
                backoff = min(backoff * 2, 30)
                continue

            try:
                body = r.json()
            except Exception:
                time.sleep(backoff)
                backoff = min(backoff * 2, 30)
                continue

            errs = body.get("errors") or []
            if errs:
                codes = {e.get("extensions", {}).get("code") for e in errs if isinstance(e, dict)}
                if "INTERNAL" in codes:
                    if retry_internal and attempt < self.cfg["max_retries"]:
                        LOG.warning("GraphQL INTERNAL error (intento %d), reintentando...", attempt)
                        time.sleep(backoff)
                        backoff = min(backoff * 2, 30)
                        continue
                    else:
                        LOG.warning("GraphQL INTERNAL error — saltando (retry_internal=False)")
                        return {"_errors": errs, "data": body.get("data") or {}}
                return {"_errors": errs, "data": body.get("data") or {}}

            return body.get("data") or {}

        return {"_exception": "max retries alcanzados"}


def paginate(
    client: WizHTTP, query: str, root_field: str,
    base_vars: Dict[str, Any], page_size: int,
    retry_internal: bool = True,
) -> Tuple[List[Dict], int]:
    after: Optional[str] = None
    all_nodes: List[Dict] = []
    pages = 0

    while True:
        pages += 1
        data = client.graphql(
            query,
            {**base_vars, "first": page_size, "after": after},
            retry_internal=retry_internal,
        )

        if data.get("_exception"):
            die(f"GraphQL exception en {root_field}: {data['_exception']}")
        if data.get("_errors"):
            LOG.error("GraphQL errors en %s: %s", root_field, data["_errors"])
            break

        conn  = data.get(root_field) or {}
        nodes = conn.get("nodes")    or []
        all_nodes.extend(n for n in nodes if isinstance(n, dict))

        pi = conn.get("pageInfo") or {}
        LOG.info("%s: pag %d -> +%d (acum %d)", root_field, pages, len(nodes), len(all_nodes))

        if not pi.get("hasNextPage") or not pi.get("endCursor"):
            break
        after = pi["endCursor"]

    return all_nodes, pages


def flush(pg: Pg, sql: str, tmpl: str, batch: List[tuple],
          dry_run: bool, label: str) -> int:
    if not batch:
        return 0
    if dry_run:
        LOG.debug("[DRY-RUN] %s: %d filas (no escritas)", label, len(batch))
        return len(batch)
    try:
        with pg.conn() as c:
            with c.cursor() as cur:
                execute_values(cur, sql, batch, template=tmpl, page_size=200)
        return len(batch)
    except Exception as e:
        LOG.error("Batch %s falló: %s | muestra=%s", label, e, batch[0], exc_info=True)
        raise


def ensure_asset_stub(pg: Pg, asset_id: str, name: str,
                      atype: str, dry_run: bool, valid_ids: Set[str],
                      extra: Optional[Dict] = None) -> None:
    if asset_id in valid_ids and not extra:
        return
    if not dry_run:
        if extra:
            pg.exec(
                "INSERT INTO public.wiz_cloud_asset "
                "  (asset_id, asset_type, asset_name, "
                "   provider_unique_id, native_type, "
                "   image_external_id, pod_namespace, pod_name, node_name, image_id) "
                "VALUES (%s,%s,%s, %s,%s, %s,%s,%s,%s,%s) "
                "ON CONFLICT (asset_id) DO UPDATE SET "
                "  asset_name         = COALESCE(EXCLUDED.asset_name,         wiz_cloud_asset.asset_name), "
                "  provider_unique_id = COALESCE(EXCLUDED.provider_unique_id, wiz_cloud_asset.provider_unique_id), "
                "  native_type        = COALESCE(EXCLUDED.native_type,        wiz_cloud_asset.native_type), "
                "  image_external_id  = COALESCE(EXCLUDED.image_external_id,  wiz_cloud_asset.image_external_id), "
                "  pod_namespace      = COALESCE(EXCLUDED.pod_namespace,      wiz_cloud_asset.pod_namespace), "
                "  pod_name           = COALESCE(EXCLUDED.pod_name,           wiz_cloud_asset.pod_name), "
                "  node_name          = COALESCE(EXCLUDED.node_name,          wiz_cloud_asset.node_name), "
                "  image_id           = COALESCE(EXCLUDED.image_id,           wiz_cloud_asset.image_id), "
                "  ingested_at        = now()",
                (
                    asset_id, atype or "unknown", name or "unknown",
                    extra.get("providerUniqueId"),
                    extra.get("nativeType"),
                    extra.get("ImageExternalId") or extra.get("imageExternalId"),
                    extra.get("PodNamespace")    or extra.get("podNamespace"),
                    extra.get("PodName")         or extra.get("podName"),
                    extra.get("NodeName")        or extra.get("nodeName"),
                    extra.get("imageId"),
                ),
            )
        else:
            pg.exec(
                "INSERT INTO public.wiz_cloud_asset (asset_id, asset_type, asset_name) "
                "VALUES (%s,%s,%s) ON CONFLICT (asset_id) DO NOTHING",
                (asset_id, atype or "unknown", name or "unknown"),
            )
    valid_ids.add(asset_id)


def upsert_assets(
    pg: Pg, nodes: List[Dict], dry_run: bool, batch_size: int
) -> Tuple[int, Set[str]]:
    SQL = """
    INSERT INTO public.wiz_cloud_asset (
      asset_id, asset_type, asset_name,
      provider_id, provider_unique_id, external_id,
      native_type, region, status,
      subscription_external_id, subscription_name,
      image_external_id, pod_namespace, pod_name, node_name,
      image_id, raw
    ) VALUES %s
    ON CONFLICT (asset_id) DO UPDATE SET
      asset_type               = EXCLUDED.asset_type,
      asset_name               = EXCLUDED.asset_name,
      subscription_external_id = EXCLUDED.subscription_external_id,
      subscription_name        = EXCLUDED.subscription_name,
      raw                      = EXCLUDED.raw,
      provider_id        = COALESCE(wiz_cloud_asset.provider_id,        EXCLUDED.provider_id),
      provider_unique_id = COALESCE(wiz_cloud_asset.provider_unique_id, EXCLUDED.provider_unique_id),
      external_id        = COALESCE(wiz_cloud_asset.external_id,        EXCLUDED.external_id),
      native_type        = COALESCE(wiz_cloud_asset.native_type,        EXCLUDED.native_type),
      region             = COALESCE(wiz_cloud_asset.region,             EXCLUDED.region),
      status             = COALESCE(wiz_cloud_asset.status,             EXCLUDED.status),
      image_external_id  = COALESCE(wiz_cloud_asset.image_external_id,  EXCLUDED.image_external_id),
      pod_namespace      = COALESCE(wiz_cloud_asset.pod_namespace,      EXCLUDED.pod_namespace),
      pod_name           = COALESCE(wiz_cloud_asset.pod_name,           EXCLUDED.pod_name),
      node_name          = COALESCE(wiz_cloud_asset.node_name,          EXCLUDED.node_name),
      image_id           = COALESCE(wiz_cloud_asset.image_id,           EXCLUDED.image_id),
      ingested_at        = now()
    """
    TMPL = """(
      %s,%s,%s,
      %s,%s,%s,
      %s,%s,%s,
      %s,%s,
      %s,%s,%s,%s,
      %s,%s::jsonb
    )"""

    inserted  = 0
    skipped   = 0
    valid_ids: Set[str] = set()
    batch: List[tuple] = []

    for n in nodes:
        aid   = n.get("id")
        atype = (n.get("type") or "").upper()
        if not isinstance(aid, str) or not aid:
            skipped += 1
            continue
        if atype in EXCLUDED_ASSET_TYPES:
            skipped += 1
            continue

        valid_ids.add(aid)
        batch.append((
            aid,
            n.get("type") or "",
            n.get("name"),
            None, None, None,
            None, None, None,
            n.get("subscriptionExternalId"),
            n.get("subscriptionName"),
            None, None, None, None,
            None,
            to_json(n),
        ))

        if len(batch) >= batch_size:
            inserted += flush(pg, SQL, TMPL, batch, dry_run, "wiz_cloud_asset")
            batch = []

    if batch:
        inserted += flush(pg, SQL, TMPL, batch, dry_run, "wiz_cloud_asset")

    LOG.info("upsert_assets: %d insertados, %d excluidos (VM/endpoint)", inserted, skipped)
    return inserted, valid_ids


def upsert_vuln_findings(
    pg: Pg, run_id: int, nodes: List[Dict],
    valid_ids: Set[str], dry_run: bool, batch_size: int,
) -> int:
    SQL = """
    INSERT INTO public.wiz_cloud_vuln_finding (
      finding_id, run_id, asset_id, cve_id,
      detailed_name, cve_description,
      cvss_severity, vendor_severity,
      score, exploitability_score, impact_score,
      has_exploit, has_cisa_kev,
      status, first_detected_at, last_detected_at,
      fixed_version, detection_method, location_path,
      portal_url, raw
    ) VALUES %s
    ON CONFLICT (finding_id) DO UPDATE SET
      run_id               = EXCLUDED.run_id,
      asset_id             = EXCLUDED.asset_id,
      cve_id               = EXCLUDED.cve_id,
      detailed_name        = EXCLUDED.detailed_name,
      cve_description      = EXCLUDED.cve_description,
      cvss_severity        = EXCLUDED.cvss_severity,
      vendor_severity      = EXCLUDED.vendor_severity,
      score                = EXCLUDED.score,
      exploitability_score = EXCLUDED.exploitability_score,
      impact_score         = EXCLUDED.impact_score,
      has_exploit          = EXCLUDED.has_exploit,
      has_cisa_kev         = EXCLUDED.has_cisa_kev,
      status               = EXCLUDED.status,
      first_detected_at    = EXCLUDED.first_detected_at,
      last_detected_at     = EXCLUDED.last_detected_at,
      fixed_version        = EXCLUDED.fixed_version,
      detection_method     = EXCLUDED.detection_method,
      location_path        = EXCLUDED.location_path,
      portal_url           = EXCLUDED.portal_url,
      raw                  = EXCLUDED.raw,
      ingested_at          = now()
    """
    TMPL = """(
      %s,%s,%s,%s,
      %s,%s,
      %s,%s,
      %s::numeric,%s::numeric,%s::numeric,
      %s,%s,
      %s,%s::timestamptz,%s::timestamptz,
      %s,%s,%s,
      %s,%s::jsonb
    )"""

    batch: List[tuple] = []
    inserted = skipped = excluded = 0

    for f in nodes:
        fid = f.get("id")
        if not isinstance(fid, str) or not fid:
            skipped += 1
            continue

        va       = f.get("vulnerableAsset") or {}
        asset_id = va.get("id")            if isinstance(va, dict) else None
        atype    = (va.get("type") or "").upper() if isinstance(va, dict) else ""

        if not isinstance(asset_id, str) or not asset_id:
            skipped += 1
            continue

        if atype in EXCLUDED_ASSET_TYPES:
            excluded += 1
            continue

        ensure_asset_stub(pg, asset_id,
                          va.get("name") or "unknown",
                          va.get("type") or "unknown",
                          dry_run, valid_ids,
                          extra=va if isinstance(va, dict) else None)

        cve_id = f.get("name")
        if not isinstance(cve_id, str) or not cve_id.upper().startswith("CVE-"):
            cve_id = None

        batch.append((
            fid, run_id, asset_id, cve_id,
            f.get("detailedName"),
            f.get("CVEDescription"),
            f.get("CVSSSeverity"),
            f.get("vendorSeverity"),
            f.get("score"),
            f.get("exploitabilityScore"),
            f.get("impactScore"),
            f.get("hasExploit"),
            f.get("hasCisaKevExploit"),
            f.get("status"),
            parse_ts(f.get("firstDetectedAt")),
            parse_ts(f.get("lastDetectedAt")),
            f.get("fixedVersion"),
            f.get("detectionMethod"),
            f.get("locationPath"),
            f.get("portalUrl"),
            to_json(f),
        ))

        if len(batch) >= batch_size:
            inserted += flush(pg, SQL, TMPL, batch, dry_run, "wiz_cloud_vuln_finding")
            batch = []

    if batch:
        inserted += flush(pg, SQL, TMPL, batch, dry_run, "wiz_cloud_vuln_finding")

    LOG.info("upsert_vuln_findings: %d insertados, %d saltados, %d excluidos (VM/endpoint)",
             inserted, skipped, excluded)
    return inserted


def upsert_cfg_findings(
    pg: Pg, run_id: int, nodes: List[Dict],
    valid_ids: Set[str], dry_run: bool, batch_size: int,
) -> int:
    SQL = """
    INSERT INTO public.wiz_cloud_cfg_finding (
      finding_id, run_id, resource_id,
      rule_id, rule_graph_id, rule_name,
      first_seen_at, severity, result, status, remediation, raw
    ) VALUES %s
    ON CONFLICT (finding_id) DO UPDATE SET
      run_id        = EXCLUDED.run_id,
      resource_id   = EXCLUDED.resource_id,
      rule_id       = EXCLUDED.rule_id,
      rule_graph_id = EXCLUDED.rule_graph_id,
      rule_name     = EXCLUDED.rule_name,
      first_seen_at = EXCLUDED.first_seen_at,
      severity      = EXCLUDED.severity,
      result        = EXCLUDED.result,
      status        = EXCLUDED.status,
      remediation   = EXCLUDED.remediation,
      raw           = EXCLUDED.raw,
      ingested_at   = now()
    """
    TMPL = "(%s,%s,%s, %s,%s,%s, %s::timestamptz,%s,%s,%s,%s,%s::jsonb)"

    batch: List[tuple] = []
    inserted = skipped = 0

    for n in nodes:
        fid = n.get("id")
        if not isinstance(fid, str) or not fid:
            skipped += 1
            continue

        resource    = n.get("resource") or {}
        rule        = n.get("rule")     or {}
        resource_id = resource.get("id") if isinstance(resource, dict) else None

        if isinstance(resource_id, str) and resource_id:
            rtype = (resource.get("type") or "").upper()
            if rtype not in EXCLUDED_ASSET_TYPES:
                ensure_asset_stub(pg, resource_id,
                                  resource.get("name") or "unknown",
                                  resource.get("type") or "unknown",
                                  dry_run, valid_ids)
            else:
                resource_id = None

        batch.append((
            fid, run_id, resource_id,
            rule.get("id")      if isinstance(rule, dict) else None,
            rule.get("graphId") if isinstance(rule, dict) else None,
            rule.get("name")    if isinstance(rule, dict) else None,
            parse_ts(n.get("firstSeenAt")),
            n.get("severity"), n.get("result"),
            n.get("status"),   n.get("remediation"),
            to_json(n),
        ))

        if len(batch) >= batch_size:
            inserted += flush(pg, SQL, TMPL, batch, dry_run, "wiz_cloud_cfg_finding")
            batch = []

    if batch:
        inserted += flush(pg, SQL, TMPL, batch, dry_run, "wiz_cloud_cfg_finding")

    LOG.info("upsert_cfg_findings: %d insertados, %d saltados", inserted, skipped)
    return inserted


def upsert_issues(
    pg: Pg, run_id: int, nodes: List[Dict],
    valid_ids: Set[str], dry_run: bool, batch_size: int,
) -> int:
    SQL = """
    INSERT INTO public.wiz_cloud_issue (
      issue_id, run_id, issue_type, status, severity,
      created_at, updated_at,
      source_rule_id, source_rule_name,
      entity_id, entity_type, entity_native_type, entity_name, entity_status,
      entity_provider_id, entity_region,
      subscription_external_id, subscription_name,
      service_tickets, raw
    ) VALUES %s
    ON CONFLICT (issue_id) DO UPDATE SET
      run_id                   = EXCLUDED.run_id,
      issue_type               = EXCLUDED.issue_type,
      status                   = EXCLUDED.status,
      severity                 = EXCLUDED.severity,
      created_at               = EXCLUDED.created_at,
      updated_at               = EXCLUDED.updated_at,
      source_rule_id           = EXCLUDED.source_rule_id,
      source_rule_name         = EXCLUDED.source_rule_name,
      entity_id                = EXCLUDED.entity_id,
      entity_type              = EXCLUDED.entity_type,
      entity_native_type       = EXCLUDED.entity_native_type,
      entity_name              = EXCLUDED.entity_name,
      entity_status            = EXCLUDED.entity_status,
      entity_provider_id       = EXCLUDED.entity_provider_id,
      entity_region            = EXCLUDED.entity_region,
      subscription_external_id = EXCLUDED.subscription_external_id,
      subscription_name        = EXCLUDED.subscription_name,
      service_tickets          = EXCLUDED.service_tickets,
      raw                      = EXCLUDED.raw,
      ingested_at              = now()
    """
    TMPL = """(
      %s,%s,%s,%s,%s,
      %s::timestamptz,%s::timestamptz,
      %s,%s,
      %s,%s,%s,%s,%s,
      %s,%s,
      %s,%s,
      %s::jsonb,%s::jsonb
    )"""

    batch: List[tuple] = []
    inserted = skipped = 0

    for n in nodes:
        iid = n.get("id")
        if not isinstance(iid, str) or not iid:
            skipped += 1
            continue

        es  = n.get("entitySnapshot") or {}
        sr  = n.get("sourceRule")     or {}
        eid = es.get("id") if isinstance(es, dict) else None

        if isinstance(eid, str) and eid:
            etype = (es.get("type") or "").upper()
            if etype not in EXCLUDED_ASSET_TYPES:
                ensure_asset_stub(pg, eid,
                                  es.get("name") or "unknown",
                                  es.get("type") or "unknown",
                                  dry_run, valid_ids)
            else:
                eid = None

        tickets = n.get("serviceTickets") or []

        batch.append((
            iid, run_id,
            n.get("type"), n.get("status"), n.get("severity"),
            parse_ts(n.get("createdAt")),
            parse_ts(n.get("updatedAt")),
            sr.get("id")   if isinstance(sr, dict) else None,
            sr.get("name") if isinstance(sr, dict) else None,
            eid,
            es.get("type")                   if isinstance(es, dict) else None,
            es.get("nativeType")             if isinstance(es, dict) else None,
            es.get("name")                   if isinstance(es, dict) else None,
            es.get("status")                 if isinstance(es, dict) else None,
            es.get("providerId")             if isinstance(es, dict) else None,
            es.get("region")                 if isinstance(es, dict) else None,
            es.get("subscriptionExternalId") if isinstance(es, dict) else None,
            es.get("subscriptionName")       if isinstance(es, dict) else None,
            to_json(tickets),
            to_json(n),
        ))

        if len(batch) >= batch_size:
            inserted += flush(pg, SQL, TMPL, batch, dry_run, "wiz_cloud_issue")
            batch = []

    if batch:
        inserted += flush(pg, SQL, TMPL, batch, dry_run, "wiz_cloud_issue")

    LOG.info("upsert_issues: %d insertados, %d saltados", inserted, skipped)
    return inserted


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Wiz Cloud ETL -> PostgreSQL")
    p.add_argument("--pg-host",    default=None)
    p.add_argument("--pg-port",    type=int, default=None)
    p.add_argument("--pg-sslmode", default="disable")
    p.add_argument("--page-size",  type=int, default=None)
    p.add_argument("--batch-size", type=int, default=500)
    p.add_argument("--dry-run",    action="store_true")
    p.add_argument("--log-level",  default="INFO",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return p.parse_args()


def load_config(args: argparse.Namespace) -> Dict[str, Any]:
    def req(name: str, env: str) -> str:
        v = read_secret(name, env_fallback=env)
        if not v:
            die(f"Secret '{name}' / env '{env}' no encontrado.")
        return v

    env_types = os.getenv("WIZ_RESOURCE_TYPES", "").strip()
    resource_types = (
        [t.strip() for t in env_types.split(",") if t.strip()]
        if env_types else DEFAULT_RESOURCE_TYPES
    )

    return {
        "wiz_client_id":     req("wiz_client_id",        "WIZ_CLIENT_ID"),
        "wiz_client_secret": req("wiz_client_secret",    "WIZ_CLIENT_SECRET"),
        "wiz_api_endpoint":  req("wiz_api_endpoint_url", "WIZ_API_ENDPOINT_URL"),
        "pg_db":             req("postgres_db",           "PGDATABASE"),
        "pg_user":           req("postgres_user",         "PGUSER"),
        "pg_password":       req("postgres_password",     "PGPASSWORD"),
        "wiz_auth_url":      os.getenv("WIZ_AUTH_URL",
                                       "https://auth.app.wiz.io/oauth/token").strip(),
        "wiz_auth_audience": os.getenv("WIZ_AUTH_AUDIENCE", "wiz-api").strip(),
        "page_size":         args.page_size or int(os.getenv("WIZ_PAGE_SIZE",  "100") or "100"),
        "timeout":           int(os.getenv("WIZ_TIMEOUT",     "180") or "180"),
        "max_retries":       int(os.getenv("WIZ_MAX_RETRIES", "8")   or "8"),
        "max_rps":           float(os.getenv("WIZ_MAX_RPS",   "2.5") or "2.5"),
        "resource_types":    resource_types,
        "pg_host":           args.pg_host or os.getenv("POSTGRES_HOST", "appdb"),
        "pg_port":           args.pg_port or int(os.getenv("POSTGRES_PORT", "5432")),
        "pg_sslmode":        args.pg_sslmode,
    }


def main() -> int:
    args = parse_args()
    setup_logging(args.log_level)
    cfg  = load_config(args)

    LOG.info("=== Wiz Cloud ETL iniciando ===")
    LOG.info("API endpoint   : %s", cfg["wiz_api_endpoint"])
    LOG.info("Resource types : %s", cfg["resource_types"])
    LOG.info("Excluidos      : %s", sorted(EXCLUDED_ASSET_TYPES))
    LOG.info("DB             : %s@%s:%s/%s",
             cfg["pg_user"], cfg["pg_host"], cfg["pg_port"], cfg["pg_db"])
    LOG.info("dry_run        : %s | batch=%d | page=%d",
             args.dry_run, args.batch_size, cfg["page_size"])

    pg = Pg(host=cfg["pg_host"], port=cfg["pg_port"],
            dbname=cfg["pg_db"], user=cfg["pg_user"],
            password=cfg["pg_password"], sslmode=cfg["pg_sslmode"])

    if not args.dry_run:
        pg.init()

    client = WizHTTP(cfg)

    run_id: Optional[int] = None
    if not args.dry_run:
        try:
            run_id = run_start(pg, cfg["wiz_api_endpoint"], cfg["page_size"])
            LOG.info("Run iniciado: run_id=%d", run_id)
        except Exception as e:
            LOG.warning("No pude registrar etl_run: %s", e)

    rows_assets = rows_vuln = rows_cfg = rows_issues = 0
    pages_cloud = pages_vuln = pages_cfg = pages_issues = 0
    valid_ids: Set[str] = set()
    error_msg: Optional[str] = None
    error_det: Optional[str] = None
    status = "error"

    try:
        LOG.info("--- PASO 1: cloudResources ---")
        all_resources: List[Dict] = []
        for rtype in cfg["resource_types"]:
            LOG.info("  Extrayendo: %s", rtype)
            try:
                nodes, pages = paginate(
                    client, QUERY_CLOUD_RESOURCES, "cloudResources",
                    {"filterBy": {"type": rtype}},
                    cfg["page_size"],
                    retry_internal=False,
                )
                pages_cloud += pages
                all_resources.extend(nodes)
                LOG.info("  %s: %d nodos", rtype, len(nodes))
            except Exception as e:
                LOG.warning("  [WARN] tipo %s falló: %s — continuando", rtype, e)

        LOG.info("Total cloud resources: %d", len(all_resources))
        rows_assets, valid_ids = upsert_assets(
            pg, all_resources, args.dry_run, args.batch_size)

        LOG.info("--- PASO 2: vulnerabilityFindings ---")
        vuln_nodes, pages_vuln = paginate(
            client, QUERY_VULN_FINDINGS, "vulnerabilityFindings",
            {"filterBy": None},
            cfg["page_size"],
        )
        LOG.info("Vulnerability findings: %d", len(vuln_nodes))
        rows_vuln = upsert_vuln_findings(
            pg, run_id or 0, vuln_nodes,
            valid_ids, args.dry_run, args.batch_size)

        LOG.info("--- PASO 3: configurationFindings ---")
        cfg_nodes, pages_cfg = paginate(
            client, QUERY_CFG_FINDINGS, "configurationFindings",
            {"filterBy": None},
            cfg["page_size"],
        )
        LOG.info("Configuration findings: %d", len(cfg_nodes))
        rows_cfg = upsert_cfg_findings(
            pg, run_id or 0, cfg_nodes,
            valid_ids, args.dry_run, args.batch_size)

        LOG.info("--- PASO 4: issuesV2 ---")
        issue_nodes, pages_issues = paginate(
            client, QUERY_ISSUES, "issuesV2",
            {"filterBy": None},
            cfg["page_size"],
        )
        LOG.info("Issues: %d", len(issue_nodes))
        rows_issues = upsert_issues(
            pg, run_id or 0, issue_nodes,
            valid_ids, args.dry_run, args.batch_size)

        status = "success"

    except SystemExit:
        raise
    except Exception as e:
        error_msg = str(e)
        error_det = traceback.format_exc()
        status    = "error"
        LOG.error("ETL FALLO: %s", e, exc_info=True)

    finally:
        if run_id is not None:
            try:
                run_finish(
                    pg, run_id, status,
                    rows_assets, rows_vuln, rows_cfg, rows_issues,
                    pages_cloud, pages_vuln, pages_cfg, pages_issues,
                    error_msg, error_det,
                )
                LOG.info("Run cerrado: run_id=%d status=%s", run_id, status)
            except Exception as fe:
                LOG.warning("No pude actualizar wiz_cloud_etl_runs: %s", fe)

        if not args.dry_run:
            pg.close()

    if status == "error":
        LOG.error("=== Wiz Cloud ETL FALLO === run_id=%s", run_id)
        return 1

    LOG.info(
        "=== Wiz Cloud ETL OK | run_id=%s | "
        "assets=%d vuln=%d cfg=%d issues=%d ===",
        run_id, rows_assets, rows_vuln, rows_cfg, rows_issues,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
