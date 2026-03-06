#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys
import csv
import json
import time
import logging
import re
import ipaddress
import xml.etree.ElementTree as ET
from datetime import datetime, date, timezone
from pathlib import Path
from collections import OrderedDict, Counter, defaultdict
from typing import Any, Dict, List, Optional

try:
    import requests
except ImportError:
    os.system(f"{sys.executable} -m pip install requests --break-system-packages -q")
    import requests

try:
    import psycopg2
    from psycopg2.extras import execute_values, Json
except ImportError:
    os.system(f"{sys.executable} -m pip install psycopg2-binary --break-system-packages -q")
    import psycopg2
    from psycopg2.extras import execute_values, Json


# ═══════════════════════════════════════════════════════════════
# DOCKER SECRETS + ENV VARS
# ═══════════════════════════════════════════════════════════════

def _read_secret(name: str) -> str:
    """Lee Docker secret desde /run/secrets/<name>."""
    try:
        p = Path(f"/run/secrets/{name}")
        if p.exists() and p.is_file():
            return p.read_text(encoding="utf-8").strip()
    except Exception:
        pass
    return ""


def _read_credential(secret_name: str, env_names: list, default: str = "") -> str:
    """
    Lee credencial con prioridad:
      1. Docker secret /run/secrets/<secret_name>
      2. Variables de entorno
      3. Valor por defecto
    """
    val = _read_secret(secret_name)
    if val:
        return val
    for env in env_names:
        val = os.environ.get(env, "").strip()
        if val:
            return val
    return default


# ─── Credenciales Qualys ──────────────────────────────────────
QUALYS_BASE_URL = _read_credential("qualys_api_url", ["QUALYS_API_URL"], "")
QUALYS_USERNAME = _read_credential("qualys_username", ["QUALYS_USERNAME"], "")
QUALYS_PASSWORD = _read_credential("qualys_password", ["QUALYS_PASSWORD"], "")

# ─── Opciones Qualys ─────────────────────────────────────────

PAGE_SIZE     = int(os.environ.get("QUALYS_PAGE_SIZE", "100"))
MAX_RETRIES   = int(os.environ.get("QUALYS_MAX_RETRIES", "5"))
TIMEOUT       = int(os.environ.get("QUALYS_TIMEOUT", "300"))
KB_CSV_PATH   = os.environ.get("QUALYS_KB_CSV", "")
DB_PAGE_SIZE  = int(os.environ.get("QUALYS_PAGE_SIZE_DB", "5000"))

# ─── Logger ──────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("qualys2db")

# ─── Endpoints Qualys ────────────────────────────────────────

AM_HOSTASSET     = "/qps/rest/2.0/search/am/hostasset"
AM_HOSTASSET_CNT = "/qps/rest/2.0/count/am/hostasset"
AM_VULN          = "/qps/rest/2.0/search/am/hostinstancevuln"
AM_VULN_CNT      = "/qps/rest/2.0/count/am/hostinstancevuln"
KB_ENDPOINTS     = [
    "/api/2.0/fo/knowledge_base/vuln/",
    "/api/2.0/fo/knowledge_base/vuln/index.php",
    "/api/3.0/fo/knowledge_base/vuln/",
]
VM_DETECTION     = "/api/2.0/fo/asset/host/vm/detection/"


# ═══════════════════════════════════════════════════════════════
# HELPERS DE TRANSFORMACIÓN (tipos seguros para DB)
# ═══════════════════════════════════════════════════════════════

def _to_dt(v: Any) -> Optional[datetime]:
    """Convierte cualquier formato de fecha a datetime UTC."""
    if v is None:
        return None
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    if isinstance(v, (int, float)):
        x = float(v)
        if x > 10_000_000_000:
            x /= 1000.0
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
            return None
    return None


def _safe_inet(v: Any) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip()
    if not s:
        return None
    try:
        ipaddress.ip_address(s)
        return s
    except Exception:
        return None


def _safe_int(v: Any) -> Optional[int]:
    if v is None:
        return None
    if isinstance(v, bool):
        return 1 if v else 0
    if isinstance(v, int):
        return v
    if isinstance(v, float):
        return int(v)
    s = str(v).strip()
    if not s:
        return None
    try:
        return int(float(s))
    except Exception:
        return None


def _safe_bool(v: Any) -> Optional[bool]:
    if v is None:
        return None
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if s in ("1", "true", "yes", "y"):
        return True
    if s in ("0", "false", "no", "n"):
        return False
    return None


def _safe_numeric(v: Any) -> Optional[float]:
    if v is None:
        return None
    try:
        return float(str(v).strip())
    except Exception:
        return None


def _json_default(o):
    if isinstance(o, (datetime, date)):
        return o.isoformat()
    return str(o)


def _wrap_json(v: Any) -> Optional[Json]:
    """Envuelve valor para inserción JSONB en psycopg2."""
    if v is None:
        return None
    return Json(v, dumps=lambda x: json.dumps(x, ensure_ascii=False, default=_json_default))


def _split_cves(cves: Any) -> List[str]:
    """Separa string 'CVE-2024-1234, CVE-2024-9999' en lista."""
    if not cves:
        return []
    if isinstance(cves, list):
        out = []
        for x in cves:
            out.extend(_split_cves(x))
        return sorted(set(out))
    s = str(cves).strip()
    if not s:
        return []
    return sorted(set(p.strip() for p in re.split(r"[;,]\s*", s) if p.strip()))


def _group_by(records: List[Dict], key: str) -> Dict[str, List[Dict]]:
    groups = defaultdict(list)
    for r in records:
        k = str(r.get(key, "")).strip()
        if k:
            groups[k].append(r)
    return dict(groups)


# ═══════════════════════════════════════════════════════════════
# CONEXIÓN A BASE DE DATOS
# ═══════════════════════════════════════════════════════════════

def get_db_config() -> Dict[str, str]:
    """Lee credenciales DB desde Docker secrets o env vars."""
    user = _read_credential("postgres_user",
                            ["DATABASE_USER", "DB_USER", "PGUSER"], "")
    password = _read_credential("postgres_password",
                                ["DATABASE_PASSWORD", "DB_PASSWORD", "PGPASSWORD"], "")
    dbname = _read_credential("postgres_db",
                              ["DATABASE_NAME", "DB_NAME", "PGDATABASE"], "")
    host = _read_credential("postgres_host",
                            ["DATABASE_HOST", "DB_HOST", "PGHOST"], "appdb")
    port = _read_credential("postgres_port",
                            ["DATABASE_PORT", "DB_PORT", "PGPORT"], "5432")

    if not user:
        raise RuntimeError(
            "DB user no encontrado.\n"
            "  Docker secret: /run/secrets/postgres_user\n"
            "  O env var: DATABASE_USER / DB_USER / PGUSER"
        )
    if not password:
        raise RuntimeError(
            "DB password no encontrado.\n"
            "  Docker secret: /run/secrets/postgres_password\n"
            "  O env var: DATABASE_PASSWORD / DB_PASSWORD / PGPASSWORD"
        )
    if not dbname:
        raise RuntimeError(
            "DB name no encontrado.\n"
            "  Docker secret: /run/secrets/postgres_db\n"
            "  O env var: DATABASE_NAME / DB_NAME / PGDATABASE"
        )
    return {"host": host, "port": port, "user": user,
            "password": password, "dbname": dbname}


def connect_db(cfg: Dict[str, str]):
    """Conecta a PostgreSQL con keepalive."""
    log.info(f"Conectando a PostgreSQL {cfg['host']}:{cfg['port']}/{cfg['dbname']} "
             f"como {cfg['user']}")
    conn = psycopg2.connect(
        host=cfg["host"], port=cfg["port"],
        user=cfg["user"], password=cfg["password"],
        dbname=cfg["dbname"],
        connect_timeout=30,
        keepalives=1, keepalives_idle=60,
        keepalives_interval=30, keepalives_count=5,
        options="-c statement_timeout=600000",
    )
    conn.autocommit = False
    log.info("✓ Conexión DB exitosa")
    return conn


# ═══════════════════════════════════════════════════════════════
# EXTRACTOR: Qualys API → datos en memoria
# ═══════════════════════════════════════════════════════════════

class QualysExtractor:

    def __init__(self):
        self.base = QUALYS_BASE_URL.rstrip("/")
        self.session = requests.Session()
        self.session.auth = (QUALYS_USERNAME, QUALYS_PASSWORD)
        self.session.headers["X-Requested-With"] = "qualys-to-db/1.0"

    # ─── HTTP ────────────────────────────────────────────────

    def _req(self, method, url, data=None, headers=None, allow_401=False):
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                fn = self.session.post if method == "POST" else self.session.get
                resp = fn(url, data=data, headers=headers, timeout=TIMEOUT)

                if resp.status_code in (409, 429):
                    wait = int(resp.headers.get("Retry-After", 60))
                    log.warning(f"  Rate limit. Esperando {wait}s...")
                    time.sleep(wait)
                    continue

                if resp.status_code == 401:
                    if allow_401:
                        raise PermissionError(f"401 en {url}")
                    log.error("Error de autenticación Qualys (401).")
                    sys.exit(1)

                resp.raise_for_status()
                return resp

            except (PermissionError, KeyboardInterrupt, SystemExit):
                raise
            except Exception as e:
                if attempt < MAX_RETRIES:
                    wait = min(120, 10 * attempt)
                    log.warning(f"  Error ({e}). Reintento {attempt}/{MAX_RETRIES} en {wait}s...")
                    time.sleep(wait)
                else:
                    raise

    def verify(self):
        log.info(f"Verificando conexión con {self.base}...")
        try:
            r = self.session.get(f"{self.base}/qps/rest/portal/version",
                                 timeout=30, headers={"Accept": "application/xml"})
            r.raise_for_status()
            log.info("✓ Conexión Qualys exitosa")
            return True
        except Exception as e:
            log.error(f"✗ Error Qualys: {e}")
            return False

    # ─── AM API: Paginación ──────────────────────────────────

    def _am_xml(self, last_id=None):
        parts = ['<?xml version="1.0" encoding="UTF-8"?>', "<ServiceRequest>",
                  "  <preferences>",
                  f"    <limitResults>{PAGE_SIZE}</limitResults>"]
        if last_id:
            parts.append(f"    <startFromId>{last_id}</startFromId>")
        parts += ["  </preferences>", "</ServiceRequest>"]
        return "\n".join(parts)

    def _am_extract(self, url, entity):
        last_id = None
        page = total = 0
        while True:
            page += 1
            log.info(f"  Pág {page:>4} | Desde: {last_id or 'inicio':>14} | Acum: {total:>8,}")
            resp = self._req("POST", url, data=self._am_xml(last_id),
                             headers={"Content-Type": "text/xml",
                                      "Accept": "application/xml"})
            root = ET.fromstring(resp.text)
            code = root.find("responseCode")
            if code is None or code.text != "SUCCESS":
                err = root.find(".//errorMessage")
                log.error(f"  AM Error: {err.text if err is not None else 'Desconocido'}")
                break
            records = []
            for elem in root.findall(f".//{entity}"):
                records.append(self._xml_to_dict(elem))
            for r in records:
                yield r
                total += 1
            hm = root.find("hasMoreRecords")
            if hm is None or hm.text != "true" or not records:
                break
            lid = root.find("lastId")
            last_id = lid.text if lid is not None and lid.text else records[-1].get("id")
            time.sleep(0.5)
        log.info(f"  → Total: {total:,}")

    def _am_count(self, url):
        try:
            r = self._req("GET", url, headers={"Accept": "application/xml"})
            root = ET.fromstring(r.text)
            c = root.find("count")
            return int(c.text) if c is not None and c.text else None
        except Exception:
            return None

    def _xml_to_dict(self, elem):
        result = OrderedDict()
        for ch in elem:
            tag = ch.tag
            if tag == "list":
                return [self._xml_to_dict(i) for i in ch]
            if len(ch) > 0:
                val = self._xml_to_dict(ch)
            else:
                val = ch.text.strip() if ch.text else ""
            if tag in result:
                if not isinstance(result[tag], list):
                    result[tag] = [result[tag]]
                result[tag].append(val)
            else:
                result[tag] = val
        return result

    # ─── PASO 1: Host Assets ─────────────────────────────────

    def extract_hosts(self):
        log.info("━" * 60)
        log.info("📦 PASO 1: Host Assets")
        cnt = self._am_count(f"{self.base}{AM_HOSTASSET_CNT}")
        if cnt:
            log.info(f"  ~{cnt:,} hosts")
        hosts = list(self._am_extract(f"{self.base}{AM_HOSTASSET}", "HostAsset"))
        log.info(f"  ✓ {len(hosts):,} hosts extraídos")
        return hosts

    # ─── PASO 2: Vulnerabilidades ────────────────────────────

    def extract_vulns(self):
        log.info("━" * 60)
        log.info("📦 PASO 2: Vulnerabilidades por Host (hostinstancevuln)")
        cnt = self._am_count(f"{self.base}{AM_VULN_CNT}")
        if cnt:
            log.info(f"  ~{cnt:,} vulnerabilidades")
        vulns = list(self._am_extract(f"{self.base}{AM_VULN}", "HostInstanceVuln"))
        log.info(f"  ✓ {len(vulns):,} vulnerabilidades extraídas")
        return vulns

    # ─── PASO 3: KnowledgeBase con waterfall ─────────────────

    def _parse_kb_vuln(self, vuln_elem):
        rec = OrderedDict()
        for field in ["QID", "VULN_TYPE", "SEVERITY_LEVEL", "TITLE", "CATEGORY",
                       "TECHNOLOGY", "LAST_SERVICE_MODIFICATION_DATETIME",
                       "PUBLISHED_DATETIME", "CODE_MODIFIED_DATETIME",
                       "PATCHABLE", "PATCH_PUBLISHED_DATE",
                       "DIAGNOSIS", "DIAGNOSIS_COMMENT",
                       "CONSEQUENCE", "CONSEQUENCE_COMMENT",
                       "SOLUTION", "SOLUTION_COMMENT",
                       "PCI_FLAG", "AUTOMATIC_PCI_FAIL",
                       "DISCOVERY_REMOTE", "IS_DISABLED"]:
            e = vuln_elem.find(field)
            if e is not None:
                rec[field] = e.text.strip() if e.text else ""

        # CVE_LIST
        cves = []
        cl = vuln_elem.find("CVE_LIST")
        if cl is not None:
            for cve in cl.findall("CVE"):
                cid = cve.find("ID")
                if cid is not None and cid.text:
                    cves.append(cid.text.strip())
        rec["CVE_IDS"] = ", ".join(cves)
        rec["CVE_COUNT"] = str(len(cves))

        cve_urls = []
        if cl is not None:
            for cve in cl.findall("CVE"):
                curl = cve.find("URL")
                if curl is not None and curl.text:
                    cve_urls.append(curl.text.strip())
        rec["CVE_URLS"] = ", ".join(cve_urls)

        # BUGTRAQ
        bts = []
        bl = vuln_elem.find("BUGTRAQ_LIST")
        if bl is not None:
            for bt in bl.findall("BUGTRAQ"):
                bid = bt.find("ID")
                if bid is not None and bid.text:
                    bts.append(bid.text.strip())
        rec["BUGTRAQ_IDS"] = ", ".join(bts)

        # VENDOR REFERENCES
        vrs = []
        vl = vuln_elem.find("VENDOR_REFERENCE_LIST")
        if vl is not None:
            for vr in vl.findall("VENDOR_REFERENCE"):
                vid = vr.find("ID")
                if vid is not None and vid.text:
                    vrs.append(vid.text.strip())
        rec["VENDOR_REFERENCES"] = ", ".join(vrs)

        # SOFTWARE_LIST
        sws = []
        sl = vuln_elem.find("SOFTWARE_LIST")
        if sl is not None:
            for sw in sl.findall("SOFTWARE"):
                product = sw.find("PRODUCT")
                vendor = sw.find("VENDOR")
                p = product.text.strip() if product is not None and product.text else ""
                v = vendor.text.strip() if vendor is not None and vendor.text else ""
                sws.append(f"{v}/{p}" if v else p)
        rec["SOFTWARE_AFFECTED"] = "; ".join(sws)

        # CVSS v2
        cvss = vuln_elem.find("CVSS")
        if cvss is not None:
            for sub in ["BASE", "TEMPORAL"]:
                e = cvss.find(sub)
                if e is not None and e.text:
                    rec[f"CVSS_{sub}"] = e.text.strip()
            vec = cvss.find("VECTOR_STRING")
            if vec is not None and vec.text:
                rec["CVSS_VECTOR"] = vec.text.strip()

        # CVSS v3
        cvss3 = vuln_elem.find("CVSS_V3")
        if cvss3 is not None:
            for sub in ["BASE", "TEMPORAL", "ATTACK_VECTOR", "ATTACK_COMPLEXITY",
                         "PRIVILEGES_REQUIRED", "USER_INTERACTION", "SCOPE",
                         "CONFIDENTIALITY_IMPACT", "INTEGRITY_IMPACT",
                         "AVAILABILITY_IMPACT"]:
                e = cvss3.find(sub)
                if e is not None and e.text:
                    rec[f"CVSS3_{sub}"] = e.text.strip()
            vec3 = cvss3.find("VECTOR_STRING")
            if vec3 is not None and vec3.text:
                rec["CVSS3_VECTOR"] = vec3.text.strip()

        # THREAT INTELLIGENCE
        rtis = []
        ti = vuln_elem.find("THREAT_INTELLIGENCE")
        if ti is not None:
            for t in ti.findall("THREAT_INTEL"):
                txt = t.find("TEXT")
                if txt is not None and txt.text:
                    rtis.append(txt.text.strip())
        rec["THREAT_INTELLIGENCE"] = "; ".join(rtis)

        # COMPLIANCE
        comps = []
        comp_el = vuln_elem.find("COMPLIANCE_LIST")
        if comp_el is not None:
            for c in comp_el.findall("COMPLIANCE"):
                ct = c.find("TYPE")
                cs = c.find("SECTION")
                t = ct.text.strip() if ct is not None and ct.text else ""
                s = cs.text.strip() if cs is not None and cs.text else ""
                comps.append(f"{t}: {s}")
        rec["COMPLIANCE"] = "; ".join(comps)

        # DISCOVERY AUTH TYPES
        auth_types = []
        atl = vuln_elem.find("DISCOVERY_AUTH_TYPE_LIST")
        if atl is not None:
            for at in atl.findall("DISCOVERY_AUTH_TYPE"):
                if at.text:
                    auth_types.append(at.text.strip())
        rec["DISCOVERY_AUTH_TYPES"] = ", ".join(auth_types)

        return rec

    def _parse_kb_xml(self, text):
        clean = re.sub(r'<!DOCTYPE[^>]*>', '', text)
        records = []
        try:
            root = ET.fromstring(clean)
        except ET.ParseError as e:
            log.error(f"  KB XML parse error: {e}")
            return records
        response = root.find(".//RESPONSE")
        if response is None:
            response = root
        vuln_list = response.find("VULN_LIST")
        if vuln_list is None:
            vuln_list = root.find(".//VULN_LIST")
        if vuln_list is not None:
            for v in vuln_list.findall("VULN"):
                try:
                    records.append(self._parse_kb_vuln(v))
                except Exception as e:
                    qe = v.find("QID")
                    log.warning(f"  Error QID {qe.text if qe is not None else '?'}: {e}")
        return records

    def _try_kb_api(self, qids):
        log.info("  [1] KB API v2.0 / v3.0...")
        headers_list = [
            {"X-Requested-With": "curl",
             "Content-Type": "application/x-www-form-urlencoded"},
            {"X-Requested-With": "qualys-to-db"},
        ]
        for ep in KB_ENDPOINTS:
            url = f"{self.base}{ep}"
            for hdrs in headers_list:
                try:
                    all_recs = []
                    batch_size = 500
                    batches = [qids[i:i+batch_size] for i in range(0, len(qids), batch_size)]
                    for bn, batch in enumerate(batches, 1):
                        log.info(f"      Lote {bn}/{len(batches)}: {len(batch)} QIDs")
                        params = {
                            "action": "list",
                            "details": "All",
                            "ids": ",".join(str(q) for q in batch),
                            "show_supported_modules_info": "1",
                            "show_pci_reasons": "1",
                        }
                        resp = self._req("POST", url, data=params,
                                         headers=hdrs, allow_401=True)
                        recs = self._parse_kb_xml(resp.text)
                        all_recs.extend(recs)
                        if bn < len(batches):
                            time.sleep(1)
                    if all_recs:
                        log.info(f"      ✓ {len(all_recs):,} QIDs del KB")
                        return all_recs
                except PermissionError:
                    continue
                except Exception as e:
                    log.debug(f"      {ep}: {e}")
                    continue
        raise PermissionError("Sin acceso a KB API (v2/v3)")

    def _try_vm_detection(self, qids):
        log.info("  [2] VM Detection API...")
        url = f"{self.base}{VM_DETECTION}"
        params = {
            "action": "list", "show_results": "1",
            "output_format": "XML",
            "qids": ",".join(str(q) for q in qids[:300]),
        }
        for hdrs in [{"X-Requested-With": "curl"},
                     {"X-Requested-With": "qualys-to-db"}]:
            try:
                resp = self._req("POST", url, data=params,
                                 headers=hdrs, allow_401=True)
                break
            except PermissionError:
                continue
        else:
            raise PermissionError("Sin acceso a VM Detection API")

        clean = re.sub(r'<!DOCTYPE[^>]*>', '', resp.text)
        root = ET.fromstring(clean)
        qid_data = {}
        cve_re = re.compile(r'CVE-\d{4}-\d{4,}')

        for det in root.iter("DETECTION"):
            qe = det.find("QID")
            if qe is None or not qe.text:
                continue
            qid = qe.text.strip()
            if qid in qid_data:
                continue
            rec = OrderedDict([("QID", qid)])
            sev = det.find("SEVERITY")
            if sev is not None and sev.text:
                rec["SEVERITY_LEVEL"] = sev.text.strip()
            tp = det.find("TYPE")
            if tp is not None and tp.text:
                rec["VULN_TYPE"] = tp.text.strip()
            results = det.find("RESULTS")
            if results is not None and results.text:
                found = cve_re.findall(results.text)
                rec["CVE_IDS"] = ", ".join(sorted(set(found)))
                rec["CVE_COUNT"] = str(len(set(found)))
            else:
                rec["CVE_IDS"] = ""
                rec["CVE_COUNT"] = "0"
            qid_data[qid] = rec

        records = list(qid_data.values())
        if not records:
            raise Exception("Sin resultados de Detection API")
        log.info(f"      ✓ {len(records):,} QIDs via Detection API")
        return records

    def _try_csv_import(self):
        log.info("  [3] CSV manual del KB...")
        search = []
        if KB_CSV_PATH:
            search.append(KB_CSV_PATH)
        for name in ["qualys_kb.csv", "knowledgebase.csv", "kb_export.csv"]:
            search.append(str(Path.cwd() / name))

        found = None
        for p in search:
            if p and Path(p).exists():
                found = p
                break
        if not found:
            raise FileNotFoundError("No se encontró CSV del KB")

        log.info(f"      Archivo: {found}")
        with open(found, "r", encoding="utf-8", errors="replace") as f:
            sample = f.read(4096)
        delim = "\t" if "\t" in sample else (";" if sample.count(";") > sample.count(",") else ",")

        col_map = {
            "QID": "QID", "qid": "QID",
            "CVE ID": "CVE_IDS", "CVE": "CVE_IDS", "CVEs": "CVE_IDS", "CVE_ID": "CVE_IDS",
            "Title": "TITLE", "TITLE": "TITLE", "Vuln Title": "TITLE",
            "Severity": "SEVERITY_LEVEL", "SEVERITY": "SEVERITY_LEVEL",
            "Category": "CATEGORY", "CATEGORY": "CATEGORY",
            "Type": "VULN_TYPE", "VULN_TYPE": "VULN_TYPE",
            "CVSS Base": "CVSS_BASE", "CVSS_BASE": "CVSS_BASE", "CVSS Score": "CVSS_BASE",
            "CVSS3 Base": "CVSS3_BASE", "CVSS3_BASE": "CVSS3_BASE",
            "Patchable": "PATCHABLE", "PATCHABLE": "PATCHABLE",
            "Solution": "SOLUTION", "SOLUTION": "SOLUTION",
            "Diagnosis": "DIAGNOSIS", "DIAGNOSIS": "DIAGNOSIS",
            "Consequence": "CONSEQUENCE", "CONSEQUENCE": "CONSEQUENCE",
            "Published": "PUBLISHED_DATETIME", "Published Date": "PUBLISHED_DATETIME",
            "Vendor Reference": "VENDOR_REFERENCES",
            "Bugtraq": "BUGTRAQ_IDS", "Bugtraq ID": "BUGTRAQ_IDS",
            "Threat": "THREAT_INTELLIGENCE",
        }
        records = []
        with open(found, "r", encoding="utf-8", errors="replace") as f:
            for row in csv.DictReader(f, delimiter=delim):
                rec = OrderedDict()
                for orig, val in row.items():
                    if orig is None:
                        continue
                    mapped = col_map.get(orig.strip(), orig.strip())
                    rec[mapped] = (val or "").strip()
                if rec.get("QID"):
                    records.append(rec)
        if not records:
            raise Exception("CSV vacío")
        log.info(f"      ✓ {len(records):,} QIDs importados de CSV")
        return records

    def extract_kb(self, qids):
        log.info("━" * 60)
        log.info(f"📦 PASO 3: KnowledgeBase — {len(qids):,} QIDs únicos")
        log.info("  Probando métodos en cascada...\n")

        methods = [
            ("KB API v2/v3",      lambda: self._try_kb_api(qids)),
            ("VM Detection API",  lambda: self._try_vm_detection(qids)),
            ("CSV manual",        lambda: self._try_csv_import()),
        ]
        for i, (name, fn) in enumerate(methods, 1):
            try:
                records = fn()
                if records:
                    has_cves = any(r.get("CVE_IDS", "") for r in records)
                    log.info(f"\n  ✓ ÉXITO con [{i}] {name}")
                    log.info(f"    {len(records):,} QIDs"
                             f"{' con CVEs' if has_cves else ' (sin CVEs)'}")
                    return records
            except PermissionError:
                log.info(f"    [{i}] {name}: sin permisos → siguiente")
            except FileNotFoundError as e:
                log.info(f"    [{i}] {name}: {e}")
            except Exception as e:
                log.info(f"    [{i}] {name}: error ({e}) → siguiente")

        log.warning("\n  ✗ No se pudo obtener KB por ningún método.")
        log.warning("    • Pedir permisos de VM API a su admin Qualys")
        log.warning("    • Exportar KB desde UI y colocar como ./qualys_kb.csv")
        return []


# ═══════════════════════════════════════════════════════════════
# DESCOMPOSICIÓN: Extraer sub-datos de hosts en memoria
# ═══════════════════════════════════════════════════════════════

def decompose_hosts(hosts: List[Dict]) -> Dict[str, List[Dict]]:
    """
    Extrae sub-datos anidados de cada HostAsset:
    openPort, software, networkInterface, volume, account,
    processor, tags, sourceInfo, agentInfo, vuln (embedded).
    Retorna dict con listas listas para los builders del ETL.
    """
    ha_open_ports = []
    ha_software = []
    ha_network_ifaces = []
    ha_volumes = []
    ha_accounts = []
    ha_processors = []
    ha_tags = []
    ha_source_info = []
    ha_agent_info = []
    ha_vulns_embedded = []

    def _expand(host, field, target_list):
        hid = str(host.get("id", ""))
        hname = host.get("name") or host.get("n", "")
        data = host.get(field)
        if data is None:
            return
        items = data if isinstance(data, list) else [data]
        for item in items:
            if isinstance(item, dict):
                item["hostAssetId"] = hid
                item["hostAssetName"] = hname
                target_list.append(item)

    for h in hosts:
        _expand(h, "openPort",         ha_open_ports)
        _expand(h, "software",         ha_software)
        _expand(h, "networkInterface",  ha_network_ifaces)
        _expand(h, "volume",           ha_volumes)
        _expand(h, "account",          ha_accounts)
        _expand(h, "processor",        ha_processors)
        _expand(h, "tags",             ha_tags)
        _expand(h, "sourceInfo",       ha_source_info)
        _expand(h, "agentInfo",        ha_agent_info)

        # Vulns embedded en el host asset
        hid = str(h.get("id", ""))
        hname = h.get("name") or h.get("n", "")
        vuln_data = h.get("vuln")
        if vuln_data:
            items = vuln_data if isinstance(vuln_data, list) else [vuln_data]
            for item in items:
                if isinstance(item, dict):
                    item["hostAssetId"] = hid
                    item["hostAssetName"] = hname
                    ha_vulns_embedded.append(item)

    log.info(f"  Sub-datos extraídos de {len(hosts):,} hosts:")
    log.info(f"    open_ports:      {len(ha_open_ports):>8,}")
    log.info(f"    software:        {len(ha_software):>8,}")
    log.info(f"    network_ifaces:  {len(ha_network_ifaces):>8,}")
    log.info(f"    volumes:         {len(ha_volumes):>8,}")
    log.info(f"    accounts:        {len(ha_accounts):>8,}")
    log.info(f"    processors:      {len(ha_processors):>8,}")
    log.info(f"    tags:            {len(ha_tags):>8,}")
    log.info(f"    source_info:     {len(ha_source_info):>8,}")
    log.info(f"    agent_info:      {len(ha_agent_info):>8,}")
    log.info(f"    vulns_embedded:  {len(ha_vulns_embedded):>8,}")

    return {
        "ha_open_ports":     ha_open_ports,
        "ha_software":       ha_software,
        "ha_network_ifaces": ha_network_ifaces,
        "ha_volumes":        ha_volumes,
        "ha_accounts":       ha_accounts,
        "ha_processors":     ha_processors,
        "ha_tags":           ha_tags,
        "ha_source_info":    ha_source_info,
        "ha_agent_info":     ha_agent_info,
        "ha_vulns_embedded": ha_vulns_embedded,
    }


# ═══════════════════════════════════════════════════════════════
# BUILDERS: datos en memoria → filas para tablas DB
# ═══════════════════════════════════════════════════════════════

def build_qid_kb_rows(kb_data: List[Dict],
                      cve_mapping: List[Dict] = None) -> List[Dict]:
    """Construye filas para public.qualys_qid_kb."""
    if not kb_data:
        log.warning("No hay datos de KB — tabla qid_kb vacía")
        return []

    # Indexar CVE mapping por QID (si tenemos)
    cve_map_by_qid = defaultdict(list)
    for r in (cve_mapping or []):
        qid = str(r.get("QID", "")).strip()
        if qid:
            cve_map_by_qid[qid].append(r)

    rows = []
    for rec in kb_data:
        qid = _safe_int(rec.get("QID"))
        if not qid:
            continue

        qid_str = str(qid)
        cve_list = _split_cves(rec.get("CVE_IDS"))

        row = {
            "qid": qid,

            # Campos directos del KB
            "vuln_type":                rec.get("VULN_TYPE"),
            "severity_level":           _safe_int(rec.get("SEVERITY_LEVEL")),
            "title":                    rec.get("TITLE"),
            "category":                 rec.get("CATEGORY"),
            "last_service_modification_at": _to_dt(rec.get("LAST_SERVICE_MODIFICATION_DATETIME")),
            "published_at":             _to_dt(rec.get("PUBLISHED_DATETIME")),
            "code_modified_at":         _to_dt(rec.get("CODE_MODIFIED_DATETIME")),
            "patchable":                _safe_bool(rec.get("PATCHABLE")),
            "diagnosis":                rec.get("DIAGNOSIS"),
            "consequence":              rec.get("CONSEQUENCE"),
            "solution":                 rec.get("SOLUTION"),
            "pci_flag":                 _safe_bool(rec.get("PCI_FLAG")),
            "cve_ids_text":             rec.get("CVE_IDS"),
            "cve_count":                _safe_int(rec.get("CVE_COUNT")) or len(cve_list),
            "cve_urls_text":            rec.get("CVE_URLS"),
            "bugtraq_ids_text":         rec.get("BUGTRAQ_IDS"),
            "vendor_references_text":   rec.get("VENDOR_REFERENCES"),
            "software_affected_text":   rec.get("SOFTWARE_AFFECTED"),
            "threat_intelligence_text":  rec.get("THREAT_INTELLIGENCE"),
            "compliance_text":          rec.get("COMPLIANCE"),
            "discovery_auth_types_text": rec.get("DISCOVERY_AUTH_TYPES"),
            "technology_text":          rec.get("TECHNOLOGY"),

            # Campos kb_* (duplicados para compatibilidad con esquema)
            "kb_bugtraq_ids":           rec.get("BUGTRAQ_IDS"),
            "kb_category":              rec.get("CATEGORY"),
            "kb_compliance":            rec.get("COMPLIANCE"),
            "kb_consequence":           rec.get("CONSEQUENCE"),
            "kb_cve_ids":               rec.get("CVE_IDS"),
            "kb_cvss3_attack_complexity": rec.get("CVSS3_ATTACK_COMPLEXITY"),
            "kb_cvss3_attack_vector":   rec.get("CVSS3_ATTACK_VECTOR"),
            "kb_cvss3_base":            rec.get("CVSS3_BASE"),
            "kb_cvss3_privileges_req":  rec.get("CVSS3_PRIVILEGES_REQUIRED"),
            "kb_cvss3_temporal":        rec.get("CVSS3_TEMPORAL"),
            "kb_cvss3_vector":          rec.get("CVSS3_VECTOR"),
            "kb_cvss_base":             rec.get("CVSS_BASE"),
            "kb_cvss_temporal":         rec.get("CVSS_TEMPORAL"),
            "kb_cvss_vector":           rec.get("CVSS_VECTOR"),
            "kb_diagnosis":             rec.get("DIAGNOSIS"),
            "kb_last_modified_at":      _to_dt(rec.get("LAST_SERVICE_MODIFICATION_DATETIME")),
            "kb_patch_published_text":  rec.get("PATCH_PUBLISHED_DATE"),
            "kb_patchable":             _safe_bool(rec.get("PATCHABLE")),
            "kb_published_at":          _to_dt(rec.get("PUBLISHED_DATETIME")),
            "kb_severity":              _safe_int(rec.get("SEVERITY_LEVEL")),
            "kb_software_affected":     rec.get("SOFTWARE_AFFECTED"),
            "kb_solution":              rec.get("SOLUTION"),
            "kb_technology":            rec.get("TECHNOLOGY"),
            "kb_threat_intelligence":   rec.get("THREAT_INTELLIGENCE"),
            "kb_title":                 rec.get("TITLE"),
            "kb_vendor_refs":           rec.get("VENDOR_REFERENCES"),
            "kb_vuln_type":             rec.get("VULN_TYPE"),

            # JSONB
            "cve_mapping_entries_raw":  _wrap_json(cve_map_by_qid.get(qid_str) or None),
            "qvs_by_cve_raw":          None,
            "raw_knowledgebase_row":    _wrap_json(rec),
        }
        rows.append(row)

    log.info(f"  → qualys_qid_kb: {len(rows):,} QIDs")
    return rows


def build_asset_rows(hosts: List[Dict],
                     sub_data: Dict[str, List[Dict]]) -> List[Dict]:
    """Construye filas para public.qualys_asset."""
    if not hosts:
        log.warning("No hay host_assets — tabla qualys_asset vacía")
        return []

    # Agrupar sub-datos por hostAssetId
    sw_by_host     = _group_by(sub_data.get("ha_software", []), "hostAssetId")
    ports_by_host  = _group_by(sub_data.get("ha_open_ports", []), "hostAssetId")
    iface_by_host  = _group_by(sub_data.get("ha_network_ifaces", []), "hostAssetId")
    vol_by_host    = _group_by(sub_data.get("ha_volumes", []), "hostAssetId")
    acct_by_host   = _group_by(sub_data.get("ha_accounts", []), "hostAssetId")
    proc_by_host   = _group_by(sub_data.get("ha_processors", []), "hostAssetId")
    tags_by_host   = _group_by(sub_data.get("ha_tags", []), "hostAssetId")
    src_by_host    = _group_by(sub_data.get("ha_source_info", []), "hostAssetId")
    agent_by_host  = _group_by(sub_data.get("ha_agent_info", []), "hostAssetId")

    rows = []
    for a in hosts:
        hid = str(a.get("id", "")).strip()
        if not hid:
            continue

        # Source info
        src_list = src_by_host.get(hid, [])
        src = src_list[0] if src_list else {}

        # Agent info
        agent_list = agent_by_host.get(hid, [])

        # AgentInfo anidado
        ai = a.get("agentInfo") or {}
        if isinstance(ai, str):
            try:
                ai = json.loads(ai)
            except Exception:
                ai = {}
        ak = ai.get("activationKey") or {}
        if isinstance(ak, str):
            try:
                ak = json.loads(ak)
            except Exception:
                ak = {}
        ac = ai.get("agentConfiguration") or {}
        if isinstance(ac, str):
            try:
                ac = json.loads(ac)
            except Exception:
                ac = {}
        mv = ai.get("manifestVersion") or {}
        if isinstance(mv, str):
            try:
                mv = json.loads(mv)
            except Exception:
                mv = {}

        # Docker info
        di = a.get("dockerInfo") or {}
        if isinstance(di, str):
            try:
                di = json.loads(di)
            except Exception:
                di = {}

        row = {
            "host_asset_id":    _safe_int(hid),
            "qweb_host_id":     _safe_int(a.get("qwebHostId")),
            "network_guid":     a.get("networkGuid"),
            "name":             a.get("name") or a.get("n"),
            "dns_host_name":    a.get("dnsHostName"),
            "fqdn":             a.get("fqdn"),
            "netbios_name":     a.get("netbiosName"),
            "address":          _safe_inet(a.get("address")),
            "os":               a.get("os"),
            "manufacturer":     a.get("manufacturer"),
            "model":            a.get("model"),
            "bios_description": a.get("biosDescription"),
            "account":          _wrap_json(a.get("account")),
            "cloud_provider":   a.get("cloudProvider"),
            "tracking_method":  a.get("trackingMethod"),
            "asset_type":       a.get("type"),
            "timezone":         a.get("timezone"),
            "total_memory_mb":  _safe_int(a.get("totalMemory")),
            "created_at":                       _to_dt(a.get("created")),
            "modified_at":                      _to_dt(a.get("modified")),
            "information_gathered_updated_at":   _to_dt(a.get("informationGatheredUpdated")),
            "last_compliance_scan_at":          _to_dt(a.get("lastComplianceScan")),
            "last_vuln_scan_at":                _to_dt(a.get("lastVulnScan")),
            "last_system_boot_at":              _to_dt(a.get("lastSystemBoot")),
            "last_logged_on_user":              a.get("lastLoggedOnUser"),
            "vulns_updated_at":                 _to_dt(a.get("vulnsUpdated")),
            "is_docker_host":           _safe_bool(a.get("isDockerHost")),
            "docker_version":           di.get("dockerVersion"),
            "docker_no_of_containers":  _safe_int(di.get("noOfContainers")),
            "docker_no_of_images":      _safe_int(di.get("noOfImages")),
            "agent_activated_module":     ai.get("activatedModule"),
            "agent_activation_id":        ak.get("activationId"),
            "agent_activation_title":     ak.get("title"),
            "agent_configuration_id":     _safe_int(ac.get("id")),
            "agent_configuration_name":   ac.get("name"),
            "agent_id":                   ai.get("agentId"),
            "agent_version":              ai.get("agentVersion"),
            "agent_chirp_status":         ai.get("chirpStatus"),
            "agent_connected_from":       ai.get("connectedFrom"),
            "agent_last_checked_in_at":   _to_dt(ai.get("lastCheckedIn")),
            "agent_location":             ai.get("location"),
            "agent_location_geo_latitude":  _safe_numeric(ai.get("locationGeoLatitude")),
            "agent_location_geo_longitude": _safe_numeric(
                ai.get("locationGeoLongtitude") or ai.get("locationGeoLongitude")),
            "agent_manifest_sca":         mv.get("sca"),
            "agent_manifest_vm":          mv.get("vm"),
            "agent_platform":             ai.get("platform"),
            "agent_status":               ai.get("status"),
            "network_interface_raw":  _wrap_json(a.get("networkInterface")),
            "open_port_raw":          _wrap_json(a.get("openPort")),
            "processor_raw":          _wrap_json(a.get("processor")),
            "software_raw":           _wrap_json(a.get("software")),
            "source_info_raw":        _wrap_json(a.get("sourceInfo")),
            "tags_raw":               _wrap_json(a.get("tags")),
            "volume_raw":             _wrap_json(a.get("volume")),
            "vuln_raw":               _wrap_json(a.get("vuln")),
            "src_asset_id":             src.get("assetId"),
            "src_first_discovered_at":  _to_dt(src.get("firstDiscovered")),
            "src_gcp_instance_tags":    _wrap_json(src.get("gcpInstanceTags")),
            "src_host_asset_name":      src.get("hostAssetName"),
            "src_hostname":             src.get("hostname"),
            "src_image_id":             src.get("imageId"),
            "src_instance_id":          src.get("instanceId"),
            "src_last_updated_at":      _to_dt(src.get("lastUpdated")),
            "src_mac_address":          src.get("macAddress"),
            "src_machine_type":         src.get("machineType"),
            "src_network":              src.get("network"),
            "src_private_ip":           _safe_inet(src.get("privateIpAddress")),
            "src_project_id":           src.get("projectId"),
            "src_project_id_no":        src.get("projectIdNo"),
            "src_public_ip":            _safe_inet(src.get("publicIpAddress")),
            "src_state":                src.get("state"),
            "src_type":                 src.get("type"),
            "src_zone":                 src.get("zone"),
            "network_interfaces_export_raw": _wrap_json(iface_by_host.get(hid) or None),
            "volumes_export_raw":            _wrap_json(vol_by_host.get(hid) or None),
            "processors_export_raw":         _wrap_json(proc_by_host.get(hid) or None),
            "accounts_export_raw":           _wrap_json(acct_by_host.get(hid) or None),
            "software_export_raw":           _wrap_json(sw_by_host.get(hid) or None),
            "tags_assigned_export_raw":      _wrap_json(tags_by_host.get(hid) or None),
            "tags_catalog_export_raw":       None,
            "agent_info_export_raw":         _wrap_json(agent_list or None),
            "raw_host_assets_row": _wrap_json(a),
        }
        rows.append(row)

    log.info(f"  → qualys_asset: {len(rows):,} hosts")
    return rows


def build_finding_rows(vulns: List[Dict], kb_data: List[Dict],
                       asset_pk_map: Dict[int, int],
                       kb_qids: set) -> List[Dict]:
    """Construye filas para public.qualys_finding."""
    if not vulns:
        log.warning("No hay vulns — tabla qualys_finding vacía")
        return []

    kb_idx = {}
    for r in (kb_data or []):
        qid = str(r.get("QID", "")).strip()
        if qid:
            kb_idx[qid] = r

    rows = []
    skipped_no_asset = 0
    skipped_no_qid = 0

    for v in vulns:
        hid = _safe_int(v.get("hostAssetId"))
        qid = _safe_int(v.get("qid"))
        if not hid or not qid:
            continue

        apk = asset_pk_map.get(hid)
        if apk is None:
            skipped_no_asset += 1
            continue
        if qid not in kb_qids:
            skipped_no_qid += 1
            continue

        kb = kb_idx.get(str(qid), {})
        cve_ids = kb.get("CVE_IDS", "")
        cves = _split_cves(cve_ids)
        first_cve = cves[0] if cves else None

        row = {
            "asset_pk":         apk,
            "host_asset_id":    hid,
            "qid":              qid,
            "cve_id":           first_cve,
            "vuln_id":          _safe_int(v.get("id")),
            "disabled":         _safe_bool(v.get("disabled")),
            "first_found_at":   _to_dt(v.get("firstFound")),
            "found":            _safe_bool(v.get("found")),
            "ignored":          _safe_bool(v.get("ignored")),
            "last_found_at":    _to_dt(v.get("lastFound")),
            "last_scanned_at":  _to_dt(v.get("lastScanned")),
            "source":           v.get("source"),
            "ssl":              _safe_bool(v.get("ssl")),
            "updated_at":       _to_dt(v.get("updated")),
            "port_text":        str(v.get("port", "") or "").strip() or None,
            "protocol":         v.get("protocol"),
            "kb_cve_ids_text":  cve_ids or None,
            "raw_vulnerabilities_row":  _wrap_json(v),
            "raw_crossed_report_row":   None,
        }
        rows.append(row)

    if skipped_no_asset:
        log.info(f"  [WARN] {skipped_no_asset:,} vulns omitidas: host sin asset_pk")
    if skipped_no_qid:
        log.info(f"  [WARN] {skipped_no_qid:,} vulns omitidas: QID no en qid_kb")
    log.info(f"  → qualys_finding: {len(rows):,} filas")
    return rows


def build_evidence_rows(embedded: List[Dict],
                        asset_pk_map: Dict[int, int],
                        kb_qids: set) -> List[Dict]:
    """Construye filas para public.qualys_finding_evidence."""
    if not embedded:
        return []
    rows = []
    for e in embedded:
        hid = _safe_int(e.get("hostAssetId"))
        qid = _safe_int(e.get("qid"))
        if not hid or not qid:
            continue
        apk = asset_pk_map.get(hid)
        if apk is None:
            continue
        if qid not in kb_qids:
            continue
        rows.append({
            "asset_pk":              apk,
            "host_asset_id":         hid,
            "qid":                   qid,
            "first_found_at":        _to_dt(e.get("firstFound")),
            "host_asset_name":       e.get("hostAssetName"),
            "host_instance_vuln_id": _safe_int(e.get("hostInstanceVulnId")),
            "last_found_at":         _to_dt(e.get("lastFound")),
            "raw_vulns_embedded_row": _wrap_json(e),
        })
    log.info(f"  → qualys_finding_evidence: {len(rows):,} filas")
    return rows


def build_open_port_rows(ports: List[Dict],
                         asset_pk_map: Dict[int, int]) -> List[Dict]:
    """Construye filas para public.qualys_asset_open_port."""
    if not ports:
        return []
    rows = []
    for p in ports:
        hid = _safe_int(p.get("hostAssetId"))
        if not hid:
            continue
        apk = asset_pk_map.get(hid)
        if apk is None:
            continue
        rows.append({
            "asset_pk":         apk,
            "host_asset_id":    hid,
            "host_asset_name":  p.get("hostAssetName"),
            "port":             _safe_int(p.get("port")),
            "protocol":         p.get("protocol"),
            "service_name":     p.get("serviceName"),
            "raw_open_ports_row": _wrap_json(p),
        })
    log.info(f"  → qualys_asset_open_port: {len(rows):,} filas")
    return rows


# ═══════════════════════════════════════════════════════════════
# DB OPERATIONS
# ═══════════════════════════════════════════════════════════════

def _exec_values(cur, query: str, rows: List[Dict], columns: List[str],
                 page_size: int = 5000):
    values = []
    for r in rows:
        values.append(tuple(r.get(c) for c in columns))
    template = "(" + ",".join(["%s"] * len(columns)) + ")"
    execute_values(cur, query, values, template=template, page_size=page_size)


def upsert_qid_kb(cur, rows: List[Dict], page_size: int = 5000):
    if not rows:
        return 0
    cols = list(rows[0].keys())
    col_sql = ", ".join(f'"{c}"' for c in cols)
    upd_cols = [c for c in cols if c != "qid"]
    upd_sql = ", ".join(f'"{c}"=EXCLUDED."{c}"' for c in upd_cols)
    q = (f'INSERT INTO public.qualys_qid_kb ({col_sql}) VALUES %s '
         f'ON CONFLICT (qid) DO UPDATE SET {upd_sql}')
    _exec_values(cur, q, rows, cols, page_size)
    return len(rows)


def upsert_assets(cur, rows: List[Dict], page_size: int = 5000):
    if not rows:
        return 0
    cols = list(rows[0].keys())
    col_sql = ", ".join(f'"{c}"' for c in cols)
    upd_cols = [c for c in cols if c != "host_asset_id"]
    upd_sql = ", ".join(f'"{c}"=EXCLUDED."{c}"' for c in upd_cols)
    q = (f'INSERT INTO public.qualys_asset ({col_sql}) VALUES %s '
         f'ON CONFLICT (host_asset_id) DO UPDATE SET {upd_sql}')
    _exec_values(cur, q, rows, cols, page_size)
    return len(rows)


def get_asset_pk_map(cur) -> Dict[int, int]:
    cur.execute("SELECT host_asset_id, asset_pk FROM public.qualys_asset "
                "WHERE host_asset_id IS NOT NULL")
    return {int(r[0]): int(r[1]) for r in cur.fetchall()}


def get_kb_qids(cur) -> set:
    cur.execute("SELECT qid FROM public.qualys_qid_kb")
    return {int(r[0]) for r in cur.fetchall()}


def insert_findings(cur, rows: List[Dict], page_size: int = 5000):
    if not rows:
        return 0
    hids = list(set(r["host_asset_id"] for r in rows if r.get("host_asset_id")))
    if hids:
        cur.execute("DELETE FROM public.qualys_finding WHERE host_asset_id = ANY(%s)", (hids,))
    cols = list(rows[0].keys())
    col_sql = ", ".join(f'"{c}"' for c in cols)
    q = f'INSERT INTO public.qualys_finding ({col_sql}) VALUES %s'
    _exec_values(cur, q, rows, cols, page_size)
    return len(rows)


def insert_evidence(cur, rows: List[Dict], page_size: int = 5000):
    if not rows:
        return 0
    hids = list(set(r["host_asset_id"] for r in rows if r.get("host_asset_id")))
    if hids:
        cur.execute("DELETE FROM public.qualys_finding_evidence WHERE host_asset_id = ANY(%s)",
                    (hids,))
    cols = list(rows[0].keys())
    col_sql = ", ".join(f'"{c}"' for c in cols)
    q = f'INSERT INTO public.qualys_finding_evidence ({col_sql}) VALUES %s'
    _exec_values(cur, q, rows, cols, page_size)
    return len(rows)


def insert_open_ports(cur, rows: List[Dict], page_size: int = 5000):
    if not rows:
        return 0
    hids = list(set(r["host_asset_id"] for r in rows if r.get("host_asset_id")))
    if hids:
        cur.execute("DELETE FROM public.qualys_asset_open_port WHERE host_asset_id = ANY(%s)",
                    (hids,))
    cols = list(rows[0].keys())
    col_sql = ", ".join(f'"{c}"' for c in cols)
    q = f'INSERT INTO public.qualys_asset_open_port ({col_sql}) VALUES %s'
    _exec_values(cur, q, rows, cols, page_size)
    return len(rows)


def ensure_qids_exist(cur, records: List[Dict], kb_qids: set) -> set:
    """Inserta QIDs mínimos faltantes para satisfacer FK."""
    needed = set()
    for v in records:
        qid = _safe_int(v.get("qid"))
        if qid and qid not in kb_qids:
            needed.add(qid)
    if not needed:
        return kb_qids
    log.info(f"  Insertando {len(needed):,} QIDs mínimos faltantes en qid_kb...")
    minimal = [{"qid": q, "title": f"(QID {q} — sin datos de KB)"} for q in sorted(needed)]
    cols = ["qid", "title"]
    col_sql = ", ".join(f'"{c}"' for c in cols)
    q = f'INSERT INTO public.qualys_qid_kb ({col_sql}) VALUES %s ON CONFLICT (qid) DO NOTHING'
    _exec_values(cur, q, minimal, cols)
    return kb_qids | needed


# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════

def main():
    print()
    print("╔" + "═" * 68 + "╗")
    print("║  QUALYS → PostgreSQL  (Extracción directa a BD)                  ║")
    print("╚" + "═" * 68 + "╝")
    print()

    # ── Diagnóstico de credenciales ──
    src_q_user = "Docker secret" if _read_secret("qualys_username") else (
                 "env var" if os.environ.get("QUALYS_USERNAME") else "NO ENCONTRADO")
    src_q_pass = "Docker secret" if _read_secret("qualys_password") else (
                 "env var" if os.environ.get("QUALYS_PASSWORD") else "NO ENCONTRADO")
    src_q_url  = "Docker secret" if _read_secret("qualys_base_url") else (
                 "env var" if os.environ.get("QUALYS_BASE_URL") else "default")
    src_d_user = "Docker secret" if _read_secret("postgres_user") else (
                 "env var" if os.environ.get("DATABASE_USER") or os.environ.get("PGUSER") else "NO ENCONTRADO")
    src_d_pass = "Docker secret" if _read_secret("postgres_password") else (
                 "env var" if os.environ.get("DATABASE_PASSWORD") or os.environ.get("PGPASSWORD") else "NO ENCONTRADO")

    log.info("Credenciales Qualys:")
    log.info(f"  Username:  {src_q_user} → {'✓ ' + QUALYS_USERNAME[:3] + '***' if QUALYS_USERNAME else '✗ vacío'}")
    log.info(f"  Password:  {src_q_pass} → {'✓ ****' if QUALYS_PASSWORD else '✗ vacío'}")
    log.info(f"  Base URL:  {src_q_url} → {QUALYS_BASE_URL}")
    log.info("Credenciales DB:")
    log.info(f"  DB User:   {src_d_user}")
    log.info(f"  DB Pass:   {src_d_pass}")

    if not QUALYS_USERNAME or not QUALYS_PASSWORD:
        log.error("\n✗ Credenciales Qualys requeridas:")
        log.error("  Docker secrets: /run/secrets/qualys_username, qualys_password")
        log.error("  O env vars: QUALYS_USERNAME, QUALYS_PASSWORD")
        sys.exit(1)

    # ── Verificar Qualys ──
    ext = QualysExtractor()
    if not ext.verify():
        sys.exit(1)

    # ── Verificar DB ──
    db_cfg = get_db_config()
    conn = connect_db(db_cfg)

    t0 = time.time()

    # ══════════════════════════════════════════════════════
    # EXTRACCIÓN (Qualys API → memoria)
    # ══════════════════════════════════════════════════════

    # PASO 1: Hosts
    try:
        hosts = ext.extract_hosts()
    except Exception as e:
        log.error(f"Error extrayendo hosts: {e}")
        hosts = []

    # PASO 2: Vulnerabilidades
    try:
        vulns = ext.extract_vulns()
    except Exception as e:
        log.error(f"Error extrayendo vulns: {e}")
        vulns = []

    # Recolectar QIDs únicos
    qid_set = set()
    for v in vulns:
        q = v.get("qid", "")
        if q:
            qid_set.add(int(q))
    for h in hosts:
        vl = h.get("vuln", {})
        if isinstance(vl, list):
            for vv in vl:
                if isinstance(vv, dict):
                    q = vv.get("qid", "")
                    if q:
                        qid_set.add(int(q))
    qids = sorted(qid_set)

    # PASO 3: KnowledgeBase
    try:
        kb_data = ext.extract_kb(qids)
    except Exception as e:
        log.error(f"Error en KB: {e}")
        kb_data = []

    # Descomponer hosts en sub-datos
    log.info("━" * 60)
    log.info("📊 Descomponiendo sub-datos de hosts...")
    sub_data = decompose_hosts(hosts)

    # ══════════════════════════════════════════════════════
    # TRANSFORMACIÓN (memoria → filas DB)
    # ══════════════════════════════════════════════════════
    log.info("━" * 60)
    log.info("📊 Transformando datos → filas DB")

    qid_kb_rows = build_qid_kb_rows(kb_data)
    asset_rows  = build_asset_rows(hosts, sub_data)

    # ══════════════════════════════════════════════════════
    # CARGA (filas → PostgreSQL)
    # ══════════════════════════════════════════════════════
    log.info("━" * 60)
    log.info("💾 Insertando en PostgreSQL...")

    stats = {}
    try:
        with conn.cursor() as cur:

            # [1/5] UPSERT qid_kb
            log.info(f"  [1/5] UPSERT public.qualys_qid_kb ({len(qid_kb_rows):,} QIDs)...")
            n = upsert_qid_kb(cur, qid_kb_rows, DB_PAGE_SIZE)
            stats["qid_kb"] = n
            log.info(f"         ✓ {n:,} filas")

            # [2/5] UPSERT assets
            log.info(f"  [2/5] UPSERT public.qualys_asset ({len(asset_rows):,} hosts)...")
            n = upsert_assets(cur, asset_rows, DB_PAGE_SIZE)
            stats["assets"] = n
            log.info(f"         ✓ {n:,} filas")

            # Obtener mapas FK
            asset_pk_map = get_asset_pk_map(cur)
            log.info(f"         → Mapa asset_pk: {len(asset_pk_map):,} entradas")

            kb_qids = get_kb_qids(cur)

            # Asegurar QIDs faltantes para vulns
            kb_qids = ensure_qids_exist(cur, vulns, kb_qids)
            # Asegurar QIDs faltantes para vulns embedded
            kb_qids = ensure_qids_exist(
                cur, sub_data.get("ha_vulns_embedded", []), kb_qids)
            kb_qids = get_kb_qids(cur)

            # [3/5] INSERT findings
            finding_rows = build_finding_rows(vulns, kb_data, asset_pk_map, kb_qids)
            log.info(f"  [3/5] INSERT public.qualys_finding ({len(finding_rows):,} vulns)...")
            n = insert_findings(cur, finding_rows, DB_PAGE_SIZE)
            stats["findings"] = n
            log.info(f"         ✓ {n:,} filas")

            # [4/5] INSERT evidence
            evidence_rows = build_evidence_rows(
                sub_data.get("ha_vulns_embedded", []), asset_pk_map, kb_qids)
            log.info(f"  [4/5] INSERT public.qualys_finding_evidence ({len(evidence_rows):,})...")
            n = insert_evidence(cur, evidence_rows, DB_PAGE_SIZE)
            stats["evidence"] = n
            log.info(f"         ✓ {n:,} filas")

            # [5/5] INSERT open ports
            port_rows = build_open_port_rows(
                sub_data.get("ha_open_ports", []), asset_pk_map)
            log.info(f"  [5/5] INSERT public.qualys_asset_open_port ({len(port_rows):,})...")
            n = insert_open_ports(cur, port_rows, DB_PAGE_SIZE)
            stats["open_ports"] = n
            log.info(f"         ✓ {n:,} filas")

        conn.commit()
        elapsed = time.time() - t0

        print()
        print("╔" + "═" * 68 + "╗")
        print("║  ✓ QUALYS → PostgreSQL COMPLETADO                                ║")
        print("╠" + "═" * 68 + "╣")
        print(f"║  Hosts extraídos:         {len(hosts):>10,}                           ║")
        print(f"║  Vulns extraídas:         {len(vulns):>10,}                           ║")
        print(f"║  KB QIDs:                 {len(kb_data):>10,}                           ║")
        print("╠" + "═" * 68 + "╣")
        print(f"║  qualys_qid_kb:           {stats.get('qid_kb',0):>10,} filas                   ║")
        print(f"║  qualys_asset:            {stats.get('assets',0):>10,} filas                   ║")
        print(f"║  qualys_finding:          {stats.get('findings',0):>10,} filas                   ║")
        print(f"║  qualys_finding_evidence: {stats.get('evidence',0):>10,} filas                   ║")
        print(f"║  qualys_asset_open_port:  {stats.get('open_ports',0):>10,} filas                   ║")
        print("╠" + "═" * 68 + "╣")
        print(f"║  Tiempo total:            {elapsed:>8.1f}s                           ║")
        print("╚" + "═" * 68 + "╝")
        print()

    except Exception as e:
        conn.rollback()
        log.error(f"\n✗ Error en carga a DB: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
