#!/usr/bin/env python3
"""
VulncheckDB - Simplified PostgreSQL CVE enrichment for vAnalyzer
Reliable vulnerability data enrichment integrated with activevulnerabilities table
"""

import os
import sys
import json
import zipfile
import logging
import requests
import pandas as pd
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime, timedelta
from sqlalchemy import create_engine, text
import urllib.parse

try:
    import psycopg2
    import psycopg2.extras
except ImportError:
    print("Error: psycopg2 not found. Install with: pip install psycopg2-binary")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=getattr(logging, os.getenv('LOG_LEVEL', 'INFO')),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('vulncheck_pg')


class VulncheckDB:
    """Simplified vulncheck integration for vAnalyzer"""
    
    def __init__(self, db_connection=None):
        """
        Initialize VulncheckDB for vAnalyzer integration
        
        Args:
            db_connection: Database connection (if None, creates from environment)
        """
        # Database connection
        if db_connection:
            self.conn = db_connection
            self.own_connection = False
        else:
            self.conn = self._get_db_connection()
            self.own_connection = True
            
        # Create SQLAlchemy engine for pandas operations
        # Use the Docker secrets method for reliable database connection
        self.engine = self._get_sqlalchemy_engine()
        
        # Configuration
        self.data_dir = Path(os.getenv('VULNCHECK_DATA_DIR', '/var/vulncheck_data'))
        if not self.data_dir.exists():
            self.data_dir.mkdir(parents=True)
        
        self.enabled_indexes = ['exploits', 'vulncheck-kev']
        self.batch_size = 100
        self.api_token = self._get_api_token()
        
        logger.info(f"Initialized VulncheckDB with data dir: {self.data_dir}")
    
    def _get_db_connection(self):
        """Get database connection from Docker secrets or environment"""
        try:
            # Try Docker secrets first
            host = "appdb"
            port = "5432"
            user = self._read_secret('postgres_user')
            password = self._read_secret('postgres_password')
            database = self._read_secret('postgres_db')
            
            if not all([user, password, database]):
                raise ValueError("Missing database credentials")
            
            conn = psycopg2.connect(
                host=host, port=port, user=user, password=password, database=database
            )
            return conn
            
        except Exception as e:
            logger.error(f"Failed to connect to database: {e}")
            raise
    
    def _read_secret(self, secret_name: str) -> Optional[str]:
        """Read Docker secret"""
        try:
            with open(f'/run/secrets/{secret_name}', 'r') as f:
                return f.read().strip()
        except:
            return os.getenv(secret_name.upper())
    
    def _get_sqlalchemy_engine(self):
        """Get SQLAlchemy engine"""
        user = self._read_secret('postgres_user')
        password = self._read_secret('postgres_password')
        database = self._read_secret('postgres_db')

        password_encoded = urllib.parse.quote_plus(password)
        return create_engine(f'postgresql://{user}:{password_encoded}@appdb:5432/{database}')
    
    def _get_api_token(self) -> Optional[str]:
        """Get vulncheck API token"""
        # Try Docker secret first
        token = self._read_secret('vulncheck_api_key')
        if not token:
            token = os.getenv('VULNCHECK_API_KEY')
        return token
    
    def setup_tables(self) -> bool:
        """Create separate vulncheck tables for exploits and kev data"""
        try:
            exploits_success = self.setup_exploits_table()
            kev_success = self.setup_kev_table()
            return exploits_success and kev_success
        except Exception as e:
            logger.error(f"Failed to setup vulncheck tables: {e}")
            return False
    
    def setup_exploits_table(self) -> bool:
        """Create vulncheck_exploits table for exploit intelligence data"""
        try:
            with self.conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS vulncheck_exploits (
                        cve_id VARCHAR(20) PRIMARY KEY,
                        
                        -- Status tracking
                        is_active BOOLEAN DEFAULT TRUE,
                        last_updated TIMESTAMP DEFAULT NOW(),
                        
                        -- Exploit intelligence boolean flags
                        public_exploit_found BOOLEAN DEFAULT FALSE,
                        commercial_exploit_found BOOLEAN DEFAULT FALSE,
                        weaponized_exploit_found BOOLEAN DEFAULT FALSE,
                        reported_exploited_by_honeypot_service BOOLEAN DEFAULT FALSE,
                        reported_exploited BOOLEAN DEFAULT FALSE,
                        reported_exploited_by_threat_actors BOOLEAN DEFAULT FALSE,
                        reported_exploited_by_ransomware BOOLEAN DEFAULT FALSE,
                        reported_exploited_by_botnets BOOLEAN DEFAULT FALSE,
                        in_kev BOOLEAN DEFAULT FALSE,
                        in_vckev BOOLEAN DEFAULT FALSE,
                        trending_github BOOLEAN DEFAULT FALSE,
                        
                        -- Exploit metadata
                        max_exploit_maturity VARCHAR(50),
                        
                        -- Threat intelligence counts
                        exploits_count INTEGER DEFAULT 0,
                        threat_actors_count INTEGER DEFAULT 0,
                        botnets_count INTEGER DEFAULT 0,
                        ransomware_families_count INTEGER DEFAULT 0,
                        
                        -- EPSS scoring
                        epss_score DECIMAL(10,8),
                        epss_percentile DECIMAL(10,8),
                        epss_last_modified TIMESTAMP,
                        
                        -- Timeline data
                        nvd_published TIMESTAMP,
                        first_exploit_published TIMESTAMP,
                        most_recent_exploit_published TIMESTAMP,
                        
                        -- Raw exploit data for complex queries
                        exploits_raw JSONB
                    )
                """)
                
                # Create performance indexes for exploits
                cur.execute("CREATE INDEX IF NOT EXISTS idx_exploits_active ON vulncheck_exploits(is_active)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_exploits_weaponized ON vulncheck_exploits(weaponized_exploit_found)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_exploits_maturity ON vulncheck_exploits(max_exploit_maturity)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_exploits_updated ON vulncheck_exploits(last_updated)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_exploits_epss ON vulncheck_exploits(epss_score)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_exploits_ransomware ON vulncheck_exploits(reported_exploited_by_ransomware)")
                
                self.conn.commit()
                logger.info("VulnCheck exploits table created successfully")
                return True
                
        except Exception as e:
            logger.error(f"Failed to setup exploits table: {e}")
            self.conn.rollback()
            return False
    
    def setup_kev_table(self) -> bool:
        """Create vulncheck_kev table for VulnCheck-KEV data"""
        try:
            with self.conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS vulncheck_kev (
                        cve_id VARCHAR(20) PRIMARY KEY,
                        
                        -- Status tracking
                        is_active BOOLEAN DEFAULT TRUE,
                        last_updated TIMESTAMP DEFAULT NOW(),
                        
                        -- VulnCheck-KEV specific fields
                        vendor_project VARCHAR(255),
                        product VARCHAR(255),
                        vulnerability_name VARCHAR(500),
                        short_description TEXT,
                        required_action TEXT,
                        
                        -- Ransomware intelligence
                        known_ransomware_campaign_use VARCHAR(50),
                        
                        -- CISA KEV dates
                        due_date DATE,
                        cisa_date_added DATE,
                        date_added DATE,
                        
                        -- VulnCheck additional intelligence
                        vulncheck_xdb JSONB,
                        vulncheck_reported_exploitation JSONB,
                        cwes TEXT,
                        
                        -- Raw VulnCheck-KEV data
                        kev_raw JSONB
                    )
                """)
                
                # Create performance indexes for KEV
                cur.execute("CREATE INDEX IF NOT EXISTS idx_kev_active ON vulncheck_kev(is_active)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_kev_ransomware ON vulncheck_kev(known_ransomware_campaign_use)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_kev_updated ON vulncheck_kev(last_updated)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_kev_vendor ON vulncheck_kev(vendor_project)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_kev_due_date ON vulncheck_kev(due_date)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_kev_cisa_added ON vulncheck_kev(cisa_date_added)")
                
                self.conn.commit()
                logger.info("VulnCheck-KEV table created successfully")
                return True
                
        except Exception as e:
            logger.error(f"Failed to setup KEV table: {e}")
            self.conn.rollback()
            return False
    
    def download_vulncheck_data(self, force: bool = False) -> bool:
        """
        Download vulncheck data using direct API calls
        
        Args:
            force: Force re-download even if files exist
            
        Returns:
            True if successful
        """
        if not self.api_token:
            logger.error("No vulncheck API token available")
            return False
        
        success_count = 0
        
        for index_name in self.enabled_indexes:
            try:
                index_file = self.data_dir / f"{index_name}.zip"
                
                # Check if fresh data exists (less than 24 hours old)
                if not force and index_file.exists():
                    file_age = datetime.now() - datetime.fromtimestamp(index_file.stat().st_mtime)
                    if file_age < timedelta(hours=24):
                        logger.info(f"Using existing {index_name} data (age: {file_age})")
                        success_count += 1
                        continue
                
                logger.info(f"Downloading {index_name} index...")
                
                # Download from vulncheck API
                url = f"https://api.vulncheck.com/v3/index/{index_name}"
                headers = {
                    'Authorization': f'Bearer {self.api_token}',
                    'Accept': 'application/zip'
                }
                
                response = requests.get(url, headers=headers, timeout=300)
                
                if response.status_code == 200:
                    # Save to file
                    with open(index_file, 'wb') as f:
                        f.write(response.content)
                    
                    logger.info(f"Successfully downloaded {index_name} ({len(response.content)} bytes)")
                    success_count += 1
                else:
                    logger.error(f"Failed to download {index_name}: HTTP {response.status_code}")
                    
            except Exception as e:
                logger.error(f"Error downloading {index_name}: {e}")
        
        logger.info(f"Download completed: {success_count}/{len(self.enabled_indexes)} indexes")
        return success_count > 0
    
    def sync_active_vulnerabilities(self) -> bool:
        """
        Main sync function - processes both exploits and vulncheck-kev data separately
        """
        try:
            # Get current active CVEs
            active_cves = self._get_active_cves()
            logger.info(f"Found {len(active_cves)} active CVEs")
            
            # Sync exploits data independently
            exploits_success = self.sync_exploits_data(active_cves)
            
            # Sync vulncheck-kev data independently  
            kev_success = self.sync_kev_data(active_cves)
            
            # Return success if at least one succeeded
            return exploits_success or kev_success
            
        except Exception as e:
            logger.error(f"Sync failed: {e}")
            return False
    
    def sync_exploits_data(self, active_cves: List[str]) -> bool:
        """Sync exploits data to vulncheck_exploits table"""
        try:
            logger.info("=== Syncing Exploits Data ===")
            
            # Update active status in exploits table
            self._update_exploits_active_status(active_cves)
            
            # Get CVEs needing exploits enrichment
            cves_to_enrich = self._get_exploits_cves_needing_enrichment()
            
            if not cves_to_enrich:
                logger.info("No CVEs need exploits enrichment")
                return True
            
            # Ensure exploits data is available
            if not self._ensure_exploits_data():
                logger.error("Exploits data not available")
                return False
            
            logger.info(f"Processing {len(cves_to_enrich)} CVEs for exploits enrichment")
            
            # Process exploits data
            return self._process_exploits_data(cves_to_enrich)
            
        except Exception as e:
            logger.error(f"Exploits sync failed: {e}")
            return False
    
    def sync_kev_data(self, active_cves: List[str]) -> bool:
        """Sync vulncheck-kev data to vulncheck_kev table"""
        try:
            logger.info("=== Syncing VulnCheck-KEV Data ===")
            
            # Update active status in kev table
            self._update_kev_active_status(active_cves)
            
            # Get CVEs needing KEV enrichment
            cves_to_enrich = self._get_kev_cves_needing_enrichment()
            
            if not cves_to_enrich:
                logger.info("No CVEs need KEV enrichment")
                return True
            
            # Ensure KEV data is available
            if not self._ensure_kev_data():
                logger.error("VulnCheck-KEV data not available")
                return False
            
            logger.info(f"Processing {len(cves_to_enrich)} CVEs for KEV enrichment")
            
            # Process KEV data
            return self._process_kev_data(cves_to_enrich)
            
        except Exception as e:
            logger.error(f"KEV sync failed: {e}")
            return False
    
    def _get_active_cves(self) -> List[str]:
        """Get CVEs from activevulnerabilities table"""
        with self.conn.cursor() as cur:
            cur.execute("SELECT DISTINCT cve FROM activevulnerabilities WHERE cve IS NOT NULL")
            return [row[0] for row in cur.fetchall()]
    
    def _update_exploits_active_status(self, active_cves: List[str]):
        """Update active status in vulncheck_exploits table"""
        with self.conn.cursor() as cur:
            # Mark all as inactive first
            cur.execute("UPDATE vulncheck_exploits SET is_active = false WHERE is_active = true")
            
            if active_cves:
                # Mark active ones and insert new ones
                cur.execute(
                    "UPDATE vulncheck_exploits SET is_active = true WHERE cve_id = ANY(%s)",
                    (active_cves,)
                )
                
                # Insert new CVEs
                cur.execute("""
                    INSERT INTO vulncheck_exploits (cve_id, is_active) 
                    SELECT unnest(%s), true 
                    ON CONFLICT (cve_id) DO UPDATE SET is_active = true
                """, (active_cves,))
            
            self.conn.commit()
            logger.info(f"Updated exploits active status for {len(active_cves)} CVEs")
    
    def _update_kev_active_status(self, active_cves: List[str]):
        """Update active status in vulncheck_kev table"""
        with self.conn.cursor() as cur:
            # Mark all as inactive first
            cur.execute("UPDATE vulncheck_kev SET is_active = false WHERE is_active = true")
            
            if active_cves:
                # Mark active ones and insert new ones
                cur.execute(
                    "UPDATE vulncheck_kev SET is_active = true WHERE cve_id = ANY(%s)",
                    (active_cves,)
                )
                
                # Insert new CVEs
                cur.execute("""
                    INSERT INTO vulncheck_kev (cve_id, is_active) 
                    SELECT unnest(%s), true 
                    ON CONFLICT (cve_id) DO UPDATE SET is_active = true
                """, (active_cves,))
            
            self.conn.commit()
            logger.info(f"Updated KEV active status for {len(active_cves)} CVEs")
    
    def _get_exploits_cves_needing_enrichment(self) -> List[str]:
        """Get CVEs needing exploits enrichment (new or >7 days old)"""
        with self.conn.cursor() as cur:
            cur.execute("""
                SELECT cve_id FROM vulncheck_exploits 
                WHERE is_active = true 
                AND (
                    exploits_raw IS NULL 
                    OR last_updated < NOW() - INTERVAL '7 days'
                )
                ORDER BY last_updated ASC NULLS FIRST
                LIMIT 1000
            """)
            return [row[0] for row in cur.fetchall()]
    
    def _get_kev_cves_needing_enrichment(self) -> List[str]:
        """Get CVEs needing KEV enrichment (new or >7 days old)"""
        with self.conn.cursor() as cur:
            cur.execute("""
                SELECT cve_id FROM vulncheck_kev 
                WHERE is_active = true 
                AND (
                    kev_raw IS NULL 
                    OR last_updated < NOW() - INTERVAL '7 days'
                )
                ORDER BY last_updated ASC NULLS FIRST
                LIMIT 1000
            """)
            return [row[0] for row in cur.fetchall()]
    
    def _ensure_exploits_data(self) -> bool:
        """Ensure exploits index data is available and fresh"""
        try:
            exploits_file = self.data_dir / "exploits.zip"
            
            # Check if file exists and is fresh (< 24 hours)
            if exploits_file.exists():
                file_age = datetime.now() - datetime.fromtimestamp(exploits_file.stat().st_mtime)
                if file_age < timedelta(hours=24):
                    logger.info("Using existing exploits data")
                    return True
            
            # Download exploits index
            logger.info("Downloading exploits index...")
            return self._download_single_index("exploits")
            
        except Exception as e:
            logger.error(f"Failed to ensure exploits data: {e}")
            return False
    
    def _ensure_kev_data(self) -> bool:
        """Ensure KEV index data is available and fresh"""
        try:
            kev_file = self.data_dir / "vulncheck-kev.zip"
            
            # Check if file exists and is fresh (< 24 hours)
            if kev_file.exists():
                file_age = datetime.now() - datetime.fromtimestamp(kev_file.stat().st_mtime)
                if file_age < timedelta(hours=24):
                    logger.info("Using existing KEV data")
                    return True
            
            # Download KEV index
            logger.info("Downloading vulncheck-kev index...")
            return self._download_single_index("vulncheck-kev")
            
        except Exception as e:
            logger.error(f"Failed to ensure KEV data: {e}")
            return False
            
    def _download_single_index(self, index_name: str) -> bool:
        """Download a single vulncheck index using backup API"""
        if not self.api_token:
            logger.error("No vulncheck API token available")
            return False
            
        try:
            # Use vulncheck SDK for backup download (returns actual zip files)
            import vulncheck_sdk
            from vulncheck_sdk.rest import ApiException
            
            configuration = vulncheck_sdk.Configuration(host="https://api.vulncheck.com/v3")
            configuration.api_key["Bearer"] = self.api_token
            
            with vulncheck_sdk.ApiClient(configuration) as api_client:
                endpoints_client = vulncheck_sdk.EndpointsApi(api_client)
                
                # Get backup URL
                api_response = endpoints_client.backup_index_get(index_name)
                
                if not api_response.data:
                    logger.error(f"No backup data available for index '{index_name}'")
                    return False
                
                backup_url = api_response.data[0].url
                logger.info(f"Downloading {index_name} backup from URL")
                
                # Download the zip file
                response = requests.get(backup_url, stream=True, timeout=300)
                response.raise_for_status()
                
                # Save to file
                index_file = self.data_dir / f"{index_name}.zip"
                with open(index_file, "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                
                file_size_mb = index_file.stat().st_size / (1024 * 1024)
                logger.info(f"Successfully downloaded {index_name}: {file_size_mb:.2f} MB")
                return True
                
        except ImportError:
            logger.error("vulncheck_sdk not available - falling back to direct API")
            return self._download_single_index_direct(index_name)
        except ApiException as e:
            logger.error(f"API Exception for '{index_name}': {e.status} - {e.reason}")
            return False
        except Exception as e:
            logger.error(f"Failed to download {index_name}: {e}")
            return False
    
    def _process_exploits_data(self, cve_list: List[str]) -> bool:
        """Process exploits data for CVEs"""
        try:
            exploits_lookup = self._load_exploits_data()
            if not exploits_lookup:
                logger.error("No exploits data available")
                return False
            
            success_count = 0
            # Process in batches
            for i in range(0, len(cve_list), self.batch_size):
                batch = cve_list[i:i + self.batch_size]
                logger.info(f"Processing exploits batch {i//self.batch_size + 1}: {len(batch)} CVEs")
                
                # Get exploits data for batch
                batch_data = {}
                for cve_id in batch:
                    if cve_id in exploits_lookup:
                        extracted_data = self._extract_exploits_fields(exploits_lookup[cve_id])
                        batch_data[cve_id] = extracted_data
                    else:
                        # Still create record to mark as processed
                        batch_data[cve_id] = {'cve_id': cve_id}
                
                if batch_data:
                    self._store_exploits_batch(batch_data)
                    success_count += len(batch_data)
            
            logger.info(f"Processed exploits data for {success_count}/{len(cve_list)} CVEs")
            return success_count > 0
            
        except Exception as e:
            logger.error(f"Exploits processing failed: {e}")
            return False
    
    def _process_kev_data(self, cve_list: List[str]) -> bool:
        """Process KEV data for CVEs"""
        try:
            kev_lookup = self._load_kev_data()
            if not kev_lookup:
                logger.error("No KEV data available")
                return False
            
            success_count = 0
            # Process in batches
            for i in range(0, len(cve_list), self.batch_size):
                batch = cve_list[i:i + self.batch_size]
                logger.info(f"Processing KEV batch {i//self.batch_size + 1}: {len(batch)} CVEs")
                
                # Get KEV data for batch
                batch_data = {}
                for cve_id in batch:
                    if cve_id in kev_lookup:
                        extracted_data = self._extract_kev_fields(kev_lookup[cve_id])
                        batch_data[cve_id] = extracted_data
                    else:
                        # Still create record to mark as processed
                        batch_data[cve_id] = {'cve_id': cve_id}
                
                if batch_data:
                    self._store_kev_batch(batch_data)
                    success_count += len(batch_data)
            
            logger.info(f"Processed KEV data for {success_count}/{len(cve_list)} CVEs")
            return success_count > 0
            
        except Exception as e:
            logger.error(f"KEV processing failed: {e}")
            return False
    
    def _download_single_index_direct(self, index_name: str) -> bool:
        """Fallback direct API download (returns JSON)"""
        try:
            headers = {
                'Authorization': f'Bearer {self.api_token}',
                'User-Agent': 'vAnalyzer-vulncheck-integration/1.0'
            }
            
            url = f"https://api.vulncheck.com/v3/index/{index_name}"
            logger.info(f"Downloading {index_name} from {url} (direct API)")
            
            response = requests.get(url, headers=headers, timeout=300, stream=True)
            response.raise_for_status()
            
            # Save to file
            index_file = self.data_dir / f"{index_name}.zip"
            with open(index_file, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            logger.info(f"Successfully downloaded {index_name}: {index_file.stat().st_size} bytes")
            return True
            
        except Exception as e:
            logger.error(f"Failed to download {index_name}: {e}")
            return False
    
    
    def _load_exploits_data(self) -> Dict[str, Dict]:
        """Load exploits data and create CVE lookup dictionary"""
        exploits_lookup = {}
        exploits_file = self.data_dir / "exploits.zip"
        
        if not exploits_file.exists():
            return exploits_lookup
            
        try:
            with zipfile.ZipFile(exploits_file, 'r') as zf:
                for filename in zf.namelist():
                    if filename.startswith('exploits-CVE-') and filename.endswith('.json'):
                        # Extract CVE ID from filename
                        cve_id = filename.replace('exploits-', '').replace('.json', '')
                        
                        with zf.open(filename) as f:
                            data = json.loads(f.read().decode('utf-8'))
                            exploits_lookup[cve_id] = data
                            
            logger.info(f"Loaded {len(exploits_lookup)} exploits records")
            
        except zipfile.BadZipFile:
            # Handle case where file is JSON instead of zip
            logger.warning("Exploits file is not a zip, trying JSON format")
            try:
                with open(exploits_file, 'r') as f:
                    data = json.load(f)
                    if 'data' in data:
                        for record in data['data']:
                            if 'id' in record:
                                exploits_lookup[record['id']] = record
                        logger.info(f"Loaded {len(exploits_lookup)} exploits records from JSON")
            except Exception as e:
                logger.error(f"Failed to load exploits JSON: {e}")
        except Exception as e:
            logger.error(f"Failed to load exploits data: {e}")
            
        return exploits_lookup
    
    def _load_kev_data(self) -> Dict[str, Dict]:
        """Load KEV data and create CVE lookup dictionary"""
        kev_lookup = {}
        kev_file = self.data_dir / "vulncheck-kev.zip"
        
        if not kev_file.exists():
            return kev_lookup
            
        try:
            with zipfile.ZipFile(kev_file, 'r') as zf:
                # Check for the actual KEV JSON file in the ZIP
                if 'vulncheck_known_exploited_vulnerabilities.json' in zf.namelist():
                    with zf.open('vulncheck_known_exploited_vulnerabilities.json') as f:
                        data = json.loads(f.read().decode('utf-8'))
                        # Data is a list of records, each with 'cve' field containing list of CVEs
                        if isinstance(data, list):
                            for record in data:
                                cves = record.get('cve', [])
                                if isinstance(cves, list):
                                    for cve_id in cves:
                                        kev_lookup[cve_id] = record
                                elif isinstance(cves, str):
                                    kev_lookup[cves] = record
                    logger.info(f"Loaded {len(kev_lookup)} KEV records from ZIP")
                else:
                    # Fallback: check for individual CVE files (legacy format)
                    for filename in zf.namelist():
                        if filename.startswith('vulncheck-kev-CVE-') and filename.endswith('.json'):
                            # Extract CVE ID from filename
                            cve_id = filename.replace('vulncheck-kev-', '').replace('.json', '')
                            
                            with zf.open(filename) as f:
                                data = json.loads(f.read().decode('utf-8'))
                                kev_lookup[cve_id] = data
                    logger.info(f"Loaded {len(kev_lookup)} KEV records from individual files")
            
        except zipfile.BadZipFile:
            # Handle case where file is JSON instead of zip
            logger.warning("KEV file is not a zip, trying JSON format")
            try:
                with open(kev_file, 'r') as f:
                    data = json.load(f)
                    if 'data' in data:
                        # Paginated API format
                        for record in data['data']:
                            cves = record.get('cve', [])
                            if isinstance(cves, list):
                                for cve_id in cves:
                                    kev_lookup[cve_id] = record
                            elif isinstance(cves, str):
                                kev_lookup[cves] = record
                    elif isinstance(data, list):
                        # Direct list format
                        for record in data:
                            cves = record.get('cve', [])
                            if isinstance(cves, list):
                                for cve_id in cves:
                                    kev_lookup[cve_id] = record
                            elif isinstance(cves, str):
                                kev_lookup[cves] = record
                    logger.info(f"Loaded {len(kev_lookup)} KEV records from JSON")
            except Exception as e:
                logger.error(f"Failed to load KEV JSON: {e}")
        except Exception as e:
            logger.error(f"Failed to load KEV data: {e}")
            
        return kev_lookup
    
    def _extract_from_zip(self, zip_file: Path, filename: str) -> Optional[Dict]:
        """Extract JSON data from zip file"""
        try:
            with zipfile.ZipFile(zip_file, 'r') as zf:
                if filename in zf.namelist():
                    with zf.open(filename) as f:
                        return json.loads(f.read().decode('utf-8'))
        except Exception as e:
            logger.debug(f"Could not extract {filename} from {zip_file.name}: {e}")
        return None
    
    def _extract_exploits_fields(self, data: Dict) -> Dict:
        """Extract all exploits fields - simple mapping"""
        return {
            # Direct boolean mappings
            'public_exploit_found': data.get('public_exploit_found', False),
            'commercial_exploit_found': data.get('commercial_exploit_found', False),
            'weaponized_exploit_found': data.get('weaponized_exploit_found', False),
            'reported_exploited_by_honeypot_service': data.get('reported_exploited_by_honeypot_service', False),
            'reported_exploited': data.get('reported_exploited', False),
            'reported_exploited_by_threat_actors': data.get('reported_exploited_by_threat_actors', False),
            'reported_exploited_by_ransomware': data.get('reported_exploited_by_ransomware', False),
            'reported_exploited_by_botnets': data.get('reported_exploited_by_botnets', False),
            'in_kev': data.get('inKEV', False),
            'in_vckev': data.get('inVCKEV', False),
            'trending_github': data.get('trending', {}).get('github', False),
            
            # String fields
            'max_exploit_maturity': data.get('max_exploit_maturity'),
            
            # Numeric fields  
            'exploits_count': data.get('counts', {}).get('exploits', 0),
            'threat_actors_count': data.get('counts', {}).get('threat_actors', 0),
            'botnets_count': data.get('counts', {}).get('botnets', 0),
            'ransomware_families_count': data.get('counts', {}).get('ransomware_families', 0),
            'epss_score': data.get('epss', {}).get('epss_score'),
            'epss_percentile': data.get('epss', {}).get('epss_percentile'),
            
            # Timestamps
            'nvd_published': self._parse_timestamp(data.get('timeline', {}).get('nvd_published')),
            'first_exploit_published': self._parse_timestamp(data.get('timeline', {}).get('first_exploit_published')),
            'most_recent_exploit_published': self._parse_timestamp(data.get('timeline', {}).get('most_recent_exploit_published')),
            'epss_last_modified': self._parse_timestamp(data.get('epss', {}).get('last_modified')),
            
            # Raw data
            'exploits_raw': data
        }
    
    def _extract_kev_fields(self, data: Dict) -> Dict:
        """Extract all VulnCheck-KEV fields - enhanced mapping"""
        return {
            'vendor_project': data.get('vendorProject'),
            'product': data.get('product'),
            'vulnerability_name': data.get('vulnerabilityName'),
            'short_description': data.get('shortDescription'),
            'required_action': data.get('required_action'),
            'known_ransomware_campaign_use': data.get('knownRansomwareCampaignUse'),
            'due_date': self._parse_date(data.get('dueDate')),
            'cisa_date_added': self._parse_date(data.get('cisa_date_added')),
            'date_added': self._parse_date(data.get('date_added')),
            'vulncheck_xdb': data.get('vulncheck_xdb'),
            'vulncheck_reported_exploitation': data.get('vulncheck_reported_exploitation'),
            'cwes': ','.join(data.get('cwes', [])) if data.get('cwes') else None,
            'kev_raw': data
        }
    
    def _parse_timestamp(self, ts_str: Optional[str]) -> Optional[datetime]:
        """Parse timestamp string"""
        if not ts_str:
            return None
        try:
            if ts_str.endswith('Z'):
                return datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
            return datetime.fromisoformat(ts_str)
        except:
            return None
    
    def _parse_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse date string"""
        if not date_str:
            return None
        try:
            return datetime.fromisoformat(date_str.split('T')[0])
        except:
            return None
    
    def _store_exploits_batch(self, exploits_data: Dict[str, Dict]):
        """Store exploits data in vulncheck_exploits table"""
        if not exploits_data:
            return
            
        try:
            with self.conn.cursor() as cur:
                upsert_sql = """
                    INSERT INTO vulncheck_exploits (
                        cve_id, is_active, last_updated,
                        public_exploit_found, commercial_exploit_found, weaponized_exploit_found,
                        reported_exploited_by_honeypot_service, reported_exploited,
                        reported_exploited_by_threat_actors, reported_exploited_by_ransomware, 
                        reported_exploited_by_botnets, in_kev, in_vckev, trending_github,
                        max_exploit_maturity, exploits_count, threat_actors_count, 
                        botnets_count, ransomware_families_count, epss_score, epss_percentile,
                        epss_last_modified, nvd_published, first_exploit_published, 
                        most_recent_exploit_published, exploits_raw
                    )
                    VALUES (
                        %(cve_id)s, true, NOW(),
                        %(public_exploit_found)s, %(commercial_exploit_found)s, %(weaponized_exploit_found)s,
                        %(reported_exploited_by_honeypot_service)s, %(reported_exploited)s,
                        %(reported_exploited_by_threat_actors)s, %(reported_exploited_by_ransomware)s,
                        %(reported_exploited_by_botnets)s, %(in_kev)s, %(in_vckev)s, %(trending_github)s,
                        %(max_exploit_maturity)s, %(exploits_count)s, %(threat_actors_count)s,
                        %(botnets_count)s, %(ransomware_families_count)s, %(epss_score)s, %(epss_percentile)s,
                        %(epss_last_modified)s, %(nvd_published)s, %(first_exploit_published)s,
                        %(most_recent_exploit_published)s, %(exploits_raw)s
                    )
                    ON CONFLICT (cve_id) DO UPDATE SET
                        is_active = true, last_updated = NOW(),
                        public_exploit_found = EXCLUDED.public_exploit_found,
                        commercial_exploit_found = EXCLUDED.commercial_exploit_found,
                        weaponized_exploit_found = EXCLUDED.weaponized_exploit_found,
                        reported_exploited_by_honeypot_service = EXCLUDED.reported_exploited_by_honeypot_service,
                        reported_exploited = EXCLUDED.reported_exploited,
                        reported_exploited_by_threat_actors = EXCLUDED.reported_exploited_by_threat_actors,
                        reported_exploited_by_ransomware = EXCLUDED.reported_exploited_by_ransomware,
                        reported_exploited_by_botnets = EXCLUDED.reported_exploited_by_botnets,
                        in_kev = EXCLUDED.in_kev, in_vckev = EXCLUDED.in_vckev,
                        trending_github = EXCLUDED.trending_github,
                        max_exploit_maturity = EXCLUDED.max_exploit_maturity,
                        exploits_count = EXCLUDED.exploits_count,
                        threat_actors_count = EXCLUDED.threat_actors_count,
                        botnets_count = EXCLUDED.botnets_count,
                        ransomware_families_count = EXCLUDED.ransomware_families_count,
                        epss_score = EXCLUDED.epss_score, epss_percentile = EXCLUDED.epss_percentile,
                        epss_last_modified = EXCLUDED.epss_last_modified,
                        nvd_published = EXCLUDED.nvd_published,
                        first_exploit_published = EXCLUDED.first_exploit_published,
                        most_recent_exploit_published = EXCLUDED.most_recent_exploit_published,
                        exploits_raw = EXCLUDED.exploits_raw
                """
                
                for cve_id, fields in exploits_data.items():
                    record = {
                        'cve_id': cve_id,
                        'public_exploit_found': fields.get('public_exploit_found', False),
                        'commercial_exploit_found': fields.get('commercial_exploit_found', False),
                        'weaponized_exploit_found': fields.get('weaponized_exploit_found', False),
                        'reported_exploited_by_honeypot_service': fields.get('reported_exploited_by_honeypot_service', False),
                        'reported_exploited': fields.get('reported_exploited', False),
                        'reported_exploited_by_threat_actors': fields.get('reported_exploited_by_threat_actors', False),
                        'reported_exploited_by_ransomware': fields.get('reported_exploited_by_ransomware', False),
                        'reported_exploited_by_botnets': fields.get('reported_exploited_by_botnets', False),
                        'in_kev': fields.get('in_kev', False),
                        'in_vckev': fields.get('in_vckev', False),
                        'trending_github': fields.get('trending_github', False),
                        'max_exploit_maturity': fields.get('max_exploit_maturity'),
                        'exploits_count': fields.get('exploits_count', 0),
                        'threat_actors_count': fields.get('threat_actors_count', 0),
                        'botnets_count': fields.get('botnets_count', 0),
                        'ransomware_families_count': fields.get('ransomware_families_count', 0),
                        'epss_score': fields.get('epss_score'),
                        'epss_percentile': fields.get('epss_percentile'),
                        'epss_last_modified': fields.get('epss_last_modified'),
                        'nvd_published': fields.get('nvd_published'),
                        'first_exploit_published': fields.get('first_exploit_published'),
                        'most_recent_exploit_published': fields.get('most_recent_exploit_published'),
                        'exploits_raw': json.dumps(fields.get('exploits_raw')) if fields.get('exploits_raw') else None
                    }
                    cur.execute(upsert_sql, record)
                
                self.conn.commit()
                logger.info(f"Stored {len(exploits_data)} exploits records")
                
        except Exception as e:
            logger.error(f"Failed to store exploits batch: {e}")
            self.conn.rollback()
            raise
    
    def _store_kev_batch(self, kev_data: Dict[str, Dict]):
        """Store KEV data in vulncheck_kev table"""
        if not kev_data:
            return
            
        try:
            with self.conn.cursor() as cur:
                upsert_sql = """
                    INSERT INTO vulncheck_kev (
                        cve_id, is_active, last_updated,
                        vendor_project, product, vulnerability_name, short_description,
                        required_action, known_ransomware_campaign_use, due_date,
                        cisa_date_added, date_added, vulncheck_xdb, vulncheck_reported_exploitation,
                        cwes, kev_raw
                    )
                    VALUES (
                        %(cve_id)s, true, NOW(),
                        %(vendor_project)s, %(product)s, %(vulnerability_name)s, %(short_description)s,
                        %(required_action)s, %(known_ransomware_campaign_use)s, %(due_date)s,
                        %(cisa_date_added)s, %(date_added)s, %(vulncheck_xdb)s, %(vulncheck_reported_exploitation)s,
                        %(cwes)s, %(kev_raw)s
                    )
                    ON CONFLICT (cve_id) DO UPDATE SET
                        is_active = true, last_updated = NOW(),
                        vendor_project = EXCLUDED.vendor_project,
                        product = EXCLUDED.product,
                        vulnerability_name = EXCLUDED.vulnerability_name,
                        short_description = EXCLUDED.short_description,
                        required_action = EXCLUDED.required_action,
                        known_ransomware_campaign_use = EXCLUDED.known_ransomware_campaign_use,
                        due_date = EXCLUDED.due_date,
                        cisa_date_added = EXCLUDED.cisa_date_added,
                        date_added = EXCLUDED.date_added,
                        vulncheck_xdb = EXCLUDED.vulncheck_xdb,
                        vulncheck_reported_exploitation = EXCLUDED.vulncheck_reported_exploitation,
                        cwes = EXCLUDED.cwes,
                        kev_raw = EXCLUDED.kev_raw
                """
                
                for cve_id, fields in kev_data.items():
                    record = {
                        'cve_id': cve_id,
                        'vendor_project': fields.get('vendor_project'),
                        'product': fields.get('product'),
                        'vulnerability_name': fields.get('vulnerability_name'),
                        'short_description': fields.get('short_description'),
                        'required_action': fields.get('required_action'),
                        'known_ransomware_campaign_use': fields.get('known_ransomware_campaign_use'),
                        'due_date': fields.get('due_date'),
                        'cisa_date_added': fields.get('cisa_date_added'),
                        'date_added': fields.get('date_added'),
                        'vulncheck_xdb': json.dumps(fields.get('vulncheck_xdb')) if fields.get('vulncheck_xdb') else None,
                        'vulncheck_reported_exploitation': json.dumps(fields.get('vulncheck_reported_exploitation')) if fields.get('vulncheck_reported_exploitation') else None,
                        'cwes': fields.get('cwes'),
                        'kev_raw': json.dumps(fields.get('kev_raw')) if fields.get('kev_raw') else None
                    }
                    cur.execute(upsert_sql, record)
                
                self.conn.commit()
                logger.info(f"Stored {len(kev_data)} KEV records")
                
        except Exception as e:
            logger.error(f"Failed to store KEV batch: {e}")
            self.conn.rollback()
            raise
    
    def get_stats(self) -> Dict[str, int]:
        """Get enrichment statistics from separated tables"""
        with self.conn.cursor() as cur:
            # Get exploits stats
            cur.execute("""
                SELECT 
                    COUNT(*) as total,
                    COUNT(*) FILTER (WHERE is_active) as active,
                    COUNT(*) FILTER (WHERE exploits_raw IS NOT NULL) as enriched,
                    COUNT(*) FILTER (WHERE weaponized_exploit_found = true) as weaponized
                FROM vulncheck_exploits
            """)
            exploits_result = cur.fetchone()
            
            # Get KEV stats
            cur.execute("""
                SELECT 
                    COUNT(*) as total,
                    COUNT(*) FILTER (WHERE is_active) as active,
                    COUNT(*) FILTER (WHERE kev_raw IS NOT NULL) as enriched,
                    COUNT(*) FILTER (WHERE known_ransomware_campaign_use = 'Known') as ransomware
                FROM vulncheck_kev
            """)
            kev_result = cur.fetchone()
            
            return {
                'exploits_total': exploits_result[0],
                'exploits_active': exploits_result[1],
                'exploits_enriched': exploits_result[2],
                'weaponized': exploits_result[3],
                'kev_total': kev_result[0],
                'kev_active': kev_result[1],
                'kev_enriched': kev_result[2],
                'ransomware': kev_result[3],
                # Legacy compatibility
                'total': max(exploits_result[0], kev_result[0]),
                'active': max(exploits_result[1], kev_result[1]),
                'enriched': exploits_result[2] + kev_result[2]
            }
    
    def get_cve_enrichment(self, cve_id: str) -> Optional[Dict]:
        """Get enrichment data for a specific CVE from both tables"""
        try:
            with self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                # Get exploits data
                cur.execute(
                    "SELECT * FROM vulncheck_exploits WHERE cve_id = %s",
                    (cve_id,)
                )
                exploits_result = cur.fetchone()
                
                # Get KEV data
                cur.execute(
                    "SELECT * FROM vulncheck_kev WHERE cve_id = %s",
                    (cve_id,)
                )
                kev_result = cur.fetchone()
                
                # Combine results
                if exploits_result or kev_result:
                    combined = {}
                    if exploits_result:
                        combined.update(dict(exploits_result))
                    if kev_result:
                        # Add KEV fields, avoiding duplicate cve_id
                        kev_dict = dict(kev_result)
                        kev_dict.pop('cve_id', None)
                        kev_dict.pop('is_active', None)
                        kev_dict.pop('last_updated', None)
                        combined.update(kev_dict)
                    return combined
                return None
                
        except Exception as e:
            logger.error(f"Failed to get enrichment data for {cve_id}: {e}")
            return None
    
    def cleanup(self):
        """Clean up resources"""
        if self.own_connection and self.conn:
            self.conn.close()
            logger.info("Database connection closed")
    
    def cleanup(self):
        """Clean up resources"""
        if self.own_connection and self.conn:
            self.conn.close()
            logger.info("Database connection closed")
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()


def main():
    """CLI interface for testing vulncheck integration"""
    import argparse
    
    parser = argparse.ArgumentParser(description="VulncheckDB - vAnalyzer Integration")
    parser.add_argument("action", choices=["setup", "sync", "stats"],
                       help="Action to perform")
    parser.add_argument("--force", "-f", action="store_true", 
                       help="Force download fresh data")
    parser.add_argument("--verbose", "-v", action="store_true",
                       help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        vulncheck = VulncheckDB()
        
        if args.action == "setup":
            success = vulncheck.setup_tables()
            print("Setup completed successfully" if success else "Setup failed")
        
        elif args.action == "sync":
            if args.force:
                vulncheck.download_vulncheck_data(force=True)
            success = vulncheck.sync_active_vulnerabilities()
            print("Sync completed successfully" if success else "Sync failed")
            
            if success:
                stats = vulncheck.get_stats()
                print(f"Stats: {stats['enriched']}/{stats['active']} CVEs enriched")
        
        elif args.action == "stats":
            stats = vulncheck.get_stats()
            print(f"Total CVEs: {stats['total']}")
            print(f"Active CVEs: {stats['active']}")
            print(f"Enriched CVEs: {stats['enriched']}")
            print(f"Weaponized: {stats['weaponized']}")
            print(f"Ransomware linked: {stats['ransomware']}")
        
        vulncheck.cleanup()
        
    except Exception as e:
        logger.error(f"Operation failed: {e}")
        sys.exit(1)

# Main integration function for vAnalyzer
def main_vulncheck_integration() -> bool:
    """
    Main function for vAnalyzer integration
    Called from updateExternalScore.py
    """
    try:
        vulncheck = VulncheckDB()
        
        # Setup tables if needed
        if not vulncheck.setup_tables():
            return False
        
        # Perform sync
        success = vulncheck.sync_active_vulnerabilities()
        
        if success:
            # Print stats
            stats = vulncheck.get_stats()
            print(f"Vulncheck enrichment complete:")
            print(f"  Active CVEs: {stats['active']}")
            print(f"  Enriched CVEs: {stats['enriched']}")
            print(f"  Weaponized: {stats['weaponized']}")
            print(f"  Ransomware linked: {stats['ransomware']}")
        
        vulncheck.cleanup()
        return success
        
    except Exception as e:
        logger.error(f"Vulncheck integration failed: {e}")
        return False


if __name__ == "__main__":
    main()