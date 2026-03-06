#!/usr/bin/env python3
"""
Vicarius API Client - PostgreSQL Version v2.0
Baseado na abordagem estável do DatabaseConnector.py com melhorias de performance e estabilidade.
"""

import requests
import pandas as pd
import json
import time
import hashlib
from datetime import datetime, date
from pathlib import Path
import logging
import psycopg2
from psycopg2.extras import execute_values
import numpy as np

# ============================================================================
# CONFIGURATION
# ============================================================================

# Rate limiting
MAX_REQUESTS_PER_MINUTE = 58
REQUEST_DELAY = 1.1
PAGE_SIZE = 500

# Batch configuration - seguindo DatabaseConnector.py
BATCH_SIZE = 100  # Reduzido de 1000 para 100
MAX_RETRIES = 3
CONNECTION_TIMEOUT = 30
STATEMENT_TIMEOUT = 120000  # 2 minutos

# ============================================================================
# LOGGING SETUP
# ============================================================================
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# ============================================================================
# DATABASE HELPER FUNCTIONS - Baseado em DatabaseConnector.py
# ============================================================================

def add_column_to_table(cur, table, columnName):
    """Adiciona colunas dinamicamente se não existirem."""
    for col in columnName:
        cur.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {col};")

def get_database_connection(db_config):
    """Cria nova conexão com configurações otimizadas."""
    return psycopg2.connect(
        **db_config,
        options=f'-c statement_timeout={STATEMENT_TIMEOUT}',
        connect_timeout=CONNECTION_TIMEOUT,
        keepalives_idle=600,
        keepalives_interval=30,
        keepalives_count=3
    )

def execute_with_retry(db_config, operation_func, *args, **kwargs):
    """Executa operação de banco com retry - padrão DatabaseConnector."""
    for attempt in range(MAX_RETRIES):
        conn = None
        try:
            conn = get_database_connection(db_config)
            conn.autocommit = False
            
            result = operation_func(conn, *args, **kwargs)
            conn.commit()
            return result
            
        except (psycopg2.OperationalError, psycopg2.InterfaceError) as e:
            if conn:
                try:
                    conn.rollback()
                    conn.close()
                except:
                    pass
            
            if 'server closed the connection' in str(e).lower() or 'connection' in str(e).lower():
                logger.warning(f"Connection lost on attempt {attempt + 1}/{MAX_RETRIES}: {str(e)}")
                if attempt < MAX_RETRIES - 1:
                    time.sleep(2 ** attempt)  # Backoff exponencial: 1s, 2s, 4s
                    continue
            raise
            
        except Exception as e:
            if conn:
                try:
                    conn.rollback()
                    conn.close()
                except:
                    pass
            raise
            
        finally:
            if conn and conn.closed == 0:
                conn.close()

# ============================================================================
# DATABASE SETUP AND OPERATIONS
# ============================================================================

class VicariusDB:
    def __init__(self, db_config):
        """Inicializa classe com configurações de banco."""
        self.db_config = db_config
        self.setup_tables()
        self.check_and_suggest_migration()
    
    def setup_tables(self):
        """Cria tabelas necessárias - usando padrão DatabaseConnector."""
        def _setup_tables_internal(conn):
            cursor = conn.cursor()
            
            # Operating systems table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS operating_system (
                    id SERIAL PRIMARY KEY,
                    fabricante TEXT,
                    os_name TEXT,
                    familia TEXT,
                    os_id TEXT,
                    hash TEXT UNIQUE,
                    ultima_atualizacao TEXT,
                    data TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Patches table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS patches (
                    id SERIAL PRIMARY KEY,
                    so_hash TEXT REFERENCES operating_system(hash),
                    fabricante TEXT,
                    os_name TEXT,
                    familia TEXT,
                    patch_name TEXT,
                    patch_id BIGINT,
                    external_ref_id TEXT,
                    assets_count INTEGER,
                    sensibilidade TEXT,
                    data_lancamento TIMESTAMP,
                    dias_desde_lancamento INTEGER,
                    data TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Assets table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS assets (
                    id SERIAL PRIMARY KEY,
                    patch_id BIGINT,
                    so_hash TEXT REFERENCES operating_system(hash),
                    asset_name TEXT,
                    asset_id BIGINT,
                    fabricante TEXT,
                    os_name TEXT,
                    familia TEXT,
                    patch_name TEXT,
                    assets_afetados INTEGER,
                    sensibilidade TEXT,
                    data_lancamento TIMESTAMP,
                    diferenca_dias INTEGER,
                    score_asset TEXT,
                    status_asset TEXT,
                    last_updated TEXT,
                    data TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Vulnerabilities table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id SERIAL PRIMARY KEY,
                    patch_id BIGINT,
                    so_hash TEXT REFERENCES operating_system(hash),
                    fabricante TEXT,
                    os_name TEXT,
                    familia TEXT,
                    patch_name TEXT,
                    vulnerability_id TEXT,
                    cve_id TEXT,
                    vulnerability_summary TEXT,
                    severity TEXT,
                    threat_level TEXT,
                    cvss_score TEXT,
                    cvss_vector TEXT,
                    impact_level TEXT,
                    exploitability_level TEXT,
                    published_at TEXT,
                    modified_at TEXT,
                    cisa_action TEXT,
                    data TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Índices para performance
            indexes = [
                'CREATE INDEX IF NOT EXISTS idx_so_hash ON patches(so_hash)',
                'CREATE INDEX IF NOT EXISTS idx_patch_id ON assets(patch_id)',
                'CREATE INDEX IF NOT EXISTS idx_asset_name ON assets(asset_name)',
                'CREATE INDEX IF NOT EXISTS idx_so_data ON operating_system(data)',
                'CREATE INDEX IF NOT EXISTS idx_patches_data ON patches(data)',
                'CREATE INDEX IF NOT EXISTS idx_assets_data ON assets(data)',
                'CREATE INDEX IF NOT EXISTS idx_vuln_patch_id ON vulnerabilities(patch_id)',
                'CREATE INDEX IF NOT EXISTS idx_vuln_cve ON vulnerabilities(cve_id)',
                'CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity)',
                'CREATE INDEX IF NOT EXISTS idx_vuln_data ON vulnerabilities(data)'
            ]
            
            for index_sql in indexes:
                cursor.execute(index_sql)
            
            logger.warning("Database tables and indexes created successfully")
        
        execute_with_retry(self.db_config, _setup_tables_internal)
    
    def insert_so(self, so_data):
        """Insere sistema operacional - padrão DatabaseConnector."""
        def _insert_so_internal(conn, so_data):
            cursor = conn.cursor()
            current_timestamp = datetime.now()
            
            sql = '''
                INSERT INTO operating_system 
                (fabricante, os_name, familia, os_id, hash, ultima_atualizacao, data)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (hash) DO UPDATE SET 
                    ultima_atualizacao = EXCLUDED.ultima_atualizacao,
                    data = EXCLUDED.data
            '''
            
            cursor.execute(sql, (
                so_data['publisher'],
                so_data['os_name'],
                so_data['family'],
                so_data['os_id'],
                so_data['hash'],
                so_data['last_update'],
                current_timestamp
            ))
        
        execute_with_retry(self.db_config, _insert_so_internal, so_data)
    
    def insert_patches_batch(self, patches_data):
        """Insere patches em lotes - abordagem DatabaseConnector."""
        if not patches_data:
            return
        
        logger.warning(f"Inserting {len(patches_data)} patches using DatabaseConnector approach...")
        
        # Dividir em chunks menores
        chunks = [patches_data[i:i + BATCH_SIZE] for i in range(0, len(patches_data), BATCH_SIZE)]
        
        total_inserted = 0
        for i, chunk in enumerate(chunks, 1):
            logger.warning(f"Processing patch chunk {i}/{len(chunks)} ({len(chunk)} records)")
            
            def _insert_patches_chunk(conn, chunk_data):
                cursor = conn.cursor()
                
                # SQL para batch e individual
                sql = '''
                    INSERT INTO patches 
                    (so_hash, fabricante, os_name, familia, patch_name, patch_id, 
                     external_ref_id, assets_count, sensibilidade, data_lancamento, 
                     dias_desde_lancamento, data)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT DO NOTHING
                '''
                
                # Preparar dados
                data_tuples = [
                    (patch[0], patch[1], patch[2], patch[3], patch[4], patch[5],
                     patch[6], patch[7], patch[8], patch[9], patch[10], datetime.now())
                    for patch in chunk_data
                ]
                
                try:
                    # Tentar batch primeiro (mais eficiente)
                    cursor.executemany(sql, data_tuples)
                    logger.warning(f"Batch insert successful: {len(data_tuples)} patches")
                    return len(data_tuples)
                    
                except psycopg2.Error as e:
                    logger.warning(f"Batch insert failed, trying individual inserts: {str(e)}")
                    conn.rollback()
                    
                    # Fallback para inserções individuais
                    inserted_count = 0
                    for j, data_tuple in enumerate(data_tuples):
                        try:
                            cursor.execute(sql, data_tuple)
                            inserted_count += 1
                        except psycopg2.Error as ie:
                            logger.error(f"Individual insert failed for record {j}: {str(ie)}")
                    
                    logger.warning(f"Individual inserts completed: {inserted_count}/{len(data_tuples)}")
                    return inserted_count
            
            inserted = execute_with_retry(self.db_config, _insert_patches_chunk, chunk)
            total_inserted += inserted
            
            # Delay entre chunks
            if i < len(chunks):
                time.sleep(0.1)
        
        logger.warning(f"Total patches inserted: {total_inserted}")
    
    def insert_assets_batch(self, assets_data):
        """Insere assets em lotes - abordagem DatabaseConnector."""
        if not assets_data:
            return
        
        logger.warning(f"Inserting {len(assets_data)} assets using DatabaseConnector approach...")
        
        chunks = [assets_data[i:i + BATCH_SIZE] for i in range(0, len(assets_data), BATCH_SIZE)]
        
        total_inserted = 0
        for i, chunk in enumerate(chunks, 1):
            logger.warning(f"Processing asset chunk {i}/{len(chunks)} ({len(chunk)} records)")
            
            def _insert_assets_chunk(conn, chunk_data):
                cursor = conn.cursor()
                
                sql = '''
                    INSERT INTO assets 
                    (patch_id, so_hash, asset_name, asset_id, fabricante, os_name, 
                     familia, patch_name, assets_afetados, sensibilidade, data_lancamento, 
                     diferenca_dias, score_asset, status_asset, last_updated, data)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT DO NOTHING
                '''
                
                data_tuples = [
                    (asset[0], asset[1], asset[2], asset[3], asset[4], asset[5],
                     asset[6], asset[7], asset[8], asset[9], asset[10], asset[11],
                     asset[12], asset[13], asset[14], datetime.now())
                    for asset in chunk_data
                ]
                
                try:
                    cursor.executemany(sql, data_tuples)
                    logger.warning(f"Assets batch insert successful: {len(data_tuples)}")
                    return len(data_tuples)
                    
                except psycopg2.Error as e:
                    logger.warning(f"Assets batch failed, trying individual: {str(e)}")
                    conn.rollback()
                    
                    inserted_count = 0
                    for j, data_tuple in enumerate(data_tuples):
                        try:
                            cursor.execute(sql, data_tuple)
                            inserted_count += 1
                        except psycopg2.Error:
                            pass  # Skip problematic records
                    
                    return inserted_count
            
            inserted = execute_with_retry(self.db_config, _insert_assets_chunk, chunk)
            total_inserted += inserted
            
            if i < len(chunks):
                time.sleep(0.1)
        
        logger.warning(f"Total assets inserted: {total_inserted}")
    
    def insert_vulnerabilities_batch(self, vulnerabilities_data):
        """Insere vulnerabilidades em lotes - abordagem DatabaseConnector."""
        if not vulnerabilities_data:
            return
        
        logger.warning(f"Inserting {len(vulnerabilities_data)} vulnerabilities using DatabaseConnector approach...")
        
        chunks = [vulnerabilities_data[i:i + BATCH_SIZE] for i in range(0, len(vulnerabilities_data), BATCH_SIZE)]
        
        total_inserted = 0
        for i, chunk in enumerate(chunks, 1):
            logger.warning(f"Processing vulnerability chunk {i}/{len(chunks)} ({len(chunk)} records)")
            
            def _insert_vulnerabilities_chunk(conn, chunk_data):
                cursor = conn.cursor()
                
                sql = '''
                    INSERT INTO vulnerabilities 
                    (patch_id, so_hash, fabricante, os_name, familia, patch_name,
                     vulnerability_id, cve_id, vulnerability_summary, severity, threat_level,
                     cvss_score, cvss_vector, impact_level, exploitability_level,
                     published_at, modified_at, cisa_action, data)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT DO NOTHING
                '''
                
                data_tuples = [
                    (vuln[0], vuln[1], vuln[2], vuln[3], vuln[4], vuln[5],
                     vuln[6], vuln[7], vuln[8], vuln[9], vuln[10], vuln[11],
                     vuln[12], vuln[13], vuln[14], vuln[15], vuln[16], vuln[17],
                     datetime.now())
                    for vuln in chunk_data
                ]
                
                try:
                    cursor.executemany(sql, data_tuples)
                    logger.warning(f"Vulnerabilities batch insert successful: {len(data_tuples)}")
                    return len(data_tuples)
                    
                except psycopg2.Error as e:
                    logger.warning(f"Vulnerabilities batch failed, trying individual: {str(e)}")
                    conn.rollback()
                    
                    inserted_count = 0
                    for j, data_tuple in enumerate(data_tuples):
                        try:
                            cursor.execute(sql, data_tuple)
                            inserted_count += 1
                        except psycopg2.Error:
                            pass
                    
                    return inserted_count
            
            inserted = execute_with_retry(self.db_config, _insert_vulnerabilities_chunk, chunk)
            total_inserted += inserted
            
            if i < len(chunks):
                time.sleep(0.1)
        
        logger.warning(f"Total vulnerabilities inserted: {total_inserted}")
    
    def get_stats(self):
        """Retorna estatísticas do banco - padrão DatabaseConnector."""
        def _get_stats_internal(conn):
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM operating_system")
            so_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM patches")
            patches_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM assets")
            assets_count = cursor.fetchone()[0]
            
            try:
                cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
                vulns_count = cursor.fetchone()[0]
            except:
                vulns_count = 0
            
            return {
                'operating_system': so_count,
                'patches': patches_count,
                'assets': assets_count,
                'vulnerabilities': vulns_count,
                'total': so_count + patches_count + assets_count + vulns_count
            }
        
        return execute_with_retry(self.db_config, _get_stats_internal)
    
    def check_and_suggest_migration(self):
        """Checks if migration is needed and suggests running migration script."""
        def _check_migration_internal(conn):
            cursor = conn.cursor()
            
            # Check if tables exist first
            cursor.execute("""
                SELECT table_name FROM information_schema.tables 
                WHERE table_schema = 'public' AND table_name IN ('patches', 'assets', 'vulnerabilities')
            """)
            existing_tables = [row[0] for row in cursor.fetchall()]
            
            if not existing_tables:
                # No tables exist yet, no migration needed
                return
            
            # Check column types
            migration_needed = False
            
            # Check patch_id columns
            for table in ['patches', 'assets', 'vulnerabilities']:
                if table in existing_tables:
                    cursor.execute("""
                        SELECT data_type FROM information_schema.columns 
                        WHERE table_name = %s AND column_name = 'patch_id'
                    """, (table,))
                    result = cursor.fetchone()
                    if result and result[0] == 'text':
                        migration_needed = True
                        break
            
            # Check asset_id column
            if 'assets' in existing_tables and not migration_needed:
                cursor.execute("""
                    SELECT data_type FROM information_schema.columns 
                    WHERE table_name = 'assets' AND column_name = 'asset_id'
                """)
                result = cursor.fetchone()
                if result and result[0] == 'text':
                    migration_needed = True
            
            # Check data_lancamento columns
            if not migration_needed:
                for table in ['patches', 'assets']:
                    if table in existing_tables:
                        cursor.execute("""
                            SELECT data_type FROM information_schema.columns 
                            WHERE table_name = %s AND column_name = 'data_lancamento'
                        """, (table,))
                        result = cursor.fetchone()
                        if result and result[0] == 'text':
                            migration_needed = True
                            break
            
            if migration_needed:
                logger.warning("="*60)
                logger.warning("DATABASE MIGRATION REQUIRED!")
                logger.warning("="*60)
                logger.warning("Your database has old column types that need migration:")
                logger.warning("- patch_id: TEXT → BIGINT")
                logger.warning("- asset_id: TEXT → BIGINT") 
                logger.warning("- data_lancamento: TEXT → TIMESTAMP")
                logger.warning("")
                logger.warning("Please run the migration script before proceeding:")
                logger.warning("python migrate_database_columns.py")
                logger.warning("")
                logger.warning("The migration script will:")
                logger.warning("1. Create backup tables automatically")
                logger.warning("2. Safely migrate existing data")
                logger.warning("3. Preserve data integrity")
                logger.warning("="*60)
        
        try:
            execute_with_retry(self.db_config, _check_migration_internal)
        except Exception as e:
            logger.warning(f"Could not check migration status: {str(e)}")

# ============================================================================
# API CLIENT - Mantendo a implementação original
# ============================================================================

class VicariusAPI:
    def __init__(self, api_key, dashboard):
        self.dashboard = f"{dashboard}.vicarius.cloud"
        self.base_url = f"https://{self.dashboard}/vicarius-external-data-api"
        self.headers = {
            'accept': 'application/json',
            'Content-Type': 'application/json',
            'vicarius-token': api_key,
        }
        self.request_count = 0
        self.last_request_time = 0
        self.cache_file = f"{dashboard}-os_data_cache.json"
        self.request_delay = REQUEST_DELAY
        self.page_size = PAGE_SIZE
    
    def _load_os_cache(self):
        """Loads OS cache if it exists."""
        try:
            if not Path(self.cache_file).exists():
                logger.warning(f"Cache not found: {self.cache_file}")
                return None
            
            with open(self.cache_file, 'r', encoding='utf-8') as f:
                cache_data = json.load(f)
            
            cache_time = datetime.fromisoformat(cache_data.get('timestamp', ''))
            age_hours = (datetime.now() - cache_time).total_seconds() / 3600
            data = cache_data.get('data', [])
            
            logger.warning(f"Cache found: {len(data)} SOs (age: {age_hours:.1f}h)")
            return data
            
        except Exception as e:
            logger.error(f"Error loading cache: {str(e)}")
            return None
    
    def _save_os_cache(self, data):
        """Saves OS cache."""
        try:
            cache_data = {
                'timestamp': datetime.now().isoformat(),
                'data': data,
                'count': len(data)
            }
            
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(cache_data, f, indent=2, ensure_ascii=False)
            
            logger.warning(f"Cache saved: {len(data)} SOs in {self.cache_file}")
            
        except Exception as e:
            logger.error(f"Error saving cache: {str(e)}")
    
    def _make_request(self, endpoint, method="POST", params=None, data=None, max_retries=3):
        """Makes request with rate limiting."""
        for attempt in range(max_retries):
            request_start = time.time()
            self.request_count += 1
            
            url = f"{self.base_url}/{endpoint}"
            
            try:
                response = requests.request(
                    method=method,
                    url=url,
                    params=params,
                    headers=self.headers,
                    json=data,
                    timeout=30
                )
                
                if response.status_code == 429:
                    backoff_delay = 10 * (attempt + 1)
                    logger.error(f"429 Rate Limit Error on attempt {attempt + 1}/{max_retries}")
                    
                    if attempt < max_retries - 1:
                        time.sleep(backoff_delay)
                    continue
                
                response.raise_for_status()
                
                request_end = time.time()
                request_duration = request_end - request_start
                
                MIN_INTERVAL = 1.3
                if request_duration < MIN_INTERVAL:
                    additional_delay = MIN_INTERVAL - request_duration
                    time.sleep(additional_delay)
                
                self.last_request_time = time.time()
                return response.json()
                
            except requests.exceptions.RequestException as e:
                logger.error(f"Request Error in {endpoint}: {str(e)}")
                
                if attempt < max_retries - 1:
                    time.sleep(2)
                    continue
                else:
                    return None
        
        return None
    
    def get_all_os_data(self):
        """Gets all operating systems with cache fallback."""
        all_data = []
        page_from = 0
        
        logger.warning("Getting OS data from API...")
        
        while True:
            params = {
                'from': str(page_from),
                'size': str(self.page_size),
                'q': '',
                'sort': '-organizationPublisherOperatingSystemsOrganizationPublisherOperatingSystemsScores.organizationPublisherOperatingSystemsScoresScore;publisherOperatingSystemHash',
                'includeFields': 'publisherId,operatingSystemId,publisherOperatingSystemHash,organizationPublisherOperatingSystemsUpdatedAt,organizationPublisherOperatingSystemsPublisher.publisherName,organizationPublisherOperatingSystemsOperatingSystem.operatingSystemUniqueIdentifier,organizationPublisherOperatingSystemsOperatingSystem.operatingSystemName,organizationPublisherOperatingSystemsOperatingSystemFamily.operatingSystemFamilyName'
            }
            
            data = [{
                "searchQueryName": "osPatchQuery",
                "searchQueryObjectName": "OrganizationEndpointPublisherOperatingSystems",
                "searchQueryObjectJoinByFieldName": "publisherOperatingSystemHash",
                "searchQueryObjectJoinByForeignFieldName": "publisherOperatingSystemHash",
                "searchQueryQuery": "publisherOperatingSystemHash=out=('_','null_null');organizationEndpointPublisherOperatingSystemsExternalReferenceSecondary.externalReferenceId=ex=\"true\""
            }]
            
            response = self._make_request("organizationPublisherOperatingSystems/search", "POST", params, data)
            
            if not response or not response.get('serverResponseObject'):
                break
            
            current_data = response.get('serverResponseObject', [])
            all_data.extend(current_data)
            
            if len(current_data) < self.page_size:
                break
            
            page_from += self.page_size
        
        if all_data:
            self._save_os_cache(all_data)
        else:
            logger.warning("API failed, trying cache...")
            all_data = self._load_os_cache() or []
        
        return all_data
    
    def get_patches_for_so(self, so_hash):
        """Gets patches for a specific OS."""
        all_patches = []
        page_from = 0
        
        while True:
            params = {
                'from': str(page_from),
                'size': str(self.page_size),
                'objectName': 'OrganizationEndpointExternalReferenceExternalReferences',
                'group': 'organizationEndpointExternalReferenceExternalReferencesPatches.patchName.raw;organizationEndpointExternalReferenceExternalReferencesPatches.patchReleaseDate;organizationEndpointExternalReferenceExternalReferencesPatches.patchDescription;organizationEndpointExternalReferenceExternalReferencesPatches.patchSensitivityLevel.sensitivityLevelName;organizationEndpointExternalReferenceExternalReferencesPatches.patchSensitivityLevel.sensitivityLevelRank;externalReferenceId;>;organizationEndpointExternalReferenceExternalReferencesPatches.patchId;externalReferenceSourceId;endpointId',
                'includeOriginalDoc': 'false',
                'q': '',
                'type': 'os',
                'sumLastSubAggregationBuckets': '8',
                'sort': 'OrganizationEndpointExternalReferenceExternalReferences.sensitivityLevelRank',
                'newParser': 'true'
            }
            
            data = [{
                "searchQueryName": "osQuery",
                "searchQueryObjectName": "OrganizationEndpointPublisherOperatingSystems",
                "searchQueryObjectJoinByFieldName": "endpointExternalReferenceSecondaryHash",
                "searchQueryObjectJoinByForeignFieldName": "endpointExternalReferenceHash",
                "searchQueryQuery": f"publisherOperatingSystemHash=in=({so_hash})"
            }]
            
            response = self._make_request("aggregation/searchGroup", "POST", params, data)
            #print (response)
            if not response:
                break
            current_data = response.get('serverResponseObject', [])
            all_patches.extend(current_data)
            
            if len(current_data) < self.page_size:
                break
            
            page_from += self.page_size
        
        return all_patches
    
    def get_assets_for_patch(self, patch_id, so_hash):
        """Gets assets affected by a patch."""
        all_assets = []
        page_from = 0
        
        while True:
            params = {
                'from': str(page_from),
                'size': str(self.page_size),
                'q': '',
                'sort': '-endpointEndpointScores.endpointScoresScore;-endpointAlive;endpointId',
                'includeFields': 'endpointId,endpointName,endpointUpdatedAt,endpointEndpointScores.endpointScoresScore,endpointEndpointScores.endpointScoresSensitivityLevel.sensitivityLevelName,endpointEndpointSubStatus.endpointSubStatusName',
            }
            
            data = [
                {
                    'searchQueryName': 'missingUpdates',
                    'searchQueryObjectName': 'OrganizationEndpointExternalReferenceExternalReferences',
                    'searchQueryObjectJoinByFieldName': 'endpointExternalReferenceHash',
                    'searchQueryObjectJoinByForeignFieldName': 'endpointExternalReferenceSecondaryHash',
                    'searchQueryQuery': f'organizationEndpointExternalReferenceExternalReferencesPatches.patchId=in=({patch_id})',
                },
                {
                    'searchQueryName': 'os',
                    'searchQueryObjectName': 'OrganizationEndpointPublisherOperatingSystems',
                    'searchQueryObjectJoinByFieldName': 'endpointId',
                    'searchQueryObjectJoinByForeignFieldName': 'endpointId',
                    'searchQueryQuery': f'publisherOperatingSystemHash=in=({so_hash});organizationEndpointPublisherOperatingSystemsExternalReferenceSecondary.externalReferenceId=ex=true',
                },
            ]
            
            response = self._make_request("endpoint/search", "POST", params, data)
            
            if not response:
                break
            
            current_data = response.get('serverResponseObject', [])
            all_assets.extend(current_data)
            
            if len(current_data) < self.page_size:
                break
            
            page_from += self.page_size
        
        return all_assets
    
    def locate_vulnerability_ids(self, external_ref_id, os_hash):
        """Locates vulnerability IDs for a specific patch."""
        params = {
            'from': '0',
            'size': '100',
            'objectName': 'OrganizationEndpointVulnerabilities',
            'group': 'organizationEndpointVulnerabilitiesPatch.externalReferenceId;vulnerabilityId;organizationEndpointVulnerabilitiesVulnerability.vulnerabilityExternalReference.externalReferenceId',
            'includeOriginalDoc': 'false',
            'q': f'organizationEndpointVulnerabilitiesPatch.externalReferenceId=in=({external_ref_id});publisherOperatingSystemHash=in=({os_hash})',
            'sort': 'aggregationId',
            'sumLastSubAggregationBuckets': '2',
            'newParser': 'true'
        }

        data = [{
            "searchQueryName": "patchVulnerabilities",
            "searchQueryObjectName": "OrganizationEndpointVulnerabilities",
            "searchQueryObjectJoinByFieldName": "organizationEndpointVulnerabilitiesPatch.externalReferenceId",
            "searchQueryObjectJoinByForeignFieldName": "organizationEndpointVulnerabilitiesPatch.externalReferenceId",
            "searchQueryQuery": f"organizationEndpointVulnerabilitiesPatch.externalReferenceId=in=({external_ref_id});publisherOperatingSystemHash=in=({os_hash})"
        }]

        try:
            response = self._make_request("aggregation/searchGroup", "POST", params, data)
            
            vulnerability_result = {
                'total_vulns': 0,
                'vuln_ids': []
            }
            
            if response and 'serverResponseObject' in response:
                for item in response.get('serverResponseObject', []):
                    for agg in item.get('aggregationAggregations', []):
                        if agg['aggregationName'] == 'vulnerabilityIds':
                            vulnerability_result['vuln_ids'].append(agg['aggregationId'])
                
                vulnerability_result['total_vulns'] = len(vulnerability_result['vuln_ids'])
            
            return vulnerability_result

        except Exception as e:
            logger.error(f"Error locating vulnerabilities: {e}")
            return {'total_vulns': 0, 'vuln_ids': []}

    def get_vulnerability_details(self, vuln_ids, os_hash, patch_id):
        """Gets vulnerability details."""
        params = {
            'from': '0',
            'size': '100',
            'objectName': 'OrganizationEndpointVulnerabilities',
            'group': 'vulnerabilityId;endpointId',
            'includeOriginalDoc': 'true',
            'q': f'vulnerabilityId=in=({",".join(map(str, vuln_ids))});publisherOperatingSystemHash=in=({os_hash});organizationEndpointVulnerabilitiesPatch.patchId=in=({patch_id})',
            'sort': 'aggregationId',
            'sumLastSubAggregationBuckets': '1'
        }

        data = [
            {
                "searchQueryName": "osCVEs",
                "searchQueryObjectName": "OrganizationEndpointPublisherOperatingSystems",
                "searchQueryObjectJoinByFieldName": "endpointExternalReferenceSecondaryHash",
                "searchQueryObjectJoinByForeignFieldName": "endpointExternalReferenceHash",
                "searchQueryQuery": f"publisherOperatingSystemHash=in=({os_hash});organizationEndpointPublisherOperatingSystemsExternalReferenceSecondary.externalReferenceId=ex=true",
                "searchQueryQueryJoinType": ""
            },
            {
                "searchQueryName": "osCVEs",
                "searchQueryObjectName": "OrganizationEndpointExternalReferenceExternalReferences",
                "searchQueryObjectJoinByFieldName": "externalReferenceSourceId",
                "searchQueryObjectJoinByForeignFieldName": "organizationEndpointVulnerabilitiesPatch.externalReferenceId",
                "searchQueryQuery": "",
                "searchQueryQueryJoinType": ""
            }
        ]

        try:
            response = self._make_request("aggregation/searchGroup", "POST", params, data)
            return response
        except Exception as e:
            logger.error(f"Error getting vulnerability details: {e}")
            return {}

# ============================================================================
# DATA PROCESSORS - Mantendo implementação original
# ============================================================================

def extract_os_info(raw_data):
    """Extracts operating system information."""
    results = []
    
    for item in raw_data:
        try:
            os_info = {
                'family': item.get('organizationPublisherOperatingSystemsOperatingSystemFamily', {}).get('operatingSystemFamilyName', 'N/A'),
                'publisher': item.get('organizationPublisherOperatingSystemsPublisher', {}).get('publisherName', 'N/A'),
                'os_name': item.get('organizationPublisherOperatingSystemsOperatingSystem', {}).get('operatingSystemName', 'N/A'),
                'os_id': item.get('operatingSystemId', 'N/A'),
                'hash': item.get('publisherOperatingSystemHash', 'N/A'),
                'last_update': datetime.fromtimestamp(
                    item.get('organizationPublisherOperatingSystemsUpdatedAt', 0) / 1000
                ).strftime('%Y-%m-%d %H:%M:%S') if item.get('organizationPublisherOperatingSystemsUpdatedAt') else 'N/A'
            }
            results.append(os_info)
        except Exception as e:
            logger.error(f"Error processing OS: {str(e)}")
            continue
    
    return results

def extract_patch_info(raw_data, so_info):
    """Extracts patch information."""
    results = []
    
    for item in raw_data:
        try:
            if item.get('aggregationName') != 'organizationEndpointExternalReferenceExternalReferencesPatches.patchName.raws':
                continue
            
            patch_info = {
                'so_hash': so_info['hash'],
                'fabricante': so_info['publisher'],
                'os_name': so_info['os_name'],
                'familia': so_info['family'],
                'patch_name': item.get('aggregationId', 'N/A'),
                'patch_id': None,
                'external_ref_id': None,
                'assets_count': item.get('aggregationCount', 0),
                'sensibilidade': None,
                'data_lancamento': None,
                'dias_desde_lancamento': None
            }
            
            # Process nested aggregations
            for agg in item.get('aggregationAggregations', []):
                if agg['aggregationName'] == 'organizationEndpointExternalReferenceExternalReferencesPatches.patchSensitivityLevel.sensitivityLevelNames':
                    patch_info['sensibilidade'] = agg['aggregationId']
                elif agg['aggregationName'] == 'organizationEndpointExternalReferenceExternalReferencesPatches.patchReleaseDates':
                    try:
                        timestamp = int(agg['aggregationId']) / 1000
                        # Store as datetime object for TIMESTAMP column
                        patch_info['data_lancamento'] = datetime.fromtimestamp(timestamp)
                        
                        release_date_obj = datetime.fromtimestamp(timestamp).date()
                        today = date.today()
                        patch_info['dias_desde_lancamento'] = (today - release_date_obj).days
                    except (ValueError, TypeError):
                        patch_info['data_lancamento'] = None  # Use NULL for invalid dates
                
                for nested_agg in agg.get('aggregationAggregations', []):
                    if nested_agg['aggregationName'] == 'organizationEndpointExternalReferenceExternalReferencesPatches.patchIds':
                        # Convert to int for BIGINT column
                        try:
                            patch_info['patch_id'] = int(nested_agg['aggregationId']) if nested_agg['aggregationId'] else None
                        except (ValueError, TypeError):
                            patch_info['patch_id'] = None
                        
                        for source_agg in nested_agg.get('aggregationAggregations', []):
                            if source_agg['aggregationName'] == 'externalReferenceSourceIds':
                                patch_info['external_ref_id'] = source_agg['aggregationId']
            
            results.append(patch_info)
            
        except Exception as e:
            logger.error(f"Error processing patch: {str(e)}")
            continue
    
    return results

def extract_asset_info(raw_data, patch_info, so_info):
    """Extracts asset information."""
    results = []
    
    for item in raw_data:
        try:
            dias_diferenca = None
            if patch_info.get('data_lancamento'):
                try:
                    # data_lancamento is now a datetime object
                    if isinstance(patch_info['data_lancamento'], datetime):
                        release_date = patch_info['data_lancamento'].date()
                        today = date.today()
                        dias_diferenca = (today - release_date).days
                    else:
                        dias_diferenca = patch_info.get('dias_desde_lancamento')
                except (ValueError, TypeError):
                    dias_diferenca = patch_info.get('dias_desde_lancamento')
            
            asset_info = {
                'patch_id': patch_info.get('patch_id'),
                'so_hash': so_info['hash'],
                'asset_name': item.get('endpointName', 'N/A'),
                'asset_id': int(item.get('endpointId')) if item.get('endpointId') and str(item.get('endpointId')).isdigit() else None,
                'fabricante': so_info['publisher'],
                'os_name': so_info['os_name'],
                'familia': so_info['family'],
                'patch_name': patch_info.get('patch_name', 'N/A'),
                'assets_afetados': patch_info.get('assets_count', 0),
                'sensibilidade': patch_info.get('sensibilidade', 'N/A'),
                'data_lancamento': patch_info.get('data_lancamento'),  # Now a datetime object or None
                'diferenca_dias': dias_diferenca,
                'score_asset': str(item.get('endpointEndpointScores', {}).get('endpointScoresScore', 'N/A')),
                'status_asset': item.get('endpointEndpointSubStatus', {}).get('endpointSubStatusName', 'N/A'),
                'last_updated': datetime.fromtimestamp(
                    item.get('endpointUpdatedAt', 0) / 1000
                ).strftime('%Y-%m-%d') if item.get('endpointUpdatedAt') else 'N/A'
            }
            results.append(asset_info)
        except Exception as e:
            logger.error(f"Error processing asset: {str(e)}")
            continue
    
    return results

def extract_vulnerability_info(raw_data, patch_info, so_info):
    """Extracts vulnerability information."""
    results = []
    
    try:
        if not raw_data or 'serverResponseObject' not in raw_data:
            return results
        
        for item in raw_data['serverResponseObject']:
            try:
                vuln_data = item.get('aggregationModelAbs', {}).get('organizationEndpointVulnerabilitiesVulnerability', {})
                
                if not vuln_data:
                    continue
                
                ext_ref = vuln_data.get('vulnerabilityExternalReference', {})
                sensitivity = vuln_data.get('vulnerabilitySensitivityLevel', {})
                threat = sensitivity.get('sensitivityLevelThreatLevel', {})
                
                vuln_info = {
                    'patch_id': patch_info.get('patch_id'),
                    'so_hash': so_info['hash'],
                    'fabricante': so_info['publisher'],
                    'os_name': so_info['os_name'],
                    'familia': so_info['family'],
                    'patch_name': patch_info.get('patch_name', 'N/A'),
                    'vulnerability_id': vuln_data.get('vulnerabilityId', 'N/A'),
                    'cve_id': ext_ref.get('externalReferenceExternalId', 'N/A'),
                    'vulnerability_summary': vuln_data.get('vulnerabilitySummary', 'N/A'),
                    'severity': sensitivity.get('sensitivityLevelName', 'N/A'),
                    'threat_level': threat.get('threatLevelName', 'N/A'),
                    'cvss_score': str(vuln_data.get('vulnerabilityV3BaseScore', 'N/A')),
                    'cvss_vector': vuln_data.get('vulnerabilityV3Vector', 'N/A'),
                    'impact_level': vuln_data.get('vulnerabilityV3ImpactLevel', 'N/A'),
                    'exploitability_level': vuln_data.get('vulnerabilityV3ExploitabilityLevel', 'N/A'),
                    'published_at': datetime.fromtimestamp(
                        vuln_data.get('vulnerabilityPublishedAt', 0) / 1000
                    ).strftime('%Y-%m-%d') if vuln_data.get('vulnerabilityPublishedAt') else 'N/A',
                    'modified_at': datetime.fromtimestamp(
                        vuln_data.get('vulnerabilityModifiedAt', 0) / 1000
                    ).strftime('%Y-%m-%d') if vuln_data.get('vulnerabilityModifiedAt') else 'N/A',
                    'cisa_action': vuln_data.get('vulnerabilityCISARequiredAction', 'N/A')
                }
                
                results.append(vuln_info)
                
            except Exception as e:
                logger.error(f"Error processing vulnerability: {str(e)}")
                continue
    
    except Exception as e:
        logger.error(f"Error extracting vulnerability info: {str(e)}")
    
    return results

def get_vulnerabilities_for_patch(api, patch_info, so_info):
    """Gets vulnerabilities for a specific patch."""
    vulnerabilities = []
    
    try:
        if not patch_info.get('external_ref_id'):
            return vulnerabilities
        
        vuln_result = api.locate_vulnerability_ids(patch_info['external_ref_id'], so_info['hash'])
        
        if vuln_result['total_vulns'] == 0:
            return vulnerabilities
        
        if patch_info.get('patch_id'):
            vulnerability_details = api.get_vulnerability_details(
                vuln_result['vuln_ids'], 
                so_info['hash'], 
                patch_info['patch_id']
            )
            
            if vulnerability_details:
                vulnerabilities = extract_vulnerability_info(vulnerability_details, patch_info, so_info)
        
        time.sleep(1)  # Rate limiting
        
    except Exception as e:
        logger.error(f"Error getting vulnerabilities: {str(e)}")
    
    return vulnerabilities

# ============================================================================
# PATCH DATE UPDATE FUNCTIONS - Integrated from update_patch_dates.py
# ============================================================================

def get_distinct_patch_ids_from_db(db_config):
    """Gets distinct patch_ids from assets table."""
    def _get_patch_ids_internal(conn):
        cursor = conn.cursor()
        
        # Query distinct patch_ids that are not null
        cursor.execute("""
            SELECT DISTINCT patch_id 
            FROM assets 
            WHERE patch_id IS NOT NULL 
            ORDER BY patch_id
        """)
        
        patch_ids = [row[0] for row in cursor.fetchall()]
        logger.warning(f"Found {len(patch_ids)} distinct patch IDs in assets table")
        
        return patch_ids
    
    try:
        return execute_with_retry(db_config, _get_patch_ids_internal)
    except Exception as e:
        logger.error(f"Error querying patch IDs: {str(e)}")
        return []

def update_patch_dates_in_db(db_config, patch_updates):
    """Updates data_lancamento for patches in both patches and assets tables."""
    if not patch_updates:
        return 0
    
    def _update_patch_dates_internal(conn, patch_updates):
        cursor = conn.cursor()
        updated_count = 0
        
        for patch_data in patch_updates:
            patch_id = patch_data['patch_id']
            patch_date = patch_data['patch_date']
            
            # Update patches table
            cursor.execute("""
                UPDATE patches 
                SET data_lancamento = %s 
                WHERE patch_id = %s AND (data_lancamento IS NULL OR data_lancamento != %s)
            """, (patch_date, patch_id, patch_date))
            
            patches_updated = cursor.rowcount
            
            # Update assets table
            cursor.execute("""
                UPDATE assets 
                SET data_lancamento = %s 
                WHERE patch_id = %s AND (data_lancamento IS NULL OR data_lancamento != %s)
            """, (patch_date, patch_id, patch_date))
            
            assets_updated = cursor.rowcount
            
            if patches_updated > 0 or assets_updated > 0:
                logger.warning(f"Updated patch_id {patch_id}: {patches_updated} patches, {assets_updated} assets")
                updated_count += 1
        
        logger.warning(f"Successfully updated {updated_count} patches with creation dates")
        return updated_count
    
    try:
        return execute_with_retry(db_config, _update_patch_dates_internal, patch_updates)
    except Exception as e:
        logger.error(f"Error updating patch dates: {str(e)}")
        return 0

def query_patch_info_from_api(dashboard_id, vicarius_token, patch_ids):
    """Queries patch information from Vicarius Customer API."""
    patch_dates = {}
    
    headers = {
        'accept': 'application/json, text/plain, */*',
        'accept-language': 'en-US,en;q=0.9',
        'priority': 'u=1, i',
        'sec-ch-ua': '"Not)A;Brand";v="8", "Chromium";v="138", "Google Chrome";v="138"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
        'vicarius-token': vicarius_token,
        'Cookie': f'Vicarius-Token={vicarius_token}; Vicarius-Token={vicarius_token}'
    }
    
    # Process patches in batches of 10 to avoid URL length issues
    batch_size = 10
    total_patches = len(patch_ids)
    processed = 0
    
    for i in range(0, len(patch_ids), batch_size):
        batch_patch_ids = patch_ids[i:i + batch_size]
        patch_ids_str = ','.join(map(str, batch_patch_ids))
        
        try:
            # Build URL with batch of patch IDs
            url = f"https://{dashboard_id}.vicarius.cloud/vicarius-external-data-api/patchManagement/patch?from=0&size=100&softwareType=OS&patchIds={patch_ids_str}"
            
            logger.warning(f"Querying batch {i//batch_size + 1} with patches: {batch_patch_ids} ({processed + 1}-{min(processed + batch_size, total_patches)}/{total_patches})")
            
            payload = {}
            response = requests.get(url, headers=headers, data=payload, timeout=30)
            
            if response.status_code == 401:
                logger.error("Authentication failed - invalid Vicarius token")
                break
            elif response.status_code == 429:
                logger.warning("Rate limit hit, waiting 5 seconds...")
                time.sleep(5)
                continue
            elif response.status_code != 200:
                logger.warning(f"API error for batch {batch_patch_ids}: HTTP {response.status_code}")
                time.sleep(REQUEST_DELAY)
                continue
            
            try:
                data = response.json()
            except json.JSONDecodeError:
                logger.warning(f"Invalid JSON response for batch {batch_patch_ids}")
                time.sleep(REQUEST_DELAY)
                continue
            
            # Check response structure
            if (data.get('serverResponseResult', {}).get('serverResponseResultCode') == 'SUCCESS' and
                data.get('serverResponseObject')):
                
                # Process all patches in the response
                for patch_info in data['serverResponseObject']:
                    patch_id = patch_info.get('patchId')
                    if patch_id:
                        # Prioritize patchReleaseDate over patchCreatedDate, but use creation date if release date is in 1970
                        patch_release_date = patch_info.get('patchReleaseDate')
                        patch_created_date = patch_info.get('patchCreatedDate')
                        
                        # Check if release date is in 1970 (invalid/placeholder data)
                        use_creation_date = False
                        if patch_release_date:
                            release_date_obj = datetime.fromtimestamp(patch_release_date / 1000)
                            if release_date_obj.year == 1970:
                                use_creation_date = True
                        
                        if use_creation_date and patch_created_date:
                            patch_timestamp = patch_created_date
                            date_type = "creation (release date in 1970)"
                        elif patch_release_date and not use_creation_date:
                            patch_timestamp = patch_release_date
                            date_type = "release"
                        elif patch_created_date:
                            patch_timestamp = patch_created_date
                            date_type = "creation"
                        else:
                            patch_timestamp = None
                            date_type = None
                        
                        if patch_timestamp:
                            # Convert milliseconds timestamp to datetime
                            patch_date = datetime.fromtimestamp(patch_timestamp / 1000)
                            patch_dates[patch_id] = patch_date
                            
                            logger.warning(f"Found patch {patch_id}: {patch_info.get('patchName', 'Unknown')} "
                                          f"{date_type} date: {patch_date.strftime('%Y-%m-%d %H:%M:%S')}")
                        else:
                            logger.warning(f"No release or creation date found for patch {patch_id}")
            else:
                result_message = data.get('serverResponseResult', {}).get('serverResponseResultMessage', 'Unknown error')
                logger.warning(f"API query failed for batch {batch_patch_ids}: {result_message}")
            
            processed += len(batch_patch_ids)
            
            # Rate limiting - wait 1 second between batch requests
            if processed < total_patches:
                time.sleep(REQUEST_DELAY)
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error querying batch {batch_patch_ids}: {str(e)}")
            time.sleep(REQUEST_DELAY)
        except Exception as e:
            logger.error(f"Unexpected error querying batch {batch_patch_ids}: {str(e)}")
            time.sleep(REQUEST_DELAY)
    
    logger.warning(f"Successfully queried {len(patch_dates)} patches out of {total_patches}")
    return patch_dates

def execute_patch_date_update(api_key, dashboard, db_config):
    """Executes patch date update process."""
    logger.warning("=== PATCH DATE UPDATE PROCESS ===")
    
    try:
        # Get distinct patch IDs from database
        logger.warning("Querying distinct patch IDs from assets table...")
        patch_ids = get_distinct_patch_ids_from_db(db_config)
        
        if not patch_ids:
            logger.warning("No patch IDs found in assets table")
            return
        
        logger.warning(f"Found {len(patch_ids)} distinct patch IDs: {patch_ids[:10]}{'...' if len(patch_ids) > 10 else ''}")
        
        # Query patch information from API
        logger.warning("Starting patch date API queries...")
        patch_dates = query_patch_info_from_api(dashboard, api_key, patch_ids)
        
        if not patch_dates:
            logger.warning("No patch dates retrieved from API")
            return
        
        # Prepare updates
        patch_updates = [
            {
                'patch_id': patch_id,
                'patch_date': patch_date
            }
            for patch_id, patch_date in patch_dates.items()
        ]
        
        # Update database
        logger.warning("Updating database with patch creation dates...")
        updated_count = update_patch_dates_in_db(db_config, patch_updates)
        
        # Summary
        logger.warning("=== PATCH DATE UPDATE SUMMARY ===")
        logger.warning(f"Total patch IDs queried: {len(patch_ids)}")
        logger.warning(f"Successful API responses: {len(patch_dates)}")
        logger.warning(f"Database records updated: {updated_count}")
        logger.warning(f"Success rate: {len(patch_dates)/len(patch_ids)*100:.1f}%")
        
        if len(patch_dates) < len(patch_ids):
            failed_patches = set(patch_ids) - set(patch_dates.keys())
            logger.warning(f"Failed patches: {sorted(list(failed_patches))[:10]}{'...' if len(failed_patches) > 10 else ''}")
        
    except Exception as e:
        logger.error(f"Patch date update failed: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())

# ============================================================================
# MAIN FUNCTIONS
# ============================================================================

def read_secret(secret_name):
    """Lê secrets do sistema."""
    try:
        with open(f'/run/secrets/{secret_name}', 'r') as secret_file:
            return secret_file.read().strip()
    except IOError:
        logger.error(f"Unable to read secret: {secret_name}")
        return None

def execute_complete_patches_collection(api_key, dashboard, db_config):
    """Função principal usando abordagem DatabaseConnector."""
    start_time = time.time()
    
    logger.warning(f"Starting Vicarius collection with DatabaseConnector approach - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.warning(f"Database: {db_config['host']}:{db_config['port']}/{db_config['database']}")
    
    try:
        # Inicializar
        db = VicariusDB(db_config)
        api = VicariusAPI(api_key, dashboard)
        
        # 1. Coletar sistemas operacionais
        logger.warning("=== COLLECTING OPERATING SYSTEMS ===")
        raw_so_data = api.get_all_os_data()
        
        if not raw_so_data:
            logger.error("Could not get operating systems data")
            return {'success': False, 'error': 'No OS data found'}
        
        so_results = extract_os_info(raw_so_data)
        logger.warning(f"Operating systems processed: {len(so_results)}")
        
        # Salvar SOs no banco
        for so in so_results:
            db.insert_so(so)
        
        # 2. Coletar patches, assets e vulnerabilidades
        logger.warning("=== COLLECTING PATCHES, ASSETS AND VULNERABILITIES ===")
        total_patches = 0
        total_assets = 0
        total_vulnerabilities = 0
        
        for i, so in enumerate(so_results, 1):
            logger.warning(f"[{i}/{len(so_results)}] Processing: {so['os_name']}")
            
            # Get OS patches
            raw_patches = api.get_patches_for_so(so['hash'])
            
            if not raw_patches:
                logger.warning(f"No patches found for {so['os_name']}")
                continue
            
            patches = extract_patch_info(raw_patches, so)
            
            if not patches:
                logger.warning(f"No valid patches for {so['os_name']}")
                continue
            
            logger.warning(f"Patches found: {len(patches)}")
            
            # Preparar dados para inserção em lote
            patches_data = []
            all_assets_data = []
            all_vulnerabilities_data = []
            
            for patch in patches:
                logger.warning(f"Processing patch '{patch['patch_name']}' (expected assets: {patch['assets_count']})")
                
                # Dados do patch
                patches_data.append((
                    patch['so_hash'],
                    patch['fabricante'],
                    patch['os_name'],
                    patch['familia'],
                    patch['patch_name'],
                    patch['patch_id'],
                    patch['external_ref_id'],
                    patch['assets_count'],
                    patch['sensibilidade'],
                    patch['data_lancamento'],
                    patch['dias_desde_lancamento']
                ))
                
                # Obter assets do patch (se tem patch_id)
                if patch['patch_id'] and patch['assets_count'] > 0:
                    logger.warning(f"Getting assets for patch '{patch['patch_name']}' (expected: {patch['assets_count']})")
                    raw_assets = api.get_assets_for_patch(patch['patch_id'], so['hash'])
                    
                    if raw_assets:
                        assets = extract_asset_info(raw_assets, patch, so)
                        actual_count = len(assets)
                        
                        # Log diferença entre esperado e real
                        if actual_count != patch['assets_count']:
                            logger.warning(f"ASSETS COUNT MISMATCH - Patch: {patch['patch_name']}")
                            logger.warning(f"  Expected: {patch['assets_count']}, Got: {actual_count}, Diff: {actual_count - patch['assets_count']}")
                        
                        for asset in assets:
                            all_assets_data.append((
                                asset['patch_id'],
                                asset['so_hash'],
                                asset['asset_name'],
                                asset['asset_id'],
                                asset['fabricante'],
                                asset['os_name'],
                                asset['familia'],
                                asset['patch_name'],
                                asset['assets_afetados'],
                                asset['sensibilidade'],
                                asset['data_lancamento'],
                                asset['diferenca_dias'],
                                asset['score_asset'],
                                asset['status_asset'],
                                asset['last_updated']
                            ))
                        
                        logger.warning(f"Assets collected for '{patch['patch_name']}': {len(assets)}")
                    else:
                        logger.warning(f"No assets returned by API for patch '{patch['patch_name']}'")
                elif patch['assets_count'] == 0:
                    logger.warning(f"Skipping patch '{patch['patch_name']}' - assets_count is 0")
                else:
                    logger.warning(f"Skipping patch '{patch['patch_name']}' - no patch_id")
                
                # PROCESSAR VULNERABILIDADES PARA CADA PATCH
                if patch['patch_id'] and patch['external_ref_id']:
                    logger.warning(f"Processing vulnerabilities for patch '{patch['patch_name']}'")
                    
                    try:
                        # Obter vulnerabilidades para este patch
                        vulnerabilities = get_vulnerabilities_for_patch(api, patch, so)
                        
                        if vulnerabilities:
                            # Preparar dados de vulnerabilidade para inserção em lote
                            for vuln in vulnerabilities:
                                all_vulnerabilities_data.append((
                                    vuln['patch_id'],
                                    vuln['so_hash'],
                                    vuln['fabricante'],
                                    vuln['os_name'],
                                    vuln['familia'],
                                    vuln['patch_name'],
                                    vuln['vulnerability_id'],
                                    vuln['cve_id'],
                                    vuln['vulnerability_summary'],
                                    vuln['severity'],
                                    vuln['threat_level'],
                                    vuln['cvss_score'],
                                    vuln['cvss_vector'],
                                    vuln['impact_level'],
                                    vuln['exploitability_level'],
                                    vuln['published_at'],
                                    vuln['modified_at'],
                                    vuln['cisa_action']
                                ))
                            
                            logger.warning(f"Vulnerabilities found for '{patch['patch_name']}': {len(vulnerabilities)}")
                        else:
                            logger.warning(f"No vulnerabilities found for '{patch['patch_name']}'")
                    
                    except Exception as e:
                        logger.error(f"Error processing vulnerabilities for '{patch['patch_name']}': {str(e)}")
                
                elif not patch['external_ref_id']:
                    logger.warning(f"Skipping vulnerabilities for '{patch['patch_name']}' - no external_ref_id")
            
            # Inserir patches, assets e vulnerabilidades em lote (usando DatabaseConnector approach)
            if patches_data:
                db.insert_patches_batch(patches_data)
                total_patches += len(patches_data)
            
            if all_assets_data:
                db.insert_assets_batch(all_assets_data)
                total_assets += len(all_assets_data)
            
            if all_vulnerabilities_data:
                db.insert_vulnerabilities_batch(all_vulnerabilities_data)
                total_vulnerabilities += len(all_vulnerabilities_data)
            
            logger.warning(f"Data saved for {so['os_name']}: {len(patches_data)} patches, {len(all_assets_data)} assets, {len(all_vulnerabilities_data)} vulnerabilities")
        
        # 3. Estatísticas finais
        stats = db.get_stats()
        execution_time = time.time() - start_time
        
        logger.warning("=== FINAL STATISTICS ===")
        logger.warning(f"Execution time: {execution_time:.2f} seconds")
        logger.warning(f"API requests: {api.request_count}")
        logger.warning(f"Operating systems: {stats['operating_system']}")
        logger.warning(f"Patches: {stats['patches']}")
        logger.warning(f"Assets: {stats['assets']}")
        logger.warning(f"Vulnerabilities: {stats['vulnerabilities']}")
        logger.warning(f"Total records: {stats['total']}")
        
        logger.warning("=== EXECUTION COMPLETED SUCCESSFULLY ===")
        
        # Execute patch date update process
        logger.warning("=== STARTING PATCH DATE UPDATE ===")
        execute_patch_date_update(api_key, dashboard, db_config)
        
        return {
            'success': True,
            'stats': stats,
            'execution_time': execution_time,
            'api_requests': api.request_count,
            'message': 'Collection completed successfully using DatabaseConnector approach with patch date updates'
        }
    
    except Exception as e:
        logger.error(f"Critical error: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return {
            'success': False,
            'error': str(e)
        }

def main():
    """Função principal usando secrets."""
    db_config = {
        'host': 'appdb',
        'port': '5432',
        'user': read_secret('postgres_user'),
        'password': read_secret('postgres_password'),
        'database': read_secret('postgres_db')
    }
    
    api_key = read_secret('api_key')
    dashboard = read_secret('dashboard_id')
    
    if api_key and dashboard:
        result = execute_complete_patches_collection(api_key, dashboard, db_config)
        print(f"Result: {result}")
    else:
        print("Error: Could not read necessary secrets")

if __name__ == "__main__":
    main()