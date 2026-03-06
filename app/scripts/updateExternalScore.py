# External vulnerability data loader for EPSS and KEV

import requests
import gzip
import json
import pandas as pd
from sqlalchemy import create_engine, text, Table, Column, String, Float, MetaData, DateTime, Boolean
from datetime import datetime, timedelta
import os
import tempfile
import urllib.parse

def download_and_load_epss_data(db_host, db_port, db_username, db_password, db_name):
    """Load EPSS data with all fields"""
    table_name = 'epssdata'
    
    # Use environment variable or default to correct URL
    url = os.environ.get('EPSS_URL', 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz')
    
    print(f"Downloading EPSS data from: {url}")
    
    # Headers for request
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
    }
    
    try:
        # Add SSL verification and timeout for security
        response = requests.get(url, headers=headers, verify=True, timeout=30)
        if response.status_code == 200:
            # Use secure temporary file instead of predictable path
            with tempfile.NamedTemporaryFile(suffix='.csv.gz', delete=False) as temp_file:
                temp_gz = temp_file.name
                temp_file.write(response.content)
            
            # Extract and read with metadata
            with gzip.open(temp_gz, "rt") as f:
                # Extract metadata from header
                header_line = f.readline()  # #model_version:v2025.03.14,score_date:2025-09-06T12:55:00Z
                model_version = None
                score_date = None
                
                if header_line.startswith('#'):
                    if 'model_version:' in header_line:
                        model_version = header_line.split('model_version:')[1].split(',')[0]
                    if 'score_date:' in header_line:
                        score_date = header_line.split('score_date:')[1].strip().replace('Z', '')
                
                # Read CSV data (all 3 fields)
                df = pd.read_csv(f)
                
                # Add metadata columns
                df['model_version'] = model_version
                df['score_date'] = score_date
                df['last_updated'] = datetime.now()
            
            # Connect to database
            db_password_encoded = urllib.parse.quote_plus(db_password)
            engine = create_engine(f'postgresql://{db_username}:{db_password_encoded}@{db_host}:{db_port}/{db_name}')
            
            # Clear old data and insert new
            with engine.connect() as conn:
                conn.execute(text(f"DROP TABLE IF EXISTS {table_name}"))
                conn.commit()
            
            # Insert new data
            df.to_sql(table_name, engine, if_exists='replace', index=False)
            
            # Clean up temporary file securely
            try:
                os.remove(temp_gz)
            except OSError:
                pass  # File might already be deleted
            
            print(f"EPSS data updated successfully: {len(df)} records")
            return True
            
        else:
            print(f"Failed to download EPSS data. Status code: {response.status_code}")
            return False
            
    except requests.exceptions.SSLError as e:
        print(f"SSL verification failed for EPSS data: {e}")
        return False
    except requests.exceptions.Timeout as e:
        print(f"Request timeout for EPSS data: {e}")
        return False
    except requests.exceptions.RequestException as e:
        print(f"Request error loading EPSS data: {e}")
        return False
    except Exception as e:
        print(f"Error loading EPSS data: {e}")
        # Clean up temp file if it exists
        if 'temp_gz' in locals():
            try:
                os.remove(temp_gz)
            except:
                pass
        return False

def download_and_load_kev_data(db_host, db_port, db_username, db_password, db_name):
    """Load KEV data with ALL fields"""
    table_name = 'kevdata'
    
    # Use environment variable or default
    url = os.environ.get('KEV_URL', 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json')
    
    print(f"Downloading KEV data from: {url}")
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
    }
    
    try:
        # Add SSL verification and timeout for security
        response = requests.get(url, headers=headers, verify=True, timeout=30)
        if response.status_code == 200:
            data = response.json()
            
            # Capture metadata
            metadata = {
                'catalog_title': data.get('title'),
                'catalog_version': data.get('catalogVersion'),
                'date_released': data.get('dateReleased'),
                'total_count': data.get('count')
            }
            
            print(f"KEV Catalog: {metadata['catalog_title']}")
            print(f"Version: {metadata['catalog_version']}, Released: {metadata['date_released']}")
            print(f"Total vulnerabilities: {metadata['total_count']}")
            
            # Capture ALL vulnerability fields
            records = []
            for vuln in data.get('vulnerabilities', []):
                record = {
                    # All main fields
                    'cve_id': vuln.get('cveID'),
                    'vendor_project': vuln.get('vendorProject'),
                    'product': vuln.get('product'),
                    'vulnerability_name': vuln.get('vulnerabilityName'),
                    'date_added': vuln.get('dateAdded'),
                    'short_description': vuln.get('shortDescription'),
                    'required_action': vuln.get('requiredAction'),
                    'due_date': vuln.get('dueDate'),
                    'known_ransomware_campaign_use': vuln.get('knownRansomwareCampaignUse'),
                    'notes': vuln.get('notes'),
                    'cwes': ','.join(vuln.get('cwes', [])) if vuln.get('cwes') else None,
                    # Add metadata
                    'catalog_version': metadata['catalog_version'],
                    'catalog_date_released': metadata['date_released'],
                    'last_updated': datetime.now()
                }
                records.append(record)
            
            if records:
                df = pd.DataFrame(records)
                
                # Connect to database
                db_password_encoded = urllib.parse.quote_plus(db_password)
                engine = create_engine(f'postgresql://{db_username}:{db_password_encoded}@{db_host}:{db_port}/{db_name}')
                
                # Replace entire table with new data
                df.to_sql(table_name, engine, if_exists='replace', index=False)
                
                print(f"KEV data updated successfully: {len(df)} records")
                return True
            else:
                print("No KEV vulnerability records found")
                return False
                
        else:
            print(f"Failed to download KEV data. Status code: {response.status_code}")
            return False
            
    except requests.exceptions.SSLError as e:
        print(f"SSL verification failed for KEV data: {e}")
        return False
    except requests.exceptions.Timeout as e:
        print(f"Request timeout for KEV data: {e}")
        return False
    except requests.exceptions.RequestException as e:
        print(f"Request error loading KEV data: {e}")
        return False
    except Exception as e:
        print(f"Error loading KEV data: {e}")
        return False

def read_secret(secret_name):
    """Read Docker secret"""
    try:
        with open(f'/run/secrets/{secret_name}', 'r') as f:
            return f.read().strip()
    except:
        return None

def load_vulncheck_data(host, port, user, password, database):
    """Load Vulncheck enrichment data"""
    # Check if vulncheck is enabled
    if os.environ.get('VULNCHECK_ENABLED', 'false').lower() != 'true':
        print("Vulncheck integration is disabled")
        return True
    
    print("Loading Vulncheck enrichment data...")
    
    try:
        # Import here to avoid dependency issues if vulncheck module is missing
        import sys
        import psycopg2
        sys.path.append('/usr/src/app/scripts')
        from vulncheck_pg.main import VulncheckDB
        
        # Create database connection
        conn = psycopg2.connect(
            host=host, port=port, user=user, password=password, database=database
        )
        
        # Initialize vulncheck with existing connection
        vulncheck_db = VulncheckDB(db_connection=conn)
        
        # Setup tables if needed
        if not vulncheck_db.setup_tables():
            print("Failed to setup vulncheck tables")
            return False
        
        # Run synchronization
        success = vulncheck_db.sync_active_vulnerabilities()
        
        if success:
            # Get and display stats
            stats = vulncheck_db.get_stats()
            print(f"Vulncheck sync completed:")
            print(f"  - Total enriched CVEs: {stats['total']}")
            print(f"  - Active CVEs: {stats['active']}")
            print(f"  - Enriched with data: {stats['enriched']}")
            print(f"  - Weaponized exploits: {stats['weaponized']}")
            print(f"  - Ransomware campaigns: {stats['ransomware']}")
        else:
            print("Vulncheck sync completed with some issues (check logs)")
        
        # Cleanup
        vulncheck_db.cleanup()
        return success
        
    except ImportError:
        print("Vulncheck module not available - skipping vulncheck sync")
        return True  # Not a failure if module doesn't exist
    except Exception as e:
        print(f"Error loading vulncheck data: {e}")
        return False

# Main function to run all external data sources if enabled
if __name__ == "__main__":
    # Get database config from secrets
    host = "appdb"
    port = "5432"
    user = read_secret('postgres_user')
    password = read_secret('postgres_password')
    database = read_secret('postgres_db')
    
    # Check if we have valid credentials
    if not all([user, password, database]):
        print("Error: Could not read database credentials from Docker secrets")
        exit(1)
    
    # Check if any external data sources are enabled
    external_enabled = os.environ.get('EXTERNAL_DATA_ENABLED', 'false').lower() == 'true'
    vulncheck_enabled = os.environ.get('VULNCHECK_ENABLED', 'false').lower() == 'true'
    
    if external_enabled or vulncheck_enabled:
        print("External data sources enabled:")
        if external_enabled:
            print("  - KEV + EPSS data sources")
        if vulncheck_enabled:
            print("  - Vulncheck integration")
        
        # Initialize success tracking
        epss_success = True  # Default to success if not enabled
        kev_success = True   # Default to success if not enabled
        vulncheck_success = True  # Default to success if not enabled
        
        # Load EPSS data (only if external data is enabled)
        if external_enabled:
            print("\n--- Loading EPSS Data ---")
            epss_success = download_and_load_epss_data(host, port, user, password, database)
        
        # Load KEV data (only if external data is enabled) 
        if external_enabled:
            print("\n--- Loading KEV Data ---")
            kev_success = download_and_load_kev_data(host, port, user, password, database)
        
        # Load Vulncheck data (if enabled)
        if vulncheck_enabled:
            print("\n--- Loading Vulncheck Data ---")
            vulncheck_success = load_vulncheck_data(host, port, user, password, database)
        
        # Summary
        print("\n--- Summary ---")
        if external_enabled:
            print(f"EPSS Update: {'Success' if epss_success else 'Failed'}")
            print(f"KEV Update: {'Success' if kev_success else 'Failed'}")
        if vulncheck_enabled:
            print(f"Vulncheck Update: {'Success' if vulncheck_success else 'Failed'}")
        
        # Count only enabled sources for success calculation
        enabled_sources = []
        if external_enabled:
            enabled_sources.extend([epss_success, kev_success])
        if vulncheck_enabled:
            enabled_sources.append(vulncheck_success)
        
        success_count = sum(enabled_sources)
        total_enabled = len(enabled_sources)
        
        if success_count == total_enabled:
            print("All enabled external data sources updated successfully")
            exit(0)
        elif success_count > 0:
            print("Some external data sources updated successfully")
            exit(0)
        else:
            print("Failed to update external data sources")
            exit(1)
    else:
        print("All external data sources are disabled")
        print("Enable with: EXTERNAL_DATA_ENABLED=true (KEV+EPSS) or VULNCHECK_ENABLED=true")
        exit(0)