#!/usr/bin/env python3
"""
Patch Date Update Script
Queries distinct patch_ids from assets table and updates data_lancamento 
with patchCreatedDate from Vicarius Customer API
"""

import requests
import psycopg2
import logging
import time
import json
import getpass
from datetime import datetime
from typing import List, Dict, Optional

# ============================================================================
# CONFIGURATION
# ============================================================================

# Connection configuration
CONNECTION_TIMEOUT = 30
STATEMENT_TIMEOUT = 120000  # 2 minutes
MAX_RETRIES = 3
REQUEST_DELAY = 1.0  # 1 second between API requests


# ============================================================================
# LOGGING SETUP
# ============================================================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# ============================================================================
# DATABASE FUNCTIONS
# ============================================================================

def read_secret(secret_name: str) -> Optional[str]:
    """Reads secrets from the system."""
    try:
        with open(f'/run/secrets/{secret_name}', 'r') as secret_file:
            return secret_file.read().strip()
    except IOError:
        logger.error(f"Unable to read secret: {secret_name}")
        return None

def get_database_connection():
    """Creates database connection."""
    db_config = {
        'host': 'appdb',
        'port': '5432',
        'user': read_secret('postgres_user'),
        'password': read_secret('postgres_password'),
        'database': read_secret('postgres_db')
    }
    
    if not all(db_config.values()):
        raise ValueError("Missing database configuration. Please check secrets.")
    
    return psycopg2.connect(
        **db_config,
        options=f'-c statement_timeout={STATEMENT_TIMEOUT}',
        connect_timeout=CONNECTION_TIMEOUT
    )

def get_distinct_patch_ids() -> List[int]:
    """Gets distinct patch_ids from assets table."""
    conn = None
    try:
        conn = get_database_connection()
        cursor = conn.cursor()
        
        # Query distinct patch_ids that are not null
        cursor.execute("""
            SELECT DISTINCT patch_id 
            FROM assets 
            WHERE patch_id IS NOT NULL 
            ORDER BY patch_id
        """)
        
        patch_ids = [row[0] for row in cursor.fetchall()]
        logger.info(f"Found {len(patch_ids)} distinct patch IDs in assets table")
        
        return patch_ids
        
    except Exception as e:
        logger.error(f"Error querying patch IDs: {str(e)}")
        return []
    finally:
        if conn:
            conn.close()

def update_patch_dates(patch_updates: List[Dict]) -> int:
    """Updates data_lancamento for patches in both patches and assets tables."""
    if not patch_updates:
        return 0
    
    conn = None
    try:
        conn = get_database_connection()
        conn.autocommit = False
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
                logger.info(f"Updated patch_id {patch_id}: {patches_updated} patches, {assets_updated} assets")
                updated_count += 1
        
        conn.commit()
        logger.info(f"Successfully updated {updated_count} patches with creation dates")
        return updated_count
        
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Error updating patch dates: {str(e)}")
        return 0
    finally:
        if conn:
            conn.close()

# ============================================================================
# API FUNCTIONS
# ============================================================================

def get_vicarius_token() -> str:
    """Gets Vicarius token interactively."""
    token = getpass.getpass("Enter your Vicarius token: ").strip()
    if not token:
        raise ValueError("Vicarius token is required")
    return token

def get_dashboard_id() -> str:
    """Gets dashboard ID from secrets."""
    dashboard_id = read_secret('dashboard_id')
    if not dashboard_id:
        raise ValueError("Dashboard ID not found in secrets")
    return dashboard_id

def query_patch_info(dashboard_id: str, vicarius_token: str, patch_ids: List[int]) -> Dict[int, datetime]:
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
            
            logger.info(f"Querying batch {i//batch_size + 1} with patches: {batch_patch_ids} ({processed + 1}-{min(processed + batch_size, total_patches)}/{total_patches})")
            
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
                            
                            logger.info(f"Found patch {patch_id}: {patch_info.get('patchName', 'Unknown')} "
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
    
    logger.info(f"Successfully queried {len(patch_dates)} patches out of {total_patches}")
    return patch_dates

# ============================================================================
# MAIN FUNCTION
# ============================================================================

def main():
    """Main function."""
    logger.info("Patch Date Update Script Starting...")
    
    try:
        # Get configuration
        logger.info("Reading configuration...")
        dashboard_id = read_secret('dashboard_id')
        vicarius_token = read_secret('api_key') 
        
        logger.info(f"Dashboard ID: {dashboard_id}")
        #logger.info(f"Token: ********{vicarius_token[-4:] if len(vicarius_token) >= 4 else '****'}")
        
        # Get distinct patch IDs from database
        logger.info("Querying distinct patch IDs from assets table...")
        patch_ids = get_distinct_patch_ids()
        
        if not patch_ids:
            logger.warning("No patch IDs found in assets table")
            return
        
        logger.info(f"Found {len(patch_ids)} distinct patch IDs: {patch_ids[:10]}{'...' if len(patch_ids) > 10 else ''}")
        
        # Confirm before proceeding
        print(f"\nAbout to query {len(patch_ids)} patches from Vicarius API")
        print(f"This will take approximately {len(patch_ids)} seconds (1 second per request)")
        #confirm = input("Do you want to proceed? (yes/no): ").lower().strip()
        
        #if confirm not in ['yes', 'y']:
        #    logger.info("Operation cancelled by user")
        #    return
        
        # Query patch information from API
        logger.info("Starting API queries...")
        patch_dates = query_patch_info(dashboard_id, vicarius_token, patch_ids)
        
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
        logger.info("Updating database with patch creation dates...")
        updated_count = update_patch_dates(patch_updates)
        
        # Summary
        print("\n" + "="*50)
        print("PATCH DATE UPDATE COMPLETED!")
        print("="*50)
        print(f"Total patch IDs queried: {len(patch_ids)}")
        print(f"Successful API responses: {len(patch_dates)}")
        print(f"Database records updated: {updated_count}")
        print(f"Success rate: {len(patch_dates)/len(patch_ids)*100:.1f}%")
        
        if len(patch_dates) < len(patch_ids):
            failed_patches = set(patch_ids) - set(patch_dates.keys())
            print(f"Failed patches: {sorted(list(failed_patches))[:10]}{'...' if len(failed_patches) > 10 else ''}")
        
    except KeyboardInterrupt:
        logger.info("Script interrupted by user")
    except Exception as e:
        logger.error(f"Script failed: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())

if __name__ == "__main__":
    main()