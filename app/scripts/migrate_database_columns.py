#!/usr/bin/env python3
"""
Database Column Migration Script
Migrates patch_id, asset_id from TEXT to BIGINT and data_lancamento from TEXT to TIMESTAMP
Handles existing data safely with validation
"""

import psycopg2
import logging
import sys
import time
from datetime import datetime

# ============================================================================
# CONFIGURATION
# ============================================================================

# Connection configuration
CONNECTION_TIMEOUT = 30
STATEMENT_TIMEOUT = 300000  # 5 minutes
MAX_RETRIES = 3

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
# DATABASE HELPER FUNCTIONS
# ============================================================================

def get_database_connection(db_config):
    """Creates database connection with optimized settings."""
    return psycopg2.connect(
        **db_config,
        options=f'-c statement_timeout={STATEMENT_TIMEOUT}',
        connect_timeout=CONNECTION_TIMEOUT,
        keepalives_idle=600,
        keepalives_interval=30,
        keepalives_count=3
    )

def execute_with_retry(db_config, operation_func, *args, **kwargs):
    """Executes database operation with retry logic."""
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
                    time.sleep(2 ** attempt)  # Exponential backoff
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
# MIGRATION FUNCTIONS
# ============================================================================

def check_column_type(conn, table_name, column_name):
    """Checks the current data type of a column."""
    cursor = conn.cursor()
    cursor.execute("""
        SELECT data_type 
        FROM information_schema.columns 
        WHERE table_name = %s AND column_name = %s
    """, (table_name, column_name))
    result = cursor.fetchone()
    return result[0] if result else None

def get_migration_status(conn):
    """Returns the current migration status."""
    cursor = conn.cursor()
    
    status = {
        'patches_patch_id': check_column_type(conn, 'patches', 'patch_id'),
        'assets_patch_id': check_column_type(conn, 'assets', 'patch_id'),
        'assets_asset_id': check_column_type(conn, 'assets', 'asset_id'),
        'vulnerabilities_patch_id': check_column_type(conn, 'vulnerabilities', 'patch_id'),
        'patches_data_lancamento': check_column_type(conn, 'patches', 'data_lancamento'),
        'assets_data_lancamento': check_column_type(conn, 'assets', 'data_lancamento')
    }
    
    return status

def backup_existing_data(conn):
    """Creates backup tables with existing data."""
    cursor = conn.cursor()
    
    logger.info("Creating backup tables...")
    
    # Create backup tables
    backup_tables = [
        ("patches_backup", "patches"),
        ("assets_backup", "assets"),
        ("vulnerabilities_backup", "vulnerabilities")
    ]
    
    for backup_table, source_table in backup_tables:
        try:
            # Drop existing backup if exists
            cursor.execute(f"DROP TABLE IF EXISTS {backup_table}")
            
            # Create backup table with current data
            cursor.execute(f"CREATE TABLE {backup_table} AS SELECT * FROM {source_table}")
            
            cursor.execute(f"SELECT COUNT(*) FROM {backup_table}")
            count = cursor.fetchone()[0]
            logger.info(f"Backed up {count} records from {source_table} to {backup_table}")
            
        except Exception as e:
            logger.error(f"Error creating backup for {source_table}: {str(e)}")
            raise

def migrate_id_columns(conn):
    """Migrates patch_id and asset_id columns from TEXT to BIGINT."""
    cursor = conn.cursor()
    
    logger.info("Starting ID columns migration...")
    
    # Step 1: Add new BIGINT columns
    logger.info("Adding new BIGINT columns...")
    
    migrations = [
        ("patches", "patch_id"),
        ("assets", "patch_id"),
        ("assets", "asset_id"),
        ("vulnerabilities", "patch_id")
    ]
    
    for table, column in migrations:
        new_column = f"{column}_new"
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {new_column} BIGINT")
        logger.info(f"Added column {new_column} to {table}")
    
    # Step 2: Migrate data with validation
    logger.info("Migrating ID data with validation...")
    
    migration_queries = [
        ("patches", "patch_id", """
            UPDATE patches SET patch_id_new = CASE 
                WHEN patch_id IS NOT NULL AND patch_id ~ '^[0-9]+$' THEN patch_id::BIGINT 
                ELSE NULL 
            END 
            WHERE patch_id_new IS NULL
        """),
        ("assets", "patch_id", """
            UPDATE assets SET patch_id_new = CASE 
                WHEN patch_id IS NOT NULL AND patch_id ~ '^[0-9]+$' THEN patch_id::BIGINT 
                ELSE NULL 
            END 
            WHERE patch_id_new IS NULL
        """),
        ("assets", "asset_id", """
            UPDATE assets SET asset_id_new = CASE 
                WHEN asset_id IS NOT NULL AND asset_id ~ '^[0-9]+$' THEN asset_id::BIGINT 
                ELSE NULL 
            END 
            WHERE asset_id_new IS NULL
        """),
        ("vulnerabilities", "patch_id", """
            UPDATE vulnerabilities SET patch_id_new = CASE 
                WHEN patch_id IS NOT NULL AND patch_id ~ '^[0-9]+$' THEN patch_id::BIGINT 
                ELSE NULL 
            END 
            WHERE patch_id_new IS NULL
        """)
    ]
    
    for table, column, query in migration_queries:
        cursor.execute(query)
        cursor.execute(f"SELECT COUNT(*) FROM {table} WHERE {column}_new IS NOT NULL")
        migrated_count = cursor.fetchone()[0]
        
        cursor.execute(f"SELECT COUNT(*) FROM {table} WHERE {column} IS NOT NULL")
        total_count = cursor.fetchone()[0]
        
        logger.info(f"Migrated {migrated_count}/{total_count} {column} values in {table}")
        
        if migrated_count < total_count:
            cursor.execute(f"""
                SELECT {column} FROM {table} 
                WHERE {column} IS NOT NULL AND {column}_new IS NULL 
                LIMIT 5
            """)
            invalid_values = cursor.fetchall()
            logger.warning(f"Found {total_count - migrated_count} invalid {column} values in {table}. Examples: {invalid_values}")

def migrate_timestamp_columns(conn):
    """Migrates data_lancamento columns from TEXT to TIMESTAMP."""
    cursor = conn.cursor()
    
    logger.info("Starting timestamp columns migration...")
    
    # Step 1: Add new TIMESTAMP columns
    logger.info("Adding new TIMESTAMP columns...")
    
    timestamp_tables = ["patches", "assets"]
    
    for table in timestamp_tables:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS data_lancamento_new TIMESTAMP")
        logger.info(f"Added column data_lancamento_new to {table}")
    
    # Step 2: Migrate data with validation
    logger.info("Migrating timestamp data with validation...")
    
    for table in timestamp_tables:
        # Try different date formats
        migration_query = f"""
            UPDATE {table} SET data_lancamento_new = CASE 
                WHEN data_lancamento IS NOT NULL AND data_lancamento ~ '^[0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}$' 
                THEN data_lancamento::DATE::TIMESTAMP
                WHEN data_lancamento IS NOT NULL AND data_lancamento ~ '^[0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}} [0-9]{{2}}:[0-9]{{2}}:[0-9]{{2}}$'
                THEN data_lancamento::TIMESTAMP
                ELSE NULL 
            END 
            WHERE data_lancamento_new IS NULL
        """
        
        cursor.execute(migration_query)
        
        cursor.execute(f"SELECT COUNT(*) FROM {table} WHERE data_lancamento_new IS NOT NULL")
        migrated_count = cursor.fetchone()[0]
        
        cursor.execute(f"SELECT COUNT(*) FROM {table} WHERE data_lancamento IS NOT NULL AND data_lancamento != 'N/A'")
        total_count = cursor.fetchone()[0]
        
        logger.info(f"Migrated {migrated_count}/{total_count} data_lancamento values in {table}")
        
        if migrated_count < total_count:
            cursor.execute(f"""
                SELECT data_lancamento FROM {table} 
                WHERE data_lancamento IS NOT NULL AND data_lancamento != 'N/A' AND data_lancamento_new IS NULL 
                LIMIT 5
            """)
            invalid_values = cursor.fetchall()
            logger.warning(f"Found {total_count - migrated_count} invalid data_lancamento values in {table}. Examples: {invalid_values}")

def finalize_migration(conn):
    """Finalizes migration by dropping old columns and renaming new ones."""
    cursor = conn.cursor()
    
    logger.info("Finalizing migration...")
    
    # ID columns
    id_migrations = [
        ("patches", "patch_id"),
        ("assets", "patch_id"),
        ("assets", "asset_id"),
        ("vulnerabilities", "patch_id")
    ]
    
    for table, column in id_migrations:
        old_column = column
        new_column = f"{column}_new"
        temp_column = f"{column}_old"
        
        # Rename old column to backup
        cursor.execute(f"ALTER TABLE {table} RENAME COLUMN {old_column} TO {temp_column}")
        
        # Rename new column to final name
        cursor.execute(f"ALTER TABLE {table} RENAME COLUMN {new_column} TO {old_column}")
        
        logger.info(f"Finalized {column} migration in {table}")
    
    # Timestamp columns
    timestamp_tables = ["patches", "assets"]
    
    for table in timestamp_tables:
        old_column = "data_lancamento"
        new_column = "data_lancamento_new"
        temp_column = "data_lancamento_old"
        
        # Rename old column to backup
        cursor.execute(f"ALTER TABLE {table} RENAME COLUMN {old_column} TO {temp_column}")
        
        # Rename new column to final name
        cursor.execute(f"ALTER TABLE {table} RENAME COLUMN {new_column} TO {old_column}")
        
        logger.info(f"Finalized data_lancamento migration in {table}")

def cleanup_migration(conn):
    """Cleans up migration artifacts (optional step)."""
    cursor = conn.cursor()
    
    logger.info("Cleaning up migration artifacts...")
    
    # Drop old columns (optional - keep for safety)
    cleanup_columns = [
        ("patches", "patch_id_old"),
        ("patches", "data_lancamento_old"),
        ("assets", "patch_id_old"),
        ("assets", "asset_id_old"),
        ("assets", "data_lancamento_old"),
        ("vulnerabilities", "patch_id_old")
    ]
    
    for table, column in cleanup_columns:
        try:
            cursor.execute(f"ALTER TABLE {table} DROP COLUMN IF EXISTS {column}")
            logger.info(f"Dropped backup column {column} from {table}")
        except Exception as e:
            logger.warning(f"Could not drop {column} from {table}: {str(e)}")

def run_migration(db_config, cleanup=False):
    """Runs the complete migration process."""
    def _migration_internal(conn):
        logger.info("Starting database column migration...")
        
        # Check current status
        status = get_migration_status(conn)
        logger.info(f"Current column types: {status}")
        
        # Check if migration is needed
        needs_id_migration = any(
            status[key] == 'text' for key in 
            ['patches_patch_id', 'assets_patch_id', 'assets_asset_id', 'vulnerabilities_patch_id']
        )
        
        needs_timestamp_migration = any(
            status[key] == 'text' for key in 
            ['patches_data_lancamento', 'assets_data_lancamento']
        )
        
        if not needs_id_migration and not needs_timestamp_migration:
            logger.info("Migration not needed - all columns already have correct types")
            return
        
        # Create backups
        backup_existing_data(conn)
        
        # Perform migrations
        if needs_id_migration:
            migrate_id_columns(conn)
        
        if needs_timestamp_migration:
            migrate_timestamp_columns(conn)
        
        # Finalize migration
        finalize_migration(conn)
        
        # Optional cleanup
        if cleanup:
            cleanup_migration(conn)
        
        # Final status check
        final_status = get_migration_status(conn)
        logger.info(f"Final column types: {final_status}")
        
        logger.info("Migration completed successfully!")
    
    execute_with_retry(db_config, _migration_internal)

# ============================================================================
# MAIN FUNCTION
# ============================================================================

def read_secret(secret_name):
    """Reads secrets from the system."""
    try:
        with open(f'/run/secrets/{secret_name}', 'r') as secret_file:
            return secret_file.read().strip()
    except IOError:
        logger.error(f"Unable to read secret: {secret_name}")
        return None

def main():
    """Main function."""
    logger.info("Database Column Migration Script Starting...")
    
    # Database configuration
    db_config = {
        'host': 'appdb',
        'port': '5432',
        'user': read_secret('postgres_user'),
        'password': read_secret('postgres_password'),
        'database': read_secret('postgres_db')
    }
    
    # Validate configuration
    if not all(db_config.values()):
        logger.error("Missing database configuration. Please check secrets.")
        sys.exit(1)
    
    logger.info(f"Connecting to database: {db_config['host']}:{db_config['port']}/{db_config['database']}")
    
    try:
        # Ask for confirmation
        print("\nThis script will migrate the following columns:")
        print("- patch_id: TEXT → BIGINT (patches, assets, vulnerabilities tables)")
        print("- asset_id: TEXT → BIGINT (assets table)")
        print("- data_lancamento: TEXT → TIMESTAMP (patches, assets tables)")
        print("\nBackup tables will be created automatically.")
        
        confirm = input("\nDo you want to proceed? (yes/no): ").lower().strip()
        if confirm not in ['yes', 'y']:
            logger.info("Migration cancelled by user")
            sys.exit(0)
        
        cleanup = input("Do you want to cleanup old columns after migration? (yes/no): ").lower().strip()
        cleanup_enabled = cleanup in ['yes', 'y']
        
        # Run migration
        run_migration(db_config, cleanup=cleanup_enabled)
        
        print("\n" + "="*50)
        print("MIGRATION COMPLETED SUCCESSFULLY!")
        print("="*50)
        print("Next steps:")
        print("1. Update your application code to use the new data types")
        print("2. Test your application thoroughly")
        print("3. Remove backup tables when confident: patches_backup, assets_backup, vulnerabilities_backup")
        if not cleanup_enabled:
            print("4. Optionally remove old columns: *_old")
        
    except KeyboardInterrupt:
        logger.info("Migration interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Migration failed: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main()