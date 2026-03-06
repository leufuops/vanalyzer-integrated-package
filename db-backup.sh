#!/bin/bash
set -euo pipefail

# vAnalyzer Database Backup & Restore Script
# Simple and reliable version

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_DIR="${SCRIPT_DIR}/backups"
DATE=$(date +"%Y%m%d_%H%M%S")

# Colors
G='\033[0;32m' # Green
R='\033[0;31m' # Red
Y='\033[1;33m' # Yellow
NC='\033[0m'   # No Color

log() { echo -e "[$(date +'%H:%M:%S')] $1"; }
success() { echo -e "${G}✓ $1${NC}"; }
error() { echo -e "${R}✗ $1${NC}"; }
warning() { echo -e "${Y}⚠ $1${NC}"; }

show_usage() {
    echo "Usage: $0 {backup|restore|restore-metabase|list}"
    echo ""
    echo "Commands:"
    echo "  backup                      - Create database backup"
    echo "  restore <backup>            - Restore all databases from backup"
    echo "  restore-metabase <backup>   - Restore only Metabase database"
    echo "  list                        - List available backups"
    echo ""
    echo "Examples:"
    echo "  $0 backup"
    echo "  $0 restore backups/backup_20250716_123456"
    echo "  $0 restore-metabase backups/backup_20250716_123456"
    echo "  $0 list"
}

find_containers() {
    # Find running database containers
    APPDB_CONTAINER=$(docker ps --format "{{.Names}}" | grep -E "(appdb|postgres)" | head -1 || echo "")
    METABASE_CONTAINER=$(docker ps --format "{{.Names}}" | grep -i metabase | head -1 || echo "")
    
    if [[ -z "$APPDB_CONTAINER" ]]; then
        error "No database container found"
        exit 1
    fi
    
    log "Found database container: $APPDB_CONTAINER"
    if [[ -n "$METABASE_CONTAINER" ]]; then
        log "Found Metabase container: $METABASE_CONTAINER"
    fi
}

get_db_info() {
    # Get database credentials
    DB_NAME=$(docker exec "$APPDB_CONTAINER" cat /run/secrets/postgres_db 2>/dev/null || echo "")
    DB_USER=$(docker exec "$APPDB_CONTAINER" cat /run/secrets/postgres_user 2>/dev/null || echo "")
    DB_PASSWORD=$(docker exec "$APPDB_CONTAINER" cat /run/secrets/postgres_password 2>/dev/null || echo "")
    
    if [[ -z "$DB_NAME" || -z "$DB_USER" || -z "$DB_PASSWORD" ]]; then
        error "Cannot read database credentials"
        exit 1
    fi
    
    success "Database: $DB_NAME (user: $DB_USER)"
}

backup_database() {
    local backup_dir="$1"
    local backup_file="${backup_dir}/database_${DB_NAME}_${DATE}.sql"
    
    log "Creating database backup..."
    
    # Create backup using pg_dump inside container
    if docker exec -e PGPASSWORD="$DB_PASSWORD" "$APPDB_CONTAINER" \
        pg_dump -h localhost -p 5432 -U "$DB_USER" -d "$DB_NAME" \
        --clean --create --no-owner --no-privileges \
        -f "/tmp/backup.sql"; then
        
        # Copy backup file out of container
        docker cp "$APPDB_CONTAINER:/tmp/backup.sql" "$backup_file"
        docker exec "$APPDB_CONTAINER" rm -f "/tmp/backup.sql"
        
        local size=$(du -h "$backup_file" | cut -f1)
        success "Database backup created: $(basename "$backup_file") ($size)"
        echo "$backup_file"
    else
        error "Database backup failed"
        return 1
    fi
}

backup_metabase() {
    local backup_dir="$1"
    
    log "Creating Metabase database backup..."
    local metabase_file="${backup_dir}/metabase_db_${DATE}.sql"
    
    # Backup Metabase PostgreSQL database
    if docker exec -e PGPASSWORD="$DB_PASSWORD" "$APPDB_CONTAINER" \
        pg_dump -h localhost -p 5432 -U "$DB_USER" -d metabase \
        --clean --create --no-owner --no-privileges \
        -f "/tmp/metabase_backup.sql" 2>/dev/null; then
        
        # Copy backup file out of container
        docker cp "$APPDB_CONTAINER:/tmp/metabase_backup.sql" "$metabase_file"
        docker exec "$APPDB_CONTAINER" rm -f "/tmp/metabase_backup.sql"
        
        local size=$(du -h "$metabase_file" | cut -f1)
        success "Metabase database backup created: $(basename "$metabase_file") ($size)"
        echo "$metabase_file"
    else
        warning "Metabase database backup failed (database may not exist yet)"
        return 1
    fi
    
    # Also backup Metabase data directory if container exists
    if [[ -n "$METABASE_CONTAINER" ]]; then
        log "Creating Metabase data backup..."
        local metabase_data_file="${backup_dir}/metabase_data_${DATE}.tar"
        
        if docker exec "$METABASE_CONTAINER" tar -cf "/tmp/metabase_data.tar" -C /metabase-data . 2>/dev/null; then
            docker cp "$METABASE_CONTAINER:/tmp/metabase_data.tar" "$metabase_data_file"
            docker exec "$METABASE_CONTAINER" rm -f "/tmp/metabase_data.tar"
            
            local data_size=$(du -h "$metabase_data_file" | cut -f1)
            success "Metabase data backup created: $(basename "$metabase_data_file") ($data_size)"
        else
            warning "Metabase data backup failed"
        fi
    fi
}

create_backup() {
    find_containers
    get_db_info
    
    # Create backup directory
    local backup_name="backup_${DATE}"
    local full_backup_dir="${BACKUP_DIR}/${backup_name}"
    mkdir -p "$full_backup_dir"
    
    log "Creating backup in: $backup_name"
    
    # Backup database
    local db_file=""
    local mb_file=""
    
    if db_file=$(backup_database "$full_backup_dir"); then
        # Backup Metabase
        mb_file=$(backup_metabase "$full_backup_dir" || echo "")
        
        # Create info file
        cat > "${full_backup_dir}/backup_info.txt" << EOF
vAnalyzer Database Backup
========================
Date: $(date)
Database: $DB_NAME
User: $DB_USER
Container: $APPDB_CONTAINER

Files:
- $(basename "$db_file") ($(du -h "$db_file" | cut -f1))
$(if [[ -n "$mb_file" ]]; then echo "- $(basename "$mb_file") ($(du -h "$mb_file" | cut -f1))"; fi)

Restore Command:
$0 restore $backup_name
EOF
        
        success "Backup completed successfully!"
        echo ""
        echo "Backup: $backup_name"
        echo "Location: $full_backup_dir"
        ls -lh "$full_backup_dir"
    else
        error "Backup failed"
        exit 1
    fi
}

restore_database() {
    local backup_dir="$1"
    
    if [[ ! -d "$backup_dir" ]]; then
        error "Backup directory not found: $backup_dir"
        echo ""
        warning "Available backups:"
        if [[ -d "$BACKUP_DIR" ]]; then
            ls -1 "$BACKUP_DIR" | grep "^backup_" 2>/dev/null || echo "  No backups found"
        else
            echo "  No backup directory exists yet"
        fi
        echo ""
        echo "Usage: $0 restore <backup_directory_name>"
        echo "Example: $0 restore backup_20250905_234550"
        exit 1
    fi
    
    find_containers
    get_db_info

    # Stop services to prevent database conflicts
    log "Stopping services to prevent database connection conflicts..."

    # Find stack name from container name
    local stack_name=""
    if [[ "$APPDB_CONTAINER" =~ ^(.+)_appdb ]]; then
        stack_name="${BASH_REMATCH[1]}"
    fi

    if [[ -n "$stack_name" ]]; then
        log "Detected stack: $stack_name"

        # Scale down app service
        if docker service ls --format "{{.Name}}" | grep -q "^${stack_name}_app$"; then
            log "Scaling down app service..."
            docker service scale "${stack_name}_app"=0 >/dev/null 2>&1
            sleep 3
        fi

        # Scale down metabase service
        if docker service ls --format "{{.Name}}" | grep -q "^${stack_name}_metabase$"; then
            log "Scaling down metabase service..."
            docker service scale "${stack_name}_metabase"=0 >/dev/null 2>&1
            sleep 5
            success "Services stopped"
        fi
    else
        warning "Could not detect stack name - services may not be stopped"
        warning "Database restore may fail if services are using the database"
        echo -n "Continue anyway? (y/N): "
        read -r response
        if [[ ! "$response" =~ ^[Yy]$ ]]; then
            log "Restore cancelled"
            exit 0
        fi
    fi

    # Find backup file - try multiple patterns for compatibility
    local backup_file=""

    # Try new format: database_<name>_<date>.sql
    backup_file=$(ls "$backup_dir"/database_*_*.sql 2>/dev/null | head -1 || echo "")

    # Try old format: <name>_<date>.sql (but not metabase_*.sql)
    if [[ -z "$backup_file" ]]; then
        backup_file=$(ls "$backup_dir"/*_*.sql 2>/dev/null | grep -v "^${backup_dir}/metabase_" | head -1 || echo "")
    fi

    # Last resort: any .sql file that's not metabase
    if [[ -z "$backup_file" ]]; then
        backup_file=$(ls "$backup_dir"/*.sql 2>/dev/null | grep -v "metabase" | head -1 || echo "")
    fi

    if [[ -z "$backup_file" ]]; then
        error "No main database backup file found in $backup_dir"
        echo "Found files:"
        ls -la "$backup_dir"
        exit 1
    fi
    
    log "Restoring from: $(basename "$backup_file")"
    
    # Confirm restore
    echo -n "This will replace the current database. Continue? (y/N): "
    read -r response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        log "Restore cancelled"
        exit 0
    fi
    
    # Copy backup file to container
    log "Copying backup file to container..."
    if ! docker cp "$backup_file" "$APPDB_CONTAINER:/tmp/restore.sql"; then
        error "Failed to copy backup file to container"
        exit 1
    fi

    # Terminate existing connections and drop database
    log "Terminating existing connections to database $DB_NAME..."
    docker exec -e PGPASSWORD="$DB_PASSWORD" "$APPDB_CONTAINER" \
        psql -h localhost -p 5432 -U "$DB_USER" -d postgres -c \
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '$DB_NAME' AND pid <> pg_backend_pid();" \
        >/dev/null 2>&1 || true

    sleep 2

    log "Dropping database $DB_NAME if it exists..."
    docker exec -e PGPASSWORD="$DB_PASSWORD" "$APPDB_CONTAINER" \
        psql -h localhost -p 5432 -U "$DB_USER" -d postgres -c \
        "DROP DATABASE IF EXISTS \"$DB_NAME\";" \
        2>&1 | grep -v "NOTICE" || true

    sleep 1

    log "Creating fresh database $DB_NAME..."
    docker exec -e PGPASSWORD="$DB_PASSWORD" "$APPDB_CONTAINER" \
        psql -h localhost -p 5432 -U "$DB_USER" -d postgres -c \
        "CREATE DATABASE \"$DB_NAME\" OWNER \"$DB_USER\";" \
        2>&1 | grep -v "NOTICE" || true

    # Restore database
    log "Restoring database $DB_NAME from backup..."
    log "This may take several minutes for large databases..."

    if docker exec -e PGPASSWORD="$DB_PASSWORD" "$APPDB_CONTAINER" \
        psql -h localhost -p 5432 -U "$DB_USER" -d "$DB_NAME" \
        -f "/tmp/restore.sql" 2>&1 | tee /tmp/restore_output.log | grep -E "^ERROR:" || true; then

        docker exec "$APPDB_CONTAINER" rm -f "/tmp/restore.sql"
        success "Database $DB_NAME restored successfully"
        
        # Restore Metabase database if available
        local metabase_db_file=$(ls "$backup_dir"/metabase_*.sql 2>/dev/null | grep -v "metabase_db_" | head -1 || echo "")
        if [[ -n "$metabase_db_file" ]]; then
            log "Restoring Metabase database..."

            # Handle compressed files
            local restore_mb_file="$metabase_db_file"
            if [[ "$metabase_db_file" == *.gz ]]; then
                log "Decompressing Metabase backup file..."
                restore_mb_file="${metabase_db_file%.gz}"
                gunzip -c "$metabase_db_file" > "$restore_mb_file"
            fi

            # Copy file to container and restore
            log "Copying Metabase backup to container..."
            if docker cp "$restore_mb_file" "$APPDB_CONTAINER:/tmp/restore_metabase.sql"; then

                # Terminate existing connections and drop Metabase database
                log "Terminating existing connections to Metabase database..."
                docker exec -e PGPASSWORD="$DB_PASSWORD" "$APPDB_CONTAINER" \
                    psql -h localhost -p 5432 -U "$DB_USER" -d postgres -c \
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'metabase' AND pid <> pg_backend_pid();" \
                    >/dev/null 2>&1 || true

                sleep 2

                log "Dropping Metabase database if it exists..."
                docker exec -e PGPASSWORD="$DB_PASSWORD" "$APPDB_CONTAINER" \
                    psql -h localhost -p 5432 -U "$DB_USER" -d postgres -c \
                    "DROP DATABASE IF EXISTS metabase;" \
                    2>&1 | grep -v "NOTICE" || true

                sleep 1

                log "Creating fresh Metabase database..."
                docker exec -e PGPASSWORD="$DB_PASSWORD" "$APPDB_CONTAINER" \
                    psql -h localhost -p 5432 -U "$DB_USER" -d postgres -c \
                    "CREATE DATABASE metabase OWNER \"$DB_USER\";" \
                    2>&1 | grep -v "NOTICE" || true

                log "Running Metabase database restore..."

                if docker exec -e PGPASSWORD="$DB_PASSWORD" "$APPDB_CONTAINER" \
                    psql -h localhost -p 5432 -U "$DB_USER" -d metabase \
                    -f "/tmp/restore_metabase.sql" 2>&1 | tee /tmp/metabase_restore_output.log | grep -E "^ERROR:" || true; then

                    docker exec "$APPDB_CONTAINER" rm -f "/tmp/restore_metabase.sql"
                    success "Metabase database restored successfully"
                else
                    docker exec "$APPDB_CONTAINER" rm -f "/tmp/restore_metabase.sql"
                    warning "Metabase database restore encountered errors - check /tmp/metabase_restore_output.log"
                fi
            else
                error "Failed to copy Metabase backup to container"
            fi

            # Cleanup
            if [[ "$restore_mb_file" != "$metabase_db_file" ]]; then
                rm -f "$restore_mb_file"
            fi
        else
            log "No Metabase database backup found - skipping"
        fi
        
        # Restore Metabase data directory if available
        local metabase_data_file=$(ls "$backup_dir"/metabase_data_*.tar 2>/dev/null | head -1 || echo "")
        if [[ -n "$metabase_data_file" && -n "$METABASE_CONTAINER" ]]; then
            log "Restoring Metabase data directory..."
            docker cp "$metabase_data_file" "$METABASE_CONTAINER:/tmp/metabase_data.tar"
            
            if docker exec "$METABASE_CONTAINER" sh -c "cd /metabase-data && tar -xf /tmp/metabase_data.tar"; then
                docker exec "$METABASE_CONTAINER" rm -f "/tmp/metabase_data.tar"
                success "Metabase data directory restored"
            else
                warning "Metabase data directory restore failed"
            fi
        fi
        
        success "Restore completed successfully!"

        # Restart services
        if [[ -n "$stack_name" ]]; then
            log "Restarting services..."

            # Restart app service
            if docker service ls --format "{{.Name}}" | grep -q "^${stack_name}_app$"; then
                log "Starting app service..."
                docker service scale "${stack_name}_app"=1 >/dev/null 2>&1
                sleep 3
            fi

            # Restart metabase service
            if docker service ls --format "{{.Name}}" | grep -q "^${stack_name}_metabase$"; then
                log "Starting metabase service..."
                docker service scale "${stack_name}_metabase"=1 >/dev/null 2>&1
                sleep 2
            fi

            success "Services restarted"
            echo ""
            log "Waiting for services to become healthy (this may take 1-2 minutes)..."
            log "You can check status with: docker service ls"
        fi
    else
        docker exec "$APPDB_CONTAINER" rm -f "/tmp/restore.sql"
        error "Database restore failed"
        log "Check /tmp/restore_output.log for details"

        # Restart services even on failure to avoid leaving them down
        if [[ -n "$stack_name" ]]; then
            warning "Attempting to restart services after failure..."
            docker service scale "${stack_name}_app"=1 >/dev/null 2>&1 || true
            docker service scale "${stack_name}_metabase"=1 >/dev/null 2>&1 || true
        fi

        exit 1
    fi
}

restore_metabase_only() {
    local backup_dir="$1"

    if [[ ! -d "$backup_dir" ]]; then
        error "Backup directory not found: $backup_dir"
        echo ""
        warning "Available backups:"
        if [[ -d "$BACKUP_DIR" ]]; then
            ls -1 "$BACKUP_DIR" | grep "^backup_" 2>/dev/null || echo "  No backups found"
        else
            echo "  No backup directory exists yet"
        fi
        echo ""
        echo "Usage: $0 restore-metabase <backup_directory_name>"
        echo "Example: $0 restore-metabase backup_20250905_234550"
        exit 1
    fi

    find_containers
    get_db_info

    # Stop metabase service to prevent database conflicts
    log "Stopping Metabase service..."

    # Find stack name from container name
    local stack_name=""
    if [[ "$APPDB_CONTAINER" =~ ^(.+)_appdb ]]; then
        stack_name="${BASH_REMATCH[1]}"
    fi

    if [[ -n "$stack_name" ]]; then
        log "Detected stack: $stack_name"

        # Scale down metabase service only
        if docker service ls --format "{{.Name}}" | grep -q "^${stack_name}_metabase$"; then
            log "Scaling down metabase service..."
            docker service scale "${stack_name}_metabase"=0 >/dev/null 2>&1
            sleep 5
            success "Metabase service stopped"
        fi
    else
        warning "Could not detect stack name - service may not be stopped"
        echo -n "Continue anyway? (y/N): "
        read -r response
        if [[ ! "$response" =~ ^[Yy]$ ]]; then
            log "Restore cancelled"
            exit 0
        fi
    fi

    # Find Metabase backup file
    local metabase_db_file=$(ls "$backup_dir"/metabase_*.sql 2>/dev/null | grep -v "metabase_db_" | head -1 || echo "")

    if [[ -z "$metabase_db_file" ]]; then
        error "No Metabase backup file found in $backup_dir"
        echo "Found files:"
        ls -la "$backup_dir"

        # Restart metabase service before exit
        if [[ -n "$stack_name" ]]; then
            docker service scale "${stack_name}_metabase"=1 >/dev/null 2>&1 || true
        fi
        exit 1
    fi

    log "Found Metabase backup: $(basename "$metabase_db_file")"

    # Confirm restore
    echo -n "This will replace the Metabase database. Continue? (y/N): "
    read -r response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        log "Restore cancelled"
        # Restart metabase service
        if [[ -n "$stack_name" ]]; then
            docker service scale "${stack_name}_metabase"=1 >/dev/null 2>&1 || true
        fi
        exit 0
    fi

    # Handle compressed files
    local restore_mb_file="$metabase_db_file"
    if [[ "$metabase_db_file" == *.gz ]]; then
        log "Decompressing Metabase backup file..."
        restore_mb_file="${metabase_db_file%.gz}"
        gunzip -c "$metabase_db_file" > "$restore_mb_file"
    fi

    # Copy file to container and restore
    log "Copying Metabase backup to container..."
    if ! docker cp "$restore_mb_file" "$APPDB_CONTAINER:/tmp/restore_metabase.sql"; then
        error "Failed to copy Metabase backup to container"
        # Restart metabase service
        if [[ -n "$stack_name" ]]; then
            docker service scale "${stack_name}_metabase"=1 >/dev/null 2>&1 || true
        fi
        exit 1
    fi

    # Terminate existing connections and drop Metabase database
    log "Terminating existing connections to Metabase database..."
    docker exec -e PGPASSWORD="$DB_PASSWORD" "$APPDB_CONTAINER" \
        psql -h localhost -p 5432 -U "$DB_USER" -d postgres -c \
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'metabase' AND pid <> pg_backend_pid();" \
        >/dev/null 2>&1 || true

    sleep 2

    log "Dropping Metabase database if it exists..."
    docker exec -e PGPASSWORD="$DB_PASSWORD" "$APPDB_CONTAINER" \
        psql -h localhost -p 5432 -U "$DB_USER" -d postgres -c \
        "DROP DATABASE IF EXISTS metabase;" \
        2>&1 | grep -v "NOTICE" || true

    sleep 1

    log "Creating fresh Metabase database..."
    docker exec -e PGPASSWORD="$DB_PASSWORD" "$APPDB_CONTAINER" \
        psql -h localhost -p 5432 -U "$DB_USER" -d postgres -c \
        "CREATE DATABASE metabase OWNER \"$DB_USER\";" \
        2>&1 | grep -v "NOTICE" || true

    log "Running Metabase database restore..."
    log "This may take several minutes..."

    if docker exec -e PGPASSWORD="$DB_PASSWORD" "$APPDB_CONTAINER" \
        psql -h localhost -p 5432 -U "$DB_USER" -d metabase \
        -f "/tmp/restore_metabase.sql" 2>&1 | tee /tmp/metabase_restore_output.log | grep -E "^ERROR:" || true; then

        docker exec "$APPDB_CONTAINER" rm -f "/tmp/restore_metabase.sql"
        success "Metabase database restored successfully"

        # Cleanup decompressed file if it was created
        if [[ "$restore_mb_file" != "$metabase_db_file" ]]; then
            rm -f "$restore_mb_file"
        fi

        # Restart Metabase service
        if [[ -n "$stack_name" ]]; then
            log "Restarting Metabase service..."
            docker service scale "${stack_name}_metabase"=1 >/dev/null 2>&1
            sleep 2
            success "Metabase service restarted"
            echo ""
            log "Waiting for Metabase to become healthy (this may take 1-2 minutes)..."
            log "You can check status with: docker service ls"
        fi

        success "Metabase restore completed successfully!"
    else
        docker exec "$APPDB_CONTAINER" rm -f "/tmp/restore_metabase.sql"
        error "Metabase database restore failed"
        log "Check /tmp/metabase_restore_output.log for details"

        # Cleanup and restart service
        if [[ "$restore_mb_file" != "$metabase_db_file" ]]; then
            rm -f "$restore_mb_file"
        fi

        if [[ -n "$stack_name" ]]; then
            warning "Attempting to restart Metabase service after failure..."
            docker service scale "${stack_name}_metabase"=1 >/dev/null 2>&1 || true
        fi

        exit 1
    fi
}

list_backups() {
    if [[ ! -d "$BACKUP_DIR" ]]; then
        warning "No backup directory found"
        return 0
    fi
    
    log "Available backups:"
    echo ""
    
    local count=0
    for backup_dir in "$BACKUP_DIR"/backup_*; do
        if [[ -d "$backup_dir" ]]; then
            local name=$(basename "$backup_dir")
            local info_file="$backup_dir/backup_info.txt"
            
            echo "📁 $name"
            
            if [[ -f "$info_file" ]]; then
                local date_line=$(grep "Date:" "$info_file" | cut -d':' -f2- | sed 's/^ *//')
                local db_line=$(grep "Database:" "$info_file" | cut -d':' -f2 | sed 's/^ *//')
                echo "   Date: $date_line"
                echo "   Database: $db_line"
                
                # Show files
                echo "   Files:"
                ls -1 "$backup_dir"/*.sql "$backup_dir"/*.tar 2>/dev/null | while read -r file; do
                    local size=$(du -h "$file" | cut -f1)
                    echo "     - $(basename "$file") ($size)"
                done
            else
                echo "   (No info file)"
            fi
            echo ""
            ((count++))
        fi
    done
    
    if [[ $count -eq 0 ]]; then
        warning "No backups found"
    else
        success "Found $count backup(s)"
    fi
}

# Main execution
case "${1:-help}" in
    "backup")
        mkdir -p "$BACKUP_DIR"
        create_backup
        ;;
    "restore")
        if [[ -z "${2:-}" ]]; then
            error "Backup directory required"
            show_usage
            exit 1
        fi

        # Handle different path formats
        backup_path="$2"

        # If it's already a full path, use as-is
        if [[ "$backup_path" == /* ]]; then
            restore_database "$backup_path"
        # If it starts with backups/, it's relative to script dir
        elif [[ "$backup_path" == backups/* ]]; then
            restore_database "$SCRIPT_DIR/$backup_path"
        # If it's just a backup name, add backup dir
        else
            restore_database "$BACKUP_DIR/$backup_path"
        fi
        ;;
    "restore-metabase")
        if [[ -z "${2:-}" ]]; then
            error "Backup directory required"
            show_usage
            exit 1
        fi

        # Handle different path formats
        backup_path="$2"

        # If it's already a full path, use as-is
        if [[ "$backup_path" == /* ]]; then
            restore_metabase_only "$backup_path"
        # If it starts with backups/, it's relative to script dir
        elif [[ "$backup_path" == backups/* ]]; then
            restore_metabase_only "$SCRIPT_DIR/$backup_path"
        # If it's just a backup name, add backup dir
        else
            restore_metabase_only "$BACKUP_DIR/$backup_path"
        fi
        ;;
    "list")
        list_backups
        ;;
    "help"|*)
        show_usage
        ;;
esac