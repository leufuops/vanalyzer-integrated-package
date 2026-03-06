#!/bin/bash
set -euo pipefail

# vAnalyzer Unified Deployment Script - RHEL 10
# Generated: 2025-07-10

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.unified.yml"
LEGACY_COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Load environment variables
if [[ -f "$ENV_FILE" ]]; then
    # Source the .env file
    source "$ENV_FILE"
    
    # Export all variables for Docker Swarm compatibility
    export VERSION ENVIRONMENT STACK_NAME
    export APP_PORT LOG_LEVEL 
    export TRAEFIK_VERSION TRAEFIK_DASHBOARD_PORT
    export METABASE_VERSION METABASE_HOST METABASE_MEMORY METABASE_BASIC_AUTH
    
    echo -e "${GREEN}✓ Environment configuration loaded and exported${NC}"
else
    echo -e "${YELLOW}⚠ No .env file found, using defaults${NC}"
fi

# Validate required environment variables
validate_environment() {
    log "Validating environment configuration..."
    
    local missing_vars=()
    
    # Check required variables
    if [[ -z "${METABASE_HOST:-}" ]]; then
        missing_vars+=("METABASE_HOST")
    fi
    
    if [[ -z "${METABASE_MEMORY:-}" ]]; then
        missing_vars+=("METABASE_MEMORY")
    fi
    
    if [[ -z "${STACK_NAME:-}" ]]; then
        missing_vars+=("STACK_NAME")
    fi
    
    if [[ -z "${VERSION:-}" ]]; then
        missing_vars+=("VERSION")
    fi
    
    
    if [[ -z "${ENVIRONMENT:-}" ]]; then
        missing_vars+=("ENVIRONMENT")
    fi
    
    # Report missing variables
    if [[ ${#missing_vars[@]} -gt 0 ]]; then
        log_error "Missing required environment variables:"
        for var in "${missing_vars[@]}"; do
            echo -e "  ${RED}✗ $var${NC}"
        done
        echo ""
        echo "Please ensure your .env file contains all required variables:"
        for var in "${missing_vars[@]}"; do
            case $var in
                "METABASE_HOST")
                    echo "  $var=reports.local"
                    ;;
                "METABASE_MEMORY")
                    echo "  $var=2g"
                    ;;
                "STACK_NAME")
                    echo "  $var=vanalyzer-stack"
                    ;;
                "VERSION")
                    echo "  $var=1.4"
                    ;;
                "ENVIRONMENT")
                    echo "  $var=production"
                    ;;
            esac
        done
        exit 1
    fi
    
    log_success "Environment validation completed"
}

# Set defaults
STACK_NAME=${STACK_NAME:-vanalyzer-stack}
COMPOSE_PROJECT_NAME=${COMPOSE_PROJECT_NAME:-vanalyzer}

# Functions
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

log_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

log_error() {
    echo -e "${RED}✗ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

show_usage() {
    echo "vAnalyzer Deployment Script - RHEL/Rocky/Alma Linux"
    echo "Usage: $0 {install|deploy|update|status|logs|cleanup|purge|help}"
    echo ""
    echo "🔧 ONLINE SETUP WORKFLOW:"
    echo "  1. $0 cleanup/purge     # Clean environment (if needed)"
    echo "  2. $0 install           # Install container runtime (Podman/Docker)"
    echo "  3. $0 deploy            # Interactive deployment with configuration"
    echo ""
    echo "📋 COMMANDS:"
    echo "  install   - Install container runtime (Podman preferred, Docker fallback)"
    echo "  deploy    - Interactive deployment with hostname, API key, and SSL setup"
    echo "  update    - Update existing stack (preserves configuration)"
    echo "  status    - Show stack and service status"
    echo "  logs      - Show service logs (usage: logs <service_name>)"
    echo "  cleanup   - Clean up resources (interactive: basic or full)"
    echo "  purge     - Completely remove container runtime and ALL data (DESTRUCTIVE)"
    echo "  help      - Show this help message"
    echo ""
    echo "📝 EXAMPLES:"
    echo "  $0 install              # Install Podman/Docker from RHEL repos"
    echo "  $0 deploy               # Interactive deployment setup"
    echo "  $0 status               # Check all services"
    echo "  $0 logs app             # View application logs"
    echo "  $0 cleanup              # Interactive cleanup options"
    echo ""
    echo "📝 CONTAINER RUNTIME NOTES:"
    echo "  • Prefers RHEL native Podman with Docker compatibility"
    echo "  • No external downloads - uses package manager only"
    echo "  • For satellite systems, ensure container-tools repo is available"
    echo "  • For offline/air-gapped systems, manual image loading required"
}

check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check Docker
    if ! command -v docker >/dev/null 2>&1; then
        log_error "Docker is required but not installed."
        exit 1
    fi
    
    # Check Docker daemon
    if ! docker info >/dev/null 2>&1; then
        log_error "Docker daemon is not running."
        exit 1
    fi
    
    # Check Docker Swarm
    if ! docker info | grep -q "Swarm: active"; then
        log_error "Docker Swarm is not initialized."
        echo "Please run: docker swarm init"
        exit 1
    fi
    
    # Check compose file
    if [[ ! -f "$COMPOSE_FILE" ]]; then
        log_error "Compose file not found: $COMPOSE_FILE"
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

interactive_update() {
    log "🔄 Interactive vAnalyzer Update"
    echo ""
    
    # Load current configuration from .env if exists
    if [[ -f ".env" ]]; then
        source .env
        CURRENT_HOSTNAME="${METABASE_HOST:-}"
    fi
    
    # Check if we have existing secrets
    local has_existing_secrets=false
    if docker secret ls | grep -q "api_key\|dashboard_id"; then
        has_existing_secrets=true
    fi
    
    # Prompt for hostname changes
    echo "📋 STEP 1: Configure vAnalyzer Hostname"
    if [[ -n "$CURRENT_HOSTNAME" ]]; then
        echo "Current hostname: $CURRENT_HOSTNAME"
        echo -n "Enter new hostname (press Enter to keep current): "
        read NEW_HOSTNAME
        VANALYZER_HOSTNAME=${NEW_HOSTNAME:-$CURRENT_HOSTNAME}
    else
        echo -n "Enter vAnalyzer hostname (e.g., reports.company.local): "
        read VANALYZER_HOSTNAME
        if [[ -z "$VANALYZER_HOSTNAME" ]]; then
            log_error "Hostname is required"
            exit 1
        fi
    fi
    
    # Only regenerate certificates if hostname changed
    if [[ "$VANALYZER_HOSTNAME" != "$CURRENT_HOSTNAME" ]]; then
        echo ""
        echo "🔐 STEP 2: Generate SSL Certificates"
        log "Generating SSL certificates for $VANALYZER_HOSTNAME..."
        
        if [[ -f "./generate-ssl-certs.sh" ]]; then
            chmod +x "./generate-ssl-certs.sh"
            ./generate-ssl-certs.sh create-all "$VANALYZER_HOSTNAME"
            log_success "SSL certificates generated and .env updated"
        else
            log_error "SSL certificate generation script not found"
            exit 1
        fi
    else
        echo ""
        log "📌 Keeping existing SSL certificates for $VANALYZER_HOSTNAME"
    fi
    
    # Ask about API credentials
    echo ""
    echo "📊 STEP 3: Configure Dashboard Connection"
    if [[ "$has_existing_secrets" == "true" ]]; then
        echo -n "Do you want to update API credentials? (y/N): "
        read UPDATE_API
        if [[ "$UPDATE_API" =~ ^[Yy]$ ]]; then
            echo -n "Enter Dashboard ID (e.g., 'company' for company.vicarius.cloud): "
            read DASHBOARD_ID
            
            if [[ -z "$DASHBOARD_ID" ]]; then
                log_error "Dashboard ID is required"
                exit 1
            fi
            
            echo -n "Enter API key: "
            read -s API_KEY
            echo
            
            if [[ -z "$API_KEY" ]]; then
                log_error "API key is required"
                exit 1
            fi
            UPDATE_SECRETS=true
        else
            log "📌 Keeping existing API credentials"
            UPDATE_SECRETS=false
        fi
    else
        echo -n "Enter Dashboard ID (e.g., 'company' for company.vicarius.cloud): "
        read DASHBOARD_ID
        
        if [[ -z "$DASHBOARD_ID" ]]; then
            log_error "Dashboard ID is required"
            exit 1
        fi
        
        echo -n "Enter API key: "
        read -s API_KEY
        echo
        
        if [[ -z "$API_KEY" ]]; then
            log_error "API key is required"
            exit 1
        fi
        UPDATE_SECRETS=true
    fi
    
    # Ask about database credentials
    echo ""
    echo "🔗 STEP 4: Configure Database Credentials"
    if [[ "$has_existing_secrets" == "true" ]]; then
        echo -n "Do you want to update database credentials? (y/N): "
        read UPDATE_DB
        if [[ "$UPDATE_DB" =~ ^[Yy]$ ]]; then
            echo -n "Enter PostgreSQL username (default: vanalyzer): "
            read POSTGRES_USER
            POSTGRES_USER=${POSTGRES_USER:-vanalyzer}
            
            echo -n "Enter PostgreSQL password: "
            read -s POSTGRES_PASSWORD
            echo
            
            if [[ -z "$POSTGRES_PASSWORD" ]]; then
                log_error "Database password is required"
                exit 1
            fi
            UPDATE_DB_SECRETS=true
        else
            log "📌 Keeping existing database credentials"
            UPDATE_DB_SECRETS=false
        fi
    else
        echo -n "Enter PostgreSQL username (default: vanalyzer): "
        read POSTGRES_USER
        POSTGRES_USER=${POSTGRES_USER:-vanalyzer}
        
        echo -n "Enter PostgreSQL password: "
        read -s POSTGRES_PASSWORD
        echo
        
        if [[ -z "$POSTGRES_PASSWORD" ]]; then
            log_error "Database password is required"
            exit 1
        fi
        UPDATE_DB_SECRETS=true
    fi
    
    # Configure sync interval
    echo ""
    echo "⏱️ STEP 5: Configure Refresh Rate"
    echo "How often should vAnalyzer sync with the dashboard?"
    echo "Common intervals: 1h (high load), 6h (recommended), 24h (low frequency)"
    echo -n "Enter sync interval in hours (default: 6): "
    read SYNC_INTERVAL_HOURS
    
    # Default to 6 hours if not specified
    SYNC_INTERVAL_HOURS=${SYNC_INTERVAL_HOURS:-6}
    
    # Validate input is a number
    if ! [[ "$SYNC_INTERVAL_HOURS" =~ ^[0-9]+$ ]]; then
        log_warning "Invalid input, using default (6 hours)"
        SYNC_INTERVAL_HOURS=6
    fi
    
    # Configure launcher.py with the single refresh rate
    configure_refresh_rate "$SYNC_INTERVAL_HOURS"
    
    # Store configuration for use in setup_secrets
    export VANALYZER_HOSTNAME
    export DASHBOARD_ID
    export API_KEY
    export POSTGRES_USER
    export POSTGRES_PASSWORD
    export UPDATE_SECRETS
    export UPDATE_DB_SECRETS
    
    # Update .env file with additional settings
    update_env_with_settings
    
    log_success "Interactive update configuration completed"
}

interactive_setup() {
    log "🚀 Interactive vAnalyzer Setup"
    echo ""
    
    # Prompt for vAnalyzer hostname
    echo "📋 STEP 1: Configure vAnalyzer Hostname"
    echo -n "Enter vAnalyzer hostname (e.g., reports.company.local): "
    read VANALYZER_HOSTNAME
    
    if [[ -z "$VANALYZER_HOSTNAME" ]]; then
        log_error "Hostname is required"
        exit 1
    fi
    
    # Generate SSL certificates
    echo ""
    echo "🔐 STEP 2: Generate SSL Certificates"
    log "Generating SSL certificates for $VANALYZER_HOSTNAME..."
    
    if [[ -f "./generate-ssl-certs.sh" ]]; then
        chmod +x "./generate-ssl-certs.sh"
        ./generate-ssl-certs.sh create-all "$VANALYZER_HOSTNAME"
        log_success "SSL certificates generated and .env updated"
    else
        log_error "SSL certificate generation script not found"
        exit 1
    fi
    
    echo ""
    echo "📊 STEP 3: Configure Dashboard Connection"
    echo -n "Enter Dashboard ID (e.g., 'company' for company.vicarius.cloud): "
    read DASHBOARD_ID
    
    if [[ -z "$DASHBOARD_ID" ]]; then
        log_error "Dashboard ID is required"
        exit 1
    fi
    
    echo -n "Enter API key: "
    read -s API_KEY
    echo
    
    if [[ -z "$API_KEY" ]]; then
        log_error "API key is required"
        exit 1
    fi
    
    echo ""
    echo "🔗 STEP 4: Configure Database Credentials"
    echo -n "Enter PostgreSQL username (default: vanalyzer): "
    read POSTGRES_USER
    POSTGRES_USER=${POSTGRES_USER:-vanalyzer}
    
    echo -n "Enter PostgreSQL password: "
    read -s POSTGRES_PASSWORD
    echo
    
    if [[ -z "$POSTGRES_PASSWORD" ]]; then
        log_error "Database password is required"
        exit 1
    fi
    
    echo ""
    echo "⏱️ STEP 5: Configure Refresh Rate"
    echo "How often should vAnalyzer sync with the dashboard?"
    echo "Common intervals: 1h (high load), 6h (recommended), 24h (low frequency)"
    echo -n "Enter sync interval in hours (default: 6): "
    read SYNC_INTERVAL_HOURS
    
    # Default to 6 hours if not specified
    SYNC_INTERVAL_HOURS=${SYNC_INTERVAL_HOURS:-6}
    
    # Validate input is a number
    if ! [[ "$SYNC_INTERVAL_HOURS" =~ ^[0-9]+$ ]]; then
        log_warning "Invalid input, using default (6 hours)"
        SYNC_INTERVAL_HOURS=6
    fi
    
    # Configure launcher.py with the single refresh rate
    configure_refresh_rate "$SYNC_INTERVAL_HOURS"
    
    echo ""
    echo "📁 STEP 6: Traefik Certificate Directory"
    log "SSL certificates are stored in: $(pwd)/traefik/config/certs/"
    log "To use custom certificates, replace files in this directory before deployment"
    
    # Store configuration for use in setup_secrets
    export VANALYZER_HOSTNAME
    export DASHBOARD_ID
    export API_KEY
    export POSTGRES_USER
    export POSTGRES_PASSWORD
    
    # Update .env file with additional settings
    update_env_with_settings
    
    log_success "Interactive setup completed"
}

update_env_with_settings() {
    log "Updating .env file with deployment settings..."
    
    local env_file=".env"
    
    # Update METABASE_BASIC_AUTH with database credentials
    if grep -q "^METABASE_BASIC_AUTH=" "$env_file"; then
        sed -i "s/^METABASE_BASIC_AUTH=.*/METABASE_BASIC_AUTH=${POSTGRES_USER}:${POSTGRES_PASSWORD}/" "$env_file"
    else
        echo "METABASE_BASIC_AUTH=${POSTGRES_USER}:${POSTGRES_PASSWORD}" >> "$env_file"
    fi
    
    # Ensure all required variables are present
    if ! grep -q "^VERSION=" "$env_file"; then
        echo "VERSION=1.4" >> "$env_file"
    fi
    
    if ! grep -q "^ENVIRONMENT=" "$env_file"; then
        echo "ENVIRONMENT=production" >> "$env_file"
    fi
    
    if ! grep -q "^METABASE_MEMORY=" "$env_file"; then
        echo "METABASE_MEMORY=2g" >> "$env_file"
    fi
    
    log_success ".env file updated with all required settings"
}

configure_refresh_rate() {
    local sync_hours=$1
    
    log "Configuring sync interval: every ${sync_hours} hours"
    
    local launcher_file="./app/scripts/launcher.py"
    if [[ -f "$launcher_file" ]]; then
        
        # Update launcher.py to run all jobs at the same interval
        # Remove the separate sync_1h and sync_24h jobs
        # Create a single sync job that runs all three scripts
        cat > "$launcher_file" << 'EOF'
import logging
import subprocess
import time
from threading import Lock
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.executors.pool import ThreadPoolExecutor
from apscheduler.triggers.interval import IntervalTrigger
from datetime import datetime
import gc

# Configure logging to log to a file
logging.basicConfig(
    filename='/var/log/scheduler_log.log',  # Log file name
    level=logging.INFO,                      # Log level
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',  # Log format
    datefmt='%Y-%m-%d %H:%M:%S'              # Date format for log entries
)
logger = logging.getLogger(__name__)

# Global lock to ensure that jobs do not run concurrently
job_lock = Lock()

def run_bash_script(script_path):
    try:
        logger.info(f"Starting execution of {script_path} at {datetime.now()}")
        subprocess.run(['bash', script_path], check=True)
        logger.info(f"Successfully executed {script_path} at {datetime.now()}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Error executing {script_path}: {e} at {datetime.now()}")
    except Exception as e:
        logger.error(f"Unexpected error executing {script_path}: {e} at {datetime.now()}")
    finally:
        logger.info(f"Finished execution of {script_path} at {datetime.now()}")
    gc.collect()

def full_sync():
    """Run all three sync jobs sequentially"""
    with job_lock:
        logger.info("Starting full sync at " + str(datetime.now()))
        
        # Job 1: Refresh Tables
        print("Running job 1 (refreshTables) at " + str(datetime.now()))
        run_bash_script("/usr/src/app/scripts/refreshTables.sh")
        
        # Job 2: Active Vulnerabilities Sync
        print("Running job 2 (activeVulnsSync) at " + str(datetime.now()))
        run_bash_script("/usr/src/app/scripts/activeVulnsSync.sh")
        
        # Job 3: Differential Tables
        print("Running job 3 (difTables) at " + str(datetime.now()))
        run_bash_script("/usr/src/app/scripts/difTables.sh")
        
        logger.info("Completed full sync at " + str(datetime.now()))

if __name__ == '__main__':
    # Run the initial task before scheduling any other tasks.
    # The command output is appended to /var/log/initialsync.log.
    initial_command = "/usr/local/bin/python /usr/src/app/scripts/VickyTopiaReportCLI.py --allreports >> /var/log/initialsync.log 2>&1"
    logger.info("Starting initial sync command")
    try:
        subprocess.run(initial_command, shell=True, check=True)
        logger.info("Initial sync command completed successfully")
    except subprocess.CalledProcessError as e:
        logger.error(f"Initial sync command failed: {e}")

    # Configure a single-threaded executor to ensure non-concurrent execution
    executors = {
        'default': ThreadPoolExecutor(max_workers=1)
    }
    scheduler = BackgroundScheduler(executors=executors)
    
    # Schedule the full sync to run every SYNC_HOURS hours
    scheduler.add_job(full_sync, trigger=IntervalTrigger(hours=SYNC_HOURS), misfire_grace_time=1)
    
    logger.info(f"Starting Scheduler with {SYNC_HOURS} hour interval at " + str(datetime.now()))
    scheduler.start()
    
    try:
        # Keep the script running
        while True:
            time.sleep(60)
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown()
        logger.info("Scheduler shut down at " + str(datetime.now()))
EOF
        
        # Replace SYNC_HOURS with actual value
        sed -i "s/SYNC_HOURS/$sync_hours/g" "$launcher_file"
        
        log_success "Launcher configured to run all jobs every ${sync_hours} hours"
    else
        log_warning "Launcher script not found at $launcher_file"
    fi
}

check_and_stop_services() {
    log "Checking for running services that might be using secrets..."
    
    # Check for running services
    local running_services=$(docker service ls --format "{{.Name}}" 2>/dev/null | wc -l)
    local running_stacks=$(docker stack ls --format "{{.Name}}" 2>/dev/null | wc -l)
    
    if [ "$running_services" -gt 0 ] || [ "$running_stacks" -gt 0 ]; then
        log_warning "Found running services/stacks that may be using secrets:"
        docker service ls 2>/dev/null || true
        docker stack ls 2>/dev/null || true
        
        echo -n "Do you want to stop all services/stacks to update secrets? (y/N): "
        read -r stop_services
        
        if [[ "$stop_services" =~ ^[Yy]$ ]]; then
            log "Stopping all services and stacks..."
            
            # Stop all stacks first
            for stack in $(docker stack ls --format "{{.Name}}" 2>/dev/null); do
                log "Stopping stack: $stack"
                docker stack rm "$stack"
            done
            
            # Stop any remaining services
            for service in $(docker service ls --format "{{.Name}}" 2>/dev/null); do
                log "Stopping service: $service"
                docker service rm "$service"
            done
            
            # Wait for services to fully stop
            log "Waiting for services to stop completely..."
            sleep 10
            
            log_success "All services stopped"
        else
            log_warning "Proceeding without stopping services - secret updates may fail"
        fi
    else
        log "No running services found - proceeding with secret setup"
    fi
}

setup_secrets() {
    log "Setting up Docker secrets..."
    
    # Check and optionally stop services first
    check_and_stop_services
    
    # Function to create or update secret with robust error handling
    create_or_update_secret() {
        local secret_name=$1
        local secret_value=$2
        local max_attempts=5
        local attempt=1
        
        # Check if secret exists
        if docker secret ls --format "{{.Name}}" | grep -q "^${secret_name}$"; then
            log_warning "Secret $secret_name already exists - forcing removal and recreation"
            
            # Try to remove the secret with multiple attempts
            while [ $attempt -le $max_attempts ]; do
                log "Attempt $attempt: Removing existing secret $secret_name"
                
                if docker secret rm "$secret_name" 2>/dev/null; then
                    log_success "Successfully removed secret $secret_name"
                    break
                else
                    if [ $attempt -eq $max_attempts ]; then
                        log_error "Failed to remove secret $secret_name after $max_attempts attempts"
                        log_error "This usually means the secret is in use by running services"
                        log_error "Try stopping services first: docker service ls && docker stack rm <stack-name>"
                        exit 1
                    else
                        log_warning "Failed to remove secret $secret_name (attempt $attempt/$max_attempts)"
                        log "Waiting 3 seconds before retry..."
                        sleep 3
                        attempt=$((attempt + 1))
                    fi
                fi
            done
        fi
        
        # Create the new secret
        log "Creating secret: $secret_name"
        if echo "$secret_value" | docker secret create "$secret_name" - 2>/dev/null; then
            log_success "✓ Created secret: $secret_name"
        else
            log_error "Failed to create secret: $secret_name"
            log_error "This might indicate a Docker Swarm issue or insufficient permissions"
            exit 1
        fi
    }
    
    # Handle API credentials - only update if requested or if new installation
    if [[ "${UPDATE_SECRETS:-true}" == "true" ]]; then
        if [[ -n "${API_KEY:-}" ]]; then
            create_or_update_secret "api_key" "$API_KEY"
        else
            log_error "API key not set - run interactive setup first"
            exit 1
        fi
        
        if [[ -n "${DASHBOARD_ID:-}" ]]; then
            create_or_update_secret "dashboard_id" "$DASHBOARD_ID"
        else
            log_error "Dashboard ID not set - run interactive setup first"
            exit 1
        fi
    else
        log "📌 Skipping API credential updates (keeping existing)"
    fi
    
    # Handle database credentials - only update if requested or if new installation
    if [[ "${UPDATE_DB_SECRETS:-true}" == "true" ]]; then
        if [[ -n "${POSTGRES_USER:-}" ]]; then
            create_or_update_secret "postgres_user" "$POSTGRES_USER"
        else
            log_error "Database user not set - run interactive setup first"
            exit 1
        fi
        
        if [[ -n "${POSTGRES_PASSWORD:-}" ]]; then
            create_or_update_secret "postgres_password" "$POSTGRES_PASSWORD"
        else
            log_error "Database password not set - run interactive setup first"
            exit 1
        fi
    else
        log "📌 Skipping database credential updates (keeping existing)"
    fi
    
    # Use dashboard ID as database name
    POSTGRES_DB=${DASHBOARD_ID}
    create_or_update_secret "postgres_db" "$POSTGRES_DB"
    
    # Set optional tools
    create_or_update_secret "optional_tools" "metabase"
    
    log_success "All secrets created successfully"
    echo ""
    echo "📋 Secrets Summary:"
    echo "  - API Key: Configured"
    echo "  - Dashboard ID: ${DASHBOARD_ID}"
    echo "  - Database User: ${POSTGRES_USER}"
    echo "  - Database Name: ${POSTGRES_DB}"
    echo "  - Database Password: Configured"
    echo ""
}

build_images() {
    # Check for offline images first
    if [[ -f "./images/.image-manifest" ]]; then
        log "Found offline images directory - importing instead of building..."
        if [[ -x "./docker-images.sh" ]]; then
            ./docker-images.sh import
            return 0
        else
            log_error "docker-images.sh script not found or not executable"
            exit 1
        fi
    fi
    
    log "Building Docker images from source..."
    
    # Build database image
    if [[ -d "appdb" ]]; then
        log "Building database image..."
        docker build -t vrx-reports-appdb:${VERSION:-latest} ./appdb
        log_success "Database image built"
    fi
    
    # Build application image
    if [[ -d "app" ]]; then
        log "Building application image..."
        docker build -t vrx-reports-app:${VERSION:-latest} ./app
        log_success "Application image built"
    fi
}


deploy_stack() {
    log "Deploying vAnalyzer stack..."
    
    # Remove existing stack if it exists
    if docker stack ls | grep -q "$STACK_NAME"; then
        log "Removing existing stack..."
        docker stack rm "$STACK_NAME"
        
        # Wait for stack to be fully removed
        log "Waiting for stack to be fully removed..."
        sleep 15
        
        # Wait for networks to be cleaned up
        while docker network ls | grep -q "${STACK_NAME}_"; do
            sleep 5
        done
    fi
    
    # Deploy new stack
    log "Deploying new stack..."
    docker stack deploy -c "$COMPOSE_FILE" "$STACK_NAME"
    
    log_success "Stack deployment initiated"
}

wait_for_services() {
    log "Waiting for services to be ready..."
    
    local max_wait=300  # 5 minutes
    local wait_time=0
    local check_interval=10
    
    while [[ $wait_time -lt $max_wait ]]; do
        local running_services=$(docker service ls --filter "name=${STACK_NAME}" --format "{{.Name}}: {{.Replicas}}" | grep -c "1/1" || true)
        local total_services=$(docker service ls --filter "name=${STACK_NAME}" --format "{{.Name}}" | wc -l)
        
        if [[ $running_services -eq $total_services ]] && [[ $total_services -gt 0 ]]; then
            log_success "All services are running ($running_services/$total_services)"
            return 0
        fi
        
        log "Services status: $running_services/$total_services ready..."
        sleep $check_interval
        wait_time=$((wait_time + check_interval))
    done
    
    log_error "Timeout waiting for services to be ready"
    return 1
}

check_health() {
    log "Performing health checks..."
    
    local services=("appdb" "app" "traefik" "metabase")
    local failed_services=()
    
    for service in "${services[@]}"; do
        local service_name="${STACK_NAME}_${service}"
        
        if docker service ps "$service_name" --format "{{.CurrentState}}" 2>/dev/null | grep -q "Running"; then
            log_success "$service is running"
        else
            log_error "$service is not running"
            failed_services+=("$service")
        fi
    done
    
    if [[ ${#failed_services[@]} -eq 0 ]]; then
        log_success "All health checks passed"
        return 0
    else
        log_error "Failed services: ${failed_services[*]}"
        return 1
    fi
}

show_status() {
    log "vAnalyzer Stack Status:"
    echo ""
    
    # Show stack info
    if docker stack ls | grep -q "$STACK_NAME"; then
        echo "Stack: $STACK_NAME"
        docker stack ps "$STACK_NAME" --format "table {{.Name}}\t{{.Image}}\t{{.CurrentState}}\t{{.Error}}"
        echo ""
        
        # Show service details
        echo "Services:"
        docker service ls --filter "name=${STACK_NAME}" --format "table {{.Name}}\t{{.Replicas}}\t{{.Image}}\t{{.Ports}}"
        echo ""
        
        # Show network info
        echo "Networks:"
        docker network ls --filter "name=${STACK_NAME}" --format "table {{.Name}}\t{{.Driver}}\t{{.Scope}}"
        echo ""
        
        # Show volume info
        echo "Volumes:"
        docker volume ls --filter "name=${STACK_NAME}" --format "table {{.Name}}\t{{.Driver}}\t{{.Scope}}"
    else
        log_warning "Stack '$STACK_NAME' is not deployed"
    fi
}

show_logs() {
    local service_name=${1:-}
    
    if [[ -z "$service_name" ]]; then
        echo "Available services:"
        docker service ls --filter "name=${STACK_NAME}" --format "{{.Name}}" | sed "s/${STACK_NAME}_//"
        echo ""
        echo "Usage: $0 logs <service_name>"
        return 1
    fi
    
    local full_service_name="${STACK_NAME}_${service_name}"
    
    if docker service ls --filter "name=${full_service_name}" --format "{{.Name}}" | grep -q "$full_service_name"; then
        echo "Logs for $full_service_name:"
        docker service logs -f "$full_service_name"
    else
        log_error "Service '$service_name' not found"
        return 1
    fi
}

rollback() {
    log "Rolling back deployment..."
    
    # Check if legacy compose file exists
    if [[ -f "$LEGACY_COMPOSE_FILE" ]]; then
        log "Using legacy compose file for rollback..."
        
        # Remove current stack
        if docker stack ls | grep -q "$STACK_NAME"; then
            docker stack rm "$STACK_NAME"
            sleep 15
        fi
        
        # Deploy with legacy compose
        docker stack deploy -c "$LEGACY_COMPOSE_FILE" "$STACK_NAME"
        log_success "Rollback completed using legacy configuration"
    else
        log_error "No legacy compose file found for rollback"
        return 1
    fi
}

cleanup() {
    log "Cleaning up resources..."
    
    # Ask for cleanup type
    echo "Cleanup options:"
    echo "1. Basic cleanup (unused resources only)"
    echo "2. Full cleanup (stack volumes, networks, secrets)"
    echo -n "Select cleanup type (1/2): "
    read -r cleanup_type
    
    case "$cleanup_type" in
        "1")
            basic_cleanup
            ;;
        "2")
            full_cleanup
            ;;
        *)
            log_error "Invalid option. Using basic cleanup."
            basic_cleanup
            ;;
    esac
    
    log_success "Cleanup completed"
}

basic_cleanup() {
    log "Performing basic cleanup of unused resources..."
    
    # Remove unused containers
    docker container prune -f
    
    # Remove unused images
    docker image prune -f
    
    # Remove unused volumes (be careful with this)
    echo -n "Remove unused volumes? (y/N): "
    read -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        docker volume prune -f
    fi
    
    # Remove unused networks
    docker network prune -f
}

full_cleanup() {
    log "Performing full cleanup..."
    
    # Confirm full cleanup
    echo -n "This will remove ALL stack data including volumes and secrets. Continue? (y/N): "
    read -r response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        log "Full cleanup cancelled"
        return 0
    fi
    
    # Remove the stack if it exists
    if docker stack ls | grep -q "$STACK_NAME"; then
        log "Removing stack: $STACK_NAME"
        docker stack rm "$STACK_NAME"
        
        # Wait for stack to be fully removed
        log "Waiting for stack to be fully removed..."
        sleep 15
        
        # Wait for networks to be cleaned up
        while docker network ls | grep -q "${STACK_NAME}_"; do
            sleep 5
        done
    fi
    
    # Remove stack-specific volumes
    log "Removing stack volumes..."
    docker volume rm ${STACK_NAME}_postgres_data 2>/dev/null || true
    docker volume rm ${STACK_NAME}_metabase_data 2>/dev/null || true
    docker volume rm ${STACK_NAME}_traefik_data 2>/dev/null || true
    docker volume rm postgres_data 2>/dev/null || true
    docker volume rm metabase_data 2>/dev/null || true
    docker volume rm traefik_data 2>/dev/null || true
    
    # Remove stack-specific secrets
    log "Removing stack secrets..."
    docker secret rm api_key 2>/dev/null || true
    docker secret rm dashboard_id 2>/dev/null || true
    docker secret rm optional_tools 2>/dev/null || true
    docker secret rm postgres_db 2>/dev/null || true
    docker secret rm postgres_password 2>/dev/null || true
    docker secret rm postgres_user 2>/dev/null || true
    
    # Clean up unused containers and images
    log "Cleaning up unused containers and images..."
    docker container prune -f
    docker image prune -f
    
    # Remove unused networks
    docker network prune -f
    
    log_success "Full cleanup completed"
}

detect_container_runtime() {
    # Check what's available and prefer RHEL native packages
    if command -v podman >/dev/null 2>&1; then
        echo "podman"
    elif command -v docker >/dev/null 2>&1; then
        echo "docker"
    else
        echo "none"
    fi
}

install_docker_ce() {
    log "Installing Docker CE using recommended RHEL method..."
    
    # Remove conflicting Podman-Docker symlink first
    if [[ -L "/usr/local/bin/docker" ]]; then
        log "Removing conflicting Podman-Docker symlink..."
        sudo rm -f /usr/local/bin/docker
        log_success "Removed Podman-Docker symlink"
    fi
    
    # Remove podman-docker package if installed
    if dnf list installed podman-docker &>/dev/null; then
        log "Removing conflicting podman-docker package..."
        sudo dnf remove -y podman-docker
        log_success "Removed podman-docker package"
    fi
    
    # Check if Docker CE repo already exists
    if dnf repolist enabled | grep -q "docker-ce"; then
        log "Docker CE repository already configured"
    else
        # Install Docker CE using dnf config-manager (RHEL recommended method)
        log "Adding Docker CE repository..."
        
        # Install dnf-plugins-core if not present
        sudo dnf install -y dnf-plugins-core 2>/dev/null || true
        
        # Add Docker repository using config-manager
        if sudo dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo 2>/dev/null; then
            log_success "Docker CE repository added successfully"
        else
            log_error "Failed to add Docker CE repository. Check network connectivity."
            echo ""
            echo "For offline installation, manually load Docker images first"
            exit 1
        fi
    fi
    
    # Install Docker CE packages
    log "Installing Docker CE packages..."
    if sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin; then
        # Enable and start Docker service
        sudo systemctl enable docker
        sudo systemctl start docker
        
        # Configure user access
        if ! getent group docker > /dev/null; then
            sudo groupadd docker 2>/dev/null || true
        fi
        sudo usermod -aG docker $USER
        
        log_success "Docker CE installation completed"
        log_success "Native Docker CE is now available and properly configured"
    else
        log_error "Failed to install Docker CE packages"
        exit 1
    fi
}

install_docker() {
    log "Installing container runtime and initializing environment..."
    
    local runtime=$(detect_container_runtime)
    
    case "$runtime" in
        "docker")
            log_success "Docker is already installed"
            if docker info >/dev/null 2>&1; then
                log "Docker daemon is running"
            else
                log "Starting Docker daemon..."
                sudo systemctl start docker
                sudo systemctl enable docker
            fi
            ;;
        "podman")
            log_warning "Podman detected - vAnalyzer requires Docker for Swarm mode"
            echo ""
            echo "Options for Docker installation:"
            echo "1. Install Docker CE alongside Podman (may cause conflicts)"
            echo "2. Purge Podman and install Docker CE cleanly (recommended)"
            echo -n "Choose option (1/2): "
            read -r install_choice
            
            case "$install_choice" in
                "2")
                    log "Purging Podman and installing Docker CE cleanly..."
                    
                    # Stop any running Podman containers/services
                    log "Stopping Podman services..."
                    sudo systemctl stop podman 2>/dev/null || true
                    sudo systemctl disable podman 2>/dev/null || true
                    
                    # Remove Podman and related packages
                    log "Removing Podman packages..."
                    sudo dnf remove -y podman podman-docker buildah skopeo 2>/dev/null || true
                    
                    # Clean up Podman data
                    log "Cleaning up Podman data..."
                    sudo rm -rf /var/lib/containers 2>/dev/null || true
                    sudo rm -rf ~/.local/share/containers 2>/dev/null || true
                    
                    # Now install Docker CE cleanly
                    install_docker_ce
                    ;;
                "1"|*)
                    log "Installing Docker CE alongside Podman..."
                    install_docker_ce
                    ;;
            esac
            ;;
        "none")
            log "Installing container runtime..."
            
            # Install Docker CE for vAnalyzer compatibility
            log "Installing Docker CE for vAnalyzer..."
            install_docker_ce
            
            # Configure user access
            log "Configuring container runtime access..."
            if ! getent group docker > /dev/null; then
                sudo groupadd docker 2>/dev/null || true
            fi
            sudo usermod -aG docker $USER
            
            log_success "Container runtime installation completed"
            ;;
    esac
    
    # Initialize Docker Swarm with portable configuration
    if ! docker info | grep -q "Swarm: active" 2>/dev/null; then
        log "Initializing Docker Swarm..."
        
        # Use automatic IP detection for better portability
        log "Initializing Docker Swarm with automatic configuration..."
        
        if docker swarm init 2>/dev/null; then
            log_success "Docker Swarm initialized automatically"
        else
            # Fallback to localhost for maximum portability
            log "Trying localhost configuration for maximum portability..."
            if docker swarm init --advertise-addr 127.0.0.1 2>/dev/null; then
                log_success "Docker Swarm initialized with localhost (most portable)"
                log "Note: This configuration works best for single-node deployments"
            else
                log_error "Could not initialize Docker Swarm automatically"
                log "Please manually initialize: docker swarm init --advertise-addr <YOUR_IP>"
                exit 1
            fi
        fi
    else
        log_success "Docker Swarm already active"
    fi
    
    
    log_success "Docker installation and setup completed"
    echo ""
    log_warning "Please log out and log back in for Docker group changes to take effect"
    log_warning "Or run: newgrp docker"
}


purge_docker() {
    log_error "WARNING: This will completely remove Docker and ALL data!"
    echo -n "Are you sure you want to proceed? (type 'yes' to confirm): "
    read -r confirmation
    
    if [[ "$confirmation" != "yes" ]]; then
        log "Purge cancelled"
        return 0
    fi
    
    log "Purging Docker and all data..."
    
    # Remove Docker stacks
    log "Removing Docker stacks..."
    docker stack ls --format "{{.Name}}" | xargs -I {} docker stack rm {} 2>/dev/null || true
    
    # Remove Docker services
    log "Removing Docker services..."
    docker service ls --format "{{.Name}}" | xargs -I {} docker service rm {} 2>/dev/null || true
    
    # Wait for cleanup
    sleep 10
    
    # Stop Docker service
    log "Stopping Docker service..."
    sudo systemctl stop docker 2>/dev/null || true
    sudo systemctl disable docker 2>/dev/null || true
    
    # Remove conflicting Podman-Docker symlink
    log "Removing conflicting Podman-Docker symlink..."
    if [[ -L "/usr/local/bin/docker" ]]; then
        sudo rm -f /usr/local/bin/docker
        log_success "Removed Podman-Docker symlink"
    fi
    
    # Uninstall Docker packages (RHEL method)
    log "Uninstalling Docker packages..."
    sudo dnf remove -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin 2>/dev/null || true
    
    # Remove Podman-Docker compatibility packages
    log "Removing Podman-Docker compatibility packages..."
    sudo dnf remove -y podman-docker 2>/dev/null || true
    
    # Remove Docker dependencies
    log "Removing Docker dependencies..."
    sudo dnf autoremove -y
    
    # Remove Docker data and configuration files
    log "Removing Docker data and configuration files..."
    sudo rm -rf /var/lib/docker
    sudo rm -rf /var/lib/containerd
    sudo rm -rf /etc/docker
    
    # Remove custom volumes
    log "Removing custom Docker volumes..."
    sudo rm -rf /mnt/metabase
    
    # Remove Docker's GPG key and repository (RHEL method)
    log "Removing Docker repository configuration..."
    sudo rm -f /etc/yum.repos.d/docker-ce.repo
    sudo rm -f /etc/pki/rpm-gpg/RPM-GPG-KEY-docker
    
    # Clean up docker group
    log "Cleaning up docker group..."
    sudo groupdel docker 2>/dev/null || true
    
    log_success "Docker has been completely purged from your system"
    log_warning "Please log out and log back in to refresh group memberships"
}

deploy_stack() {
    log "Deploying vAnalyzer stack..."
    
    
    # Remove existing stack if it exists
    if docker stack ls | grep -q "$STACK_NAME"; then
        log "Removing existing stack..."
        docker stack rm "$STACK_NAME"
        
        # Wait for stack to be fully removed
        log "Waiting for stack to be fully removed..."
        sleep 15
        
        # Wait for networks to be cleaned up
        while docker network ls | grep -q "${STACK_NAME}_"; do
            sleep 5
        done
    fi
    
    # Create a modified compose file without registry service and with absolute paths
    local temp_compose="/tmp/docker-compose-no-registry.yml"
    local current_dir=$(pwd)
    
    # Remove registry service and convert relative paths to absolute
    awk -v current_dir="$current_dir" '
    /^  registry:/ { skip = 1; next }
    /^  [a-zA-Z]/ && skip { skip = 0 }
    !skip { 
        # Convert relative paths to absolute paths for Swarm compatibility
        gsub(/source: \.\//, "source: " current_dir "/")
        print 
    }
    ' "$COMPOSE_FILE" > "$temp_compose"
    
    # Deploy new stack with --resolve-image never to use local images
    log "Deploying new stack (using local images)..."
    docker stack deploy --resolve-image never -c "$temp_compose" "$STACK_NAME"
    
    # Clean up temporary file
    rm -f "$temp_compose"
    
    # Clean up dangling images after deployment
    log "Cleaning up dangling images..."
    docker image prune -f >/dev/null 2>&1 || true
    
    log_success "Stack deployment initiated (using local images)"
}

# Main execution
case "${1:-help}" in
    "install")
        install_docker
        ;;
    "deploy")
        # Skip interactive setup if called from import script
        if [[ "${SKIP_INTERACTIVE_SETUP:-false}" != "true" ]]; then
            interactive_setup
        fi
        
        # Reload environment variables after interactive setup
        if [[ -f "$ENV_FILE" ]]; then
            source "$ENV_FILE"
            export VERSION ENVIRONMENT STACK_NAME
            export APP_PORT LOG_LEVEL 
            export TRAEFIK_VERSION TRAEFIK_DASHBOARD_PORT
            export METABASE_VERSION METABASE_HOST METABASE_MEMORY METABASE_BASIC_AUTH
        fi
        
        validate_environment
        check_prerequisites
        setup_secrets
        build_images
        deploy_stack
        if wait_for_services; then
            check_health
            log_success "🎉 Deployment completed successfully!"
            echo ""
            echo "📋 Next Steps:"
            echo "1. Access dashboard: https://${VANALYZER_HOSTNAME:-reports.local}"
            echo "2. Add to /etc/hosts if needed: echo '127.0.0.1 ${VANALYZER_HOSTNAME:-reports.local}' | sudo tee -a /etc/hosts"
            echo "3. Install CA certificate from: ./traefik/config/certs/ca.crt"
            echo "4. Default Metabase credentials:"
            echo "   - Username: vrxadmin@vrxadmin.com"
            echo "   - Password: Vicarius123!@#"
            echo "5. Database configured with:"
            echo "   - User: ${POSTGRES_USER}"
            echo "   - Database: ${DASHBOARD_ID}"
            echo ""
            show_status
        else
            log_error "Deployment failed - some services are not ready"
            exit 1
        fi
        ;;
    "update")
        log "🔄 Starting vAnalyzer Update Process"
        echo ""
        interactive_update
        validate_environment
        check_prerequisites
        setup_secrets
        build_images
        deploy_stack
        if wait_for_services; then
            check_health
            log_success "Update completed successfully"
            echo ""
            log "Access your updated vAnalyzer at: https://$VANALYZER_HOSTNAME"
        else
            log_error "Update failed - some services are not ready"
            exit 1
        fi
        ;;
    "rollback")
        rollback
        ;;
    "status")
        show_status
        ;;
    "logs")
        show_logs "${2:-}"
        ;;
    "health")
        check_health
        ;;
    "cleanup")
        cleanup
        ;;
    "purge")
        purge_docker
        ;;
    "help")
        show_usage
        ;;
    *)
        echo "Unknown command: $1"
        show_usage
        exit 1
        ;;
esac