#!/bin/bash
set -euo pipefail

# vAnalyzer Unified Deployment Script
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
    echo "vAnalyzer Deployment Script - Ubuntu/Debian"
    echo "Usage: $0 {install|deploy|update|status|logs|cleanup|purge|help}"
    echo ""
    echo "🔧 NEW SETUP WORKFLOW (Recommended):"
    echo "  1. $0 cleanup/purge     # Clean environment (if needed)"
    echo "  2. $0 install           # Install Docker and dependencies"
    echo "  3. $0 deploy            # Interactive deployment with configuration"
    echo ""
    echo "📋 COMMANDS:"
    echo "  install   - Install Docker, Docker Swarm, and system dependencies"
    echo "  deploy    - Interactive deployment with hostname, API key, and SSL setup"
    echo "  update    - Update existing stack (preserves configuration)"
    echo "  status    - Show stack and service status"
    echo "  logs      - Show service logs (usage: logs <service_name>)"
    echo "  cleanup   - Clean up resources (interactive: basic or full)"
    echo "  purge     - Completely remove Docker and ALL data (DESTRUCTIVE)"
    echo "  help      - Show this help message"
    echo ""
    echo "📝 EXAMPLES:"
    echo "  $0 install              # Fresh Docker installation"
    echo "  $0 deploy               # Interactive deployment setup"
    echo "  $0 status               # Check all services"
    echo "  $0 logs app             # View application logs"
    echo "  $0 cleanup              # Interactive cleanup options"
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
            # Get existing credentials from secrets for .env update
            if docker secret ls | grep -q "postgres_user"; then
                POSTGRES_USER=$(docker secret inspect postgres_user --format '{{.Spec.Data}}' 2>/dev/null | base64 -d 2>/dev/null || echo "vanalyzer")
            fi
            if docker secret ls | grep -q "postgres_password"; then
                POSTGRES_PASSWORD=$(docker secret inspect postgres_password --format '{{.Spec.Data}}' 2>/dev/null | base64 -d 2>/dev/null || echo "")
            fi
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
    echo "Configure how often scripts should run:"
    echo "1. High frequency (1h refresh, 6h full sync)"
    echo "2. Medium frequency (2h refresh, 12h full sync)" 
    echo "3. Low frequency (6h refresh, 24h full sync)"
    echo -n "Choose option (1-3): "
    read FREQ_CHOICE
    
    # Configure sync schedules based on choice
    case $FREQ_CHOICE in
        1)
            SYNC_1H_INTERVAL="1h"
            SYNC_24H_INTERVAL="6h"
            ;;
        2)
            SYNC_1H_INTERVAL="2h"
            SYNC_24H_INTERVAL="12h"
            ;;
        3)
            SYNC_1H_INTERVAL="6h"
            SYNC_24H_INTERVAL="24h"
            ;;
        *)
            log_warning "Invalid choice, using medium frequency"
            SYNC_1H_INTERVAL="2h"
            SYNC_24H_INTERVAL="12h"
            ;;
    esac
    
    log "Configured: Refresh every $SYNC_1H_INTERVAL, Full sync every $SYNC_24H_INTERVAL"
    
    # Store configuration for use in setup_secrets
    export VANALYZER_HOSTNAME
    export DASHBOARD_ID
    export API_KEY
    export POSTGRES_USER
    export POSTGRES_PASSWORD
    export UPDATE_SECRETS
    export UPDATE_DB_SECRETS
    
    # Update .env file with new settings
    update_env_with_settings
    
    log_success "Interactive update configuration completed"
}

update_env_with_settings() {
    log "Updating .env file with deployment settings..."
    
    local env_file=".env"
    
    # Update METABASE_BASIC_AUTH with database credentials if we have them
    if [[ -n "${POSTGRES_USER:-}" && -n "${POSTGRES_PASSWORD:-}" ]]; then
        if grep -q "^METABASE_BASIC_AUTH=" "$env_file"; then
            sed -i "s/^METABASE_BASIC_AUTH=.*/METABASE_BASIC_AUTH=${POSTGRES_USER}:${POSTGRES_PASSWORD}/" "$env_file"
        else
            echo "METABASE_BASIC_AUTH=${POSTGRES_USER}:${POSTGRES_PASSWORD}" >> "$env_file"
        fi
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
    echo "⏱️ STEP 4: Configure Refresh Rate"
    echo "Configure how often scripts should run:"
    echo "1. High frequency (1h refresh, 6h full sync)"
    echo "2. Medium frequency (2h refresh, 12h full sync)" 
    echo "3. Low frequency (6h refresh, 24h full sync)"
    echo "4. Custom"
    echo -n "Select option (1-4): "
    read REFRESH_OPTION
    
    case "$REFRESH_OPTION" in
        "1")
            QUICK_REFRESH_HOURS=1
            FULL_REFRESH_HOURS=6
            ;;
        "2")
            QUICK_REFRESH_HOURS=2
            FULL_REFRESH_HOURS=12
            ;;
        "3")
            QUICK_REFRESH_HOURS=6
            FULL_REFRESH_HOURS=24
            ;;
        "4")
            echo -n "Enter quick refresh interval (hours): "
            read QUICK_REFRESH_HOURS
            echo -n "Enter full refresh interval (hours): "
            read FULL_REFRESH_HOURS
            ;;
        *)
            log_warning "Invalid option, using default (option 3)"
            QUICK_REFRESH_HOURS=6
            FULL_REFRESH_HOURS=24
            ;;
    esac
    
    # Configure launcher.py with new refresh rates
    configure_refresh_rates "$QUICK_REFRESH_HOURS" "$FULL_REFRESH_HOURS"
    
    echo ""
    echo "📁 STEP 5: Traefik Certificate Directory"
    log "SSL certificates are stored in: $(pwd)/traefik/config/certs/"
    log "To use custom certificates, replace files in this directory before deployment"
    
    # Store configuration for use in setup_secrets
    export VANALYZER_HOSTNAME
    export DASHBOARD_ID
    export API_KEY
    
    log_success "Interactive setup completed"
}

configure_refresh_rates() {
    local quick_hours=$1
    local full_hours=$2
    
    log "Configuring refresh rates: ${quick_hours}h quick, ${full_hours}h full"
    
    local launcher_file="./app/scripts/launcher.py"
    if [[ -f "$launcher_file" ]]; then
        
        # Update the refresh rates in launcher.py
        sed -i "s/trigger=IntervalTrigger(hours=24)/trigger=IntervalTrigger(hours=$full_hours)/g" "$launcher_file"
        sed -i "s/trigger=IntervalTrigger(hours=1)/trigger=IntervalTrigger(hours=$quick_hours)/g" "$launcher_file"
        
        log_success "Launcher configured with ${quick_hours}h/${full_hours}h intervals"
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
    
    # Use values from interactive setup or prompt if not set
    if [[ -z "${API_KEY:-}" ]]; then
        if ! docker secret ls | grep -q "api_key"; then
            echo -n "Enter API key: "
            read -s API_KEY
            echo
        fi
    fi
    
    if [[ -z "${DASHBOARD_ID:-}" ]]; then
        if ! docker secret ls | grep -q "dashboard_id"; then
            echo -n "Enter Dashboard ID: "
            read DASHBOARD_ID
        fi
    fi
    
    # Handle API credentials - only update if requested or if new installation
    if [[ "${UPDATE_SECRETS:-true}" == "true" ]]; then
        if [[ -n "${API_KEY:-}" ]]; then
            create_or_update_secret "api_key" "$API_KEY"
        fi
        
        if [[ -n "${DASHBOARD_ID:-}" ]]; then
            create_or_update_secret "dashboard_id" "$DASHBOARD_ID"
        fi
    else
        log "📌 Skipping API credential updates (keeping existing)"
    fi
    
    if ! docker secret ls | grep -q "postgres_user"; then
        echo -n "Enter PostgreSQL username: "
        read POSTGRES_USER
        create_or_update_secret "postgres_user" "$POSTGRES_USER"
    fi
    
    if ! docker secret ls | grep -q "postgres_password"; then
        echo -n "Enter PostgreSQL password: "
        read -s POSTGRES_PASSWORD
        echo
        create_or_update_secret "postgres_password" "$POSTGRES_PASSWORD"
    fi
    
    if ! docker secret ls | grep -q "postgres_db"; then
        POSTGRES_DB=${DASHBOARD_ID:-vanalyzer}
        create_or_update_secret "postgres_db" "$POSTGRES_DB"
    fi
    
    if ! docker secret ls | grep -q "optional_tools"; then
        create_or_update_secret "optional_tools" "metabase"
    fi
    
    log_success "Secrets setup completed"
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
        local service_name
        
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

install_docker() {
    log "Installing Docker and initializing environment..."
    
    # Check if Docker is already installed
    if command -v docker >/dev/null 2>&1; then
        log_warning "Docker is already installed"
        if docker info >/dev/null 2>&1; then
            log "Docker daemon is running"
        else
            log "Starting Docker daemon..."
            sudo systemctl start docker
        fi
    else
        log "Installing Docker..."
        
        # Update package list
        log "Updating package list..."
        sudo apt-get update -y
        
        # Install necessary dependencies
        log "Installing dependencies..."
        sudo apt-get install ca-certificates curl gnupg -y
        
        # Add Docker's official GPG key
        log "Adding Docker GPG key..."
        sudo install -m 0755 -d /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        sudo chmod a+r /etc/apt/keyrings/docker.gpg
        
        # Add Docker repository
        log "Adding Docker repository..."
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
        
        # Update package list with Docker packages
        sudo apt-get update -y
        
        # Install Docker
        log "Installing Docker components..."
        sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y
        
        # Create Docker group and add user
        log "Configuring Docker group..."
        if ! getent group docker > /dev/null; then
            sudo groupadd docker
        fi
        sudo usermod -aG docker $USER
        
        log_success "Docker installation completed"
    fi
    
    # Initialize Docker Swarm
    if ! docker info | grep -q "Swarm: active"; then
        log "Initializing Docker Swarm..."
        DEFAULT_IPV4=$(ip -4 route get 8.8.8.8 2>/dev/null | head -1 | awk '{print $7}')
        
        if [ -z "$DEFAULT_IPV4" ]; then
            DEFAULT_IPV4=$(ip -4 addr show scope global | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
        fi
        
        if [ -z "$DEFAULT_IPV4" ]; then
            log_error "Could not detect IPv4 address for Docker Swarm"
            log "Please manually initialize: docker swarm init --advertise-addr <YOUR_IP>"
            exit 1
        fi
        
        log "Initializing Docker Swarm with IP: $DEFAULT_IPV4"
        docker swarm init --advertise-addr "$DEFAULT_IPV4"
        log_success "Docker Swarm initialized"
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
    sudo systemctl stop docker
    
    # Uninstall Docker packages
    log "Uninstalling Docker packages..."
    sudo apt-get purge -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin 2>/dev/null || true
    
    # Remove Docker dependencies
    log "Removing Docker dependencies..."
    sudo apt-get autoremove -y
    
    # Remove Docker data and configuration files
    log "Removing Docker data and configuration files..."
    sudo rm -rf /var/lib/docker
    sudo rm -rf /var/lib/containerd
    sudo rm -rf /etc/docker
    
    # Remove custom volumes
    log "Removing custom Docker volumes..."
    sudo rm -rf /mnt/metabase
    
    # Remove Docker's GPG key and repository
    log "Removing Docker repository configuration..."
    sudo rm -f /etc/apt/sources.list.d/docker.list
    sudo rm -f /etc/apt/keyrings/docker.gpg
    
    log_success "Docker has been completely purged from your system"
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
    
    # Deploy new stack
    log "Deploying new stack..."
    docker stack deploy -c "$temp_compose" "$STACK_NAME"
    
    # Clean up temporary file
    rm -f "$temp_compose"
    
    # Clean up dangling images after deployment
    log "Cleaning up dangling images..."
    docker image prune -f >/dev/null 2>&1 || true
    
    log_success "Stack deployment initiated"
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