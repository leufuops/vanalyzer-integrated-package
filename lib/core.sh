#!/bin/bash
# vAnalyzer Core Library
# Common functions used across all modules

# Logging functions
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

log_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

log_success() {
    echo -e "${GREEN}✓${NC} $1"
}

log_error() {
    echo -e "${RED}✗${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

log_step() {
    echo -e "${CYAN}▶${NC} $1"
}

# Progress indicator
show_spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

# Error handling
handle_error() {
    local line_no=$1
    local exit_code=$2
    log_error "Error on line $line_no with exit code $exit_code"
}

# Command existence check
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

trap 'handle_error ${LINENO} $?' ERR

# Confirmation prompt
confirm() {
    local message="${1:-Are you sure?}"
    local default="${2:-n}"
    
    local prompt
    if [[ "$default" == "y" ]]; then
        prompt="$message [Y/n]: "
    else
        prompt="$message [y/N]: "
    fi
    
    read -p "$prompt" response
    response=${response:-$default}
    
    [[ "$response" =~ ^[Yy]$ ]]
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        log_warning "Running as root user"
        return 0
    else
        return 1
    fi
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Get stack name
get_stack_name() {
    local stack_name="${STACK_NAME:-vanalyzer-stack}"
    
    # Try to read from .env
    if [[ -f "$ENV_FILE" ]]; then
        local env_stack=$(grep "^STACK_NAME=" "$ENV_FILE" | cut -d'=' -f2)
        [[ -n "$env_stack" ]] && stack_name="$env_stack"
    fi
    
    echo "$stack_name"
}

# Get service name
get_service_name() {
    local service="$1"
    local stack_name=$(get_stack_name)
    echo "${stack_name}_${service}"
}

# Check if Docker/Podman is running
check_runtime() {
    if [[ "$RUNTIME" == "docker" ]]; then
        if docker info >/dev/null 2>&1; then
            return 0
        else
            log_error "Docker daemon is not running"
            log_info "Start Docker with: sudo systemctl start docker"
            return 1
        fi
    elif [[ "$RUNTIME" == "podman" ]]; then
        if podman info >/dev/null 2>&1; then
            return 0
        else
            log_error "Podman is not running"
            return 1
        fi
    else
        log_error "No container runtime found (Docker or Podman required)"
        log_info "Install Docker with: sudo ./vanalyzer install"
        return 1
    fi
}

# Check if Docker Swarm is initialized
check_swarm() {
    local swarm_state=$(docker info --format '{{.Swarm.LocalNodeState}}' 2>/dev/null)

    if [[ "$swarm_state" == "active" ]]; then
        return 0
    else
        log_warning "Docker Swarm is not initialized (state: ${swarm_state:-unknown})"

        if confirm "Initialize Docker Swarm now?"; then
            init_swarm
        else
            return 1
        fi
    fi
}

# Initialize Docker Swarm
init_swarm() {
    log_info "Initializing Docker Swarm..."

    # First check if swarm is already initialized
    local swarm_state=$(docker info --format '{{.Swarm.LocalNodeState}}' 2>/dev/null)
    if [[ "$swarm_state" == "active" ]]; then
        log_success "Docker Swarm already active"
        return 0
    fi
    
    # Try to get default IP
    local default_ip=""
    local swarm_error=""
    
    # Method 1: Get IP from default route
    default_ip=$(ip -4 route get 8.8.8.8 2>/dev/null | head -1 | awk '{print $7}' 2>/dev/null || true)
    
    # Method 2: Get first global IP
    if [[ -z "$default_ip" ]]; then
        default_ip=$(ip -4 addr show scope global 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1 2>/dev/null || true)
    fi
    
    # Method 3: Use localhost for single-node
    if [[ -z "$default_ip" ]]; then
        default_ip="127.0.0.1"
        log_warning "Using localhost for single-node Swarm"
    fi
    
    log_step "Attempting swarm initialization with IP: $default_ip"
    
    # Try swarm init with detailed error capture
    swarm_error=$(docker swarm init --advertise-addr "$default_ip" 2>&1)
    local init_result=$?
    
    if [[ $init_result -eq 0 ]]; then
        log_success "Docker Swarm initialized with IP: $default_ip"
        return 0
    fi
    
    # Handle specific error cases
    if echo "$swarm_error" | grep -q "already part of a swarm"; then
        log_warning "Node already part of a swarm, leaving and reinitializing..."
        docker swarm leave --force >/dev/null 2>&1 || true
        sleep 2
        if docker swarm init --advertise-addr "$default_ip" >/dev/null 2>&1; then
            log_success "Docker Swarm reinitialized with IP: $default_ip"
            return 0
        fi
    fi
    
    # Try without advertise-addr as fallback
    log_step "Trying swarm init without advertise-addr..."
    if docker swarm init >/dev/null 2>&1; then
        log_success "Docker Swarm initialized (default configuration)"
        return 0
    fi
    
    # Final attempt with forced single-node setup
    log_step "Attempting forced single-node setup..."
    if docker swarm init --advertise-addr "127.0.0.1" >/dev/null 2>&1; then
        log_success "Docker Swarm initialized in single-node mode"
        return 0
    fi
    
    log_error "Failed to initialize Docker Swarm. Error details:"
    echo "$swarm_error" | head -3
    log_error "Please check Docker daemon status and network configuration"
    return 1
}

# Wait for services to be ready
wait_for_services() {
    local stack_name=$(get_stack_name)
    local max_wait=${1:-300}  # Default 5 minutes
    local wait_time=0
    local check_interval=10
    
    log_info "Waiting for services to be ready..."
    
    while [[ $wait_time -lt $max_wait ]]; do
        local running=$(docker service ls --filter "name=${stack_name}" --format "{{.Name}}: {{.Replicas}}" | grep -c "1/1" || true)
        local total=$(docker service ls --filter "name=${stack_name}" --format "{{.Name}}" | wc -l)
        
        if [[ $running -eq $total ]] && [[ $total -gt 0 ]]; then
            log_success "All services are running ($running/$total)"
            return 0
        fi
        
        echo -ne "\rServices: $running/$total ready... (${wait_time}s)     "
        sleep $check_interval
        wait_time=$((wait_time + check_interval))
    done
    
    echo ""
    log_error "Timeout waiting for services to be ready"
    return 1
}

# Show service status
show_service_status() {
    local stack_name=$(get_stack_name)
    
    echo ""
    echo -e "${BOLD}Service Status:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    docker service ls --filter "name=${stack_name}" --format "table {{.Name}}\t{{.Replicas}}\t{{.Image}}" | tail -n +2 | while read line; do
        local name=$(echo "$line" | awk '{print $1}')
        local replicas=$(echo "$line" | awk '{print $2}')
        local image=$(echo "$line" | awk '{print $3}')
        
        # Determine status icon
        if [[ "$replicas" == "1/1" ]]; then
            icon="${GREEN}✓${NC}"
        elif [[ "$replicas" == "0/1" ]]; then
            icon="${RED}✗${NC}"
        else
            icon="${YELLOW}⟳${NC}"
        fi
        
        printf "%s %-30s %-8s %s\n" "$icon" "${name#${stack_name}_}" "$replicas" "$image"
    done
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Database backup function
backup_database() {
    local backup_file="${1:-}"
    local backup_dir="${SCRIPT_DIR}/backups"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    
    # Create backup directory if it doesn't exist
    mkdir -p "$backup_dir"
    
    # Create a subdirectory for this backup session
    local session_dir="${backup_dir}/backup_${timestamp}"
    mkdir -p "$session_dir"
    
    log_info "Creating database backups..."
    
    # Find container with 'appdb' in the name (handles various naming conventions)
    local db_container=$(docker ps --format "{{.Names}}" | grep -i "appdb" | head -1)
    
    if [[ -z "$db_container" ]]; then
        log_error "Database container not found (looking for container with 'appdb' in name)"
        return 1
    fi
    
    log_info "Found database container: $db_container"
    
    # Get database credentials from Docker secrets
    local db_user=$(docker exec "$db_container" cat /run/secrets/postgres_user 2>/dev/null || echo "postgres")
    local db_pass=$(docker exec "$db_container" cat /run/secrets/postgres_password 2>/dev/null)
    local db_name=$(docker exec "$db_container" cat /run/secrets/postgres_db 2>/dev/null || echo "vanalyzer")
    
    local backup_success=true
    
    # Backup main vAnalyzer database
    log_info "Backing up main vAnalyzer database..."
    local main_backup="${session_dir}/vanalyzer_${timestamp}.sql"
    local error_file="/tmp/backup_error_$$"
    
    if docker exec -e PGPASSWORD="$db_pass" "$db_container" \
        pg_dump -h localhost -U "$db_user" -d "$db_name" > "$main_backup" 2>"$error_file"; then
        local size=$(du -h "$main_backup" | cut -f1)
        log_success "Main database backed up: $(basename "$main_backup") ($size)"
    else
        local error_msg=$(cat "$error_file" 2>/dev/null)
        log_error "Main database backup failed: ${error_msg:-Unknown error}"
        backup_success=false
    fi
    rm -f "$error_file"
    
    # Backup Metabase database
    log_info "Backing up Metabase database..."
    local metabase_backup="${session_dir}/metabase_${timestamp}.sql"
    
    if docker exec -e PGPASSWORD="$db_pass" "$db_container" \
        pg_dump -h localhost -U "$db_user" -d metabase > "$metabase_backup" 2>"$error_file"; then
        local size=$(du -h "$metabase_backup" | cut -f1)
        log_success "Metabase database backed up: $(basename "$metabase_backup") ($size)"
    else
        # Metabase database might not exist yet, which is ok
        local error_msg=$(cat "$error_file" 2>/dev/null)
        if [[ "$error_msg" == *"does not exist"* ]]; then
            log_warning "Metabase database does not exist yet (this is normal for new installations)"
            rm -f "$metabase_backup"  # Remove empty file
        else
            log_error "Metabase backup failed: ${error_msg:-Unknown error}"
            [[ -f "$metabase_backup" && ! -s "$metabase_backup" ]] && rm -f "$metabase_backup"
        fi
    fi
    rm -f "$error_file"
    
    # Create a summary file
    echo "Backup created: $(date)" > "${session_dir}/backup_info.txt"
    echo "Main database: vanalyzer" >> "${session_dir}/backup_info.txt"
    echo "Metabase database: metabase" >> "${session_dir}/backup_info.txt"
    echo "Container: $db_container" >> "${session_dir}/backup_info.txt"
    
    if [[ "$backup_success" == true ]]; then
        log_success "Backup completed: ${session_dir}"
        return 0
    else
        log_warning "Backup completed with some errors: ${session_dir}"
        return 1
    fi
}

# Database restore function
# restore_database function moved to db-backup.sh for comprehensive backup/restore
# This ensures both main database and Metabase are properly restored

# Clean logs and temporary files
clean_logs() {
    log_info "Cleaning logs and temporary files..."
    
    # Clean application logs
    if [[ -d "${SCRIPT_DIR}/app/logs" ]]; then
        find "${SCRIPT_DIR}/app/logs" -type f -not -name ".gitignore" -delete 2>/dev/null || true
        log_success "Application logs cleaned"
    fi
    
    # Clean reports
    if [[ -d "${SCRIPT_DIR}/app/reports" ]]; then
        find "${SCRIPT_DIR}/app/reports" -type f -not -name ".gitignore" -delete 2>/dev/null || true
        log_success "Reports cleaned"
    fi
    
    # Clean Docker logs
    if confirm "Clean Docker container logs?" "n"; then
        docker ps -q | xargs -r docker inspect --format='{{.LogPath}}' | xargs -r truncate -s 0
        log_success "Docker logs cleaned"
    fi
}

# Cleanup resources
cleanup_resources() {
    echo ""
    echo -e "${BOLD}Resource Cleanup Options:${NC}"
    echo "1. Basic cleanup (unused resources only)"
    echo "2. Full cleanup (includes volumes and secrets)"
    echo "3. Cancel"
    echo ""
    
    read -p "Select option [1-3]: " choice
    
    case "$choice" in
        1)
            basic_cleanup
            ;;
        2)
            full_cleanup
            ;;
        *)
            log_info "Cleanup cancelled"
            ;;
    esac
}

# Basic cleanup
basic_cleanup() {
    log_info "Performing basic cleanup..."
    
    # Remove unused containers
    log_step "Removing unused containers..."
    docker container prune -f
    
    # Remove unused images
    log_step "Removing unused images..."
    docker image prune -f
    
    # Remove unused networks
    log_step "Removing unused networks..."
    docker network prune -f
    
    log_success "Basic cleanup completed"
}

# Full cleanup
full_cleanup() {
    log_warning "This will remove ALL vAnalyzer data including volumes and secrets!"
    
    if ! confirm "Continue with full cleanup?"; then
        log_info "Cleanup cancelled"
        return 0
    fi
    
    log_info "Performing full cleanup..."
    
    local stack_name=$(get_stack_name)
    
    # Remove stack
    if docker stack ls | grep -q "$stack_name"; then
        log_step "Removing stack: $stack_name"
        docker stack rm "$stack_name"
        sleep 10
    fi
    
    # Remove volumes
    log_step "Removing volumes..."
    docker volume ls --format "{{.Name}}" | grep -E "(${stack_name}|vanalyzer)" | xargs -r docker volume rm 2>/dev/null || true
    
    # Remove secrets
    log_step "Removing secrets..."
    docker secret ls --format "{{.Name}}" | grep -E "(api_key|dashboard_id|postgres)" | xargs -r docker secret rm 2>/dev/null || true
    
    # Basic cleanup
    basic_cleanup
    
    log_success "Full cleanup completed"
}

# Complete system purge
purge_all() {
    log_error "WARNING: This will completely remove Docker/Podman and ALL data!"
    echo "This action cannot be undone!"
    echo ""
    
    if ! confirm "Are you absolutely sure?" "n"; then
        log_info "Purge cancelled"
        return 0
    fi
    
    echo -n "Type 'DESTROY' to confirm: "
    read confirmation
    
    if [[ "$confirmation" != "DESTROY" ]]; then
        log_info "Purge cancelled"
        return 0
    fi
    
    log_warning "Starting complete system purge..."
    
    # Step 1: Remove vAnalyzer stacks and services
    log_step "Removing vAnalyzer stacks..."
    docker stack ls --format "{{.Name}}" | grep -E "(vanalyzer|vrx)" | xargs -I {} docker stack rm {} 2>/dev/null || true
    
    # Step 2: Clean up all Docker resources
    log_step "Stopping all containers..."
    docker stop $(docker ps -aq) 2>/dev/null || true
    
    log_step "Removing all containers..."
    docker rm -f $(docker ps -aq) 2>/dev/null || true
    
    log_step "Removing all images..."
    docker rmi -f $(docker images -aq) 2>/dev/null || true
    
    log_step "Removing all volumes..."
    docker volume rm -f $(docker volume ls -q) 2>/dev/null || true
    
    log_step "Removing all networks..."
    docker network rm $(docker network ls -q | grep -v bridge | grep -v host | grep -v none) 2>/dev/null || true
    
    log_step "Removing all secrets..."
    docker secret rm $(docker secret ls -q) 2>/dev/null || true
    
    log_step "Final Docker system prune..."
    docker system prune -af --volumes 2>/dev/null || true
    
    # Wait for cleanup
    sleep 5
    
    # Step 3: Stop and disable Docker service
    log_step "Stopping Docker service..."
    sudo systemctl stop docker 2>/dev/null || true
    sudo systemctl disable docker 2>/dev/null || true
    
    # Step 4: Remove Docker packages (OS-specific)
    log_step "Uninstalling Docker packages..."
    if [[ "${OS_TYPE:-}" == "rhel" ]] || [[ -f /etc/redhat-release ]]; then
        # RHEL/Rocky/Alma/CentOS
        sudo dnf remove -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin 2>/dev/null || true
        sudo dnf remove -y podman-docker 2>/dev/null || true
        sudo dnf autoremove -y 2>/dev/null || true
        
        # Remove Docker repository
        sudo rm -f /etc/yum.repos.d/docker-ce.repo
        sudo rm -f /etc/pki/rpm-gpg/RPM-GPG-KEY-docker
        
    elif [[ "${OS_TYPE:-}" == "ubuntu" ]] || [[ -f /etc/debian_version ]]; then
        # Ubuntu/Debian
        sudo apt-get purge -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin 2>/dev/null || true
        sudo apt-get autoremove -y 2>/dev/null || true
        sudo apt-get autoclean 2>/dev/null || true
        
        # Remove Docker repository
        sudo rm -f /etc/apt/sources.list.d/docker.list
        sudo rm -f /etc/apt/keyrings/docker.gpg
    fi
    
    # Step 5: Remove Docker data directories
    log_step "Removing Docker data and configuration..."
    sudo rm -rf /var/lib/docker 2>/dev/null || true
    sudo rm -rf /var/lib/containerd 2>/dev/null || true
    sudo rm -rf /etc/docker 2>/dev/null || true
    sudo rm -rf /var/run/docker.sock 2>/dev/null || true
    
    # Step 6: Remove custom application volumes
    log_step "Removing custom application volumes..."
    sudo rm -rf /mnt/metabase 2>/dev/null || true
    
    # Step 7: Clean up Docker group and symlinks
    log_step "Cleaning up Docker group and symlinks..."
    if [[ -L "/usr/local/bin/docker" ]]; then
        sudo rm -f /usr/local/bin/docker
    fi
    sudo groupdel docker 2>/dev/null || true
    
    # Step 8: Remove vAnalyzer configuration and logs
    log_step "Removing vAnalyzer configuration..."
    [[ -f "${SCRIPT_DIR:-}/.env" ]] && rm -f "${SCRIPT_DIR}/.env" 2>/dev/null || true
    sudo rm -rf /var/log/scheduler_log.log 2>/dev/null || true
    sudo rm -rf /var/log/initialsync.log 2>/dev/null || true
    
    log_success "Complete system purge completed!"
    echo ""
    log_warning "Docker and all associated components have been removed"
    log_warning "Please log out and log back in to refresh group memberships"
    echo ""
    log_info "To reinstall vAnalyzer:"
    log_info "  1. sudo ./vanalyzer install"
    log_info "  2. sudo ./vanalyzer init"
    log_info "  3. sudo ./vanalyzer deploy"
}

# Export functions for use in other modules
export -f log log_info log_success log_error log_warning log_step
export -f show_spinner handle_error confirm check_root command_exists
export -f get_stack_name get_service_name check_runtime check_swarm init_swarm
export -f wait_for_services show_service_status
export -f backup_database clean_logs
export -f cleanup_resources basic_cleanup full_cleanup purge_all