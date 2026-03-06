#!/bin/bash
# vAnalyzer Docker Operations Library
# Handles Docker/Podman operations, stack deployment, and service management

# Install container runtime based on OS
install_runtime() {
    log_info "Installing container runtime for $OS_TYPE..."
    
    case "$OS_TYPE" in
        ubuntu)
            install_docker_ubuntu
            ;;
        rhel)
            install_docker_rhel
            ;;
        *)
            log_error "Unsupported OS type: $OS_TYPE"
            return 1
            ;;
    esac
}

# Install Docker on Ubuntu/Debian
install_docker_ubuntu() {
    log_info "Installing Docker on Ubuntu/Debian..."
    
    # Update package list
    log_step "Updating package list..."
    sudo apt-get update -y
    
    # Install dependencies
    log_step "Installing dependencies..."
    sudo apt-get install ca-certificates curl gnupg lsb-release -y
    
    # Add Docker's official GPG key
    log_step "Adding Docker GPG key..."
    sudo install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    sudo chmod a+r /etc/apt/keyrings/docker.gpg
    
    # Add Docker repository
    log_step "Adding Docker repository..."
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    
    # Update package list with Docker
    sudo apt-get update -y
    
    # Install Docker
    log_step "Installing Docker..."
    sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y
    
    # Configure Docker
    configure_docker
    
    log_success "Docker installed successfully"
}

# Install Docker on RHEL/Rocky/Alma
install_docker_rhel() {
    log_info "Installing container runtime on RHEL/Rocky/Alma..."
    
    # Check for existing Podman
    if command_exists podman; then
        log_warning "Podman detected - vAnalyzer requires Docker for Swarm mode"
        echo ""
        echo "Options:"
        echo "1. Install Docker CE alongside Podman"
        echo "2. Remove Podman and install Docker CE cleanly (recommended)"
        read -p "Choose option (1/2): " choice
        
        if [[ "$choice" == "2" ]]; then
            remove_podman_cleanly
        fi
    fi
    
    # Install Docker CE
    log_step "Installing Docker CE..."
    
    # Install dependencies
    sudo dnf install -y dnf-plugins-core
    
    # Add Docker repository
    sudo dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo
    
    # Install Docker
    sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    
    # Configure Docker
    configure_docker
    
    log_success "Docker CE installed successfully"
}

# Remove Podman cleanly
remove_podman_cleanly() {
    log_info "Removing Podman cleanly..."
    
    # Stop Podman services
    sudo systemctl stop podman 2>/dev/null || true
    sudo systemctl disable podman 2>/dev/null || true
    
    # Remove Podman packages
    sudo dnf remove -y podman podman-docker buildah skopeo 2>/dev/null || true
    
    # Clean Podman data
    sudo rm -rf /var/lib/containers 2>/dev/null || true
    sudo rm -rf ~/.local/share/containers 2>/dev/null || true
    
    log_success "Podman removed cleanly"
}

# Configure Docker
configure_docker() {
    log_step "Configuring Docker..."
    
    # Get current user (more reliable than $USER)
    local current_user=$(whoami)
    
    # Create docker group if it doesn't exist
    if ! getent group docker > /dev/null; then
        log_step "Creating docker group..."
        sudo groupadd docker
    fi
    
    # Add current user to docker group
    log_step "Adding $current_user to docker group..."
    sudo usermod -aG docker "$current_user"
    
    # Verify user was added to group
    if groups "$current_user" | grep -q docker; then
        log_success "User $current_user successfully added to docker group"
    else
        log_warning "Failed to verify docker group membership for $current_user"
    fi
    
    # Enable and start Docker
    log_step "Enabling and starting Docker service..."
    sudo systemctl enable docker
    sudo systemctl start docker
    
    # Wait for Docker to be ready
    local max_attempts=10
    local attempt=1
    while [[ $attempt -le $max_attempts ]]; do
        if sudo docker info >/dev/null 2>&1; then
            log_success "Docker service is running"
            break
        else
            if [[ $attempt -eq $max_attempts ]]; then
                log_warning "Docker service may not be fully ready"
            else
                sleep 2
                ((attempt++))
            fi
        fi
    done
    
    log_success "Docker configured successfully"
    echo ""
    log_warning "IMPORTANT: Group membership changes require one of the following:"
    echo -e "  ${CYAN}Option 1:${NC} Log out and log back in"
    echo -e "  ${CYAN}Option 2:${NC} Run: ${YELLOW}newgrp docker${NC}"
    echo -e "  ${CYAN}Option 3:${NC} Use: ${YELLOW}sudo ./vanalyzer deploy${NC} (for this session only)"
}

# Setup Docker secrets
setup_secrets() {
    log_info "Setting up Docker secrets..."
    
    # Check if Docker secrets exist
    local required_secrets=("api_key" "dashboard_id" "postgres_user" "postgres_password" "postgres_db" "optional_tools" "vulncheck_api_key")
    local missing_secrets=()
    
    for secret in "${required_secrets[@]}"; do
        if ! docker secret ls --format "{{.Name}}" | grep -q "^${secret}$"; then
            missing_secrets+=("$secret")
        fi
    done
    
    if [[ ${#missing_secrets[@]} -gt 0 ]]; then
        log_error "Missing Docker secrets: ${missing_secrets[*]}"
        log_error "Run 'vanalyzer init' to create secrets"
        return 1
    fi
    
    log_success "All required Docker secrets are present"
}

# Check and stop services if needed
check_and_stop_services() {
    local running_services=$(docker service ls --format "{{.Name}}" 2>/dev/null | wc -l)
    local running_stacks=$(docker stack ls --format "{{.Name}}" 2>/dev/null | wc -l)
    
    if [[ $running_services -gt 0 ]] || [[ $running_stacks -gt 0 ]]; then
        log_warning "Found running services/stacks that may use secrets"
        
        if confirm "Stop services to update secrets?"; then
            log_info "Stopping services..."
            
            # Stop stacks
            for stack in $(docker stack ls --format "{{.Name}}" 2>/dev/null); do
                docker stack rm "$stack"
            done
            
            # Stop services
            for service in $(docker service ls --format "{{.Name}}" 2>/dev/null); do
                docker service rm "$service"
            done
            
            sleep 10
            log_success "Services stopped"
        else
            log_warning "Proceeding without stopping services - secret updates may fail"
        fi
    fi
}

# Create or update a Docker secret
create_secret() {
    local secret_name="$1"
    local secret_value="$2"
    local max_attempts=5
    local attempt=1
    
    # Remove existing secret
    if docker secret ls --format "{{.Name}}" | grep -q "^${secret_name}$"; then
        log_step "Removing existing secret: $secret_name"
        
        while [[ $attempt -le $max_attempts ]]; do
            if docker secret rm "$secret_name" 2>/dev/null; then
                break
            else
                if [[ $attempt -eq $max_attempts ]]; then
                    log_error "Failed to remove secret $secret_name after $max_attempts attempts"
                    return 1
                fi
                sleep 3
                ((attempt++))
            fi
        done
    fi
    
    # Create new secret
    log_step "Creating secret: $secret_name"
    if echo "$secret_value" | docker secret create "$secret_name" - 2>/dev/null; then
        log_success "Created secret: $secret_name"
    else
        log_error "Failed to create secret: $secret_name"
        return 1
    fi
}

# Build images from source
build_images() {
    log_info "Building Docker images from source..."
    
    local version="${VERSION:-1.4}"
    
    # Build database image
    if [[ -d "${SCRIPT_DIR}/appdb" ]]; then
        log_step "Building database image..."
        docker build -t "vrx-reports-appdb:${version}" "${SCRIPT_DIR}/appdb"
        log_success "Database image built"
    fi
    
    # Build application image
    if [[ -d "${SCRIPT_DIR}/app" ]]; then
        log_step "Building application image..."
        docker build -t "vrx-reports-app:${version}" "${SCRIPT_DIR}/app"
        log_success "Application image built"
    fi
    
    log_success "All images built successfully"
}

# Fallback function to import images directly from tar files
import_images_directly() {
    local images_dir="${SCRIPT_DIR}/images"
    log_info "Importing Docker images directly from tar files..."
    
    if [[ ! -d "$images_dir" ]]; then
        log_error "Images directory not found: $images_dir"
        return 1
    fi
    
    # Check if any tar files exist
    local tar_files=($(find "$images_dir" -name "*.tar" -type f 2>/dev/null))
    if [[ ${#tar_files[@]} -eq 0 ]]; then
        log_error "No .tar files found in $images_dir"
        return 1
    fi
    
    log_info "Found ${#tar_files[@]} image archive(s) to import"
    
    # Import each tar file found
    local imported_count=0
    local failed_count=0
    
    for tar_file in "${tar_files[@]}"; do
        local filename=$(basename "$tar_file")
        log_step "Importing $filename..."
        
        # Validate tar file before attempting import
        if ! tar -tf "$tar_file" >/dev/null 2>&1; then
            log_error "Invalid or corrupted tar file: $filename"
            ((failed_count++))
            continue
        fi
        
        # Attempt to import with detailed error reporting
        local load_output
        if load_output=$(docker load -i "$tar_file" 2>&1); then
            log_success "Imported $filename"
            ((imported_count++))
            
            # Extract and log the loaded image name for verification
            local loaded_image=$(echo "$load_output" | grep "Loaded image" | sed 's/Loaded image: //')
            if [[ -n "$loaded_image" ]]; then
                log_step "Loaded: $loaded_image"
            fi
        else
            log_error "Failed to import $filename"
            log_error "Docker load error: $load_output"
            ((failed_count++))
        fi
    done
    
    if [[ $failed_count -eq 0 ]] && [[ $imported_count -gt 0 ]]; then
        log_success "Image import completed successfully ($imported_count images)"
        return 0
    else
        log_error "Image import failed: $failed_count failures, $imported_count successful"
        return 1
    fi
}

# Deploy the stack
deploy_stack() {
    log_info "Deploying vAnalyzer stack..."
    
    # Validate prerequisites
    if ! validate_deployment_prerequisites; then
        return 1
    fi
    
    # Load environment configuration
    if ! load_env_configuration 2>/dev/null; then
        log_error "Configuration not found. Run 'vanalyzer init' first."
        return 1
    fi
    
    # Generate .env if needed
    if [[ ! -f "$ENV_FILE" ]]; then
        generate_env_file
    fi
    
    # Setup Docker secrets
    setup_secrets
    
    # Build or import images
    if [[ "$OFFLINE_MODE" == "true" ]]; then
        log_info "Offline mode detected - ensuring images are available..."
        
        # In offline mode, always import images to ensure they're available for deployment
        # This handles cases where images may have been removed or corrupted
        log_info "Importing images for offline deployment..."
        
        local import_success=false
        
        # Use docker-images.sh script as primary import method
        if [[ -x "${SCRIPT_DIR}/docker-images.sh" ]]; then
            log_step "Using docker-images.sh script for image import..."
            if "${SCRIPT_DIR}/docker-images.sh" import; then
                # Verify the script actually imported the required images
                local images_needed=("vrx-reports-app:1.4" "vrx-reports-appdb:1.4")
                local script_import_verified=true
                
                for image in "${images_needed[@]}"; do
                    if ! docker image inspect "$image" >/dev/null 2>&1; then
                        script_import_verified=false
                        break
                    fi
                done
                
                if [[ "$script_import_verified" == "true" ]]; then
                    import_success=true
                    log_success "docker-images.sh successfully imported required images"
                else
                    log_warning "docker-images.sh completed but required images still missing"
                fi
            else
                log_warning "docker-images.sh import failed, trying fallback methods..."
            fi
        fi
        
        # Fallback to offline module function if docker-images.sh failed
        if [[ "$import_success" != "true" ]] && type -t import_offline_images >/dev/null 2>&1; then
            log_step "Using offline module function as fallback..."
            if import_offline_images; then
                # Verify the offline function actually imported images
                local images_needed=("vrx-reports-app:1.4" "vrx-reports-appdb:1.4")
                local offline_import_verified=true
                
                for image in "${images_needed[@]}"; do
                    if ! docker image inspect "$image" >/dev/null 2>&1; then
                        offline_import_verified=false
                        break
                    fi
                done
                
                if [[ "$offline_import_verified" == "true" ]]; then
                    import_success=true
                    log_success "Offline module successfully imported required images"
                else
                    log_warning "Offline module completed but required images still missing"
                fi
            else
                log_warning "Offline module import function failed"
            fi
        fi
        
        # Final fallback to direct import if other methods failed
        if [[ "$import_success" != "true" ]]; then
            log_step "Using direct image import as final fallback..."
            if import_images_directly; then
                import_success=true
            fi
        fi
        
        # Verify all required images are now available
        if [[ "$import_success" == "true" ]]; then
            local images_needed=("vrx-reports-app:1.4" "vrx-reports-appdb:1.4" "traefik:latest" "metabase/metabase:v0.55.x")
            local verification_failed=false
            
            log_step "Verifying imported images..."
            for image in "${images_needed[@]}"; do
                if ! docker image inspect "$image" >/dev/null 2>&1; then
                    log_error "Required image not available after import: $image"
                    verification_failed=true
                fi
            done
            
            if [[ "$verification_failed" == "true" ]]; then
                log_error "Image import verification failed - some required images are missing"
                return 1
            else
                log_success "All required images verified and ready for deployment"
            fi
        else
            log_error "Failed to import Docker images - deployment cannot continue"
            return 1
        fi
    else
        log_info "Online mode - building images from source..."
        build_images
    fi
    
    # Remove existing stack if present
    local stack_name=$(get_stack_name)
    if docker stack ls | grep -q "$stack_name"; then
        log_step "Removing existing stack..."
        docker stack rm "$stack_name"
        sleep 15
        
        # Wait for networks to be cleaned up
        while docker network ls | grep -q "${stack_name}_"; do
            sleep 5
        done
    fi
    
    # Deploy new stack
    local compose_file="${SCRIPT_DIR}/docker-compose.unified.yml"
    
    if [[ ! -f "$compose_file" ]]; then
        log_error "Compose file not found: $compose_file"
        return 1
    fi
    
    # Create temporary compose file without registry service and with absolute paths
    local temp_compose="/tmp/docker-compose-deploy.yml"
    local current_dir="${SCRIPT_DIR}"
    
    awk -v current_dir="$current_dir" '
    /^  registry:/ { skip = 1; next }
    /^  [a-zA-Z]/ && skip { skip = 0 }
    !skip { 
        gsub(/source: \.\//, "source: " current_dir "/")
        print 
    }
    ' "$compose_file" > "$temp_compose"
    
    log_step "Deploying stack: $stack_name"
    
    # Load and validate environment variables
    local env_file_path="$(realpath "$ENV_FILE")"
    if [[ ! -f "$env_file_path" ]]; then
        log_error "Environment file not found: $env_file_path"
        return 1
    fi

    if [[ ! -r "$env_file_path" ]]; then
        log_error "Environment file not readable: $env_file_path"
        return 1
    fi

    log_step "Loading environment variables from: $env_file_path"
    set -a
    if ! source "$env_file_path"; then
        log_error "Failed to source environment file"
        return 1
    fi
    set +a

    # Verify critical variables were loaded
    local required_vars=("EXTERNAL_DATA_ENABLED" "EPSS_URL" "KEV_URL" "METABASE_HOST")
    for var in "${required_vars[@]}"; do
        if [[ -z "${!var:-}" ]]; then
            log_warning "Required variable not set: $var"
        else
            log_success "Loaded $var=${!var}"
        fi
    done
    
    if docker stack deploy --resolve-image never -c "$temp_compose" "$stack_name"; then
        rm -f "$temp_compose"
        log_success "Stack deployment initiated"
        
        # Wait for services
        if wait_for_services; then
            log_success "Deployment completed successfully!"
            show_deployment_success
            return 0
        else
            log_error "Some services failed to start"
            return 1
        fi
    else
        rm -f "$temp_compose"
        log_error "Stack deployment failed"
        return 1
    fi
}

# Validate deployment prerequisites
validate_deployment_prerequisites() {
    log_info "Validating deployment prerequisites..."
    
    local errors=0
    
    # Check Docker
    if ! check_runtime; then
        log_warning "Docker is not installed or not running"
        log_info "To install Docker, run: sudo ./vanalyzer install"
        ((errors++))
    fi
    
    # Check Swarm
    if ! check_swarm; then
        ((errors++))
    fi
    
    # Check compose file
    if [[ ! -f "${SCRIPT_DIR}/docker-compose.unified.yml" ]]; then
        log_error "Docker compose file not found"
        ((errors++))
    fi
    
    if [[ $errors -eq 0 ]]; then
        log_success "Prerequisites validation passed"
        return 0
    else
        log_error "Prerequisites validation failed"
        return 1
    fi
}

# Show deployment success message
show_deployment_success() {
    local hostname="${VANALYZER_HOSTNAME:-reports.local}"
    
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}          ${BOLD}Deployment Completed!${NC}             ${CYAN}║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BOLD}Access Information:${NC}"
    echo -e "  🌐 URL:       ${GREEN}https://$hostname${NC}"
    echo -e "  👤 Username:  ${GREEN}vrxadmin@vrxadmin.com${NC}"
    echo -e "  🔑 Password:  ${GREEN}Vicarius123!@#${NC}"
    echo ""
    echo -e "${BOLD}Next Steps:${NC}"
    echo -e "  1. Add to /etc/hosts: ${CYAN}echo '127.0.0.1 $hostname' | sudo tee -a /etc/hosts${NC}"
    echo -e "  2. Install CA certificate: ${CYAN}${SCRIPT_DIR}/traefik/config/certs/ca.crt${NC}"
    echo -e "  3. Change default Metabase password after first login"
    echo ""
    echo -e "${BOLD}Management Commands:${NC}"
    echo -e "  📊 Status:    ${CYAN}vanalyzer status${NC}"
    echo -e "  📝 Logs:      ${CYAN}vanalyzer logs <service>${NC}"
    echo -e "  🔄 Update:    ${CYAN}vanalyzer update${NC}"
    echo ""
}

# Update deployment
update_deployment() {
    log_info "Updating vAnalyzer deployment..."
    
    # Check current configuration
    if [[ -f "$CONFIG_FILE" ]]; then
        log_info "Using existing configuration"
        load_env_configuration
    elif [[ -f "$ENV_FILE" ]]; then
        log_warning "Found .env file but no vanalyzer.yaml"
        if confirm "Migrate from .env to vanalyzer.yaml?"; then
            migrate_from_env
        else
            log_info "Continuing with .env file"
        fi
    else
        log_error "No configuration found. Run 'vanalyzer init' first."
        return 1
    fi
    
    # Interactive update (if needed)
    if confirm "Update configuration interactively?" "n"; then
        interactive_config_update
    fi
    
    # Deploy
    deploy_stack
}

# Interactive configuration update
interactive_config_update() {
    log_info "Interactive configuration update"
    echo ""
    
    # Load current configuration
    load_configuration
    
    local current_hostname="${VANALYZER_HOSTNAME}"
    local new_hostname=""
    
    # Hostname
    echo -e "${BOLD}Hostname Configuration${NC}"
    echo "Current hostname: $current_hostname"
    read -p "Enter new hostname (press Enter to keep current): " new_hostname
    new_hostname="${new_hostname:-$current_hostname}"
    
    # Update configuration if hostname changed
    if [[ "$new_hostname" != "$current_hostname" ]]; then
        log_info "Updating hostname from $current_hostname to $new_hostname"
        
        # Update configuration file
        if [[ -f "$CONFIG_FILE" ]]; then
            sed -i "s/hostname: $current_hostname/hostname: $new_hostname/" "$CONFIG_FILE"
            load_env_configuration  # Reload
        fi
        
        # Generate new certificates
        "${SCRIPT_DIR}/generate-ssl-certs.sh" create-all "$new_hostname"
        
        # Update .env
        generate_env_file
    fi
    
    # API credentials
    if confirm "Update API credentials?" "n"; then
        local new_dashboard_id=""
        local new_api_key=""
        
        read -p "Enter Dashboard ID: " new_dashboard_id
        read -s -p "Enter API Key: " new_api_key
        echo ""
        
        # Update configuration
        if [[ -n "$new_dashboard_id" ]] && [[ -n "$new_api_key" ]]; then
            if [[ -f "$CONFIG_FILE" ]]; then
                sed -i "s/dashboard_id: .*/dashboard_id: $new_dashboard_id/" "$CONFIG_FILE"
                sed -i "s/api_key: .*/api_key: $(encrypt_value "$new_api_key")/" "$CONFIG_FILE"
                load_env_configuration  # Reload
            fi
        fi
    fi
    
    log_success "Configuration update completed"
}

# Show deployment status
show_status() {
    local stack_name=$(get_stack_name)
    
    echo ""
    echo -e "${CYAN}╔════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}          ${BOLD}vAnalyzer Status${NC}                  ${CYAN}║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════╝${NC}"
    
    # Check if stack exists
    if ! docker stack ls | grep -q "$stack_name"; then
        echo ""
        echo -e "${YELLOW}⚠ Stack '$stack_name' is not deployed${NC}"
        echo ""
        echo "Run 'vanalyzer deploy' to deploy the stack"
        return 1
    fi
    
    echo ""
    show_service_status
    
    echo ""
    echo -e "${BOLD}Stack Information:${NC}"
    docker stack ps "$stack_name" --format "table {{.Name}}\t{{.CurrentState}}\t{{.Error}}" | head -10
    
    echo ""
    echo -e "${BOLD}Network Information:${NC}"
    docker network ls --filter "name=${stack_name}" --format "table {{.Name}}\t{{.Driver}}\t{{.Scope}}"
    
    echo ""
    echo -e "${BOLD}Volume Information:${NC}"
    docker volume ls --filter "name=${stack_name}" --format "table {{.Name}}\t{{.Driver}}"
}

# Show service logs
show_logs() {
    local service="${1:-}"
    local stack_name=$(get_stack_name)
    
    if [[ -z "$service" ]]; then
        echo "Usage: vanalyzer logs <service>"
        echo ""
        echo "Available services:"
        docker service ls --filter "name=${stack_name}" --format "{{.Name}}" | sed "s/${stack_name}_/  /"
        return 1
    fi
    
    local service_name="${stack_name}_${service}"
    
    if docker service ls --filter "name=${service_name}" --format "{{.Name}}" | grep -q "$service_name"; then
        echo -e "${CYAN}Logs for ${service_name}:${NC}"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        docker service logs -f --tail 100 "$service_name"
    else
        log_error "Service '$service' not found"
        return 1
    fi
}

# Check health of all services
check_health() {
    local stack_name=$(get_stack_name)
    
    echo ""
    echo -e "${BOLD}Health Check Results:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    local services=("app" "appdb" "traefik" "metabase")
    local failed_services=()
    
    for service in "${services[@]}"; do
        local service_name="${stack_name}_${service}"
        
        if docker service ps "$service_name" --format "{{.CurrentState}}" 2>/dev/null | grep -q "Running"; then
            echo -e "  ${GREEN}✓${NC} $service is running"
        else
            echo -e "  ${RED}✗${NC} $service is not running"
            failed_services+=("$service")
        fi
    done
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    if [[ ${#failed_services[@]} -eq 0 ]]; then
        echo -e "${GREEN}✓ All health checks passed${NC}"
        return 0
    else
        echo -e "${RED}✗ Failed services: ${failed_services[*]}${NC}"
        echo ""
        echo "Run 'vanalyzer logs <service>' to view logs for failed services"
        return 1
    fi
}

# Export Docker functions
export -f install_runtime install_docker_ubuntu install_docker_rhel remove_podman_cleanly configure_docker
export -f setup_secrets check_and_stop_services create_secret
export -f build_images import_images_directly deploy_stack validate_deployment_prerequisites show_deployment_success
export -f update_deployment interactive_config_update
export -f show_status show_logs check_health