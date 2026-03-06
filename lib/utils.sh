#!/bin/bash
# vAnalyzer Utilities Library
# Additional utilities and certificate management

# Certificate management functions
manage_certificates() {
    local action="${1:-generate}"
    local hostname="${2:-}"
    
    case "$action" in
        generate|create|create-all)
            generate_certificates "$hostname"
            ;;
        list)
            list_certificates
            ;;
        info)
            show_certificate_info "$hostname"
            ;;
        clean)
            clean_certificates
            ;;
        verify)
            verify_certificates "$hostname"
            ;;
        *)
            show_cert_help
            ;;
    esac
}

# Generate certificates
generate_certificates() {
    local hostname="$1"
    
    if [[ -z "$hostname" ]]; then
        # Try to get hostname from configuration
        if [[ -f "$CONFIG_FILE" ]]; then
            hostname=$(grep "hostname:" "$CONFIG_FILE" | awk '{print $2}')
        fi
        
        if [[ -z "$hostname" ]]; then
            log_error "Hostname required for certificate generation"
            echo "Usage: vanalyzer certs generate <hostname>"
            return 1
        fi
    fi
    
    log_info "Generating SSL certificates for: $hostname"
    
    # Use existing generate-ssl-certs.sh if available
    if [[ -f "${SCRIPT_DIR}/generate-ssl-certs.sh" ]]; then
        "${SCRIPT_DIR}/generate-ssl-certs.sh" create-all "$hostname"
    else
        log_error "SSL certificate generation script not found"
        return 1
    fi
}

# List certificates
list_certificates() {
    local cert_dir="${SCRIPT_DIR}/traefik/config/certs"
    
    echo -e "${BOLD}SSL Certificates:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    if [[ ! -d "$cert_dir" ]]; then
        echo -e "${YELLOW}Certificate directory not found${NC}"
        return 1
    fi
    
    local certs=($(find "$cert_dir" -name "*.crt" | sort))
    
    if [[ ${#certs[@]} -eq 0 ]]; then
        echo -e "${YELLOW}No certificates found${NC}"
        return 1
    fi
    
    for cert_file in "${certs[@]}"; do
        local filename=$(basename "$cert_file")
        local hostname="${filename%.crt}"
        
        if [[ "$filename" != "ca.crt" ]]; then
            local expiry=$(openssl x509 -in "$cert_file" -noout -enddate 2>/dev/null | cut -d= -f2)
            local days_left=""
            
            if [[ -n "$expiry" ]]; then
                local expiry_epoch=$(date -d "$expiry" +%s 2>/dev/null)
                local now_epoch=$(date +%s)
                local days_left=$(( (expiry_epoch - now_epoch) / 86400 ))
                
                if [[ $days_left -lt 30 ]]; then
                    local status="${RED}Expires soon ($days_left days)${NC}"
                elif [[ $days_left -lt 0 ]]; then
                    local status="${RED}Expired${NC}"
                else
                    local status="${GREEN}Valid ($days_left days)${NC}"
                fi
            else
                local status="${YELLOW}Unknown${NC}"
            fi
            
            echo -e "  🔐 ${CYAN}$hostname${NC}"
            echo -e "     Status: $status"
            echo -e "     Files:  $cert_file, ${cert_file%.crt}.key"
            echo ""
        fi
    done
    
    # Show CA certificate
    if [[ -f "$cert_dir/ca.crt" ]]; then
        echo -e "  📋 ${MAGENTA}Certificate Authority${NC}"
        echo -e "     File: $cert_dir/ca.crt"
        echo ""
    fi
}

# Show certificate information
show_certificate_info() {
    local hostname="$1"
    local cert_dir="${SCRIPT_DIR}/traefik/config/certs"
    
    if [[ -z "$hostname" ]]; then
        log_error "Hostname required"
        echo "Usage: vanalyzer certs info <hostname>"
        return 1
    fi
    
    local cert_file="$cert_dir/${hostname}.crt"
    local key_file="$cert_dir/${hostname}.key"
    
    if [[ ! -f "$cert_file" ]]; then
        log_error "Certificate not found: $cert_file"
        return 1
    fi
    
    echo -e "${BOLD}Certificate Information for $hostname:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Basic info
    openssl x509 -in "$cert_file" -noout -text | grep -A1 "Subject:"
    openssl x509 -in "$cert_file" -noout -text | grep -A1 "Issuer:"
    openssl x509 -in "$cert_file" -noout -dates
    
    echo ""
    
    # Subject Alternative Names
    local sans=$(openssl x509 -in "$cert_file" -noout -text | grep -A1 "Subject Alternative Name" | tail -1 | sed 's/^ *//')
    if [[ -n "$sans" ]]; then
        echo "Subject Alternative Names: $sans"
    fi
    
    echo ""
    
    # File status
    echo "Files:"
    if [[ -f "$cert_file" ]]; then
        local cert_size=$(du -h "$cert_file" | cut -f1)
        echo -e "  Certificate: ${GREEN}✓${NC} $cert_file ($cert_size)"
    else
        echo -e "  Certificate: ${RED}✗${NC} Not found"
    fi
    
    if [[ -f "$key_file" ]]; then
        local key_size=$(du -h "$key_file" | cut -f1)
        echo -e "  Private Key: ${GREEN}✓${NC} $key_file ($key_size)"
    else
        echo -e "  Private Key: ${RED}✗${NC} Not found"
    fi
}

# Verify certificates
verify_certificates() {
    local hostname="$1"
    local cert_dir="${SCRIPT_DIR}/traefik/config/certs"
    
    if [[ -n "$hostname" ]]; then
        # Verify specific certificate
        verify_single_certificate "$hostname"
    else
        # Verify all certificates
        log_info "Verifying all certificates..."
        
        local certs=($(find "$cert_dir" -name "*.crt" | grep -v ca.crt | sort))
        local errors=0
        
        for cert_file in "${certs[@]}"; do
            local filename=$(basename "$cert_file")
            local hostname="${filename%.crt}"
            
            if ! verify_single_certificate "$hostname" >/dev/null 2>&1; then
                ((errors++))
            fi
        done
        
        if [[ $errors -eq 0 ]]; then
            log_success "All certificates verified successfully"
        else
            log_error "$errors certificate(s) failed verification"
        fi
    fi
}

# Verify single certificate
verify_single_certificate() {
    local hostname="$1"
    local cert_dir="${SCRIPT_DIR}/traefik/config/certs"
    local cert_file="$cert_dir/${hostname}.crt"
    local key_file="$cert_dir/${hostname}.key"
    
    if [[ ! -f "$cert_file" ]] || [[ ! -f "$key_file" ]]; then
        echo -e "  ${RED}✗${NC} $hostname - Missing files"
        return 1
    fi
    
    # Verify certificate and key match
    local cert_hash=$(openssl x509 -noout -modulus -in "$cert_file" | openssl md5)
    local key_hash=$(openssl rsa -noout -modulus -in "$key_file" 2>/dev/null | openssl md5)
    
    if [[ "$cert_hash" == "$key_hash" ]]; then
        # Check expiration
        local expiry=$(openssl x509 -in "$cert_file" -noout -enddate | cut -d= -f2)
        local expiry_epoch=$(date -d "$expiry" +%s 2>/dev/null)
        local now_epoch=$(date +%s)
        
        if [[ $expiry_epoch -gt $now_epoch ]]; then
            echo -e "  ${GREEN}✓${NC} $hostname - Valid"
            return 0
        else
            echo -e "  ${RED}✗${NC} $hostname - Expired"
            return 1
        fi
    else
        echo -e "  ${RED}✗${NC} $hostname - Certificate/key mismatch"
        return 1
    fi
}

# Clean certificates
clean_certificates() {
    local cert_dir="${SCRIPT_DIR}/traefik/config/certs"
    
    if [[ ! -d "$cert_dir" ]]; then
        log_info "No certificates directory found"
        return 0
    fi
    
    log_warning "This will remove ALL SSL certificates!"
    
    if confirm "Continue with certificate cleanup?" "n"; then
        rm -f "$cert_dir"/*.crt "$cert_dir"/*.key "$cert_dir"/*.srl 2>/dev/null || true
        log_success "SSL certificates removed"
        log_info "Run 'vanalyzer certs generate <hostname>' to create new certificates"
    else
        log_info "Certificate cleanup cancelled"
    fi
}

# Show certificate help
show_cert_help() {
    echo "Certificate Management Commands:"
    echo "  generate <hostname>  - Generate SSL certificates"
    echo "  list                 - List all certificates"
    echo "  info <hostname>      - Show certificate details"
    echo "  verify [hostname]    - Verify certificates"
    echo "  clean                - Remove all certificates"
    echo ""
    echo "Examples:"
    echo "  vanalyzer certs generate reports.company.com"
    echo "  vanalyzer certs list"
    echo "  vanalyzer certs info reports.company.com"
}

# System information
show_system_info() {
    echo -e "${BOLD}System Information:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # OS Information
    if [[ -f /etc/os-release ]]; then
        local os_name=$(grep "^NAME=" /etc/os-release | cut -d'"' -f2)
        local os_version=$(grep "^VERSION=" /etc/os-release | cut -d'"' -f2)
        echo -e "  OS:          ${GREEN}$os_name $os_version${NC}"
    fi
    
    echo -e "  Kernel:      ${GREEN}$(uname -r)${NC}"
    echo -e "  Architecture:${GREEN}$(uname -m)${NC}"
    
    # Memory
    local memory_info=$(free -h | grep "^Mem:")
    local total_mem=$(echo "$memory_info" | awk '{print $2}')
    local used_mem=$(echo "$memory_info" | awk '{print $3}')
    local avail_mem=$(echo "$memory_info" | awk '{print $7}')
    echo -e "  Memory:      ${GREEN}$used_mem / $total_mem${NC} (${avail_mem} available)"
    
    # Disk space
    local disk_info=$(df -h / | tail -1)
    local disk_used=$(echo "$disk_info" | awk '{print $3}')
    local disk_total=$(echo "$disk_info" | awk '{print $2}')
    local disk_avail=$(echo "$disk_info" | awk '{print $4}')
    echo -e "  Disk (root): ${GREEN}$disk_used / $disk_total${NC} ($disk_avail available)"
    
    echo ""
    
    # Container Runtime
    echo -e "${BOLD}Container Runtime:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    if [[ "$RUNTIME" != "none" ]]; then
        echo -e "  Runtime:     ${GREEN}$RUNTIME${NC}"
        echo -e "  Version:     ${GREEN}$RUNTIME_VERSION${NC}"
        
        # Docker info
        if [[ "$RUNTIME" == "docker" ]]; then
            if docker info >/dev/null 2>&1; then
                local swarm_status=$(docker info | grep "Swarm:" | awk '{print $2}')
                echo -e "  Swarm Mode:  ${GREEN}$swarm_status${NC}"
                
                local containers=$(docker ps -q | wc -l)
                echo -e "  Containers:  ${GREEN}$containers running${NC}"
                
                local images=$(docker images -q | wc -l)
                echo -e "  Images:      ${GREEN}$images total${NC}"
            else
                echo -e "  Status:      ${RED}Not running${NC}"
            fi
        fi
    else
        echo -e "  Runtime:     ${RED}Not installed${NC}"
    fi
}

# Performance monitoring
show_performance() {
    echo -e "${BOLD}Performance Metrics:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # System load
    local load_avg=$(uptime | awk -F'load average:' '{print $2}')
    echo -e "  Load Average:$load_avg"
    
    # CPU usage
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    echo -e "  CPU Usage:   ${GREEN}${cpu_usage}%${NC}"
    
    echo ""
    
    # Docker stats if available
    if [[ "$RUNTIME" == "docker" ]] && docker info >/dev/null 2>&1; then
        local stack_name=$(get_stack_name)
        
        if docker stack ls | grep -q "$stack_name"; then
            echo -e "${BOLD}Service Resource Usage:${NC}"
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            
            # Get service containers
            local containers=$(docker ps --filter "name=${stack_name}" --format "{{.Names}}" | sort)
            
            if [[ -n "$containers" ]]; then
                docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}" $containers
            else
                echo -e "${YELLOW}No running containers found${NC}"
            fi
        fi
    fi
}

# Network diagnostics
check_network() {
    echo -e "${BOLD}Network Diagnostics:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Check DNS
    echo -e "  DNS Resolution:"
    if nslookup google.com >/dev/null 2>&1; then
        echo -e "    ${GREEN}✓${NC} DNS working"
    else
        echo -e "    ${RED}✗${NC} DNS resolution failed"
    fi
    
    # Check internet connectivity
    echo -e "  Internet Access:"
    if curl -s --head --max-time 5 https://google.com >/dev/null 2>&1; then
        echo -e "    ${GREEN}✓${NC} Internet accessible"
    else
        echo -e "    ${RED}✗${NC} No internet access"
    fi
    
    # Check ports
    echo -e "  Port Status:"
    local ports=("80:HTTP" "443:HTTPS" "8080:Traefik Dashboard")
    
    for port_info in "${ports[@]}"; do
        local port=$(echo "$port_info" | cut -d':' -f1)
        local service=$(echo "$port_info" | cut -d':' -f2)
        
        if netstat -tlnp 2>/dev/null | grep -q ":$port "; then
            echo -e "    ${GREEN}✓${NC} Port $port ($service) - In use"
        else
            echo -e "    ${YELLOW}○${NC} Port $port ($service) - Available"
        fi
    done
    
    # Docker networks
    if [[ "$RUNTIME" == "docker" ]] && docker info >/dev/null 2>&1; then
        echo ""
        echo -e "${BOLD}Docker Networks:${NC}"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        
        docker network ls --format "table {{.Name}}\t{{.Driver}}\t{{.Scope}}" | grep -E "(bridge|overlay|$(get_stack_name))"
    fi
}

# File permissions check
check_permissions() {
    echo -e "${BOLD}File Permissions:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    local files_to_check=(
        "$CONFIG_FILE:Configuration"
        "$ENV_FILE:Environment"
        "${SCRIPT_DIR}/traefik/config/certs:Certificates"
        "${SCRIPT_DIR}/vanalyzer:Main script"
    )
    
    for file_info in "${files_to_check[@]}"; do
        local file_path=$(echo "$file_info" | cut -d':' -f1)
        local description=$(echo "$file_info" | cut -d':' -f2)
        
        if [[ -e "$file_path" ]]; then
            local perms=$(ls -ld "$file_path" | awk '{print $1}')
            local owner=$(ls -ld "$file_path" | awk '{print $3}')
            echo -e "  ${GREEN}✓${NC} $description: $perms ($owner)"
        else
            echo -e "  ${YELLOW}○${NC} $description: Not found"
        fi
    done
}

# Export utility functions
export -f manage_certificates generate_certificates list_certificates
export -f show_certificate_info verify_certificates verify_single_certificate
export -f clean_certificates show_cert_help
export -f show_system_info show_performance check_network check_permissions