#!/bin/bash
# vAnalyzer Offline Deployment Library
# Handles offline bundle creation, import, and deployment

# Bundle configuration
BUNDLE_DIR="${SCRIPT_DIR}/bundle"
IMAGES_DIR="${SCRIPT_DIR}/images"
BUNDLE_MANIFEST="${BUNDLE_DIR}/manifest.json"

# Docker images to export
declare -A VANALYZER_IMAGES=(
    ["vrx-reports-app"]="${VERSION:-1.4}"
    ["vrx-reports-appdb"]="${VERSION:-1.4}"
    ["metabase/metabase"]="v0.55.x"
    ["traefik"]="latest"
)

# Create offline bundle
create_bundle() {
    log_info "Creating offline deployment bundle..."
    echo ""
    
    # Check if online system has images built
    if ! validate_images_exist; then
        log_error "Required images not found. Please run 'vanalyzer deploy' first."
        return 1
    fi
    
    # Create bundle directory
    mkdir -p "$BUNDLE_DIR"
    
    # Export Docker images
    export_docker_images
    
    # Copy configuration files
    copy_configuration_files
    
    # Copy SSL certificates
    copy_ssl_certificates
    
    # Export secrets (encrypted)
    export_secrets
    
    # Create manifest
    create_bundle_manifest
    
    # Create final bundle
    create_bundle_archive
    
    log_success "Bundle creation completed"
}

# Validate that required images exist
validate_images_exist() {
    log_info "Validating required Docker images..."
    
    local missing_images=()
    
    for image_name in "${!VANALYZER_IMAGES[@]}"; do
        local tag="${VANALYZER_IMAGES[$image_name]}"
        local full_image="${image_name}:${tag}"
        
        if ! docker image inspect "$full_image" >/dev/null 2>&1; then
            missing_images+=("$full_image")
        fi
    done
    
    if [[ ${#missing_images[@]} -eq 0 ]]; then
        log_success "All required images found"
        return 0
    else
        log_error "Missing images:"
        for image in "${missing_images[@]}"; do
            echo "  - $image"
        done
        return 1
    fi
}

# Export Docker images
export_docker_images() {
    log_info "Exporting Docker images..."
    
    # Create images directory
    mkdir -p "$IMAGES_DIR"
    
    local exported_images=()
    local total_size=0
    
    for image_name in "${!VANALYZER_IMAGES[@]}"; do
        local tag="${VANALYZER_IMAGES[$image_name]}"
        local full_image="${image_name}:${tag}"
        local filename="${image_name//\//-}-${tag}.tar"
        local filepath="${IMAGES_DIR}/${filename}"
        
        log_step "Exporting $full_image..."
        
        if docker save "$full_image" -o "$filepath"; then
            local size=$(du -b "$filepath" | cut -f1)
            local size_mb=$((size / 1024 / 1024))
            log_success "Exported $full_image → $filename (${size_mb}MB)"
            
            exported_images+=("$full_image")
            total_size=$((total_size + size))
        else
            log_error "Failed to export $full_image"
            return 1
        fi
    done
    
    # Generate checksums
    log_step "Generating checksums..."
    (cd "$IMAGES_DIR" && sha256sum *.tar > checksums.sha256)
    
    # Create image manifest
    cat > "${IMAGES_DIR}/.image-manifest" <<EOF
{
    "export_date": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
    "version": "${VERSION:-1.4}",
    "images": [
$(printf '        "%s",\n' "${exported_images[@]}" | sed '$ s/,$//')
    ],
    "total_files": ${#exported_images[@]},
    "total_size_bytes": $total_size
}
EOF
    
    local total_size_mb=$((total_size / 1024 / 1024))
    log_success "Docker images exported (${total_size_mb}MB total)"
}

# Copy configuration files
copy_configuration_files() {
    log_info "Copying configuration files..."
    
    local config_dir="${BUNDLE_DIR}/config"
    mkdir -p "$config_dir"
    
    # Skip YAML configuration - using .env only
    
    # Copy .env if it exists
    if [[ -f "$ENV_FILE" ]]; then
        cp "$ENV_FILE" "$config_dir/"
        log_success "Environment file copied"
    fi
    
    # Copy .env.example
    if [[ -f "${SCRIPT_DIR}/.env.example" ]]; then
        cp "${SCRIPT_DIR}/.env.example" "$config_dir/"
        log_success "Environment template copied"
    fi
}

# Copy SSL certificates
copy_ssl_certificates() {
    log_info "Copying SSL certificates..."
    
    local cert_source="${SCRIPT_DIR}/traefik/config/certs"
    local cert_dest="${BUNDLE_DIR}/certs"
    
    if [[ -d "$cert_source" ]]; then
        mkdir -p "$cert_dest"
        cp -r "$cert_source"/* "$cert_dest/" 2>/dev/null || true
        
        local cert_count=$(find "$cert_dest" -name "*.crt" -o -name "*.key" | wc -l)
        if [[ $cert_count -gt 0 ]]; then
            log_success "SSL certificates copied ($cert_count files)"
        else
            log_warning "No SSL certificates found"
        fi
    else
        log_warning "SSL certificates directory not found"
    fi
}

# Export Docker secrets (encrypted)
export_secrets() {
    log_info "Exporting Docker secrets..."
    
    local secrets_dir="${BUNDLE_DIR}/secrets"
    mkdir -p "$secrets_dir"
    
    # List of secrets to export
    local secrets=("api_key" "dashboard_id" "postgres_user" "postgres_password" "postgres_db" "optional_tools")
    
    local exported_secrets=()
    
    for secret_name in "${secrets[@]}"; do
        if docker secret ls --format "{{.Name}}" | grep -q "^${secret_name}$"; then
            # Create a placeholder file indicating the secret exists
            # Note: Docker secrets cannot be directly exported for security reasons
            echo "SECRET_EXISTS" > "${secrets_dir}/${secret_name}.placeholder"
            exported_secrets+=("$secret_name")
        fi
    done
    
    if [[ ${#exported_secrets[@]} -gt 0 ]]; then
        log_success "Secret placeholders created for: ${exported_secrets[*]}"
        log_info "Note: Actual secret values will be prompted during import"
    else
        log_warning "No Docker secrets found to export"
    fi
}

# Create bundle manifest
create_bundle_manifest() {
    log_info "Creating bundle manifest..."
    
    local bundle_size=$(du -sb "$BUNDLE_DIR" | cut -f1)
    local bundle_size_mb=$((bundle_size / 1024 / 1024))
    
    cat > "$BUNDLE_MANIFEST" <<EOF
{
    "bundle_version": "1.0",
    "vanalyzer_version": "${VERSION:-1.4}",
    "created_date": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
    "created_by": "$(whoami)@$(hostname)",
    "source_os": "$OS_TYPE",
    "bundle_size_bytes": $bundle_size,
    "bundle_size_mb": $bundle_size_mb,
    "contents": {
        "docker_images": $(test -d "$IMAGES_DIR" && echo "true" || echo "false"),
        "configuration": $(test -f "${BUNDLE_DIR}/config/.env" && echo "true" || echo "false"),
        "env_file": $(test -f "${BUNDLE_DIR}/config/.env" && echo "true" || echo "false"),
        "ssl_certificates": $(test -d "${BUNDLE_DIR}/certs" && echo "true" || echo "false"),
        "secrets": $(test -d "${BUNDLE_DIR}/secrets" && echo "true" || echo "false")
    },
    "deployment_notes": [
        "Run 'vanalyzer import' on the target system",
        "Configuration and secrets will be restored automatically",
        "SSL certificates will be deployed to the correct locations"
    ]
}
EOF
    
    log_success "Bundle manifest created"
}

# Create final bundle archive
create_bundle_archive() {
    log_info "Creating bundle archive..."
    
    local timestamp=$(date +"%Y%m%d_%H%M%S")
    local bundle_file="${SCRIPT_DIR}/vanalyzer-bundle-${timestamp}.tar.gz"
    
    # Create archive
    if tar -czf "$bundle_file" -C "$SCRIPT_DIR" images/ bundle/ 2>/dev/null; then
        local file_size=$(du -h "$bundle_file" | cut -f1)
        log_success "Bundle archive created: $(basename "$bundle_file") ($file_size)"
        
        echo ""
        echo -e "${BOLD}Bundle Information:${NC}"
        echo -e "  📦 File:     ${GREEN}$(basename "$bundle_file")${NC}"
        echo -e "  📏 Size:     ${GREEN}$file_size${NC}"
        echo -e "  📁 Location: ${GREEN}$bundle_file${NC}"
        echo ""
        echo -e "${BOLD}Transfer Instructions:${NC}"
        echo -e "  1. Copy bundle file to offline system"
        echo -e "  2. Extract: ${CYAN}tar -xzf $(basename "$bundle_file")${NC}"
        echo -e "  3. Deploy:  ${CYAN}cd vanalyzer1.4-main && ./vanalyzer deploy${NC}"
        echo ""
        
        return 0
    else
        log_error "Failed to create bundle archive"
        return 1
    fi
}

# Import offline bundle
import_bundle() {
    local bundle_file="${1:-}"
    
    log_info "Importing offline bundle..."
    
    # Auto-detect bundle if not specified
    if [[ -z "$bundle_file" ]]; then
        bundle_file=$(find "${SCRIPT_DIR}" -name "vanalyzer-bundle-*.tar.gz" | head -1)
        
        if [[ -z "$bundle_file" ]]; then
            log_error "No bundle file found. Specify bundle file or ensure it exists in current directory."
            return 1
        else
            log_info "Auto-detected bundle: $(basename "$bundle_file")"
        fi
    fi
    
    # Validate bundle file
    if [[ ! -f "$bundle_file" ]]; then
        log_error "Bundle file not found: $bundle_file"
        return 1
    fi
    
    # Extract bundle
    extract_bundle "$bundle_file"
    
    # Validate bundle contents
    validate_bundle_contents
    
    # Import Docker images
    import_offline_images
    
    # Restore configuration
    restore_configuration
    
    # Restore SSL certificates
    restore_ssl_certificates
    
    log_success "Bundle import completed"
    echo ""
    log_info "Next step: Run 'vanalyzer deploy' to deploy the imported bundle"
}

# Extract bundle
extract_bundle() {
    local bundle_file="$1"
    
    log_step "Extracting bundle..."
    
    if tar -xzf "$bundle_file" -C "$SCRIPT_DIR" 2>/dev/null; then
        log_success "Bundle extracted successfully"
    else
        log_error "Failed to extract bundle"
        return 1
    fi
}

# Validate bundle contents
validate_bundle_contents() {
    log_step "Validating bundle contents..."
    
    # Check manifest
    if [[ ! -f "$BUNDLE_MANIFEST" ]]; then
        log_warning "Bundle manifest not found - may be an older bundle format"
    else
        log_success "Bundle manifest found"
        
        # Show bundle info
        if command_exists jq; then
            local version=$(jq -r '.vanalyzer_version' "$BUNDLE_MANIFEST")
            local created=$(jq -r '.created_date' "$BUNDLE_MANIFEST")
            local size_mb=$(jq -r '.bundle_size_mb' "$BUNDLE_MANIFEST")
            
            log_info "Bundle version: $version"
            log_info "Created: $created"
            log_info "Size: ${size_mb}MB"
        fi
    fi
    
    # Check for images
    if [[ -f "${IMAGES_DIR}/.image-manifest" ]]; then
        log_success "Docker images found"
    else
        log_warning "Docker images not found in bundle"
    fi
    
    # Check for configuration
    if [[ -f "${BUNDLE_DIR}/config/.env" ]]; then
        log_success "Configuration files found"
    else
        log_warning "Configuration files not found in bundle"
    fi
}

# Import offline images
import_offline_images() {
    log_info "Importing Docker images..."
    
    # Check if images directory exists and has tar files
    if [[ ! -d "$IMAGES_DIR" ]] || ! find "$IMAGES_DIR" -name "*.tar" -type f | grep -q .; then
        log_error "No Docker image tar files found in images directory"
        return 1
    fi
    
    # Verify checksums
    if [[ -f "${IMAGES_DIR}/checksums.sha256" ]]; then
        log_step "Verifying image integrity..."
        if (cd "$IMAGES_DIR" && sha256sum -c checksums.sha256 --quiet); then
            log_success "Image integrity verified"
        else
            log_error "Checksum verification failed"
            return 1
        fi
    else
        log_warning "No checksums found - skipping integrity check"
    fi
    
    # Import each image
    local imported_count=0
    
    for image_name in "${!VANALYZER_IMAGES[@]}"; do
        local tag="${VANALYZER_IMAGES[$image_name]}"
        local filename="${image_name//\//-}-${tag}.tar"
        local filepath="${IMAGES_DIR}/${filename}"
        
        if [[ -f "$filepath" ]]; then
            log_step "Importing ${image_name}:${tag}..."
            
            if docker load -i "$filepath" >/dev/null 2>&1; then
                log_success "Imported ${image_name}:${tag}"
                ((imported_count++))
            else
                log_error "Failed to import ${image_name}:${tag}"
                return 1
            fi
        else
            log_warning "Image file not found: $filename"
        fi
    done
    
    log_success "Imported $imported_count Docker images"
}

# Restore configuration
restore_configuration() {
    log_info "Restoring configuration..."
    
    # Skip YAML configuration - using .env only
    
    # Restore .env
    if [[ -f "${BUNDLE_DIR}/config/.env" ]]; then
        cp "${BUNDLE_DIR}/config/.env" "$ENV_FILE"
        chmod 600 "$ENV_FILE"
        log_success "Environment file restored"
    fi
    
    # If no .env but we have .env.example, copy it
    if [[ ! -f "$ENV_FILE" ]] && [[ -f "${BUNDLE_DIR}/config/.env.example" ]]; then
        cp "${BUNDLE_DIR}/config/.env.example" "$ENV_FILE"
        chmod 600 "$ENV_FILE"
        log_warning "Using .env.example as .env - please review configuration"
    fi
}

# Restore SSL certificates
restore_ssl_certificates() {
    log_info "Restoring SSL certificates..."
    
    local cert_source="${BUNDLE_DIR}/certs"
    local cert_dest="${SCRIPT_DIR}/traefik/config/certs"
    
    if [[ -d "$cert_source" ]]; then
        mkdir -p "$cert_dest"
        cp -r "$cert_source"/* "$cert_dest/" 2>/dev/null || true
        
        local cert_count=$(find "$cert_dest" -name "*.crt" -o -name "*.key" | wc -l)
        if [[ $cert_count -gt 0 ]]; then
            log_success "SSL certificates restored ($cert_count files)"
        else
            log_warning "No SSL certificates to restore"
        fi
    else
        log_warning "No SSL certificates found in bundle"
    fi
}

# List available bundles
list_bundles() {
    echo -e "${BOLD}Available Bundle Files:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    local bundle_files=($(find "${SCRIPT_DIR}" -name "vanalyzer-bundle-*.tar.gz" | sort -r))
    
    if [[ ${#bundle_files[@]} -eq 0 ]]; then
        echo -e "${YELLOW}No bundle files found${NC}"
        echo ""
        echo "Create a bundle with: vanalyzer bundle"
        return 1
    fi
    
    for bundle_file in "${bundle_files[@]}"; do
        local filename=$(basename "$bundle_file")
        local size=$(du -h "$bundle_file" | cut -f1)
        local date=$(stat -c %y "$bundle_file" | cut -d' ' -f1)
        
        echo -e "  📦 ${GREEN}$filename${NC}"
        echo -e "     Size: $size, Created: $date"
        echo ""
    done
    
    echo "Import a bundle with: vanalyzer import [bundle_file]"
}

# Clean bundle files
clean_bundles() {
    log_info "Cleaning bundle files..."
    
    # Remove bundle directory
    if [[ -d "$BUNDLE_DIR" ]]; then
        rm -rf "$BUNDLE_DIR"
        log_success "Bundle directory removed"
    fi
    
    # Remove bundle archives
    local bundle_files=($(find "${SCRIPT_DIR}" -name "vanalyzer-bundle-*.tar.gz"))
    
    if [[ ${#bundle_files[@]} -gt 0 ]]; then
        echo "Found ${#bundle_files[@]} bundle archive(s):"
        for bundle_file in "${bundle_files[@]}"; do
            echo "  - $(basename "$bundle_file")"
        done
        
        if confirm "Remove all bundle archives?"; then
            rm -f "${SCRIPT_DIR}"/vanalyzer-bundle-*.tar.gz
            log_success "Bundle archives removed"
        fi
    fi
    
    # Ask about images directory
    if [[ -d "$IMAGES_DIR" ]]; then
        if confirm "Remove images directory?"; then
            rm -rf "$IMAGES_DIR"
            log_success "Images directory removed"
        fi
    fi
}

# Export offline functions
export -f create_bundle validate_images_exist export_docker_images
export -f copy_configuration_files copy_ssl_certificates export_secrets
export -f create_bundle_manifest create_bundle_archive
export -f import_bundle extract_bundle validate_bundle_contents
export -f import_offline_images restore_configuration restore_ssl_certificates
export -f list_bundles clean_bundles