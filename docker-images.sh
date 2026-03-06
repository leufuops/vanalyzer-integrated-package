#!/bin/bash
set -euo pipefail

# vAnalyzer Docker Images Export/Import Script
# Handles offline deployment scenarios

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGES_DIR="${SCRIPT_DIR}/images"
VERSION_FILE="${SCRIPT_DIR}/Version"
MANIFEST_FILE="${IMAGES_DIR}/.image-manifest"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

log_success() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] ✓ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] ⚠ $1${NC}"
}

log_error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ✗ $1${NC}"
}

# Get version from Version file
get_version() {
    if [[ -f "$VERSION_FILE" ]]; then
        cat "$VERSION_FILE" | tr -d '\n'
    else
        echo "1.4"
    fi
}

VERSION=$(get_version)

# Define image names and tags
declare -A IMAGES=(
    ["vrx-reports-app"]="$VERSION"
    ["vrx-reports-appdb"]="$VERSION"
    ["metabase/metabase"]="v0.55.x"
    ["traefik"]="latest"
)

show_usage() {
    echo "vAnalyzer Docker Images Management Script"
    echo "Usage: $0 {export|import|list|clean|help}"
    echo ""
    echo "COMMANDS:"
    echo "  export    - Export all Docker images to ./images/ directory"
    echo "  import    - Import Docker images from ./images/ directory"
    echo "  list      - List available offline images"
    echo "  clean     - Remove ./images/ directory and all exported images"
    echo "  help      - Show this help message"
    echo ""
    echo "WORKFLOW:"
    echo "  Online system:  $0 export"
    echo "  Transfer:       Copy ./images/ folder to offline system"
    echo "  Offline system: $0 import  (or just run ./vanalyzer deploy)"
    echo ""
    echo "NOTES:"
    echo "  • Export creates ./images/ directory with tar files"
    echo "  • Import loads images into Docker from tar files"
    echo "  • vanalyzer script automatically detects and uses offline images"
    echo "  • Use 'clean' to force rebuild from source code"
}

export_images() {
    log "🚀 Starting Docker images export process"
    
    # Create images directory
    mkdir -p "$IMAGES_DIR"
    
    # Check if Docker is available
    if ! command -v docker >/dev/null 2>&1; then
        log_error "Docker is not installed or not in PATH"
        exit 1
    fi
    
    if ! docker info >/dev/null 2>&1; then
        log_error "Docker daemon is not running"
        exit 1
    fi
    
    log "Exporting vAnalyzer images to $IMAGES_DIR/"
    echo ""
    
    # Export each image
    local exported_images=()
    local total_size=0
    
    for image_name in "${!IMAGES[@]}"; do
        local tag="${IMAGES[$image_name]}"
        local full_image="${image_name}:${tag}"
        local filename="${image_name//\//-}-${tag}.tar"
        local filepath="${IMAGES_DIR}/${filename}"
        
        log "Exporting $full_image..."
        
        # Check if image exists
        if ! docker image inspect "$full_image" >/dev/null 2>&1; then
            log_error "Image $full_image not found locally"
            log_error "Run 'vanalyzer deploy' first to build images"
            exit 1
        fi
        
        # Export image
        if docker save "$full_image" -o "$filepath"; then
            local size=$(du -h "$filepath" | cut -f1)
            log_success "Exported $full_image → $filename ($size)"
            exported_images+=("$full_image")
            total_size=$((total_size + $(du -b "$filepath" | cut -f1)))
        else
            log_error "Failed to export $full_image"
            exit 1
        fi
    done
    
    # Create manifest file
    log "Creating image manifest..."
    cat > "$MANIFEST_FILE" << EOF
{
    "export_date": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
    "version": "$VERSION",
    "images": [
$(printf '        "%s",\n' "${exported_images[@]}" | sed '$ s/,$//')
    ],
    "total_files": ${#exported_images[@]},
    "total_size_bytes": $total_size
}
EOF
    
    # Generate checksums
    log "Generating checksums..."
    (cd "$IMAGES_DIR" && sha256sum *.tar > checksums.sha256)
    
    local total_size_mb=$((total_size / 1024 / 1024))
    log_success "Export completed successfully!"
    echo ""
    log "📊 Export Summary:"
    log "  • Images exported: ${#exported_images[@]}"
    log "  • Total size: ${total_size_mb} MB"
    log "  • Location: $IMAGES_DIR/"
    log "  • Transfer this directory to your offline system"
}

import_images() {
    log "🚀 Starting Docker images import process"
    
    # Check if images directory exists
    if [[ ! -d "$IMAGES_DIR" ]]; then
        log_error "Images directory not found: $IMAGES_DIR"
        log_error "Run '$0 export' first or copy images/ directory from source system"
        exit 1
    fi
    
    # Check if manifest exists
    if [[ ! -f "$MANIFEST_FILE" ]]; then
        log_error "Image manifest not found: $MANIFEST_FILE"
        log_error "Invalid or incomplete images directory"
        exit 1
    fi
    
    # Verify checksums
    log "Verifying image integrity..."
    if [[ -f "$IMAGES_DIR/checksums.sha256" ]]; then
        if (cd "$IMAGES_DIR" && sha256sum -c checksums.sha256 --quiet); then
            log_success "All image files verified successfully"
        else
            log_error "Checksum verification failed - images may be corrupted"
            exit 1
        fi
    else
        log_warning "No checksums found - skipping integrity check"
    fi
    
    # Check Docker availability
    if ! command -v docker >/dev/null 2>&1; then
        log_error "Docker is not installed or not in PATH"
        exit 1
    fi
    
    if ! docker info >/dev/null 2>&1; then
        log_error "Docker daemon is not running"
        exit 1
    fi
    
    log "Importing vAnalyzer images from $IMAGES_DIR/"
    echo ""
    
    # Import each image
    local imported_images=()
    
    for image_name in "${!IMAGES[@]}"; do
        local tag="${IMAGES[$image_name]}"
        local filename="${image_name//\//-}-${tag}.tar"
        local filepath="${IMAGES_DIR}/${filename}"
        
        if [[ ! -f "$filepath" ]]; then
            log_error "Image file not found: $filename"
            exit 1
        fi
        
        log "Importing ${image_name}:${tag}..."
        
        if docker load -i "$filepath" >/dev/null 2>&1; then
            log_success "Imported ${image_name}:${tag}"
            imported_images+=("${image_name}:${tag}")
        else
            log_error "Failed to import ${image_name}:${tag}"
            exit 1
        fi
    done
    
    log_success "Import completed successfully!"
    echo ""
    log "📊 Import Summary:"
    log "  • Images imported: ${#imported_images[@]}"
    log "  • Images ready for deployment"
    echo ""
    log "Next steps:"
    log "  • Run 'vanalyzer deploy' to deploy with imported images"
}

list_images() {
    if [[ ! -d "$IMAGES_DIR" ]]; then
        log_warning "No images directory found"
        return 0
    fi
    
    if [[ ! -f "$MANIFEST_FILE" ]]; then
        log_warning "No manifest file found"
        return 0
    fi
    
    log "📦 Available Offline Images:"
    echo ""
    
    # Read and display manifest
    if command -v jq >/dev/null 2>&1; then
        local export_date=$(jq -r '.export_date' "$MANIFEST_FILE")
        local version=$(jq -r '.version' "$MANIFEST_FILE")
        local total_files=$(jq -r '.total_files' "$MANIFEST_FILE")
        local total_size=$(jq -r '.total_size_bytes' "$MANIFEST_FILE")
        local total_size_mb=$((total_size / 1024 / 1024))
        
        echo "Export Date: $export_date"
        echo "Version: $version"
        echo "Total Images: $total_files"
        echo "Total Size: ${total_size_mb} MB"
        echo ""
        echo "Images:"
        jq -r '.images[]' "$MANIFEST_FILE" | sed 's/^/  • /'
    else
        # Fallback without jq
        log "Manifest file exists: $(basename "$MANIFEST_FILE")"
        echo "Image files:"
        ls -lh "$IMAGES_DIR"/*.tar 2>/dev/null | awk '{print "  • " $9 " (" $5 ")"}' || log_warning "No .tar files found"
    fi
    
    echo ""
    # Check if images are loaded in Docker
    log "Docker Image Status:"
    for image_name in "${!IMAGES[@]}"; do
        local tag="${IMAGES[$image_name]}"
        local full_image="${image_name}:${tag}"
        
        if docker image inspect "$full_image" >/dev/null 2>&1; then
            echo "  ✓ $full_image (loaded)"
        else
            echo "  ✗ $full_image (not loaded)"
        fi
    done
}

clean_images() {
    if [[ -d "$IMAGES_DIR" ]]; then
        log_warning "This will remove all exported images in $IMAGES_DIR/"
        echo -n "Are you sure? (y/N): "
        read -r confirm
        
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            rm -rf "$IMAGES_DIR"
            log_success "Images directory removed"
            log "Next 'vanalyzer deploy' will rebuild from source"
        else
            log "Operation cancelled"
        fi
    else
        log "No images directory found - nothing to clean"
    fi
}

# Main execution
case "${1:-help}" in
    "export")
        export_images
        ;;
    "import")
        import_images
        ;;
    "list")
        list_images
        ;;
    "clean")
        clean_images
        ;;
    "help"|*)
        show_usage
        ;;
esac