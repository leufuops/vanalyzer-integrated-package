#!/bin/bash
set -euo pipefail

# Generic SSL Certificate Generation Script
# Generates CA and server certificates with flexible hostname support

# Default configuration
DEFAULT_CERT_DIR="./traefik/config/certs/"
DEFAULT_ORGANIZATION="Local CA"
DEFAULT_COUNTRY="US"
DEFAULT_STATE="State"
DEFAULT_CITY="City"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
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

# Configuration
set_config() {
    CERT_DIR="${CERT_DIR:-$DEFAULT_CERT_DIR}"
    ORGANIZATION="${ORGANIZATION:-$DEFAULT_ORGANIZATION}"
    COUNTRY="${COUNTRY:-$DEFAULT_COUNTRY}"
    STATE="${STATE:-$DEFAULT_STATE}"
    CITY="${CITY:-$DEFAULT_CITY}"
    
    # Ensure cert directory is absolute
    if [[ ! "$CERT_DIR" =~ ^/ ]]; then
        CERT_DIR="$(pwd)/$CERT_DIR"
    fi
    
    log "Configuration:"
    echo "  Certificate Directory: $CERT_DIR"
    echo "  Organization: $ORGANIZATION"
    echo "  Country: $COUNTRY"
    echo "  State: $STATE"
    echo "  City: $CITY"
}

# Create certificate directory
create_cert_dir() {
    mkdir -p "$CERT_DIR"
    log_success "Certificate directory created: $CERT_DIR"
}

# Generate CA certificate
generate_ca() {
    log "Generating Certificate Authority (CA)..."
    
    # Check if CA already exists
    if [[ -f "$CERT_DIR/ca.crt" ]] && [[ -f "$CERT_DIR/ca.key" ]]; then
        log_warning "CA certificate already exists!"
        echo -n "Do you want to regenerate it? This will invalidate all existing server certificates. (y/N): "
        read -r response
        if [[ ! "$response" =~ ^[Yy]$ ]]; then
            log "Keeping existing CA certificate"
            return 0
        fi
    fi
    
    cat > "$CERT_DIR/ca.conf" << EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[req_distinguished_name]
C = $COUNTRY
ST = $STATE
L = $CITY
O = $ORGANIZATION
CN = $ORGANIZATION Root CA

[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
EOF

    # Generate CA private key
    openssl genrsa -out "$CERT_DIR/ca.key" 4096
    log_success "CA private key generated"
    
    # Generate CA certificate
    openssl req -new -x509 -days 3650 -key "$CERT_DIR/ca.key" \
        -out "$CERT_DIR/ca.crt" -config "$CERT_DIR/ca.conf"
    log_success "CA certificate generated (valid for 10 years)"
    
    # Clean up config file
    rm -f "$CERT_DIR/ca.conf"
}

# Generate server certificate
generate_server_cert() {
    local hostname="$1"
    
    if [[ -z "$hostname" ]]; then
        log_error "Hostname is required for server certificate generation"
        return 1
    fi
    
    log "Generating server certificate for $hostname..."
    
    # Check if CA exists
    if [[ ! -f "$CERT_DIR/ca.crt" ]] || [[ ! -f "$CERT_DIR/ca.key" ]]; then
        log_error "CA certificate not found. Generate CA first with: $0 create-ca"
        return 1
    fi
    
    # Generate hostname-based certificate names
    local hostname_safe="${hostname//[^a-zA-Z0-9.-]/_}"
    local server_key="${hostname_safe}.key"
    local server_crt="${hostname_safe}.crt"
    
    # Check if server cert already exists
    if [[ -f "$CERT_DIR/$server_crt" ]] && [[ -f "$CERT_DIR/$server_key" ]]; then
        log_warning "Server certificate already exists for $hostname!"
        echo -n "Do you want to regenerate it? (y/N): "
        read -r response
        if [[ ! "$response" =~ ^[Yy]$ ]]; then
            log "Keeping existing server certificate"
            return 0
        fi
    fi
    
    cat > "$CERT_DIR/server.conf" << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = $COUNTRY
ST = $STATE
L = $CITY
O = $ORGANIZATION
CN = $hostname

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = $hostname
DNS.2 = localhost
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

    # Add wildcard subdomain if hostname contains a dot
    if [[ "$hostname" == *.* ]]; then
        echo "DNS.3 = *.${hostname}" >> "$CERT_DIR/server.conf"
    fi

    # Generate server private key
    openssl genrsa -out "$CERT_DIR/$server_key" 2048
    log_success "Server private key generated: $server_key"
    
    # Generate certificate signing request
    openssl req -new -key "$CERT_DIR/$server_key" \
        -out "$CERT_DIR/server.csr" -config "$CERT_DIR/server.conf"
    log_success "Certificate signing request generated"
    
    # Generate server certificate signed by CA
    openssl x509 -req -in "$CERT_DIR/server.csr" -CA "$CERT_DIR/ca.crt" \
        -CAkey "$CERT_DIR/ca.key" -CAcreateserial -out "$CERT_DIR/$server_crt" \
        -days 365 -extensions v3_req -extfile "$CERT_DIR/server.conf"
    log_success "Server certificate generated: $server_crt (valid for 1 year)"
    
    # Clean up temporary files
    rm -f "$CERT_DIR/server.conf" "$CERT_DIR/server.csr"
    
    # Store the generated filenames for later use
    LAST_SERVER_KEY="$server_key"
    LAST_SERVER_CRT="$server_crt"
    LAST_HOSTNAME="$hostname"
}

# Set proper permissions
set_permissions() {
    log "Setting certificate permissions..."
    
    # Set restrictive permissions on private keys
    chmod 600 "$CERT_DIR"/*.key 2>/dev/null || true
    chmod 644 "$CERT_DIR"/*.crt 2>/dev/null || true
    
    log_success "Certificate permissions set"
}

# Update .env file with certificate information
update_env_file() {
    local hostname="$1"
    local server_key="$2"
    local server_crt="$3"
    
    local env_file=".env"
    local env_example=".env.example"
    
    log "Updating .env file with certificate configuration..."
    
    # Create .env file from .env.example if it doesn't exist
    if [[ ! -f "$env_file" ]] && [[ -f "$env_example" ]]; then
        cp "$env_example" "$env_file"
        log_success "Created .env file from .env.example"
    elif [[ ! -f "$env_file" ]]; then
        log_warning ".env file and .env.example not found, creating minimal .env file"
        cat > "$env_file" << EOF
# vAnalyzer Environment Configuration
# Auto-generated by generate-ssl-certs.sh

# Project Information  
PROJECT_NAME=vanalyzer
VERSION=1.4
ENVIRONMENT=production

# Note: No registry required - images built locally
# REGISTRY_URL=127.0.0.1:5000  # Not used anymore

# Application Configuration
APP_PORT=8000
LOG_LEVEL=INFO

# Traefik Configuration
TRAEFIK_VERSION=latest
TRAEFIK_DASHBOARD_PORT=8080

# Stack Configuration
STACK_NAME=vanalyzer-stack
COMPOSE_PROJECT_NAME=vanalyzer

# SSL/TLS Configuration
USE_LOCAL_CA=true
SSL_CA_FILE=ca.crt
EOF
        log_success "Created minimal .env file"
    fi
    
    # Update hostname and certificate file names in .env file
    if [[ -f "$env_file" ]]; then
        
        # Update METABASE_HOST
        if grep -q "^METABASE_HOST=" "$env_file"; then
            sed -i "s/^METABASE_HOST=.*/METABASE_HOST=$hostname/" "$env_file"
        else
            echo "METABASE_HOST=$hostname" >> "$env_file"
        fi
        
        # Update SSL certificate file names
        if grep -q "^SSL_KEY_FILE=" "$env_file"; then
            sed -i "s/^SSL_KEY_FILE=.*/SSL_KEY_FILE=$server_key/" "$env_file"
        else
            echo "SSL_KEY_FILE=$server_key" >> "$env_file"
        fi
        
        if grep -q "^SSL_CRT_FILE=" "$env_file"; then
            sed -i "s/^SSL_CRT_FILE=.*/SSL_CRT_FILE=$server_crt/" "$env_file"
        else
            echo "SSL_CRT_FILE=$server_crt" >> "$env_file"
        fi
        
        # Ensure METABASE_MEMORY and METABASE_VERSION are set if not present
        if ! grep -q "^METABASE_MEMORY=" "$env_file"; then
            echo "METABASE_MEMORY=2g" >> "$env_file"
        fi
        
        if ! grep -q "^METABASE_VERSION=" "$env_file"; then
            echo "METABASE_VERSION=v0.55.x" >> "$env_file"
        fi
        
        log_success ".env file updated successfully"
        log "Updated configuration:"
        echo "  METABASE_HOST=$hostname"
        echo "  SSL_KEY_FILE=$server_key"  
        echo "  SSL_CRT_FILE=$server_crt"
        echo ""
    else
        log_error "Could not update .env file"
        return 1
    fi
}

# Update Traefik configuration files
update_traefik_config() {
    local hostname="$1"
    local server_key="$2"
    local server_crt="$3"
    
    local traefik_config="./traefik/config/traefik.yaml"
    local dynamic_config="./traefik/config/dynamic.yaml"
    
    log "Updating Traefik configuration files..."
    
    # Update traefik.yaml
    if [[ -f "$traefik_config" ]]; then
        # Update default certificate paths
        sed -i "s|certFile: /etc/traefik/certs/.*\.crt|certFile: /etc/traefik/certs/$server_crt|g" "$traefik_config"
        sed -i "s|keyFile: /etc/traefik/certs/.*\.key|keyFile: /etc/traefik/certs/$server_key|g" "$traefik_config"
        log_success "Updated traefik.yaml with certificate paths"
    else
        log_warning "traefik.yaml not found at $traefik_config"
    fi
    
    # Update dynamic.yaml
    if [[ -f "$dynamic_config" ]]; then
        # Update certificate paths in dynamic config
        sed -i "s|certFile: /etc/traefik/certs/.*\.crt|certFile: /etc/traefik/certs/$server_crt|g" "$dynamic_config"
        sed -i "s|keyFile: /etc/traefik/certs/.*\.key|keyFile: /etc/traefik/certs/$server_key|g" "$dynamic_config"
        log_success "Updated dynamic.yaml with certificate paths"
    else
        log_warning "dynamic.yaml not found at $dynamic_config"
    fi
}

# Display certificate information
show_cert_info() {
    local hostname="$1"
    
    log "Certificate Information:"
    echo ""
    echo "📁 Certificate Directory: $CERT_DIR"
    echo "🔐 CA Certificate: ca.crt"
    
    if [[ -n "$hostname" ]]; then
        local hostname_safe="${hostname//[^a-zA-Z0-9.-]/_}"
        echo "🔐 Server Certificate: ${hostname_safe}.crt"
        echo "🔐 Server Key: ${hostname_safe}.key"
        echo "🌐 Hostname: $hostname"
        
        local cert_file="$CERT_DIR/${hostname_safe}.crt"
        if [[ -f "$cert_file" ]]; then
            echo ""
            log "Certificate Details:"
            openssl x509 -in "$cert_file" -text -noout | grep -E "(Subject:|DNS:|IP Address:|Not Before|Not After)"
        fi
    else
        echo "🔐 Server Certificates:"
        for cert in "$CERT_DIR"/*.crt; do
            if [[ -f "$cert" ]] && [[ "$(basename "$cert")" != "ca.crt" ]]; then
                echo "  - $(basename "$cert")"
            fi
        done
    fi
    
    echo ""
    log_success "Certificate information displayed"
    
    if [[ -f "$CERT_DIR/ca.crt" ]]; then
        echo ""
        echo "To trust certificates, install CA in your system:"
        echo "  CA file: $CERT_DIR/ca.crt"
        echo ""
        echo "Linux (Ubuntu/Debian):"
        echo "  sudo cp $CERT_DIR/ca.crt /usr/local/share/ca-certificates/local-ca.crt"
        echo "  sudo update-ca-certificates"
        echo ""
        echo "macOS:"
        echo "  sudo security add-trusted-cert -d root -r trustRoot -k /Library/Keychains/System.keychain $CERT_DIR/ca.crt"
        echo ""
        echo "Windows:"
        echo "  Import ca.crt into 'Trusted Root Certification Authorities' store"
    fi
}

# Clean certificates
clean_certs() {
    log "Removing all certificates..."
    
    if [[ -d "$CERT_DIR" ]]; then
        rm -rf "$CERT_DIR"/*.crt "$CERT_DIR"/*.key "$CERT_DIR"/*.srl 2>/dev/null || true
        log_success "Certificates removed from $CERT_DIR"
    else
        log_warning "Certificate directory does not exist: $CERT_DIR"
    fi
}

# List available certificates
list_certs() {
    log "Available certificates in $CERT_DIR:"
    echo ""
    
    if [[ ! -d "$CERT_DIR" ]]; then
        log_warning "Certificate directory does not exist: $CERT_DIR"
        return 1
    fi
    
    local found=false
    
    if [[ -f "$CERT_DIR/ca.crt" ]]; then
        echo "🔐 CA Certificate: ca.crt"
        found=true
    fi
    
    echo "🔐 Server Certificates:"
    for cert in "$CERT_DIR"/*.crt; do
        if [[ -f "$cert" ]] && [[ "$(basename "$cert")" != "ca.crt" ]]; then
            local cert_name=$(basename "$cert" .crt)
            echo "  - $cert_name ($(basename "$cert"))"
            found=true
        fi
    done
    
    if [[ "$found" == false ]]; then
        echo "  No certificates found"
    fi
    
    echo ""
}

# Show usage
show_usage() {
    echo "Usage: $0 COMMAND [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  create-ca                    Generate Certificate Authority"
    echo "  create-server <hostname>     Generate server certificate for hostname"
    echo "  create-all <hostname>        Generate both CA and server certificate"
    echo "  clean                        Remove all certificates"
    echo "  list                         List available certificates"
    echo "  info [hostname]              Show certificate information"
    echo "  help                         Show this help message"
    echo ""
    echo "Options:"
    echo "  -d, --cert-dir <directory>   Certificate directory (default: ./certs)"
    echo ""
    echo "Environment Variables:"
    echo "  CERT_DIR          Certificate directory (default: ./certs)"
    echo "  ORGANIZATION      Organization name (default: Local CA)"
    echo "  COUNTRY           Country code (default: US)"
    echo "  STATE             State/province (default: State)"
    echo "  CITY              City (default: City)"
    echo ""
    echo "Examples:"
    echo "  $0 create-ca                                    # Generate CA only"
    echo "  $0 create-server myapp.local                    # Generate server cert + update .env"
    echo "  $0 create-all api.company.com                   # Generate both + update .env"
    echo "  $0 -d /etc/ssl/certs create-all myapp.local    # Use custom directory"
    echo "  ORGANIZATION='My Company' $0 create-ca          # Custom organization"
    echo ""
    echo "Generated Files:"
    echo "  - ca.crt, ca.key            # Certificate Authority"
    echo "  - <hostname>.crt, <hostname>.key  # Server certificates"
    echo "  - .env (updated)            # Environment file with matching hostnames"
    echo ""
    echo "Automatic .env Configuration:"
    echo "  This script automatically updates your .env file with:"
    echo "  - METABASE_HOST=<hostname>  # Matches certificate hostname"
    echo "  - SSL_KEY_FILE=<hostname>.key"
    echo "  - SSL_CRT_FILE=<hostname>.crt"
    echo "  - Creates .env from .env.example if .env doesn't exist"
    echo "  - Creates backup before making changes"
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|--cert-dir)
                CERT_DIR="$2"
                shift 2
                ;;
            create-ca)
                COMMAND="create-ca"
                shift
                ;;
            create-server)
                COMMAND="create-server"
                HOSTNAME="$2"
                shift 2
                ;;
            create-all)
                COMMAND="create-all"
                HOSTNAME="$2"
                shift 2
                ;;
            clean)
                COMMAND="clean"
                shift
                ;;
            list)
                COMMAND="list"
                shift
                ;;
            info)
                COMMAND="info"
                HOSTNAME="${2:-}"
                shift
                [[ -n "${2:-}" ]] && shift
                ;;
            help|--help|-h)
                COMMAND="help"
                shift
                ;;
            *)
                log_error "Unknown argument: $1"
                show_usage
                exit 1
                ;;
        esac
    done
}

# Main execution
main() {
    local command="${1:-help}"
    
    # Initialize variables
    COMMAND=""
    HOSTNAME=""
    
    # Parse arguments
    parse_args "$@"
    
    # Use the parsed command or fall back to the first argument
    command="${COMMAND:-$command}"
    
    # Set configuration
    set_config
    
    case "$command" in
        create-ca)
            create_cert_dir
            generate_ca
            set_permissions
            log_success "CA generation completed!"
            ;;
        create-server)
            if [[ -z "$HOSTNAME" ]]; then
                log_error "Hostname is required for server certificate generation"
                echo "Usage: $0 create-server <hostname>"
                exit 1
            fi
            create_cert_dir
            generate_server_cert "$HOSTNAME"
            set_permissions
            update_env_file "$LAST_HOSTNAME" "$LAST_SERVER_KEY" "$LAST_SERVER_CRT"
            update_traefik_config "$LAST_HOSTNAME" "$LAST_SERVER_KEY" "$LAST_SERVER_CRT"
            show_cert_info "$HOSTNAME"
            ;;
        create-all)
            if [[ -z "$HOSTNAME" ]]; then
                log_error "Hostname is required for certificate generation"
                echo "Usage: $0 create-all <hostname>"
                exit 1
            fi
            create_cert_dir
            generate_ca
            generate_server_cert "$HOSTNAME"
            set_permissions
            update_env_file "$LAST_HOSTNAME" "$LAST_SERVER_KEY" "$LAST_SERVER_CRT"
            update_traefik_config "$LAST_HOSTNAME" "$LAST_SERVER_KEY" "$LAST_SERVER_CRT"
            show_cert_info "$HOSTNAME"
            ;;
        clean)
            clean_certs
            ;;
        list)
            list_certs
            ;;
        info)
            show_cert_info "$HOSTNAME"
            ;;
        help)
            show_usage
            ;;
        *)
            log_error "Unknown command: $command"
            show_usage
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"