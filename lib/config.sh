#!/bin/bash
# vAnalyzer Configuration Management Library
# Simplified .env-only approach with external integrations support

# Create or update a Docker secret
create_or_update_secret() {
    local secret_name="$1"
    local secret_value="$2"
    
    # Remove existing secret if it exists
    if docker secret ls --format "{{.Name}}" 2>/dev/null | grep -q "^${secret_name}$"; then
        docker secret rm "$secret_name" >/dev/null 2>&1 || true
        sleep 1
    fi
    
    # Create new secret
    if echo "$secret_value" | docker secret create "$secret_name" - >/dev/null 2>&1; then
        log_step "Created secret: $secret_name"
    else
        log_error "Failed to create secret: $secret_name"
        return 1
    fi
}

# Initialize configuration with interactive setup
init_configuration() {
    log_info "Starting vAnalyzer Configuration Setup"
    echo ""
    
    # Check for existing configuration
    if [[ -f "$ENV_FILE" ]]; then
        log_warning "Configuration file already exists: $ENV_FILE"
        if ! confirm "Overwrite existing configuration?" "n"; then
            log_info "Configuration setup cancelled"
            return 0
        fi
    fi
    
    # Interactive setup - only 4 essential questions
    interactive_simple_setup
    
    # Generate SSL certificates
    generate_certificates_for_hostname
    
    log_success "Configuration completed successfully"
    echo ""
    log_info "Next step: Run 'vanalyzer deploy' to deploy the stack"
}

# Interactive setup with secure secret handling
interactive_simple_setup() {
    echo -e "${BOLD}vAnalyzer Configuration Setup${NC}"
    echo ""

    # Integration status flags (used in summary at the end)
    local tenable_enabled="false"
    local falcon_enabled="false"
    local qualys_enabled="false"
    local servicenow_enabled="false"
    local mde_enabled="false"
    local automox_enabled="false"
    local wiz_enabled="false"
    local sentinelone_enabled="false"
    local trendmicro_enabled="false"
    local rapid7_enabled="false"
    
    # ============================================================================
    # CORE VICARIUS CONFIGURATION
    # ============================================================================
    
    # Hostname
    local vanalyzer_hostname=""
    while [[ -z "$vanalyzer_hostname" ]]; do
        read -p "Enter vAnalyzer hostname (e.g., reports.company.com): " vanalyzer_hostname
        if [[ -z "$vanalyzer_hostname" ]]; then
            log_error "Hostname is required"
        fi
    done
    
    # Dashboard ID
    local dashboard_id=""
    while [[ -z "$dashboard_id" ]]; do
        local input_dashboard=""
        read -p "Enter Dashboard ID or URL (e.g., 'company' or 'https://company.vicarius.cloud'): " input_dashboard
        if [[ -z "$input_dashboard" ]]; then
            log_error "Dashboard ID is required"
            continue
        fi
        
        # Extract dashboard ID from URL if full URL provided
        if [[ "$input_dashboard" =~ ^https?://([^.]+)\.vicarius\.cloud ]]; then
            dashboard_id="${BASH_REMATCH[1]}"
            log_success "Extracted dashboard ID: $dashboard_id from URL"
        elif [[ "$input_dashboard" =~ ^([^.]+)\.vicarius\.cloud ]]; then
            dashboard_id="${BASH_REMATCH[1]}"
            log_success "Extracted dashboard ID: $dashboard_id from domain"
        else
            dashboard_id="$input_dashboard"
        fi
        
        # Validate dashboard ID format (alphanumeric, hyphens, underscores)
        if [[ ! "$dashboard_id" =~ ^[a-zA-Z0-9_-]+$ ]]; then
            log_error "Invalid dashboard ID format. Use only letters, numbers, hyphens, and underscores."
            dashboard_id=""
        fi
    done
    
    # API Key
    local api_key=""
    while [[ -z "$api_key" ]]; do
        read -s -p "Enter API Key: " api_key
        echo ""
        if [[ -z "$api_key" ]]; then
            log_error "API Key is required"
        fi
    done
    
    # ============================================================================
    # DATABASE CONFIGURATION
    # ============================================================================
    echo ""
    echo -e "${BOLD}Database Configuration${NC}"
    
    # PostgreSQL Username
    local db_user=""
    read -p "Enter PostgreSQL username (default: vanalyzer): " db_user
    db_user="${db_user:-vanalyzer}"
    
    # Database Name
    local db_name=""
    read -p "Enter database name (default: vanalyzer): " db_name
    db_name="${db_name:-vanalyzer}"
    
    # Database Password
    local db_password=""
    while [[ -z "$db_password" ]]; do
        read -s -p "Enter Database Password: " db_password
        echo ""
        if [[ -z "$db_password" ]]; then
            log_error "Database password is required"
        fi
        
        read -s -p "Confirm password: " db_password_confirm
        echo ""
        
        if [[ "$db_password" != "$db_password_confirm" ]]; then
            log_error "Passwords do not match"
            db_password=""
        fi
    done
    
    # ============================================================================
    # SYNC CONFIGURATION
    # ============================================================================
    echo ""
    echo -e "${BOLD}Sync Configuration${NC}"
    
    # Sync interval
    read -p "Sync interval in hours (default: 6): " sync_interval
    sync_interval="${sync_interval:-6}"
    # Remove any 'h' suffix if user added it
    sync_interval="${sync_interval%h}"
    
    # ============================================================================
    # EXTERNAL DATA SOURCES (KEV + EPSS)
    # ============================================================================
    echo ""
    echo -e "${BOLD}External Vulnerability Data (KEV + EPSS)${NC}"
    
    read -p "Enable external vulnerability data (KEV + EPSS)? [y/N]: " enable_external
    external_data_enabled="false"
    epss_url=""
    kev_url=""
    
    if [[ "$enable_external" =~ ^[Yy] ]]; then
        external_data_enabled="true"
        
        # Ask about custom URLs
        read -p "Use custom data source URLs? [y/N]: " custom_urls
        if [[ "$custom_urls" =~ ^[Yy] ]]; then
            echo "Leave blank to use defaults:"
            read -p "EPSS URL [https://epss.empiricalsecurity.com/epss_scores-current.csv.gz]: " epss_url_input
            epss_url="${epss_url_input:-https://epss.empiricalsecurity.com/epss_scores-current.csv.gz}"
            
            read -p "KEV URL [https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json]: " kev_url_input
            kev_url="${kev_url_input:-https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json}"
        else
            epss_url="https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
            kev_url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        fi
        
        log_success "External data sources (KEV + EPSS) configured"
    else
        # Set empty URLs when external data is disabled
        epss_url=""
        kev_url=""
        log_info "External data sources (KEV + EPSS) disabled"
    fi
    
    # ============================================================================
    # ADVANCED THREAT INTELLIGENCE (VULNCHECK)
    # ============================================================================
    echo ""
    echo -e "${BOLD}Advanced Threat Intelligence (VulnCheck)${NC}"
    
    read -p "Enable advanced threat intelligence integration (requires API key)? [y/N]: " enable_vulncheck
    vulncheck_enabled="false"

    if [[ "$enable_vulncheck" =~ ^[Yy] ]]; then
        vulncheck_enabled="true"

        # Get threat intelligence API key
        local vulncheck_api_key=""
        while [[ -z "$vulncheck_api_key" ]]; do
            read -s -p "Enter VulnCheck API key: " vulncheck_api_key
            echo ""
            if [[ -z "$vulncheck_api_key" ]]; then
                log_error "VulnCheck API key is required"
            fi
        done

        # Create threat intelligence secret
        if ! create_or_update_secret "vulncheck_api_key" "$vulncheck_api_key"; then
            log_error "Failed to create VulnCheck API key secret"
            return 1
        fi
        log_success "VulnCheck integration configured"
        
        # Clear from memory
        unset vulncheck_api_key
    else
        # Create empty secret to satisfy Docker Compose requirements
        if ! create_or_update_secret "vulncheck_api_key" "disabled"; then
            log_error "Failed to create placeholder secret"
            return 1
        fi
        log_info "VulnCheck integration disabled"
    fi
    
    # ============================================================================
    # TENABLE.IO INTEGRATION
    # ============================================================================
    echo ""
    echo -e "${BOLD}Tenable.io Integration${NC}"
    echo "Tenable.io provides vulnerability scanning and management."
    echo ""
    
    read -p "Enable Tenable.io integration? [y/N]: " enable_tenable
    
    if [[ "$enable_tenable" =~ ^[Yy] ]]; then
        tenable_enabled="true"

        # Tenable Access Key
        local tenable_access_key=""
        while [[ -z "$tenable_access_key" ]]; do
            read -s -p "Enter Tenable Access Key: " tenable_access_key
            echo ""
            if [[ -z "$tenable_access_key" ]]; then
                log_error "Tenable Access Key is required"
            fi
        done
        
        # Tenable Secret Key
        local tenable_secret_key=""
        while [[ -z "$tenable_secret_key" ]]; do
            read -s -p "Enter Tenable Secret Key: " tenable_secret_key
            echo ""
            if [[ -z "$tenable_secret_key" ]]; then
                log_error "Tenable Secret Key is required"
            fi
        done
        
        # Create Tenable secrets
        if ! create_or_update_secret "tenable_access_key" "$tenable_access_key"; then
            log_error "Failed to create Tenable Access Key secret"
            return 1
        fi
        
        if ! create_or_update_secret "tenable_secret_key" "$tenable_secret_key"; then
            log_error "Failed to create Tenable Secret Key secret"
            return 1
        fi
        
        log_success "Tenable.io integration configured"
        
        # Clear from memory
        unset tenable_access_key
        unset tenable_secret_key
    else
        # Create placeholder secrets
        create_or_update_secret "tenable_access_key" "not_configured"
        create_or_update_secret "tenable_secret_key" "not_configured"
        log_info "Tenable.io integration disabled"
    fi
    
    # ============================================================================
    # CROWDSTRIKE FALCON SPOTLIGHT INTEGRATION
    # ============================================================================
    echo ""
    echo -e "${BOLD}CrowdStrike Falcon Spotlight Integration${NC}"
    echo "Falcon Spotlight provides endpoint vulnerability detection."
    echo ""
    
    read -p "Enable CrowdStrike Falcon Spotlight integration? [y/N]: " enable_falcon
    
    if [[ "$enable_falcon" =~ ^[Yy] ]]; then
        falcon_enabled="true"

        # Falcon API Region Selection
        echo ""
        echo "Select Falcon API Region:"
        echo "  1. US-1  (https://api.crowdstrike.com)"
        echo "  2. US-2  (https://api.us-2.crowdstrike.com)"
        echo "  3. EU-1  (https://api.eu-1.crowdstrike.com)"
        echo "  4. US-GOV-1 (https://api.laggar.gcw.crowdstrike.com)"
        echo "  5. Custom URL"
        
        local region_choice=""
        read -p "Select region [1-5] (default: 2): " region_choice
        region_choice="${region_choice:-2}"
        
        local falcon_base_url=""
        case $region_choice in
            1) falcon_base_url="https://api.crowdstrike.com" ;;
            2) falcon_base_url="https://api.us-2.crowdstrike.com" ;;
            3) falcon_base_url="https://api.eu-1.crowdstrike.com" ;;
            4) falcon_base_url="https://api.laggar.gcw.crowdstrike.com" ;;
            5) 
                read -p "Enter custom Falcon API URL: " falcon_base_url
                ;;
            *) 
                falcon_base_url="https://api.us-2.crowdstrike.com"
                log_warning "Invalid selection, using default: US-2"
                ;;
        esac
        
        echo "Selected: $falcon_base_url"
        
        # Falcon Client ID
        local falcon_client_id=""
        while [[ -z "$falcon_client_id" ]]; do
            read -p "Enter Falcon Client ID: " falcon_client_id
            if [[ -z "$falcon_client_id" ]]; then
                log_error "Falcon Client ID is required"
            fi
        done
        
        # Falcon Client Secret
        local falcon_client_secret=""
        while [[ -z "$falcon_client_secret" ]]; do
            read -s -p "Enter Falcon Client Secret: " falcon_client_secret
            echo ""
            if [[ -z "$falcon_client_secret" ]]; then
                log_error "Falcon Client Secret is required"
            fi
        done
        
        # Create Falcon secrets
        if ! create_or_update_secret "falcon_base_url" "$falcon_base_url"; then
            log_error "Failed to create Falcon Base URL secret"
            return 1
        fi
        
        if ! create_or_update_secret "falcon_client_id" "$falcon_client_id"; then
            log_error "Failed to create Falcon Client ID secret"
            return 1
        fi
        
        if ! create_or_update_secret "falcon_client_secret" "$falcon_client_secret"; then
            log_error "Failed to create Falcon Client Secret secret"
            return 1
        fi
        
        log_success "CrowdStrike Falcon Spotlight integration configured"
        
        # Clear from memory
        unset falcon_client_id
        unset falcon_client_secret
    else
        # Create placeholder secrets
        create_or_update_secret "falcon_base_url" "https://api.us-2.crowdstrike.com"
        create_or_update_secret "falcon_client_id" "not_configured"
        create_or_update_secret "falcon_client_secret" "not_configured"
        log_info "CrowdStrike Falcon Spotlight integration disabled"
    fi
    
    # ============================================================================
    # QUALYS VMDR INTEGRATION
    # ============================================================================
    echo ""
    echo -e "${BOLD}Qualys VMDR Integration${NC}"
    echo "Qualys VMDR provides vulnerability management and detection."
    echo ""
    
    read -p "Enable Qualys VMDR integration? [y/N]: " enable_qualys
    
    if [[ "$enable_qualys" =~ ^[Yy] ]]; then
        qualys_enabled="true"

        # Qualys Platform Selection
        echo ""
        echo "Select Qualys Platform:"
        echo "  1. US Platform 1 (https://qualysapi.qualys.com)"
        echo "  2. US Platform 2 (https://qualysapi.qg2.apps.qualys.com)"
        echo "  3. US Platform 3 (https://qualysapi.qg3.apps.qualys.com)"
        echo "  4. US Platform 4 (https://qualysapi.qg4.apps.qualys.com)"
        echo "  5. EU Platform 1 (https://qualysapi.qualys.eu)"
        echo "  6. EU Platform 2 (https://qualysapi.qg2.apps.qualys.eu)"
        echo "  7. India (https://qualysapi.qg1.apps.qualys.in)"
        echo "  8. Canada (https://qualysapi.qg1.apps.qualys.ca)"
        echo "  9. Custom URL"
        
        local platform_choice=""
        read -p "Select platform [1-9] (default: 1): " platform_choice
        platform_choice="${platform_choice:-1}"
        
        local qualys_api_url=""
        case $platform_choice in
            1) qualys_api_url="https://qualysapi.qualys.com" ;;
            2) qualys_api_url="https://qualysapi.qg2.apps.qualys.com" ;;
            3) qualys_api_url="https://qualysapi.qg3.apps.qualys.com" ;;
            4) qualys_api_url="https://qualysapi.qg4.apps.qualys.com" ;;
            5) qualys_api_url="https://qualysapi.qualys.eu" ;;
            6) qualys_api_url="https://qualysapi.qg2.apps.qualys.eu" ;;
            7) qualys_api_url="https://qualysapi.qg1.apps.qualys.in" ;;
            8) qualys_api_url="https://qualysapi.qg1.apps.qualys.ca" ;;
            9) 
                read -p "Enter custom Qualys API URL: " qualys_api_url
                ;;
            *) 
                qualys_api_url="https://qualysapi.qualys.com"
                log_warning "Invalid selection, using default: US Platform 1"
                ;;
        esac
        
        echo "Selected: $qualys_api_url"
        
        # Qualys Username
        local qualys_username=""
        while [[ -z "$qualys_username" ]]; do
            read -p "Enter Qualys Username: " qualys_username
            if [[ -z "$qualys_username" ]]; then
                log_error "Qualys Username is required"
            fi
        done
        
        # Qualys Password
        local qualys_password=""
        while [[ -z "$qualys_password" ]]; do
            read -s -p "Enter Qualys Password: " qualys_password
            echo ""
            if [[ -z "$qualys_password" ]]; then
                log_error "Qualys Password is required"
            fi
        done
        
        # Create Qualys secrets
        if ! create_or_update_secret "qualys_api_url" "$qualys_api_url"; then
            log_error "Failed to create Qualys API URL secret"
            return 1
        fi
        
        if ! create_or_update_secret "qualys_username" "$qualys_username"; then
            log_error "Failed to create Qualys Username secret"
            return 1
        fi
        
        if ! create_or_update_secret "qualys_password" "$qualys_password"; then
            log_error "Failed to create Qualys Password secret"
            return 1
        fi
        
        log_success "Qualys VMDR integration configured"
        
        # Clear from memory
        unset qualys_username
        unset qualys_password
    else
        # Create placeholder secrets
        create_or_update_secret "qualys_api_url" "https://qualysapi.qualys.com"
        create_or_update_secret "qualys_username" "not_configured"
        create_or_update_secret "qualys_password" "not_configured"
        log_info "Qualys VMDR integration disabled"
    fi

    # ============================================================================
    # SERVICENOW INTEGRATION
    # ============================================================================
    echo ""
    echo -e "${BOLD}ServiceNow Integration${NC}"
    echo "ServiceNow provides IT service management and vulnerability ticketing."
    echo ""

    read -p "Enable ServiceNow integration? [y/N]: " enable_servicenow

    if [[ "$enable_servicenow" =~ ^[Yy] ]]; then
        servicenow_enabled="true"

        # ServiceNow Instance URL
        local servicenow_instance_url=""
        while [[ -z "$servicenow_instance_url" ]]; do
            read -p "Enter ServiceNow Instance URL (e.g., https://company.service-now.com): " servicenow_instance_url
            if [[ -z "$servicenow_instance_url" ]]; then
                log_error "ServiceNow Instance URL is required"
            fi
        done

        # ServiceNow Username
        local servicenow_user=""
        while [[ -z "$servicenow_user" ]]; do
            read -p "Enter ServiceNow Username: " servicenow_user
            if [[ -z "$servicenow_user" ]]; then
                log_error "ServiceNow Username is required"
            fi
        done

        # ServiceNow Password
        local servicenow_password=""
        while [[ -z "$servicenow_password" ]]; do
            read -s -p "Enter ServiceNow Password: " servicenow_password
            echo ""
            if [[ -z "$servicenow_password" ]]; then
                log_error "ServiceNow Password is required"
            fi
        done

        # Create ServiceNow secrets
        if ! create_or_update_secret "servicenow_instance_url" "$servicenow_instance_url"; then
            log_error "Failed to create ServiceNow Instance URL secret"
            return 1
        fi

        if ! create_or_update_secret "servicenow_user" "$servicenow_user"; then
            log_error "Failed to create ServiceNow Username secret"
            return 1
        fi

        if ! create_or_update_secret "servicenow_password" "$servicenow_password"; then
            log_error "Failed to create ServiceNow Password secret"
            return 1
        fi

        log_success "ServiceNow integration configured"

        # Clear from memory
        unset servicenow_user
        unset servicenow_password
    else
        # Create placeholder secrets
        create_or_update_secret "servicenow_instance_url" "https://company.service-now.com"
        create_or_update_secret "servicenow_user" "not_configured"
        create_or_update_secret "servicenow_password" "not_configured"
        log_info "ServiceNow integration disabled"
    fi

    # ============================================================================
    # MICROSOFT DEFENDER FOR ENDPOINT (MDE) INTEGRATION
    # ============================================================================
    echo ""
    echo -e "${BOLD}Microsoft Defender for Endpoint (MDE) Integration${NC}"
    echo "MDE provides endpoint vulnerability data via the Microsoft Security API."
    echo "You will need an Azure App Registration with the following API permission:"
    echo "  Microsoft Graph / WindowsDefenderATP: Vulnerability.Read.All"
    echo ""

    read -p "Enable Microsoft Defender for Endpoint integration? [y/N]: " enable_mde

    if [[ "$enable_mde" =~ ^[Yy] ]]; then
        mde_enabled="true"

        # MDE Tenant ID
        local mde_tenant_id=""
        while [[ -z "$mde_tenant_id" ]]; do
            read -p "Enter Azure Tenant ID (GUID, e.g., xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx): " mde_tenant_id
            if [[ -z "$mde_tenant_id" ]]; then
                log_error "Tenant ID is required"
            elif [[ ! "$mde_tenant_id" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
                log_error "Invalid Tenant ID format. Must be a valid UUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)"
                mde_tenant_id=""
            fi
        done

        # MDE Client ID (App Registration Application ID)
        local mde_client_id=""
        while [[ -z "$mde_client_id" ]]; do
            read -p "Enter App Registration Client ID (GUID): " mde_client_id
            if [[ -z "$mde_client_id" ]]; then
                log_error "Client ID is required"
            elif [[ ! "$mde_client_id" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
                log_error "Invalid Client ID format. Must be a valid UUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)"
                mde_client_id=""
            fi
        done

        # MDE Client Secret
        local mde_client_secret=""
        while [[ -z "$mde_client_secret" ]]; do
            read -s -p "Enter App Registration Client Secret: " mde_client_secret
            echo ""
            if [[ -z "$mde_client_secret" ]]; then
                log_error "Client Secret is required"
            fi
        done

        # Create MDE secrets
        if ! create_or_update_secret "mde_tenant_id" "$mde_tenant_id"; then
            log_error "Failed to create MDE Tenant ID secret"
            return 1
        fi

        if ! create_or_update_secret "mde_client_id" "$mde_client_id"; then
            log_error "Failed to create MDE Client ID secret"
            return 1
        fi

        if ! create_or_update_secret "mde_client_secret" "$mde_client_secret"; then
            log_error "Failed to create MDE Client Secret secret"
            return 1
        fi

        log_success "Microsoft Defender for Endpoint integration configured"
        echo "  Tenant ID: ${mde_tenant_id}"
        echo "  Client ID: ${mde_client_id}"

        # Clear from memory
        unset mde_tenant_id
        unset mde_client_id
        unset mde_client_secret
    else
        # Create placeholder secrets to satisfy Docker Compose requirements
        create_or_update_secret "mde_tenant_id" "not_configured"
        create_or_update_secret "mde_client_id" "not_configured"
        create_or_update_secret "mde_client_secret" "not_configured"
        log_info "Microsoft Defender for Endpoint integration disabled"
    fi

    # ============================================================================
    # AUTOMOX INTEGRATION
    # ============================================================================
    echo ""
    echo -e "${BOLD}Automox Integration${NC}"
    echo "Automox provides patch management and software vulnerability data."
    echo "You will need an Automox API key and your Organization ID."
    echo ""

    read -p "Enable Automox integration? [y/N]: " enable_automox

    if [[ "$enable_automox" =~ ^[Yy] ]]; then
        automox_enabled="true"

        # Automox API Key
        local automox_api_key=""
        while [[ -z "$automox_api_key" ]]; do
            read -s -p "Enter Automox API Key: " automox_api_key
            echo ""
            if [[ -z "$automox_api_key" ]]; then
                log_error "Automox API Key is required"
            fi
        done

        # Automox Organization ID
        local automox_org_id=""
        while [[ -z "$automox_org_id" ]]; do
            read -p "Enter Automox Organization ID: " automox_org_id
            if [[ -z "$automox_org_id" ]]; then
                log_error "Automox Organization ID is required"
            elif [[ ! "$automox_org_id" =~ ^[0-9]+$ ]]; then
                log_error "Invalid Organization ID format. Must be a numeric value."
                automox_org_id=""
            fi
        done

        # Create Automox secrets
        if ! create_or_update_secret "automox_api_key" "$automox_api_key"; then
            log_error "Failed to create Automox API Key secret"
            return 1
        fi

        if ! create_or_update_secret "automox_org_id" "$automox_org_id"; then
            log_error "Failed to create Automox Organization ID secret"
            return 1
        fi

        log_success "Automox integration configured"
        echo "  Organization ID: ${automox_org_id}"

        # Clear from memory
        unset automox_api_key
        unset automox_org_id
    else
        # Create placeholder secrets to satisfy Docker Compose requirements
        create_or_update_secret "automox_api_key" "not_configured"
        create_or_update_secret "automox_org_id" "not_configured"
        log_info "Automox integration disabled"
    fi

    # ============================================================================
    # WIZ INTEGRATION
    # ============================================================================
    echo ""
    echo -e "${BOLD}Wiz Integration${NC}"
    echo "Wiz provides cloud security posture management and vulnerability detection."
    echo "You will need a Wiz Service Account with the following scope:"
    echo "  read:vulnerabilities, read:assets"
    echo ""

    read -p "Enable Wiz integration? [y/N]: " enable_wiz

    if [[ "$enable_wiz" =~ ^[Yy] ]]; then
        wiz_enabled="true"

        # Wiz Client ID
        local wiz_client_id=""
        while [[ -z "$wiz_client_id" ]]; do
            read -p "Enter Wiz Client ID: " wiz_client_id
            if [[ -z "$wiz_client_id" ]]; then
                log_error "Wiz Client ID is required"
            fi
        done

        # Wiz Client Secret
        local wiz_client_secret=""
        while [[ -z "$wiz_client_secret" ]]; do
            read -s -p "Enter Wiz Client Secret: " wiz_client_secret
            echo ""
            if [[ -z "$wiz_client_secret" ]]; then
                log_error "Wiz Client Secret is required"
            fi
        done

        # Wiz API Endpoint URL (direct input, no menu)
        local wiz_api_endpoint_url=""
        while [[ -z "$wiz_api_endpoint_url" ]]; do
            read -p "Enter Wiz API Endpoint URL (e.g., https://api.us1.app.wiz.io/graphql): " wiz_api_endpoint_url
            if [[ -z "$wiz_api_endpoint_url" ]]; then
                log_error "Wiz API Endpoint URL is required"
            elif [[ ! "$wiz_api_endpoint_url" =~ ^https?:// ]]; then
                log_error "Invalid URL format. Must start with http:// or https://"
                wiz_api_endpoint_url=""
            fi
        done

        # Create Wiz secrets
        if ! create_or_update_secret "wiz_client_id" "$wiz_client_id"; then
            log_error "Failed to create Wiz Client ID secret"
            return 1
        fi

        if ! create_or_update_secret "wiz_client_secret" "$wiz_client_secret"; then
            log_error "Failed to create Wiz Client Secret secret"
            return 1
        fi

        if ! create_or_update_secret "wiz_api_endpoint_url" "$wiz_api_endpoint_url"; then
            log_error "Failed to create Wiz API Endpoint URL secret"
            return 1
        fi

        log_success "Wiz integration configured"
        echo "  Client ID:    ${wiz_client_id}"
        echo "  API Endpoint: ${wiz_api_endpoint_url}"

        # Clear from memory
        unset wiz_client_id
        unset wiz_client_secret
    else
        # Create placeholder secrets to satisfy Docker Compose requirements
        create_or_update_secret "wiz_client_id" "not_configured"
        create_or_update_secret "wiz_client_secret" "not_configured"
        create_or_update_secret "wiz_api_endpoint_url" "not_configured"
        log_info "Wiz integration disabled"
    fi

    # ============================================================================
    # SENTINELONE INTEGRATION
    # ============================================================================
    echo ""
    echo -e "${BOLD}SentinelOne Integration${NC}"
    echo "SentinelOne provides endpoint detection, response, and vulnerability data."
    echo "You will need a SentinelOne API token with Read scope on your account."
    echo ""

    read -p "Enable SentinelOne integration? [y/N]: " enable_sentinelone

    if [[ "$enable_sentinelone" =~ ^[Yy] ]]; then
        sentinelone_enabled="true"

        # SentinelOne API URL
        local sentinelone_api_url=""
        while [[ -z "$sentinelone_api_url" ]]; do
            read -p "Enter SentinelOne API URL (e.g., https://usea1-021.sentinelone.net): " sentinelone_api_url
            if [[ -z "$sentinelone_api_url" ]]; then
                log_error "SentinelOne API URL is required"
            elif [[ ! "$sentinelone_api_url" =~ ^https?:// ]]; then
                log_error "Invalid URL format. Must start with http:// or https://"
                sentinelone_api_url=""
            fi
        done

        # SentinelOne API Token
        local sentinelone_api_token=""
        while [[ -z "$sentinelone_api_token" ]]; do
            read -s -p "Enter SentinelOne API Token: " sentinelone_api_token
            echo ""
            if [[ -z "$sentinelone_api_token" ]]; then
                log_error "SentinelOne API Token is required"
            fi
        done

        # Create SentinelOne secrets
        if ! create_or_update_secret "sentinelone_api_url" "$sentinelone_api_url"; then
            log_error "Failed to create SentinelOne API URL secret"
            return 1
        fi

        if ! create_or_update_secret "sentinelone_api_token" "$sentinelone_api_token"; then
            log_error "Failed to create SentinelOne API Token secret"
            return 1
        fi

        log_success "SentinelOne integration configured"
        echo "  API URL: ${sentinelone_api_url}"

        # Clear from memory
        unset sentinelone_api_token
    else
        # Create placeholder secrets to satisfy Docker Compose requirements
        create_or_update_secret "sentinelone_api_url" "not_configured"
        create_or_update_secret "sentinelone_api_token" "not_configured"
        log_info "SentinelOne integration disabled"
    fi

    # ============================================================================
    # TRENDMICRO VISION ONE INTEGRATION
    # ============================================================================
    echo ""
    echo -e "${BOLD}TrendMicro Vision One Integration${NC}"
    echo "TrendMicro Vision One provides EDR/EPP endpoint telemetry and OAT detections."
    echo "You will need a Vision One API key with the following permissions:"
    echo "  Endpoint Security / Endpoint Inventory: Read"
    echo "  XDR / Workbench Alerts: Read"
    echo "  XDR / OAT Detections: Read"
    echo ""

    read -p "Enable TrendMicro Vision One integration? [y/N]: " enable_trendmicro

    if [[ "$enable_trendmicro" =~ ^[Yy] ]]; then
        trendmicro_enabled="true"

        # TrendMicro API Region Selection
        echo ""
        echo "Select TrendMicro Vision One Region:"
        echo "  1. Global  (https://api.xdr.trendmicro.com)          [default]"
        echo "  2. US      (https://api.xdr.us.trendmicro.com)"
        echo "  3. EU      (https://api.xdr.eu.trendmicro.com)"
        echo "  4. Japan   (https://api.xdr.jp.trendmicro.com)"
        echo "  5. Australia/NZ (https://api.xdr.au.trendmicro.com)"
        echo "  6. India   (https://api.xdr.in.trendmicro.com)"
        echo "  7. Singapore (https://api.xdr.sg.trendmicro.com)"
        echo "  8. Custom URL"

        local tm_region_choice=""
        read -p "Select region [1-8] (default: 1): " tm_region_choice
        tm_region_choice="${tm_region_choice:-1}"

        local trendmicro_api_url=""
        case $tm_region_choice in
            1) trendmicro_api_url="https://api.xdr.trendmicro.com" ;;
            2) trendmicro_api_url="https://api.xdr.us.trendmicro.com" ;;
            3) trendmicro_api_url="https://api.xdr.eu.trendmicro.com" ;;
            4) trendmicro_api_url="https://api.xdr.jp.trendmicro.com" ;;
            5) trendmicro_api_url="https://api.xdr.au.trendmicro.com" ;;
            6) trendmicro_api_url="https://api.xdr.in.trendmicro.com" ;;
            7) trendmicro_api_url="https://api.xdr.sg.trendmicro.com" ;;
            8)
                read -p "Enter custom TrendMicro API URL: " trendmicro_api_url
                ;;
            *)
                trendmicro_api_url="https://api.xdr.trendmicro.com"
                log_warning "Invalid selection, using default: Global"
                ;;
        esac

        echo "Selected: $trendmicro_api_url"

        # TrendMicro API Key
        local trendmicro_api_key=""
        while [[ -z "$trendmicro_api_key" ]]; do
            read -s -p "Enter TrendMicro Vision One API Key: " trendmicro_api_key
            echo ""
            if [[ -z "$trendmicro_api_key" ]]; then
                log_error "TrendMicro API Key is required"
            fi
        done

        # Create TrendMicro secrets
        if ! create_or_update_secret "trendmicro_api_url" "$trendmicro_api_url"; then
            log_error "Failed to create TrendMicro API URL secret"
            return 1
        fi

        if ! create_or_update_secret "trendmicro_api_key" "$trendmicro_api_key"; then
            log_error "Failed to create TrendMicro API Key secret"
            return 1
        fi

        log_success "TrendMicro Vision One integration configured"
        echo "  API URL: ${trendmicro_api_url}"

        # Clear from memory
        unset trendmicro_api_key
    else
        # Create placeholder secrets to satisfy Docker Compose requirements
        create_or_update_secret "trendmicro_api_url" "https://api.xdr.trendmicro.com"
        create_or_update_secret "trendmicro_api_key" "not_configured"
        log_info "TrendMicro Vision One integration disabled"
    fi

    # ============================================================================
    # RAPID7 INSIGHTVM INTEGRATION
    # ============================================================================
    echo ""
    echo -e "${BOLD}Rapid7 InsightVM Integration${NC}"
    echo "Rapid7 InsightVM provides vulnerability assessment and risk scoring."
    echo "You will need a Rapid7 Insight API key and your region."
    echo ""

    read -p "Enable Rapid7 InsightVM integration? [y/N]: " enable_rapid7

    if [[ "$enable_rapid7" =~ ^[Yy] ]]; then
        rapid7_enabled="true"

        # Rapid7 Region Selection
        echo ""
        echo "Select Rapid7 Insight Platform Region:"
        echo "  1. US  (us)  — https://us.api.insight.rapid7.com   [default]"
        echo "  2. US2 (us2) — https://us2.api.insight.rapid7.com"
        echo "  3. US3 (us3) — https://us3.api.insight.rapid7.com"
        echo "  4. EU  (eu)  — https://eu.api.insight.rapid7.com"
        echo "  5. CA  (ca)  — https://ca.api.insight.rapid7.com"
        echo "  6. AU  (au)  — https://au.api.insight.rapid7.com"
        echo "  7. AP  (ap)  — https://ap.api.insight.rapid7.com"

        local r7_region_choice=""
        read -p "Select region [1-7] (default: 3): " r7_region_choice
        r7_region_choice="${r7_region_choice:-3}"

        local rapid7_region=""
        case $r7_region_choice in
            1) rapid7_region="us" ;;
            2) rapid7_region="us2" ;;
            3) rapid7_region="us3" ;;
            4) rapid7_region="eu" ;;
            5) rapid7_region="ca" ;;
            6) rapid7_region="au" ;;
            7) rapid7_region="ap" ;;
            *)
                rapid7_region="us3"
                log_warning "Invalid selection, using default: us3"
                ;;
        esac

        echo "Selected region: $rapid7_region  (https://${rapid7_region}.api.insight.rapid7.com)"

        # Rapid7 API Key
        local rapid7_api_key=""
        while [[ -z "$rapid7_api_key" ]]; do
            read -s -p "Enter Rapid7 Insight API Key: " rapid7_api_key
            echo ""
            if [[ -z "$rapid7_api_key" ]]; then
                log_error "Rapid7 API Key is required"
            fi
        done

        # Create Rapid7 secrets
        if ! create_or_update_secret "rapid7_region" "$rapid7_region"; then
            log_error "Failed to create Rapid7 region secret"
            return 1
        fi

        if ! create_or_update_secret "rapid7_api_key" "$rapid7_api_key"; then
            log_error "Failed to create Rapid7 API Key secret"
            return 1
        fi

        log_success "Rapid7 InsightVM integration configured"
        echo "  Region: ${rapid7_region}  (https://${rapid7_region}.api.insight.rapid7.com)"

        # Clear from memory
        unset rapid7_api_key
    else
        # Create placeholder secrets to satisfy Docker Compose requirements
        create_or_update_secret "rapid7_region" "us3"
        create_or_update_secret "rapid7_api_key" "not_configured"
        log_info "Rapid7 InsightVM integration disabled"
    fi

    # ============================================================================
    # CREATE .ENV FILE (NON-SENSITIVE CONFIGURATION)
    # ============================================================================
    
    cat > "$ENV_FILE" <<EOF
# vAnalyzer Configuration
# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# NOTE: Sensitive data (API keys, passwords) are stored in Docker secrets, not here

# Public Configuration
VANALYZER_HOSTNAME=$vanalyzer_hostname
DB_USER=$db_user
DB_NAME=$db_name
SYNC_INTERVAL=$sync_interval
METABASE_MEMORY=2g

# External Data Sources
EXTERNAL_DATA_ENABLED=$external_data_enabled
EPSS_URL=$epss_url
KEV_URL=$kev_url
VULNCHECK_ENABLED=$vulncheck_enabled

# Generated Settings
PROJECT_NAME=vanalyzer
VERSION=1.4
ENVIRONMENT=production
APP_PORT=8000
LOG_LEVEL=INFO
TRAEFIK_VERSION=latest
TRAEFIK_DASHBOARD_PORT=8080
METABASE_VERSION=v0.55.x
METABASE_HOST=$vanalyzer_hostname
STACK_NAME=vanalyzer-stack
COMPOSE_PROJECT_NAME=vanalyzer
HEALTH_CHECK_INTERVAL=30s
HEALTH_CHECK_TIMEOUT=10s
HEALTH_CHECK_RETRIES=3
HEALTH_CHECK_START_PERIOD=40s
USE_LOCAL_CA=true
SSL_CA_FILE=ca.crt
SSL_KEY_FILE=$vanalyzer_hostname.key
SSL_CRT_FILE=$vanalyzer_hostname.crt
EOF
    
    # Set proper permissions - readable by owner and group, but not world
    chmod 640 "$ENV_FILE"
    # Ensure ownership is correct (important when run with sudo)
    if [[ "${SUDO_USER:-}" ]]; then
        chown "${SUDO_USER}:${SUDO_USER}" "$ENV_FILE"
        log_step "Set ownership to ${SUDO_USER}:${SUDO_USER}"
    fi
    log_success "Configuration saved to: $ENV_FILE (non-sensitive data only)"
    
    # ============================================================================
    # CREATE DOCKER SECRETS (SENSITIVE DATA)
    # ============================================================================
    
    log_info "Creating Docker secrets for sensitive data..."
    
    # Ensure Docker Swarm is initialized
    local swarm_state=$(docker info --format '{{.Swarm.LocalNodeState}}' 2>/dev/null)
    if [[ "$swarm_state" != "active" ]]; then
        if ! init_swarm; then
            log_error "Failed to initialize Docker Swarm during configuration"
            log_warning "You may need to initialize it manually: docker swarm init"
        fi
    fi
    
    # Stop existing services to allow secret updates
    local stack_name="${STACK_NAME:-vanalyzer-stack}"
    if docker stack ls --format "{{.Name}}" 2>/dev/null | grep -q "^${stack_name}$"; then
        log_step "Stopping existing services to update secrets..."
        docker stack rm "$stack_name" >/dev/null 2>&1 || true
        # Wait for stack to be fully removed
        while docker stack ls --format "{{.Name}}" 2>/dev/null | grep -q "^${stack_name}$"; do
            sleep 2
        done
        log_success "Services stopped"
    fi
    
    # Create core Vicarius secrets
    create_or_update_secret "api_key" "$api_key"
    create_or_update_secret "dashboard_id" "$dashboard_id"
    create_or_update_secret "postgres_user" "$db_user"
    create_or_update_secret "postgres_password" "$db_password"
    create_or_update_secret "postgres_db" "$db_name"
    create_or_update_secret "optional_tools" "metabase"
    
    log_success "Docker secrets created successfully"
    
    # ============================================================================
    # SUMMARY
    # ============================================================================
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${BOLD}Configuration Summary${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "Core Configuration:"
    echo "  Hostname:        $vanalyzer_hostname"
    echo "  Dashboard ID:    $dashboard_id"
    echo "  Database:        $db_name"
    echo "  Sync Interval:   ${sync_interval}h"
    echo ""
    echo "Integrations:"
    echo "  KEV + EPSS:       $([ "$external_data_enabled" = "true" ] && echo "✓ Enabled" || echo "✗ Disabled")"
    echo "  VulnCheck:        $([ "$vulncheck_enabled"      = "true" ] && echo "✓ Enabled" || echo "✗ Disabled")"
    echo "  Tenable.io:       $([ "$tenable_enabled"        = "true" ] && echo "✓ Enabled" || echo "✗ Disabled")"
    echo "  Falcon Spotlight: $([ "$falcon_enabled"         = "true" ] && echo "✓ Enabled" || echo "✗ Disabled")"
    echo "  Qualys VMDR:      $([ "$qualys_enabled"         = "true" ] && echo "✓ Enabled" || echo "✗ Disabled")"
    echo "  ServiceNow:       $([ "$servicenow_enabled"     = "true" ] && echo "✓ Enabled" || echo "✗ Disabled")"
    echo "  MS Defender:      $([ "$mde_enabled"            = "true" ] && echo "✓ Enabled" || echo "✗ Disabled")"
    echo "  Automox:          $([ "$automox_enabled"        = "true" ] && echo "✓ Enabled" || echo "✗ Disabled")"
    echo "  Wiz:              $([ "$wiz_enabled"            = "true" ] && echo "✓ Enabled" || echo "✗ Disabled")"
    echo "  SentinelOne:      $([ "$sentinelone_enabled"    = "true" ] && echo "✓ Enabled" || echo "✗ Disabled")"
    echo "  TrendMicro V1:    $([ "$trendmicro_enabled"     = "true" ] && echo "✓ Enabled" || echo "✗ Disabled")"
    echo "  Rapid7 InsightVM: $([ "$rapid7_enabled"         = "true" ] && echo "✓ Enabled" || echo "✗ Disabled")"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Clear all sensitive variables from memory
    unset api_key
    unset db_password
    unset dashboard_id
}

# Load configuration from .env file
load_env_configuration() {
    if [[ ! -f "$ENV_FILE" ]]; then
        log_error "Configuration file not found: $ENV_FILE"
        return 1
    fi
    
    # Source the .env file
    source "$ENV_FILE"
    log_success "Configuration loaded from: $ENV_FILE"
}

# Backup function removed to prevent file clutter

# Generate certificates for configured hostname
generate_certificates_for_hostname() {
    if [[ ! -f "$ENV_FILE" ]]; then
        log_error "Configuration file not found"
        return 1
    fi
    
    # Load hostname from .env
    source "$ENV_FILE"
    local hostname="$VANALYZER_HOSTNAME"
    
    if [[ -z "$hostname" ]]; then
        log_error "Hostname not found in configuration"
        return 1
    fi
    
    log_info "Generating SSL certificates for: $hostname"
    
    # Use existing generate-ssl-certs.sh if available
    if [[ -f "${SCRIPT_DIR}/generate-ssl-certs.sh" ]]; then
        "${SCRIPT_DIR}/generate-ssl-certs.sh" create-all "$hostname"
    else
        log_warning "SSL certificate script not found, skipping certificate generation"
        log_info "Run 'vanalyzer certs generate $hostname' to generate certificates"
    fi
}

# Validate configuration
validate_configuration() {
    log_info "Validating configuration..."
    echo ""
    
    local errors=0
    local warnings=0
    
    # Check .env file
    if [[ -f "$ENV_FILE" ]]; then
        echo -e "  Environment file:   ${GREEN}✓${NC} Found"
        
        # Load configuration
        source "$ENV_FILE"
        
        # Check required fields in .env (non-sensitive)
        local required_env_fields=("VANALYZER_HOSTNAME" "DB_USER" "DB_NAME")
        for field in "${required_env_fields[@]}"; do
            if grep -q "^${field}=" "$ENV_FILE" && [[ -n "$(grep "^${field}=" "$ENV_FILE" | cut -d'=' -f2-)" ]]; then
                echo -e "  Config '$field':    ${GREEN}✓${NC} Present"
            else
                echo -e "  Config '$field':    ${RED}✗${NC} Missing"
                ((errors++))
            fi
        done
        
        # Check required Docker secrets (sensitive data)
        echo ""
        echo "  Checking Docker secrets:"
        local required_secrets=("api_key" "dashboard_id" "postgres_user" "postgres_password" "postgres_db")
        for secret in "${required_secrets[@]}"; do
            if docker secret ls --format "{{.Name}}" 2>/dev/null | grep -q "^${secret}$"; then
                echo -e "  Secret '$secret':   ${GREEN}✓${NC} Present"
            else
                echo -e "  Secret '$secret':   ${RED}✗${NC} Missing"
                ((errors++))
            fi
        done
        
        # Check optional integration secrets
        echo ""
        echo "  Checking integration secrets:"
        local integration_secrets=(
            "tenable_access_key"
            "tenable_secret_key"
            "falcon_client_id"
            "falcon_client_secret"
            "falcon_base_url"
            "qualys_username"
            "qualys_password"
            "qualys_api_url"
            "servicenow_user"
            "servicenow_password"
            "servicenow_instance_url"
            "mde_tenant_id"
            "mde_client_id"
            "mde_client_secret"
            "automox_api_key"
            "automox_org_id"
            "wiz_client_id"
            "wiz_client_secret"
            "wiz_api_endpoint_url"
            "sentinelone_api_url"
            "sentinelone_api_token"
            "trendmicro_api_key"
            "trendmicro_api_url"
            "rapid7_api_key"
            "rapid7_region"
        )
        for secret in "${integration_secrets[@]}"; do
            if docker secret ls --format "{{.Name}}" 2>/dev/null | grep -q "^${secret}$"; then
                echo -e "  Secret '$secret':   ${GREEN}✓${NC} Present"
            else
                echo -e "  Secret '$secret':   ${YELLOW}⚠${NC} Missing (optional)"
                ((warnings++))
            fi
        done
        
        # Check certificates
        local hostname=$(grep "^VANALYZER_HOSTNAME=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2- | tr -d '"')
        if [[ -n "$hostname" ]]; then
            local cert_file="${SCRIPT_DIR}/traefik/config/certs/${hostname}.crt"
            local key_file="${SCRIPT_DIR}/traefik/config/certs/${hostname}.key"
            
            if [[ -f "$cert_file" ]] && [[ -f "$key_file" ]]; then
                echo -e "  SSL certificates:   ${GREEN}✓${NC} Found"
            else
                echo -e "  SSL certificates:   ${YELLOW}⚠${NC} Not found (will be generated)"
                ((warnings++))
            fi
        else
            echo -e "  SSL certificates:   ${YELLOW}⚠${NC} No hostname configured"
            ((warnings++))
        fi
    else
        echo -e "  Environment file:   ${RED}✗${NC} Not found"
        echo -e "                      Run 'vanalyzer init' to create configuration"
        ((errors++))
    fi
    
    echo ""
    
    # Check Docker
    if check_runtime 2>/dev/null; then
        echo -e "  Container runtime:  ${GREEN}✓${NC} ${RUNTIME} running"
    else
        echo -e "  Container runtime:  ${RED}✗${NC} Not running"
        ((errors++))
    fi
    
    # Check Swarm
    if docker info 2>/dev/null | grep -q "Swarm: active"; then
        echo -e "  Docker Swarm:       ${GREEN}✓${NC} Active"
    else
        echo -e "  Docker Swarm:       ${YELLOW}⚠${NC} Not initialized"
        ((warnings++))
    fi
    
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    if [[ $errors -eq 0 ]]; then
        if [[ $warnings -eq 0 ]]; then
            echo -e "${GREEN}✓ Configuration is valid and ready${NC}"
        else
            echo -e "${YELLOW}⚠ Configuration has $warnings warning(s)${NC}"
            echo "  These will be addressed during deployment"
        fi
        return 0
    else
        echo -e "${RED}✗ Configuration has $errors error(s)${NC}"
        echo "  Please run 'vanalyzer init' to fix configuration"
        return 1
    fi
}

# Export simplified config functions
export -f create_or_update_secret
export -f init_configuration interactive_simple_setup
export -f load_env_configuration
export -f generate_certificates_for_hostname validate_configuration
