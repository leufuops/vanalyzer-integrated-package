# Author: Raúl Herrera Pailemilla
# Supports: Tenable, CrowdStrike Falcon Spotlight, Qualys, ServiceNow,
#           Microsoft Defender for Endpoint (MDE), Automox, Wiz,
#           SentinelOne, TrendMicro Vision One, Rapid7 InsightVM

import psycopg2
from datetime import datetime

# ============================================================================
# TENABLE INTEGRATION TABLES
# ============================================================================

def check_create_table_tenable_assets_current(host, port, user, password, database):
    """
    Creates table for Tenable current assets
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS tenable_assets_current (
        asset_uuid UUID NOT NULL PRIMARY KEY,
        hostname TEXT,
        ipv4 INET,
        os_name TEXT,
        last_seen TIMESTAMP WITH TIME ZONE,
        data JSONB,
        ingested_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
    );
    
    CREATE INDEX IF NOT EXISTS tenable_assets_current_hostname_idx 
        ON tenable_assets_current(hostname);
    CREATE INDEX IF NOT EXISTS tenable_assets_current_ipv4_idx 
        ON tenable_assets_current(ipv4);
    CREATE INDEX IF NOT EXISTS tenable_assets_current_last_seen_idx 
        ON tenable_assets_current(last_seen);
    """
    
    cur.execute(create_table_query)
    print("The table 'tenable_assets_current' was created or already exists")
    
    cur.close()
    conn.close()

def check_create_table_tenable_findings_current(host, port, user, password, database):
    """
    Creates table for Tenable current vulnerability findings
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS tenable_findings_current (
        finding_id TEXT NOT NULL PRIMARY KEY,
        asset_uuid UUID NOT NULL,
        plugin_id INTEGER NOT NULL,
        cve_id TEXT NOT NULL,
        severity TEXT,
        vpr_score NUMERIC(4,1),
        state TEXT,
        first_found TIMESTAMP WITH TIME ZONE,
        plugin_output TEXT,
        ingested_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
        CONSTRAINT tenable_findings_current_asset_uuid_fkey 
            FOREIGN KEY (asset_uuid) 
            REFERENCES tenable_assets_current(asset_uuid) 
            ON DELETE CASCADE
    );
    
    CREATE INDEX IF NOT EXISTS tenable_findings_current_asset_idx 
        ON tenable_findings_current(asset_uuid);
    CREATE INDEX IF NOT EXISTS tenable_findings_current_cve_idx 
        ON tenable_findings_current(cve_id);
    CREATE INDEX IF NOT EXISTS tenable_findings_current_state_idx 
        ON tenable_findings_current(state);
    """
    
    cur.execute(create_table_query)
    print("The table 'tenable_findings_current' was created or already exists")
    
    cur.close()
    conn.close()

def check_create_table_tenable_finding_evidence_current(host, port, user, password, database):
    """
    Creates table for Tenable finding evidence
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS tenable_finding_evidence_current (
        finding_id TEXT NOT NULL PRIMARY KEY,
        protocol TEXT,
        port INTEGER,
        service_name TEXT,
        plugin_output_full TEXT,
        data JSONB NOT NULL DEFAULT '{}'::JSONB,
        updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
        CONSTRAINT fk_tenable_finding_evidence_current_finding 
            FOREIGN KEY (finding_id) 
            REFERENCES tenable_findings_current(finding_id) 
            ON DELETE CASCADE
    );
    """
    
    cur.execute(create_table_query)
    print("The table 'tenable_finding_evidence_current' was created or already exists")
    
    cur.close()
    conn.close()

def check_create_table_tenable_finding_ports(host, port, user, password, database):
    """
    Creates table for Tenable finding port details
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS tenable_finding_ports (
        id BIGSERIAL PRIMARY KEY,
        finding_id TEXT NOT NULL,
        asset_uuid UUID NOT NULL,
        plugin_id INTEGER NOT NULL,
        cve_id TEXT,
        protocol TEXT,
        port INTEGER,
        service_name TEXT,
        plugin_output_full TEXT,
        data JSONB,
        updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
        CONSTRAINT fk_tenable_finding_ports_finding 
            FOREIGN KEY (finding_id) 
            REFERENCES tenable_findings_current(finding_id) 
            ON DELETE CASCADE
    );
    
    CREATE INDEX IF NOT EXISTS ix_tenable_finding_ports_asset_uuid 
        ON tenable_finding_ports(asset_uuid);
    CREATE INDEX IF NOT EXISTS ix_tenable_finding_ports_cve_id 
        ON tenable_finding_ports(cve_id);
    CREATE INDEX IF NOT EXISTS ix_tenable_finding_ports_finding_id 
        ON tenable_finding_ports(finding_id);
    CREATE INDEX IF NOT EXISTS ix_tenable_finding_ports_plugin_id 
        ON tenable_finding_ports(plugin_id);
    CREATE INDEX IF NOT EXISTS ix_tenable_finding_ports_port 
        ON tenable_finding_ports(port);
    CREATE UNIQUE INDEX IF NOT EXISTS ux_tenable_finding_ports_dedupe 
        ON tenable_finding_ports(finding_id, COALESCE(protocol, ''), port, COALESCE(service_name, ''))
        WHERE port IS NOT NULL;
    """
    
    cur.execute(create_table_query)
    print("The table 'tenable_finding_ports' was created or already exists")
    
    cur.close()
    conn.close()

def check_create_table_tenable_findings_history(host, port, user, password, database):
    """
    Creates table for Tenable findings history (remediated vulnerabilities)
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS tenable_findings_history (
        history_id BIGSERIAL PRIMARY KEY,
        asset_uuid UUID NOT NULL,
        cve_id TEXT NOT NULL,
        severity TEXT,
        first_found TIMESTAMP WITH TIME ZONE,
        fixed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
        days_to_fix INTEGER
    );
    """
    
    cur.execute(create_table_query)
    print("The table 'tenable_findings_history' was created or already exists")
    
    cur.close()
    conn.close()

def check_create_table_tenable_ingest_runs(host, port, user, password, database):
    """
    Creates table for tracking Tenable ingestion runs
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS tenable_ingest_runs (
        run_id BIGSERIAL PRIMARY KEY,
        start_time TIMESTAMP WITH TIME ZONE NOT NULL,
        end_time TIMESTAMP WITH TIME ZONE NOT NULL,
        status TEXT NOT NULL,
        assets_count INTEGER NOT NULL DEFAULT 0,
        findings_count INTEGER NOT NULL DEFAULT 0
    );
    
    CREATE INDEX IF NOT EXISTS tenable_ingest_runs_start_idx 
        ON tenable_ingest_runs(start_time);
    CREATE INDEX IF NOT EXISTS tenable_ingest_runs_status_idx 
        ON tenable_ingest_runs(status);
    """
    
    cur.execute(create_table_query)
    print("The table 'tenable_ingest_runs' was created or already exists")
    
    cur.close()
    conn.close()

def check_create_table_tenable_plugin_cve_map(host, port, user, password, database):
    """
    Creates table for Tenable plugin to CVE mapping
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS tenable_plugin_cve_map (
        plugin_id INTEGER NOT NULL,
        cve_id TEXT NOT NULL,
        mapping_added TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
        PRIMARY KEY (plugin_id, cve_id)
    );
    
    CREATE INDEX IF NOT EXISTS tenable_plugin_cve_map_cve_idx 
        ON tenable_plugin_cve_map(cve_id);
    """
    
    cur.execute(create_table_query)
    print("The table 'tenable_plugin_cve_map' was created or already exists")
    
    cur.close()
    conn.close()

# ============================================================================
# CROWDSTRIKE FALCON SPOTLIGHT INTEGRATION TABLES
# ============================================================================

def check_create_table_falcon_spotlight_dim_hosts(host, port, user, password, database):
    """
    Creates table for CrowdStrike Falcon Spotlight host dimension
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS falcon_spotlight_dim_hosts (
        aid TEXT NOT NULL PRIMARY KEY,
        device_id TEXT,
        hostname TEXT,
        os_version TEXT,
        os_build TEXT,
        local_ip TEXT,
        external_ip TEXT,
        machine_domain TEXT,
        system_serial_number TEXT,
        last_seen TIMESTAMP WITH TIME ZONE,
        updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
        raw_host_info_b64 TEXT NOT NULL DEFAULT '',
        raw_device_b64 TEXT NOT NULL DEFAULT '',
        raw_host_info_text TEXT,
        raw_device_text TEXT,
        platform TEXT,
        product_type_desc TEXT,
        service_provider TEXT,
        service_provider_account_id TEXT,
        system_manufacturer TEXT,
        internet_exposure TEXT,
        asset_criticality TEXT,
        managed_by TEXT,
        ou TEXT,
        site_name TEXT,
        tags_csv TEXT,
        host_instance_id TEXT,
        raw_host_kv_text TEXT,
        raw_device_kv_text TEXT
    );
    
    CREATE INDEX IF NOT EXISTS idx_fss_hosts_hostname 
        ON falcon_spotlight_dim_hosts(hostname);
    CREATE INDEX IF NOT EXISTS idx_fss_hosts_last_seen 
        ON falcon_spotlight_dim_hosts(last_seen);
    """
    
    cur.execute(create_table_query)
    print("The table 'falcon_spotlight_dim_hosts' was created or already exists")
    
    cur.close()
    conn.close()

def check_create_table_falcon_spotlight_dim_vulnerabilities(host, port, user, password, database):
    """
    Creates table for CrowdStrike Falcon Spotlight vulnerability dimension
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS falcon_spotlight_dim_vulnerabilities (
        cve_id TEXT NOT NULL PRIMARY KEY,
        severity TEXT,
        cvss_score NUMERIC,
        exprt_score NUMERIC,
        exploit_status TEXT,
        cisa_kev BOOLEAN,
        description TEXT,
        updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
        raw_cve_b64 TEXT NOT NULL DEFAULT '',
        vector TEXT,
        published_date TIMESTAMP WITH TIME ZONE,
        spotlight_published_date TIMESTAMP WITH TIME ZONE,
        cwes_csv TEXT,
        references_csv TEXT,
        vendor_advisory_csv TEXT,
        types_csv TEXT,
        raw_cve_text TEXT,
        exploitability_score NUMERIC,
        impact_score NUMERIC,
        exprt_rating TEXT,
        remediation_level TEXT,
        raw_cve_kv_text TEXT
    );
    
    CREATE INDEX IF NOT EXISTS idx_fss_vuln_exprt_score 
        ON falcon_spotlight_dim_vulnerabilities(exprt_score DESC);
    CREATE INDEX IF NOT EXISTS idx_fss_vuln_severity 
        ON falcon_spotlight_dim_vulnerabilities(severity);
    """
    
    cur.execute(create_table_query)
    print("The table 'falcon_spotlight_dim_vulnerabilities' was created or already exists")
    
    cur.close()
    conn.close()

def check_create_table_falcon_spotlight_dim_evaluation_logic(host, port, user, password, database):
    """
    Creates table for CrowdStrike Falcon Spotlight evaluation logic dimension
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS falcon_spotlight_dim_evaluation_logic (
        evaluation_logic_id TEXT NOT NULL PRIMARY KEY,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
        raw_evaluation_logic_b64 TEXT NOT NULL DEFAULT '',
        raw_evaluation_logic_text TEXT,
        raw_evaluation_logic_kv_text TEXT
    );
    """
    
    cur.execute(create_table_query)
    print("The table 'falcon_spotlight_dim_evaluation_logic' was created or already exists")
    
    cur.close()
    conn.close()

def check_create_table_falcon_spotlight_dim_remediations(host, port, user, password, database):
    """
    Creates table for CrowdStrike Falcon Spotlight remediation dimension
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS falcon_spotlight_dim_remediations (
        remediation_id TEXT NOT NULL PRIMARY KEY,
        title TEXT,
        action_priority TEXT,
        vendor_url TEXT,
        description TEXT,
        updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
        raw_remediation_b64 TEXT NOT NULL DEFAULT '',
        raw_remediation_text TEXT,
        action TEXT,
        recommendation_type TEXT,
        reference TEXT,
        status TEXT,
        raw_remediation_kv_text TEXT
    );
    
    CREATE INDEX IF NOT EXISTS idx_fss_rem_priority 
        ON falcon_spotlight_dim_remediations(action_priority);
    CREATE INDEX IF NOT EXISTS idx_fss_rem_title 
        ON falcon_spotlight_dim_remediations(title);
    """
    
    cur.execute(create_table_query)
    print("The table 'falcon_spotlight_dim_remediations' was created or already exists")
    
    cur.close()
    conn.close()

def check_create_table_falcon_spotlight_fact_vulnerability_instances(host, port, user, password, database):
    """
    Creates table for CrowdStrike Falcon Spotlight vulnerability instances fact table
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS falcon_spotlight_fact_vulnerability_instances (
        instance_id TEXT NOT NULL PRIMARY KEY,
        aid TEXT NOT NULL,
        cve_id TEXT,
        status TEXT,
        created_timestamp TIMESTAMP WITH TIME ZONE,
        updated_timestamp TIMESTAMP WITH TIME ZONE,
        closed_timestamp TIMESTAMP WITH TIME ZONE,
        confidence TEXT,
        remediation_id TEXT,
        remediation_ids_csv TEXT,
        remediation_ids_count INTEGER,
        raw_instance_b64 TEXT NOT NULL DEFAULT '',
        cid TEXT,
        data_providers_csv TEXT,
        raw_instance_text TEXT,
        vulnerability_id TEXT,
        vulnerability_metadata_id TEXT,
        sub_status TEXT,
        suppression_is_suppressed BOOLEAN,
        raw_instance_kv_text TEXT,
        CONSTRAINT fk_fss_fvi_cves 
            FOREIGN KEY (cve_id) 
            REFERENCES falcon_spotlight_dim_vulnerabilities(cve_id) 
            ON UPDATE CASCADE ON DELETE RESTRICT,
        CONSTRAINT fk_fss_fvi_hosts 
            FOREIGN KEY (aid) 
            REFERENCES falcon_spotlight_dim_hosts(aid) 
            ON UPDATE CASCADE ON DELETE RESTRICT
    );
    
    CREATE INDEX IF NOT EXISTS idx_fss_fvi_aid 
        ON falcon_spotlight_fact_vulnerability_instances(aid);
    CREATE INDEX IF NOT EXISTS idx_fss_fvi_cve_id 
        ON falcon_spotlight_fact_vulnerability_instances(cve_id);
    CREATE INDEX IF NOT EXISTS idx_fss_fvi_status 
        ON falcon_spotlight_fact_vulnerability_instances(status);
    CREATE INDEX IF NOT EXISTS idx_fss_fvi_updated_ts 
        ON falcon_spotlight_fact_vulnerability_instances(updated_timestamp DESC);
    """
    
    cur.execute(create_table_query)
    print("The table 'falcon_spotlight_fact_vulnerability_instances' was created or already exists")
    
    cur.close()
    conn.close()

def check_create_table_falcon_spotlight_rel_apps(host, port, user, password, database):
    """
    Creates table for CrowdStrike Falcon Spotlight application relationships
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS falcon_spotlight_rel_apps (
        instance_id TEXT NOT NULL,
        seq INTEGER NOT NULL,
        sub_status TEXT,
        vendor_normalized TEXT,
        product_name_normalized TEXT,
        product_name_version TEXT,
        remediation_ids_csv TEXT,
        recommended_remediation_id TEXT,
        evaluation_logic_id TEXT,
        raw_app_kv_text TEXT,
        PRIMARY KEY (instance_id, seq),
        CONSTRAINT fk_fss_apps_instance 
            FOREIGN KEY (instance_id) 
            REFERENCES falcon_spotlight_fact_vulnerability_instances(instance_id) 
            ON DELETE CASCADE
    );
    """
    
    cur.execute(create_table_query)
    print("The table 'falcon_spotlight_rel_apps' was created or already exists")
    
    cur.close()
    conn.close()

def check_create_table_falcon_spotlight_rel_evaluation_logic(host, port, user, password, database):
    """
    Creates table for CrowdStrike Falcon Spotlight evaluation logic relationships
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS falcon_spotlight_rel_evaluation_logic (
        instance_id TEXT NOT NULL,
        seq INTEGER NOT NULL,
        logic_type TEXT,
        app_name TEXT,
        app_version TEXT,
        file_path TEXT,
        evidence_id TEXT,
        aid TEXT,
        cid TEXT,
        data_provider TEXT,
        created_timestamp TIMESTAMP WITH TIME ZONE,
        updated_timestamp TIMESTAMP WITH TIME ZONE,
        simplified_logic_text TEXT,
        evidence_details_b64 TEXT NOT NULL DEFAULT '',
        entities_matched_csv TEXT,
        logic_items_csv TEXT,
        evidence_details_text TEXT,
        simplified_logic_csv TEXT,
        logic_titles_csv TEXT,
        raw_evidence_kv_text TEXT,
        CONSTRAINT pk_fss_eval PRIMARY KEY (instance_id, seq),
        CONSTRAINT fk_fss_eval_instance 
            FOREIGN KEY (instance_id) 
            REFERENCES falcon_spotlight_fact_vulnerability_instances(instance_id) 
            ON UPDATE CASCADE ON DELETE CASCADE
    );
    
    CREATE INDEX IF NOT EXISTS idx_fss_eval_app_name 
        ON falcon_spotlight_rel_evaluation_logic(app_name);
    CREATE INDEX IF NOT EXISTS idx_fss_eval_file_path 
        ON falcon_spotlight_rel_evaluation_logic(file_path);
    """
    
    cur.execute(create_table_query)
    print("The table 'falcon_spotlight_rel_evaluation_logic' was created or already exists")
    
    cur.close()
    conn.close()

# ============================================================================
# QUALYS INTEGRATION TABLES
# ============================================================================

def check_create_table_qualys_asset(host, port, user, password, database):
    """
    Creates table for Qualys assets
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS qualys_asset (
        asset_pk BIGSERIAL PRIMARY KEY,
        host_asset_id BIGINT UNIQUE,
        qweb_host_id BIGINT,
        network_guid TEXT,
        name TEXT,
        dns_host_name TEXT,
        fqdn TEXT,
        netbios_name TEXT,
        address INET,
        os TEXT,
        manufacturer TEXT,
        model TEXT,
        bios_description TEXT,
        account JSONB,
        cloud_provider TEXT,
        tracking_method TEXT,
        asset_type TEXT,
        timezone TEXT,
        total_memory_mb INTEGER,
        created_at TIMESTAMP WITH TIME ZONE,
        modified_at TIMESTAMP WITH TIME ZONE,
        information_gathered_updated_at TIMESTAMP WITH TIME ZONE,
        last_compliance_scan_at TIMESTAMP WITH TIME ZONE,
        last_vuln_scan_at TIMESTAMP WITH TIME ZONE,
        last_system_boot_at TIMESTAMP WITH TIME ZONE,
        last_logged_on_user TEXT,
        vulns_updated_at TIMESTAMP WITH TIME ZONE,
        is_docker_host BOOLEAN,
        docker_version TEXT,
        docker_no_of_containers INTEGER,
        docker_no_of_images INTEGER,
        agent_activated_module TEXT,
        agent_activation_id TEXT,
        agent_activation_title TEXT,
        agent_configuration_id INTEGER,
        agent_configuration_name TEXT,
        agent_id TEXT,
        agent_version TEXT,
        agent_chirp_status TEXT,
        agent_connected_from TEXT,
        agent_last_checked_in_at TIMESTAMP WITH TIME ZONE,
        agent_location TEXT,
        agent_location_geo_latitude NUMERIC,
        agent_location_geo_longitude NUMERIC,
        agent_manifest_sca TEXT,
        agent_manifest_vm TEXT,
        agent_platform TEXT,
        agent_status TEXT,
        network_interface_raw JSONB,
        open_port_raw JSONB,
        processor_raw JSONB,
        software_raw JSONB,
        source_info_raw JSONB,
        tags_raw JSONB,
        volume_raw JSONB,
        vuln_raw JSONB,
        src_asset_id TEXT,
        src_first_discovered_at TIMESTAMP WITH TIME ZONE,
        src_gcp_instance_tags JSONB,
        src_host_asset_name TEXT,
        src_hostname TEXT,
        src_image_id TEXT,
        src_instance_id TEXT,
        src_last_updated_at TIMESTAMP WITH TIME ZONE,
        src_mac_address TEXT,
        src_machine_type TEXT,
        src_network TEXT,
        src_private_ip INET,
        src_project_id TEXT,
        src_project_id_no TEXT,
        src_public_ip INET,
        src_state TEXT,
        src_type TEXT,
        src_zone TEXT,
        network_interfaces_export_raw JSONB,
        volumes_export_raw JSONB,
        processors_export_raw JSONB,
        accounts_export_raw JSONB,
        software_export_raw JSONB,
        tags_assigned_export_raw JSONB,
        tags_catalog_export_raw JSONB,
        agent_info_export_raw JSONB,
        vicarius_endpoint_hash TEXT,
        vicarius_endpoint_id TEXT,
        raw_host_assets_row JSONB
    );
    
    CREATE INDEX IF NOT EXISTS idx_qualys_asset_address 
        ON qualys_asset(address);
    CREATE INDEX IF NOT EXISTS idx_qualys_asset_dns 
        ON qualys_asset(dns_host_name);
    CREATE INDEX IF NOT EXISTS idx_qualys_asset_fqdn 
        ON qualys_asset(fqdn);
    CREATE INDEX IF NOT EXISTS idx_qualys_asset_host_asset_id 
        ON qualys_asset(host_asset_id);
    """
    
    cur.execute(create_table_query)
    print("The table 'qualys_asset' was created or already exists")
    
    cur.close()
    conn.close()

def check_create_table_qualys_asset_open_port(host, port, user, password, database):
    """
    Creates table for Qualys asset open ports
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS qualys_asset_open_port (
        open_port_pk BIGSERIAL PRIMARY KEY,
        asset_pk BIGINT NOT NULL,
        host_asset_id BIGINT NOT NULL,
        host_asset_name TEXT,
        port INTEGER,
        protocol TEXT,
        service_name TEXT,
        raw_open_ports_row JSONB,
        CONSTRAINT qualys_asset_open_port_asset_pk_fkey 
            FOREIGN KEY (asset_pk) 
            REFERENCES qualys_asset(asset_pk)
    );
    
    CREATE INDEX IF NOT EXISTS idx_qualys_open_port_hostasset 
        ON qualys_asset_open_port(host_asset_id);
    CREATE INDEX IF NOT EXISTS idx_qualys_open_port_portproto 
        ON qualys_asset_open_port(protocol, port);
    """
    
    cur.execute(create_table_query)
    print("The table 'qualys_asset_open_port' was created or already exists")
    
    cur.close()
    conn.close()

def check_create_table_qualys_qid_kb(host, port, user, password, database):
    """
    Creates table for Qualys QID knowledge base
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS qualys_qid_kb (
        qid INTEGER NOT NULL PRIMARY KEY,
        vuln_type TEXT,
        severity_level INTEGER,
        title TEXT,
        category TEXT,
        last_service_modification_at TIMESTAMP WITH TIME ZONE,
        published_at TIMESTAMP WITH TIME ZONE,
        code_modified_at TIMESTAMP WITH TIME ZONE,
        patchable BOOLEAN,
        diagnosis TEXT,
        consequence TEXT,
        solution TEXT,
        pci_flag BOOLEAN,
        cve_ids_text TEXT,
        cve_count INTEGER,
        cve_urls_text TEXT,
        bugtraq_ids_text TEXT,
        vendor_references_text TEXT,
        software_affected_text TEXT,
        threat_intelligence_text TEXT,
        compliance_text TEXT,
        discovery_auth_types_text TEXT,
        technology_text TEXT,
        kb_bugtraq_ids TEXT,
        kb_category TEXT,
        kb_compliance TEXT,
        kb_consequence TEXT,
        kb_cve_ids TEXT,
        kb_cvss3_attack_complexity TEXT,
        kb_cvss3_attack_vector TEXT,
        kb_cvss3_base TEXT,
        kb_cvss3_privileges_req TEXT,
        kb_cvss3_temporal TEXT,
        kb_cvss3_vector TEXT,
        kb_cvss_base TEXT,
        kb_cvss_temporal TEXT,
        kb_cvss_vector TEXT,
        kb_diagnosis TEXT,
        kb_last_modified_at TIMESTAMP WITH TIME ZONE,
        kb_patch_published_text TEXT,
        kb_patchable BOOLEAN,
        kb_published_at TIMESTAMP WITH TIME ZONE,
        kb_severity INTEGER,
        kb_software_affected TEXT,
        kb_solution TEXT,
        kb_technology TEXT,
        kb_threat_intelligence TEXT,
        kb_title TEXT,
        kb_vendor_refs TEXT,
        kb_vuln_type TEXT,
        cve_mapping_entries_raw JSONB,
        qvs_by_cve_raw JSONB,
        raw_knowledgebase_row JSONB
    );
    
    CREATE INDEX IF NOT EXISTS idx_qualys_qid_kb_patchable 
        ON qualys_qid_kb(patchable);
    CREATE INDEX IF NOT EXISTS idx_qualys_qid_kb_severity 
        ON qualys_qid_kb(severity_level);
    """
    
    cur.execute(create_table_query)
    print("The table 'qualys_qid_kb' was created or already exists")
    
    cur.close()
    conn.close()

def check_create_table_qualys_finding(host, port, user, password, database):
    """
    Creates table for Qualys vulnerability findings
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS qualys_finding (
        finding_pk BIGSERIAL PRIMARY KEY,
        asset_pk BIGINT NOT NULL,
        host_asset_id BIGINT NOT NULL,
        qid INTEGER NOT NULL,
        cve_id TEXT,
        vuln_id BIGINT,
        disabled BOOLEAN,
        first_found_at TIMESTAMP WITH TIME ZONE,
        found BOOLEAN,
        ignored BOOLEAN,
        last_found_at TIMESTAMP WITH TIME ZONE,
        last_scanned_at TIMESTAMP WITH TIME ZONE,
        source TEXT,
        ssl BOOLEAN,
        updated_at TIMESTAMP WITH TIME ZONE,
        port_text TEXT,
        protocol TEXT,
        kb_cve_ids_text TEXT,
        raw_vulnerabilities_row JSONB,
        raw_crossed_report_row JSONB,
        CONSTRAINT qualys_finding_asset_pk_fkey 
            FOREIGN KEY (asset_pk) 
            REFERENCES qualys_asset(asset_pk),
        CONSTRAINT qualys_finding_qid_fkey 
            FOREIGN KEY (qid) 
            REFERENCES qualys_qid_kb(qid)
    );
    
    CREATE INDEX IF NOT EXISTS idx_qualys_finding_cve 
        ON qualys_finding(cve_id);
    CREATE INDEX IF NOT EXISTS idx_qualys_finding_hostasset 
        ON qualys_finding(host_asset_id);
    CREATE INDEX IF NOT EXISTS idx_qualys_finding_qid 
        ON qualys_finding(qid);
    """
    
    cur.execute(create_table_query)
    print("The table 'qualys_finding' was created or already exists")
    
    cur.close()
    conn.close()

def check_create_table_qualys_finding_evidence(host, port, user, password, database):
    """
    Creates table for Qualys finding evidence
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS qualys_finding_evidence (
        evidence_pk BIGSERIAL PRIMARY KEY,
        asset_pk BIGINT NOT NULL,
        host_asset_id BIGINT NOT NULL,
        qid INTEGER NOT NULL,
        first_found_at TIMESTAMP WITH TIME ZONE,
        host_asset_name TEXT,
        host_instance_vuln_id BIGINT,
        last_found_at TIMESTAMP WITH TIME ZONE,
        raw_vulns_embedded_row JSONB,
        CONSTRAINT qualys_finding_evidence_asset_pk_fkey 
            FOREIGN KEY (asset_pk) 
            REFERENCES qualys_asset(asset_pk),
        CONSTRAINT qualys_finding_evidence_qid_fkey 
            FOREIGN KEY (qid) 
            REFERENCES qualys_qid_kb(qid)
    );
    
    CREATE INDEX IF NOT EXISTS idx_qualys_evidence_hostasset 
        ON qualys_finding_evidence(host_asset_id);
    CREATE INDEX IF NOT EXISTS idx_qualys_evidence_instance 
        ON qualys_finding_evidence(host_instance_vuln_id);
    CREATE INDEX IF NOT EXISTS idx_qualys_evidence_qid 
        ON qualys_finding_evidence(qid);
    """
    
    cur.execute(create_table_query)
    print("The table 'qualys_finding_evidence' was created or already exists")
    
    cur.close()
    conn.close()

# ============================================================================
# SERVICENOW INTEGRATION TABLES
# ============================================================================

def check_create_table_snow_problem_vuln_tickets(host, port, user, password, database):
    """
    Creates table for ServiceNow Problem vulnerability tickets
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS snow_problem_vuln_tickets (
        id                                    BIGSERIAL NOT NULL PRIMARY KEY,
        correlation_key                       TEXT NOT NULL UNIQUE,
        asset                                 TEXT NOT NULL,
        cve                                   TEXT NOT NULL,
        endpoint_hash                         TEXT,
        endpoint_id                           INTEGER,
        product_name                          TEXT,
        product_raw_entry_name                TEXT,
        version                               TEXT,
        sensitivity_level_name                TEXT,
        cvss_v3_base_score                    DOUBLE PRECISION,
        vulnerability_v3_exploitability_level DOUBLE PRECISION,
        vulnerability_summary                 TEXT,
        reference_link                        TEXT,
        sn_table                              TEXT NOT NULL DEFAULT 'problem',
        sn_sys_id                             TEXT NOT NULL,
        sn_number                             TEXT,
        sn_url                                TEXT,
        sn_state                              TEXT,
        sn_state_category                     TEXT NOT NULL DEFAULT 'open',
        is_active                             BOOLEAN NOT NULL DEFAULT TRUE,
        first_detected_at                     TIMESTAMP WITHOUT TIME ZONE NOT NULL,
        last_detected_at                      TIMESTAMP WITHOUT TIME ZONE NOT NULL,
        ticket_created_at                     TIMESTAMP WITHOUT TIME ZONE NOT NULL,
        mitigated_detected_at                 TIMESTAMP WITHOUT TIME ZONE,
        ticket_resolved_at                    TIMESTAMP WITHOUT TIME ZONE,
        closed_reason                         TEXT
    );

    CREATE INDEX IF NOT EXISTS snow_problem_vuln_tickets_asset_cve_idx
        ON snow_problem_vuln_tickets(asset, cve);
    CREATE INDEX IF NOT EXISTS snow_problem_vuln_tickets_endpointhash_cve_idx
        ON snow_problem_vuln_tickets(endpoint_hash, cve);
    CREATE INDEX IF NOT EXISTS snow_problem_vuln_tickets_sn_sys_id_idx
        ON snow_problem_vuln_tickets(sn_sys_id);
    CREATE INDEX IF NOT EXISTS snow_problem_vuln_tickets_state_active_idx
        ON snow_problem_vuln_tickets(sn_state_category, is_active);
    """

    cur.execute(create_table_query)
    print("The table 'snow_problem_vuln_tickets' was created or already exists")

    cur.close()
    conn.close()

# ============================================================================
# MICROSOFT DEFENDER FOR ENDPOINT (MDE) INTEGRATION TABLES
# ============================================================================

def check_create_table_mde_etl_runs(host, port, user, password, database):
    """
    Creates table for tracking MDE ETL runs.
    Must be created before mde_asset_vuln due to FK dependency.
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS public.mde_etl_runs (
        run_id        BIGINT      NOT NULL GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
        source        TEXT        NOT NULL DEFAULT 'mde',
        object_type   TEXT        NOT NULL DEFAULT 'tvm_vulns',
        started_at    TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
        finished_at   TIMESTAMP WITH TIME ZONE,
        status        TEXT        NOT NULL DEFAULT 'running',
        rows_fetched  INTEGER,
        rows_upserted INTEGER,
        error         TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_mde_etl_runs_src
        ON public.mde_etl_runs(source, object_type, started_at DESC);
    """

    cur.execute(create_table_query)
    print("The table 'mde_etl_runs' was created or already exists")

    cur.close()
    conn.close()


def check_create_table_mde_asset(host, port, user, password, database):
    """
    Creates table for MDE device/asset inventory.
    Must be created before mde_asset_vuln due to FK dependency.
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS public.mde_asset (
        device_id         TEXT                     NOT NULL PRIMARY KEY,
        computer_dns_name TEXT,
        device_name       TEXT,
        rbac_group_name   TEXT,
        os_platform       TEXT,
        os_version        TEXT,
        os_architecture   TEXT,
        os_processor      TEXT,
        agent_version     TEXT,
        health_status     TEXT,
        risk_score        TEXT,
        exposure_level    TEXT,
        device_value      TEXT,
        onboarding_status TEXT,
        is_aad_joined     BOOLEAN,
        last_seen         TIMESTAMP WITH TIME ZONE,
        machine_tags      JSONB,
        inventory_json    JSONB,
        created_at        TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
        updated_at        TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_mde_asset_dns
        ON public.mde_asset(computer_dns_name);
    CREATE INDEX IF NOT EXISTS idx_mde_asset_lastseen
        ON public.mde_asset(last_seen DESC);
    CREATE INDEX IF NOT EXISTS idx_mde_asset_os
        ON public.mde_asset(os_platform, os_version);
    CREATE INDEX IF NOT EXISTS idx_mde_asset_rbac
        ON public.mde_asset(rbac_group_name);
    CREATE INDEX IF NOT EXISTS idx_mde_asset_tags_gin
        ON public.mde_asset USING GIN (machine_tags);
    """

    cur.execute(create_table_query)
    print("The table 'mde_asset' was created or already exists")

    cur.close()
    conn.close()


def check_create_table_mde_cve(host, port, user, password, database):
    """
    Creates table for MDE CVE/vulnerability knowledge base.
    Must be created before mde_asset_vuln due to FK dependency.
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS public.mde_cve (
        cve_id           TEXT          NOT NULL PRIMARY KEY
            CONSTRAINT chk_mde_cve_format CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
        name             TEXT,
        severity         TEXT,
        description      TEXT,
        cvss_v3          NUMERIC(5,2),
        cvss_vector      TEXT,
        epss             NUMERIC(6,5),
        published_on     TIMESTAMP WITH TIME ZONE,
        updated_on       TIMESTAMP WITH TIME ZONE,
        public_exploit   BOOLEAN,
        exploit_verified BOOLEAN,
        exploit_in_kit   BOOLEAN,
        exploit_types    JSONB,
        exploit_uris     JSONB,
        cve_json         JSONB,
        created_at       TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
        updated_at       TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_mde_cve_sev
        ON public.mde_cve(severity);
    CREATE INDEX IF NOT EXISTS idx_mde_cve_cvss
        ON public.mde_cve(cvss_v3 DESC NULLS LAST);
    CREATE INDEX IF NOT EXISTS idx_mde_cve_epss
        ON public.mde_cve(epss DESC NULLS LAST);
    CREATE INDEX IF NOT EXISTS idx_mde_cve_exploit
        ON public.mde_cve(public_exploit, exploit_verified, exploit_in_kit);
    CREATE INDEX IF NOT EXISTS idx_mde_cve_json_gin
        ON public.mde_cve USING GIN (cve_json);
    """

    cur.execute(create_table_query)
    print("The table 'mde_cve' was created or already exists")

    cur.close()
    conn.close()


def check_create_table_mde_asset_vuln(host, port, user, password, database):
    """
    Creates table for MDE asset-vulnerability relationship (fact table).
    Depends on mde_asset, mde_cve and mde_etl_runs — create those first.
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS public.mde_asset_vuln (
        id                             BIGINT                   NOT NULL GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
        run_ts                         TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
        run_id                         BIGINT,
        device_id                      TEXT                     NOT NULL,
        cve_id                         TEXT                     NOT NULL,
        software_vendor                TEXT                     NOT NULL
            CONSTRAINT chk_mde_av_vendor CHECK (LENGTH(TRIM(software_vendor)) > 0),
        software_name                  TEXT                     NOT NULL
            CONSTRAINT chk_mde_av_name   CHECK (LENGTH(TRIM(software_name))   > 0),
        software_version               TEXT                     NOT NULL
            CONSTRAINT chk_mde_av_ver    CHECK (LENGTH(TRIM(software_version)) > 0),
        cvss_score                     NUMERIC(5,2),
        exploitability_level           TEXT,
        first_seen                     TIMESTAMP WITH TIME ZONE,
        last_seen                      TIMESTAMP WITH TIME ZONE,
        security_update_available      BOOLEAN,
        recommended_security_update_id TEXT,
        recommended_security_update    TEXT,
        fixing_kb_id                   TEXT,
        evidence_json                  JSONB,
        row_json                       JSONB,
        created_at                     TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

        CONSTRAINT uq_mde_asset_vuln_run
            UNIQUE (run_ts, device_id, cve_id, software_vendor, software_name, software_version),

        CONSTRAINT mde_asset_vuln_device_id_fkey
            FOREIGN KEY (device_id)
            REFERENCES public.mde_asset(device_id)
            ON DELETE CASCADE
            DEFERRABLE INITIALLY DEFERRED,

        CONSTRAINT mde_asset_vuln_cve_id_fkey
            FOREIGN KEY (cve_id)
            REFERENCES public.mde_cve(cve_id)
            ON DELETE RESTRICT
            DEFERRABLE INITIALLY DEFERRED,

        CONSTRAINT mde_asset_vuln_run_id_fkey
            FOREIGN KEY (run_id)
            REFERENCES public.mde_etl_runs(run_id)
            ON DELETE SET NULL
            DEFERRABLE INITIALLY DEFERRED
    );

    CREATE INDEX IF NOT EXISTS idx_mde_av_run
        ON public.mde_asset_vuln(run_ts DESC);
    CREATE INDEX IF NOT EXISTS idx_mde_av_device
        ON public.mde_asset_vuln(device_id);
    CREATE INDEX IF NOT EXISTS idx_mde_av_cve
        ON public.mde_asset_vuln(cve_id);
    CREATE INDEX IF NOT EXISTS idx_mde_av_sw
        ON public.mde_asset_vuln(software_vendor, software_name, software_version);
    CREATE INDEX IF NOT EXISTS idx_mde_av_cvss
        ON public.mde_asset_vuln(cvss_score DESC NULLS LAST);
    CREATE INDEX IF NOT EXISTS idx_mde_av_expl
        ON public.mde_asset_vuln(exploitability_level);
    CREATE INDEX IF NOT EXISTS idx_mde_av_lastseen
        ON public.mde_asset_vuln(last_seen DESC NULLS LAST);
    CREATE INDEX IF NOT EXISTS idx_mde_av_evidence_gin
        ON public.mde_asset_vuln USING GIN (evidence_json);
    CREATE INDEX IF NOT EXISTS idx_mde_av_row_gin
        ON public.mde_asset_vuln USING GIN (row_json);
    """

    cur.execute(create_table_query)
    print("The table 'mde_asset_vuln' was created or already exists")

    cur.close()
    conn.close()


# ============================================================================
# AUTOMOX INTEGRATION TABLES
# ============================================================================

def check_create_table_automox_etl_runs(host, port, user, password, database):
    """
    Creates table for tracking Automox ETL runs.
    Must be created first due to FK dependencies from other automox_ tables.
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS automox_etl_runs (
        run_id         BIGSERIAL NOT NULL PRIMARY KEY,
        source_system  TEXT      NOT NULL,
        org_id         TEXT,
        started_at     TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
        finished_at    TIMESTAMP WITH TIME ZONE,
        status         TEXT      NOT NULL DEFAULT 'running',
        rows_assets    INTEGER   NOT NULL DEFAULT 0,
        rows_pending_sw INTEGER  NOT NULL DEFAULT 0,
        rows_cves      INTEGER   NOT NULL DEFAULT 0,
        request_params JSONB     NOT NULL DEFAULT '{}'::JSONB,
        response_meta  JSONB     NOT NULL DEFAULT '{}'::JSONB,
        error_message  TEXT,
        error_detail   TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_automox_etl_runs_source
        ON automox_etl_runs(source_system);
    CREATE INDEX IF NOT EXISTS idx_automox_etl_runs_started
        ON automox_etl_runs(started_at);
    """

    cur.execute(create_table_query)
    print("The table 'automox_etl_runs' was created or already exists")

    cur.close()
    conn.close()


def check_create_table_automox_assets_inventory(host, port, user, password, database):
    """
    Creates table for Automox asset inventory.
    Depends on automox_etl_runs — create that first.
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS automox_assets_inventory (
        run_id               BIGINT    NOT NULL,
        source_system        TEXT      NOT NULL,
        source_asset_id      BIGINT    NOT NULL,
        source_uuid          TEXT,
        asset_ref            TEXT,
        hostname             TEXT,
        hostname_norm        TEXT,
        fqdn                 TEXT,
        fqdn_norm            TEXT,
        domain               TEXT,
        serial_number        TEXT,
        ip_primary           INET,
        ip_addrs             TEXT[],
        mac_addrs            TEXT[],
        subnet               TEXT,
        site                 TEXT,
        os_family            TEXT,
        os_name              TEXT,
        os_version           TEXT,
        os_build             TEXT,
        kernel_version       TEXT,
        manufacturer         TEXT,
        model                TEXT,
        cpu_cores            INTEGER,
        ram_mb               INTEGER,
        disk_total_gb        INTEGER,
        connected            BOOLEAN,
        last_seen_at         TIMESTAMP WITH TIME ZONE,
        last_scan_at         TIMESTAMP WITH TIME ZONE,
        needs_reboot         BOOLEAN,
        pending_updates_count  INTEGER,
        pending_patches_count  INTEGER,
        tags                 TEXT[],
        raw_inventory        JSONB     NOT NULL DEFAULT '{}'::JSONB,
        raw_detail           JSONB     NOT NULL DEFAULT '{}'::JSONB,
        ingested_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
        PRIMARY KEY (run_id, source_system, source_asset_id),
        CONSTRAINT automox_assets_inventory_run_id_fkey
            FOREIGN KEY (run_id)
            REFERENCES automox_etl_runs(run_id)
            ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_automox_assets_inv_asset_ref
        ON automox_assets_inventory(asset_ref);
    CREATE INDEX IF NOT EXISTS idx_automox_assets_inv_hostname_norm
        ON automox_assets_inventory(hostname_norm);
    CREATE INDEX IF NOT EXISTS idx_automox_assets_inv_fqdn_norm
        ON automox_assets_inventory(fqdn_norm);
    CREATE INDEX IF NOT EXISTS idx_automox_assets_inv_ip_primary
        ON automox_assets_inventory(ip_primary);
    CREATE INDEX IF NOT EXISTS idx_automox_assets_inv_ip_addrs_gin
        ON automox_assets_inventory USING GIN (ip_addrs);
    CREATE INDEX IF NOT EXISTS idx_automox_assets_inv_serial
        ON automox_assets_inventory(serial_number);
    """

    cur.execute(create_table_query)
    print("The table 'automox_assets_inventory' was created or already exists")

    cur.close()
    conn.close()


def check_create_table_automox_pending_software(host, port, user, password, database):
    """
    Creates table for Automox pending software updates.
    Depends on automox_etl_runs and automox_assets_inventory — create those first.
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS automox_pending_software (
        pending_id           BIGSERIAL NOT NULL PRIMARY KEY,
        run_id               BIGINT    NOT NULL,
        source_system        TEXT      NOT NULL,
        source_asset_id      BIGINT    NOT NULL,
        source_update_row_id BIGINT,
        package_id           BIGINT,
        software_id          BIGINT,
        software_name        TEXT      NOT NULL,
        vendor               TEXT,
        package_type         TEXT,
        current_version      TEXT,
        available_version    TEXT,
        kb_id                TEXT,
        patch_id             TEXT,
        is_pending           BOOLEAN   NOT NULL DEFAULT TRUE,
        is_ignored           BOOLEAN   NOT NULL DEFAULT FALSE,
        is_deferred          BOOLEAN   NOT NULL DEFAULT FALSE,
        deferred_until       TIMESTAMP WITH TIME ZONE,
        severity             TEXT,
        cvss_score           NUMERIC,
        reboot_required      BOOLEAN,
        cve_ids              TEXT[],
        raw_update           JSONB     NOT NULL DEFAULT '{}'::JSONB,
        ingested_at          TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
        CONSTRAINT automox_pending_software_run_id_fkey
            FOREIGN KEY (run_id)
            REFERENCES automox_etl_runs(run_id)
            ON DELETE CASCADE,
        CONSTRAINT fk_automox_pending_sw_asset
            FOREIGN KEY (run_id, source_system, source_asset_id)
            REFERENCES automox_assets_inventory(run_id, source_system, source_asset_id)
            ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_automox_pending_sw_run
        ON automox_pending_software(run_id);
    CREATE INDEX IF NOT EXISTS idx_automox_pending_sw_asset
        ON automox_pending_software(source_system, source_asset_id);
    CREATE INDEX IF NOT EXISTS idx_automox_pending_sw_severity
        ON automox_pending_software(severity);
    CREATE INDEX IF NOT EXISTS idx_automox_pending_sw_cves_gin
        ON automox_pending_software USING GIN (cve_ids);
    """

    cur.execute(create_table_query)
    print("The table 'automox_pending_software' was created or already exists")

    cur.close()
    conn.close()


def check_create_table_automox_asset_cves(host, port, user, password, database):
    """
    Creates table for Automox asset-CVE relationships.
    Depends on automox_etl_runs, automox_assets_inventory and automox_pending_software — create those first.
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS automox_asset_cves (
        asset_cve_id             BIGSERIAL NOT NULL PRIMARY KEY,
        run_id                   BIGINT    NOT NULL,
        source_system            TEXT      NOT NULL,
        source_asset_id          BIGINT    NOT NULL,
        pending_id               BIGINT,
        cve_id                   TEXT      NOT NULL,
        severity                 TEXT,
        cvss_score               NUMERIC,
        cvss_vector              TEXT,
        epss_score               NUMERIC,
        exploited                BOOLEAN,
        patch_available          BOOLEAN,
        fixed_in_version         TEXT,
        affected_software_name   TEXT,
        affected_software_version TEXT,
        evidence                 TEXT,
        reference_urls           TEXT[],
        raw_cve                  JSONB     NOT NULL DEFAULT '{}'::JSONB,
        raw_relation             JSONB     NOT NULL DEFAULT '{}'::JSONB,
        ingested_at              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
        CONSTRAINT automox_asset_cves_run_id_source_system_source_asset_id_cve_key
            UNIQUE (run_id, source_system, source_asset_id, cve_id),
        CONSTRAINT automox_asset_cves_run_id_fkey
            FOREIGN KEY (run_id)
            REFERENCES automox_etl_runs(run_id)
            ON DELETE CASCADE,
        CONSTRAINT fk_automox_asset_cves_asset
            FOREIGN KEY (run_id, source_system, source_asset_id)
            REFERENCES automox_assets_inventory(run_id, source_system, source_asset_id)
            ON DELETE CASCADE,
        CONSTRAINT automox_asset_cves_pending_id_fkey
            FOREIGN KEY (pending_id)
            REFERENCES automox_pending_software(pending_id)
            ON DELETE SET NULL
    );

    CREATE INDEX IF NOT EXISTS idx_automox_asset_cves_asset
        ON automox_asset_cves(source_system, source_asset_id);
    CREATE INDEX IF NOT EXISTS idx_automox_asset_cves_cve
        ON automox_asset_cves(cve_id);
    CREATE INDEX IF NOT EXISTS idx_automox_asset_cves_pending_id
        ON automox_asset_cves(pending_id);
    """

    cur.execute(create_table_query)
    print("The table 'automox_asset_cves' was created or already exists")

    cur.close()
    conn.close()


# ============================================================================
# WIZ INTEGRATION TABLES
# ============================================================================

def check_create_table_wiz_etl_runs(host, port, user, password, database):
    """
    Creates table for tracking Wiz ETL runs (VM/software vulnerability pipeline).
    Must be created before wiz_software_vulnerable due to FK dependency.
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS wiz_etl_runs (
        run_id                   BIGSERIAL NOT NULL PRIMARY KEY,
        started_at               TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
        finished_at              TIMESTAMP WITH TIME ZONE,
        status                   TEXT      NOT NULL DEFAULT 'running',
        rows_assets              INTEGER   NOT NULL DEFAULT 0,
        rows_cves                INTEGER   NOT NULL DEFAULT 0,
        rows_findings            INTEGER   NOT NULL DEFAULT 0,
        rows_graph_entities      INTEGER   NOT NULL DEFAULT 0,
        api_endpoint_url         TEXT,
        page_size                INTEGER,
        pages_findings           INTEGER,
        pages_graph              INTEGER,
        reported_total_findings  INTEGER,
        filters_applied          JSONB     NOT NULL DEFAULT '{}'::JSONB,
        error_message            TEXT,
        error_detail             TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_wiz_etl_runs_started
        ON wiz_etl_runs(started_at DESC);
    CREATE INDEX IF NOT EXISTS idx_wiz_etl_runs_status
        ON wiz_etl_runs(status);
    """

    cur.execute(create_table_query)
    print("The table 'wiz_etl_runs' was created or already exists")

    cur.close()
    conn.close()


def check_create_table_wiz_assets(host, port, user, password, database):
    """
    Creates table for Wiz VM/compute asset inventory.
    Must be created before wiz_software_vulnerable due to FK dependency.
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS wiz_assets (
        asset_id                       TEXT                     NOT NULL PRIMARY KEY,
        asset_name                     TEXT                     NOT NULL,
        asset_name_norm                TEXT,
        asset_type                     TEXT                     NOT NULL,
        native_type                    TEXT,
        cloud_platform                 TEXT,
        subscription_id                TEXT,
        subscription_external_id       TEXT,
        subscription_name              TEXT,
        has_limited_internet_exposure  BOOLEAN,
        has_wide_internet_exposure     BOOLEAN,
        is_accessible_from_vpn         BOOLEAN,
        is_accessible_from_other_vnets BOOLEAN,
        is_accessible_from_other_subs  BOOLEAN,
        operating_system               TEXT,
        image_name                     TEXT,
        image_id                       TEXT,
        compute_instance_group         TEXT,
        ingested_at                    TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
        first_seen_at                  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_wiz_assets_type
        ON wiz_assets(asset_type);
    CREATE INDEX IF NOT EXISTS idx_wiz_assets_cloud
        ON wiz_assets(cloud_platform);
    CREATE INDEX IF NOT EXISTS idx_wiz_assets_name_norm
        ON wiz_assets(asset_name_norm);
    CREATE INDEX IF NOT EXISTS idx_wiz_assets_subscription_ext
        ON wiz_assets(subscription_external_id);
    """

    cur.execute(create_table_query)
    print("The table 'wiz_assets' was created or already exists")

    cur.close()
    conn.close()


def check_create_table_wiz_cves(host, port, user, password, database):
    """
    Creates table for Wiz CVE knowledge base.
    Must be created before wiz_software_vulnerable due to FK dependency.
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS wiz_cves (
        cve_id                          TEXT          NOT NULL PRIMARY KEY,
        description                     TEXT,
        is_high_profile_threat          BOOLEAN,
        categories                      TEXT[],
        severity                        TEXT,
        vendor_severity                 TEXT,
        nvd_severity                    TEXT,
        score                           NUMERIC(5,2),
        cna_score                       NUMERIC(5,2),
        vendor_score                    NUMERIC(5,2),
        epss_severity                   TEXT,
        epss_percentile                 NUMERIC(8,5),
        epss_probability                NUMERIC(8,6),
        has_exploit                     BOOLEAN,
        has_cisa_kev_exploit            BOOLEAN,
        has_initial_access_potential    BOOLEAN,
        published_date                  TIMESTAMP WITH TIME ZONE,
        fix_date                        TIMESTAMP WITH TIME ZONE,
        is_operating_system_end_of_life BOOLEAN,
        ignore_rules                    JSONB,
        last_seen_at                    TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_wiz_cves_severity
        ON wiz_cves(severity);
    CREATE INDEX IF NOT EXISTS idx_wiz_cves_has_exploit
        ON wiz_cves(has_exploit);
    CREATE INDEX IF NOT EXISTS idx_wiz_cves_cisa_kev
        ON wiz_cves(has_cisa_kev_exploit);
    CREATE INDEX IF NOT EXISTS idx_wiz_cves_epss
        ON wiz_cves(epss_probability DESC);
    CREATE INDEX IF NOT EXISTS idx_wiz_cves_categories_gin
        ON wiz_cves USING GIN (categories);
    """

    cur.execute(create_table_query)
    print("The table 'wiz_cves' was created or already exists")

    cur.close()
    conn.close()


def check_create_table_wiz_software_vulnerable(host, port, user, password, database):
    """
    Creates table for Wiz vulnerable software findings (VM/agent-based).
    Depends on wiz_etl_runs, wiz_assets and wiz_cves — create those first.
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS wiz_software_vulnerable (
        run_id                       BIGINT NOT NULL,
        finding_id                   TEXT   NOT NULL,
        asset_id                     TEXT   NOT NULL,
        cve_id                       TEXT,
        software_name                TEXT   NOT NULL,
        detection_method             TEXT,
        location_path                TEXT,
        code_library_language        TEXT,
        technology                   TEXT,
        fixed_version                TEXT,
        recommended_version          TEXT,
        has_fix                      BOOLEAN,
        has_triggerable_remediation  BOOLEAN,
        status                       TEXT,
        validated_in_runtime         BOOLEAN,
        layer_id                     TEXT,
        layer_details                TEXT,
        is_base_layer                BOOLEAN,
        first_detected_at            TIMESTAMP WITH TIME ZONE,
        last_detected_at             TIMESTAMP WITH TIME ZONE,
        resolved_at                  TIMESTAMP WITH TIME ZONE,
        ingested_at                  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

        CONSTRAINT uidx_wsv_dedup
            UNIQUE (run_id, asset_id, COALESCE(cve_id, ''), software_name, COALESCE(location_path, '')),

        CONSTRAINT fk_wiz_sw_vuln_run
            FOREIGN KEY (run_id)
            REFERENCES wiz_etl_runs(run_id)
            ON DELETE CASCADE,

        CONSTRAINT fk_wiz_sw_vuln_asset
            FOREIGN KEY (asset_id)
            REFERENCES wiz_assets(asset_id)
            ON DELETE CASCADE,

        CONSTRAINT fk_wiz_sw_vuln_cve
            FOREIGN KEY (cve_id)
            REFERENCES wiz_cves(cve_id)
            ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_wsv_asset
        ON wiz_software_vulnerable(run_id, asset_id);
    CREATE INDEX IF NOT EXISTS idx_wsv_cve_id
        ON wiz_software_vulnerable(cve_id);
    CREATE INDEX IF NOT EXISTS idx_wsv_finding_id
        ON wiz_software_vulnerable(finding_id);
    CREATE INDEX IF NOT EXISTS idx_wsv_has_fix
        ON wiz_software_vulnerable(has_fix);
    CREATE INDEX IF NOT EXISTS idx_wsv_status
        ON wiz_software_vulnerable(status);
    """

    cur.execute(create_table_query)
    print("The table 'wiz_software_vulnerable' was created or already exists")

    cur.close()
    conn.close()


def check_create_table_wiz_cloud_etl_runs(host, port, user, password, database):
    """
    Creates table for tracking Wiz cloud security ETL runs (CSPM pipeline).
    Must be created before wiz_cloud_asset, wiz_cloud_vuln_finding,
    wiz_cloud_cfg_finding and wiz_cloud_issue due to FK dependencies.
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS wiz_cloud_etl_runs (
        run_id                  SERIAL    NOT NULL PRIMARY KEY,
        started_at              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
        finished_at             TIMESTAMP WITH TIME ZONE,
        status                  TEXT      NOT NULL DEFAULT 'running',
        api_endpoint_url        TEXT,
        page_size               INTEGER,
        rows_assets             INTEGER            DEFAULT 0,
        rows_vuln_findings      INTEGER            DEFAULT 0,
        rows_cfg_findings       INTEGER            DEFAULT 0,
        rows_issues             INTEGER            DEFAULT 0,
        pages_cloud_resources   INTEGER            DEFAULT 0,
        pages_vuln_findings     INTEGER            DEFAULT 0,
        pages_cfg_findings      INTEGER            DEFAULT 0,
        pages_issues            INTEGER            DEFAULT 0,
        error_message           TEXT,
        error_detail            TEXT
    );
    """

    cur.execute(create_table_query)
    print("The table 'wiz_cloud_etl_runs' was created or already exists")

    cur.close()
    conn.close()


def check_create_table_wiz_cloud_asset(host, port, user, password, database):
    """
    Creates table for Wiz cloud resource/asset inventory (CSPM).
    Depends on wiz_cloud_etl_runs — create that first.
    Must be created before wiz_cloud_vuln_finding, wiz_cloud_cfg_finding
    and wiz_cloud_issue due to FK dependencies.
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS wiz_cloud_asset (
        asset_id                 TEXT                     NOT NULL PRIMARY KEY,
        asset_type               TEXT                     NOT NULL,
        asset_name               TEXT,
        asset_name_norm          TEXT,
        provider_id              TEXT,
        provider_unique_id       TEXT,
        external_id              TEXT,
        native_type              TEXT,
        region                   TEXT,
        status                   TEXT,
        subscription_external_id TEXT,
        subscription_name        TEXT,
        image_external_id        TEXT,
        pod_namespace            TEXT,
        pod_name                 TEXT,
        node_name                TEXT,
        image_id                 TEXT,
        raw                      JSONB,
        first_seen_at            TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
        ingested_at              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_wca_type
        ON wiz_cloud_asset(asset_type);
    CREATE INDEX IF NOT EXISTS idx_wca_name_norm
        ON wiz_cloud_asset(asset_name_norm);
    CREATE INDEX IF NOT EXISTS idx_wca_region
        ON wiz_cloud_asset(region);
    CREATE INDEX IF NOT EXISTS idx_wca_sub_ext
        ON wiz_cloud_asset(subscription_external_id);
    CREATE INDEX IF NOT EXISTS idx_wca_prov_uniq
        ON wiz_cloud_asset(provider_unique_id);
    CREATE INDEX IF NOT EXISTS idx_wca_pod_ns
        ON wiz_cloud_asset(pod_namespace)
        WHERE pod_namespace IS NOT NULL;
    """

    cur.execute(create_table_query)
    print("The table 'wiz_cloud_asset' was created or already exists")

    cur.close()
    conn.close()


def check_create_table_wiz_cloud_vuln_finding(host, port, user, password, database):
    """
    Creates table for Wiz cloud vulnerability findings (CSPM/agentless).
    Depends on wiz_cloud_etl_runs and wiz_cloud_asset — create those first.
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS wiz_cloud_vuln_finding (
        finding_id          TEXT                     NOT NULL PRIMARY KEY,
        run_id              INTEGER,
        asset_id            TEXT,
        cve_id              TEXT,
        detailed_name       TEXT,
        cve_description     TEXT,
        cvss_severity       TEXT,
        vendor_severity     TEXT,
        score               NUMERIC(8,4),
        exploitability_score NUMERIC(8,4),
        impact_score        NUMERIC(8,4),
        has_exploit         BOOLEAN,
        has_cisa_kev        BOOLEAN,
        status              TEXT,
        first_detected_at   TIMESTAMP WITH TIME ZONE,
        last_detected_at    TIMESTAMP WITH TIME ZONE,
        fixed_version       TEXT,
        detection_method    TEXT,
        location_path       TEXT,
        portal_url          TEXT,
        raw                 JSONB,
        ingested_at         TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

        CONSTRAINT fk_wiz_cvf_run
            FOREIGN KEY (run_id)
            REFERENCES wiz_cloud_etl_runs(run_id)
            ON DELETE SET NULL,

        CONSTRAINT fk_wiz_cvf_asset
            FOREIGN KEY (asset_id)
            REFERENCES wiz_cloud_asset(asset_id)
            ON DELETE SET NULL
    );

    CREATE INDEX IF NOT EXISTS idx_wcvf_asset
        ON wiz_cloud_vuln_finding(asset_id);
    CREATE INDEX IF NOT EXISTS idx_wcvf_cve
        ON wiz_cloud_vuln_finding(cve_id)
        WHERE cve_id IS NOT NULL;
    CREATE INDEX IF NOT EXISTS idx_wcvf_asset_cve
        ON wiz_cloud_vuln_finding(asset_id, cve_id)
        WHERE cve_id IS NOT NULL;
    CREATE INDEX IF NOT EXISTS idx_wcvf_severity
        ON wiz_cloud_vuln_finding(cvss_severity);
    CREATE INDEX IF NOT EXISTS idx_wcvf_status
        ON wiz_cloud_vuln_finding(status);
    CREATE INDEX IF NOT EXISTS idx_wcvf_run
        ON wiz_cloud_vuln_finding(run_id);
    CREATE INDEX IF NOT EXISTS idx_wcvf_first_seen
        ON wiz_cloud_vuln_finding(first_detected_at);
    """

    cur.execute(create_table_query)
    print("The table 'wiz_cloud_vuln_finding' was created or already exists")

    cur.close()
    conn.close()


def check_create_table_wiz_cloud_cfg_finding(host, port, user, password, database):
    """
    Creates table for Wiz cloud configuration/posture findings (CSPM rules).
    Depends on wiz_cloud_etl_runs and wiz_cloud_asset — create those first.
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS wiz_cloud_cfg_finding (
        finding_id   TEXT                     NOT NULL PRIMARY KEY,
        run_id       INTEGER,
        resource_id  TEXT,
        rule_id      TEXT,
        rule_graph_id TEXT,
        rule_name    TEXT,
        first_seen_at TIMESTAMP WITH TIME ZONE,
        severity     TEXT,
        result       TEXT,
        status       TEXT,
        remediation  TEXT,
        raw          JSONB,
        ingested_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

        CONSTRAINT fk_wiz_ccf_run
            FOREIGN KEY (run_id)
            REFERENCES wiz_cloud_etl_runs(run_id)
            ON DELETE SET NULL,

        CONSTRAINT fk_wiz_ccf_asset
            FOREIGN KEY (resource_id)
            REFERENCES wiz_cloud_asset(asset_id)
            ON DELETE SET NULL
    );

    CREATE INDEX IF NOT EXISTS idx_wccf_resource
        ON wiz_cloud_cfg_finding(resource_id);
    CREATE INDEX IF NOT EXISTS idx_wccf_rule_id
        ON wiz_cloud_cfg_finding(rule_id);
    CREATE INDEX IF NOT EXISTS idx_wccf_sev_status
        ON wiz_cloud_cfg_finding(severity, status);
    CREATE INDEX IF NOT EXISTS idx_wccf_run
        ON wiz_cloud_cfg_finding(run_id);
    CREATE INDEX IF NOT EXISTS idx_wccf_first_seen
        ON wiz_cloud_cfg_finding(first_seen_at);
    """

    cur.execute(create_table_query)
    print("The table 'wiz_cloud_cfg_finding' was created or already exists")

    cur.close()
    conn.close()


def check_create_table_wiz_cloud_issue(host, port, user, password, database):
    """
    Creates table for Wiz cloud security issues.
    Depends on wiz_cloud_etl_runs and wiz_cloud_asset — create those first.
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS wiz_cloud_issue (
        issue_id                 TEXT                     NOT NULL PRIMARY KEY,
        run_id                   INTEGER,
        issue_type               TEXT,
        status                   TEXT,
        severity                 TEXT,
        created_at               TIMESTAMP WITH TIME ZONE,
        updated_at               TIMESTAMP WITH TIME ZONE,
        source_rule_id           TEXT,
        source_rule_name         TEXT,
        entity_id                TEXT,
        entity_type              TEXT,
        entity_native_type       TEXT,
        entity_name              TEXT,
        entity_status            TEXT,
        entity_provider_id       TEXT,
        entity_region            TEXT,
        subscription_external_id TEXT,
        subscription_name        TEXT,
        service_tickets          JSONB,
        raw                      JSONB,
        ingested_at              TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

        CONSTRAINT fk_wiz_issue_run
            FOREIGN KEY (run_id)
            REFERENCES wiz_cloud_etl_runs(run_id)
            ON DELETE SET NULL,

        CONSTRAINT fk_wiz_issue_entity
            FOREIGN KEY (entity_id)
            REFERENCES wiz_cloud_asset(asset_id)
            ON DELETE SET NULL
    );

    CREATE INDEX IF NOT EXISTS idx_wci_type
        ON wiz_cloud_issue(issue_type);
    CREATE INDEX IF NOT EXISTS idx_wci_sev_status
        ON wiz_cloud_issue(severity, status);
    CREATE INDEX IF NOT EXISTS idx_wci_entity
        ON wiz_cloud_issue(entity_id);
    CREATE INDEX IF NOT EXISTS idx_wci_src_rule
        ON wiz_cloud_issue(source_rule_id);
    CREATE INDEX IF NOT EXISTS idx_wci_run
        ON wiz_cloud_issue(run_id);
    CREATE INDEX IF NOT EXISTS idx_wci_created
        ON wiz_cloud_issue(created_at);
    """

    cur.execute(create_table_query)
    print("The table 'wiz_cloud_issue' was created or already exists")

    cur.close()
    conn.close()


def check_create_table_wiz_cloud_resource_type_probe(host, port, user, password, database):
    """
    Creates table for Wiz cloud resource-type probe results.
    Depends on wiz_cloud_etl_runs — create that first.
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS wiz_cloud_resource_type_probe (
        run_id        BIGINT NOT NULL,
        resource_type TEXT   NOT NULL,
        probe_status  TEXT   NOT NULL,
        nodes_seen    INTEGER NOT NULL DEFAULT 0,
        error_code    TEXT,
        error_message TEXT,
        request_id    TEXT,
        probed_at     TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
        PRIMARY KEY (run_id, resource_type),

        CONSTRAINT fk_wiz_probe_run
            FOREIGN KEY (run_id)
            REFERENCES wiz_cloud_etl_runs(run_id)
            ON DELETE CASCADE
    );
    """

    cur.execute(create_table_query)
    print("The table 'wiz_cloud_resource_type_probe' was created or already exists")

    cur.close()
    conn.close()


# ============================================================================
# SENTINELONE INTEGRATION TABLES
# ============================================================================

def check_create_table_sentinelone_etl_runs(host, port, user, password, database):
    """
    Creates table for tracking SentinelOne ETL runs.
    Must be created first due to FK dependency from sentinelone_vuln_finding.
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS public.sentinelone_etl_runs (
        run_id        BIGSERIAL   PRIMARY KEY,
        started_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
        finished_at   TIMESTAMPTZ,
        status        TEXT        NOT NULL DEFAULT 'running'
                                  CHECK (status IN ('running','success','partial','error')),
        api_base_url  TEXT,
        tool_version  TEXT,
        rows_agents   INTEGER     NOT NULL DEFAULT 0,
        rows_apps     INTEGER     NOT NULL DEFAULT 0,
        rows_vulns    INTEGER     NOT NULL DEFAULT 0,
        rows_cves     INTEGER     NOT NULL DEFAULT 0,
        error_message TEXT,
        error_detail  TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_s1_etl_runs_started
        ON public.sentinelone_etl_runs(started_at DESC);
    CREATE INDEX IF NOT EXISTS idx_s1_etl_runs_status
        ON public.sentinelone_etl_runs(status);
    """

    cur.execute(create_table_query)
    print("The table 'sentinelone_etl_runs' was created or already exists")

    cur.close()
    conn.close()


def check_create_table_sentinelone_agent(host, port, user, password, database):
    """
    Creates table for SentinelOne agent inventory.
    Must be created before sentinelone_installed_app and sentinelone_vuln_finding.
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS public.sentinelone_agent (
        agent_id                  TEXT        PRIMARY KEY,
        uuid                      TEXT        UNIQUE,
        computer_name             TEXT        NOT NULL,
        computer_name_norm        TEXT GENERATED ALWAYS AS (lower(trim(computer_name))) STORED,
        account_id                TEXT,
        account_name              TEXT,
        site_id                   TEXT,
        site_name                 TEXT,
        group_id                  TEXT,
        group_name                TEXT,
        os_name                   TEXT,
        os_type                   TEXT,
        os_revision               TEXT,
        os_arch                   TEXT,
        machine_type              TEXT,
        model_name                TEXT,
        core_count                INTEGER,
        cpu_count                 INTEGER,
        total_memory_mb           INTEGER,
        last_ip_to_mgmt           TEXT,
        external_ip               TEXT,
        domain                    TEXT,
        agent_version             TEXT,
        installer_type            TEXT,
        mitigation_mode           TEXT,
        network_status            TEXT,
        is_active                 BOOLEAN,
        is_decommissioned         BOOLEAN,
        is_up_to_date             BOOLEAN,
        apps_vulnerability_status TEXT,
        active_threats            INTEGER,
        infected                  BOOLEAN,
        cloud_provider            TEXT,
        cloud_account             TEXT,
        cloud_instance_id         TEXT,
        cloud_instance_size       TEXT,
        cloud_location            TEXT,
        cloud_image               TEXT,
        registered_at             TIMESTAMPTZ,
        last_active_date          TIMESTAMPTZ,
        last_successful_scan_date TIMESTAMPTZ,
        created_at                TIMESTAMPTZ,
        updated_at                TIMESTAMPTZ,
        raw                       JSONB,
        ingested_at               TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE INDEX IF NOT EXISTS idx_s1_agent_computer_name_norm
        ON public.sentinelone_agent(computer_name_norm);
    CREATE INDEX IF NOT EXISTS idx_s1_agent_site
        ON public.sentinelone_agent(site_id);
    CREATE INDEX IF NOT EXISTS idx_s1_agent_os
        ON public.sentinelone_agent(os_type, os_name);
    CREATE INDEX IF NOT EXISTS idx_s1_agent_active
        ON public.sentinelone_agent(is_active, is_decommissioned);
    CREATE INDEX IF NOT EXISTS idx_s1_agent_last_active
        ON public.sentinelone_agent(last_active_date DESC);
    CREATE INDEX IF NOT EXISTS idx_s1_agent_cloud
        ON public.sentinelone_agent(cloud_provider, cloud_account);
    CREATE INDEX IF NOT EXISTS idx_s1_agent_raw_gin
        ON public.sentinelone_agent USING GIN (raw);
    """

    cur.execute(create_table_query)
    print("The table 'sentinelone_agent' was created or already exists")

    cur.close()
    conn.close()


def check_create_table_sentinelone_installed_app(host, port, user, password, database):
    """
    Creates table for SentinelOne installed applications per agent.
    Depends on sentinelone_agent — create that first.
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS public.sentinelone_installed_app (
        app_id       TEXT        PRIMARY KEY,
        agent_id     TEXT        NOT NULL
                                   REFERENCES public.sentinelone_agent(agent_id)
                                   ON DELETE CASCADE,
        name         TEXT        NOT NULL,
        publisher    TEXT,
        version      TEXT,
        size         BIGINT,
        installed_at TIMESTAMPTZ,
        risk_level   TEXT,
        ingested_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE INDEX IF NOT EXISTS idx_s1_app_agent
        ON public.sentinelone_installed_app(agent_id);
    CREATE INDEX IF NOT EXISTS idx_s1_app_name_version
        ON public.sentinelone_installed_app(name, version);
    CREATE INDEX IF NOT EXISTS idx_s1_app_risk
        ON public.sentinelone_installed_app(risk_level)
        WHERE risk_level <> 'none';
    """

    cur.execute(create_table_query)
    print("The table 'sentinelone_installed_app' was created or already exists")

    cur.close()
    conn.close()


def check_create_table_sentinelone_cve(host, port, user, password, database):
    """
    Creates table for SentinelOne CVE knowledge base.
    Must be created before sentinelone_vuln_finding due to FK dependency.
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS public.sentinelone_cve (
        cve_id                TEXT          PRIMARY KEY,
        published_date        DATE,
        s1_score              NUMERIC(4,1),
        nvd_base_score        NUMERIC(4,1),
        risk_score            NUMERIC(4,1),
        epss_score            NUMERIC(8,5),
        exploited_in_the_wild BOOLEAN,
        exploit_maturity      TEXT,
        remediation_level     TEXT,
        report_confidence     TEXT,
        last_seen_at          TIMESTAMPTZ   NOT NULL DEFAULT now()
    );

    CREATE INDEX IF NOT EXISTS idx_s1_cve_nvd_score
        ON public.sentinelone_cve(nvd_base_score DESC);
    CREATE INDEX IF NOT EXISTS idx_s1_cve_epss
        ON public.sentinelone_cve(epss_score DESC);
    CREATE INDEX IF NOT EXISTS idx_s1_cve_exploited
        ON public.sentinelone_cve(exploited_in_the_wild);
    """

    cur.execute(create_table_query)
    print("The table 'sentinelone_cve' was created or already exists")

    cur.close()
    conn.close()


def check_create_table_sentinelone_vuln_finding(host, port, user, password, database):
    """
    Creates table for SentinelOne vulnerability findings (xSPM).
    Depends on sentinelone_etl_runs, sentinelone_agent and sentinelone_cve — create those first.
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS public.sentinelone_vuln_finding (
        finding_id           TEXT        PRIMARY KEY,
        run_id               BIGINT
                               REFERENCES public.sentinelone_etl_runs(run_id)
                               ON DELETE SET NULL,
        cve_id               TEXT
                               REFERENCES public.sentinelone_cve(cve_id)
                               ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
        agent_id             TEXT
                               REFERENCES public.sentinelone_agent(agent_id)
                               ON DELETE SET NULL,
        xspm_asset_id        TEXT,
        asset_name           TEXT        NOT NULL,
        asset_name_norm      TEXT GENERATED ALWAYS AS (lower(trim(asset_name))) STORED,
        asset_type           TEXT,
        asset_category       TEXT,
        asset_subcategory    TEXT,
        asset_os_type        TEXT,
        asset_privileged     BOOLEAN,
        cloud_provider       TEXT,
        cloud_region         TEXT,
        cloud_account_id     TEXT,
        name                 TEXT,
        severity             TEXT,
        status               TEXT,
        detected_at          TIMESTAMPTZ,
        software_name        TEXT,
        software_version     TEXT,
        software_type        TEXT,
        software_vendor      TEXT,
        software_fix_version TEXT,
        has_fix              BOOLEAN GENERATED ALWAYS AS
                               (software_fix_version IS NOT NULL) STORED,
        account_id           TEXT,
        account_name         TEXT,
        site_id              TEXT,
        site_name            TEXT,
        ingested_at          TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE INDEX IF NOT EXISTS idx_s1_vf_run
        ON public.sentinelone_vuln_finding(run_id);
    CREATE INDEX IF NOT EXISTS idx_s1_vf_cve
        ON public.sentinelone_vuln_finding(cve_id);
    CREATE INDEX IF NOT EXISTS idx_s1_vf_agent
        ON public.sentinelone_vuln_finding(agent_id);
    CREATE INDEX IF NOT EXISTS idx_s1_vf_asset_name_norm
        ON public.sentinelone_vuln_finding(asset_name_norm);
    CREATE INDEX IF NOT EXISTS idx_s1_vf_asset_cve
        ON public.sentinelone_vuln_finding(asset_name_norm, cve_id);
    CREATE INDEX IF NOT EXISTS idx_s1_vf_severity
        ON public.sentinelone_vuln_finding(severity);
    CREATE INDEX IF NOT EXISTS idx_s1_vf_status
        ON public.sentinelone_vuln_finding(status);
    CREATE INDEX IF NOT EXISTS idx_s1_vf_detected
        ON public.sentinelone_vuln_finding(detected_at DESC);
    CREATE INDEX IF NOT EXISTS idx_s1_vf_sw_name
        ON public.sentinelone_vuln_finding(software_name, software_version);
    CREATE INDEX IF NOT EXISTS idx_s1_vf_has_fix
        ON public.sentinelone_vuln_finding(has_fix);
    """

    cur.execute(create_table_query)
    print("The table 'sentinelone_vuln_finding' was created or already exists")

    cur.close()
    conn.close()


# ============================================================================
# TRENDMICRO VISION ONE INTEGRATION TABLES
# ============================================================================

def check_create_table_trendmicro_etl_runs(host, port, user, password, database):
    """
    Creates table for tracking TrendMicro Vision One ETL runs.
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS public.trendmicro_etl_runs (
        run_id          BIGSERIAL   PRIMARY KEY,
        started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
        finished_at     TIMESTAMPTZ,
        status          TEXT        NOT NULL DEFAULT 'running'
                                    CHECK (status IN ('running','success','partial','error')),
        api_base_url    TEXT,
        rows_endpoints  INTEGER     NOT NULL DEFAULT 0,
        rows_alerts     INTEGER     NOT NULL DEFAULT 0,
        rows_oat        INTEGER     NOT NULL DEFAULT 0,
        error_message   TEXT,
        error_detail    TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_tm_etl_runs_started
        ON public.trendmicro_etl_runs(started_at DESC);
    """

    cur.execute(create_table_query)
    print("The table 'trendmicro_etl_runs' was created or already exists")

    cur.close()
    conn.close()


def check_create_table_trendmicro_endpoint(host, port, user, password, database):
    """
    Creates table for TrendMicro Vision One endpoint inventory.
    Must be created before trendmicro_endpoint_iface due to FK dependency.
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS public.trendmicro_endpoint (
        agent_guid                      TEXT        PRIMARY KEY,
        endpoint_name                   TEXT        NOT NULL,
        endpoint_name_norm              TEXT GENERATED ALWAYS AS (
                                          lower(split_part(trim(endpoint_name), '.', 1))
                                        ) STORED,
        description                     TEXT,
        type                            TEXT,
        os_name                         TEXT,
        os_version                      TEXT,
        os_platform                     TEXT,
        os_architecture                 TEXT,
        os_kernel_version               TEXT,
        cpu_architecture                TEXT,
        last_used_ip                    TEXT,
        isolation_status                TEXT,
        service_gateway_or_proxy        TEXT,
        security_policy                 TEXT,
        security_policy_overridden      TEXT,
        credit_allocated_licenses       TEXT[],
        epp_status                      TEXT,
        epp_version                     TEXT,
        epp_component_version           TEXT,
        epp_component_update_status     TEXT,
        epp_policy_name                 TEXT,
        epp_endpoint_group              TEXT,
        epp_protection_manager          TEXT,
        epp_last_connected_at           TIMESTAMPTZ,
        epp_last_scanned_at             TIMESTAMPTZ,
        epp_product_names               TEXT[],
        edr_status                      TEXT,
        edr_connectivity                TEXT,
        edr_version                     TEXT,
        edr_last_connected_at           TIMESTAMPTZ,
        edr_advanced_risk_telemetry     TEXT,
        edr_component_update_status     TEXT,
        edr_endpoint_group              TEXT,
        raw_inventory                   JSONB,
        raw_detail                      JSONB,
        ingested_at                     TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE INDEX IF NOT EXISTS idx_tm_endpoint_name_norm
        ON public.trendmicro_endpoint(endpoint_name_norm);
    CREATE INDEX IF NOT EXISTS idx_tm_endpoint_os
        ON public.trendmicro_endpoint(os_platform, os_name);
    CREATE INDEX IF NOT EXISTS idx_tm_endpoint_type
        ON public.trendmicro_endpoint(type);
    CREATE INDEX IF NOT EXISTS idx_tm_endpoint_epp_status
        ON public.trendmicro_endpoint(epp_status);
    CREATE INDEX IF NOT EXISTS idx_tm_endpoint_edr_status
        ON public.trendmicro_endpoint(edr_status);
    CREATE INDEX IF NOT EXISTS idx_tm_endpoint_raw_inv_gin
        ON public.trendmicro_endpoint USING GIN (raw_inventory);
    """

    cur.execute(create_table_query)
    print("The table 'trendmicro_endpoint' was created or already exists")

    cur.close()
    conn.close()


def check_create_table_trendmicro_endpoint_iface(host, port, user, password, database):
    """
    Creates table for TrendMicro endpoint network interfaces.
    Depends on trendmicro_endpoint — create that first.
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS public.trendmicro_endpoint_iface (
        iface_id        BIGSERIAL   PRIMARY KEY,
        agent_guid      TEXT        NOT NULL
                                      REFERENCES public.trendmicro_endpoint(agent_guid)
                                      ON DELETE CASCADE,
        mac_address     TEXT,
        ip_addresses    TEXT[]      NOT NULL DEFAULT '{}',
        ingested_at     TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE INDEX IF NOT EXISTS idx_tm_iface_agent
        ON public.trendmicro_endpoint_iface(agent_guid);
    CREATE INDEX IF NOT EXISTS idx_tm_iface_mac
        ON public.trendmicro_endpoint_iface(mac_address);
    CREATE INDEX IF NOT EXISTS idx_tm_iface_ips_gin
        ON public.trendmicro_endpoint_iface USING GIN (ip_addresses);
    """

    cur.execute(create_table_query)
    print("The table 'trendmicro_endpoint_iface' was created or already exists")

    cur.close()
    conn.close()


def check_create_table_trendmicro_alert(host, port, user, password, database):
    """
    Creates table for TrendMicro Workbench alerts.
    Must be created before trendmicro_alert_host due to FK dependency.
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS public.trendmicro_alert (
        alert_id                TEXT        PRIMARY KEY,
        incident_id             TEXT,
        schema_version          TEXT,
        status                  TEXT,
        investigation_status    TEXT,
        investigation_result    TEXT,
        alert_provider          TEXT,
        model_id                TEXT,
        model                   TEXT,
        model_type              TEXT,
        score                   INTEGER,
        severity                TEXT,
        description             TEXT,
        workbench_link          TEXT,
        created_at              TIMESTAMPTZ,
        updated_at              TIMESTAMPTZ,
        impact_desktop_count    INTEGER,
        impact_server_count     INTEGER,
        impact_account_count    INTEGER,
        impact_container_count  INTEGER,
        mitre_technique_ids     TEXT[],
        matched_rule_names      TEXT[],
        raw                     JSONB,
        ingested_at             TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE INDEX IF NOT EXISTS idx_tm_alert_severity
        ON public.trendmicro_alert(severity);
    CREATE INDEX IF NOT EXISTS idx_tm_alert_status
        ON public.trendmicro_alert(status, investigation_status);
    CREATE INDEX IF NOT EXISTS idx_tm_alert_created
        ON public.trendmicro_alert(created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_tm_alert_mitre_gin
        ON public.trendmicro_alert USING GIN (mitre_technique_ids);
    """

    cur.execute(create_table_query)
    print("The table 'trendmicro_alert' was created or already exists")

    cur.close()
    conn.close()


def check_create_table_trendmicro_alert_host(host, port, user, password, database):
    """
    Creates table for TrendMicro alert host entities.
    Depends on trendmicro_alert — create that first.
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS public.trendmicro_alert_host (
        id                  BIGSERIAL   PRIMARY KEY,
        alert_id            TEXT        NOT NULL
                                          REFERENCES public.trendmicro_alert(alert_id)
                                          ON DELETE CASCADE,
        agent_guid          TEXT,
        endpoint_name       TEXT,
        endpoint_name_norm  TEXT GENERATED ALWAYS AS (
                              lower(split_part(trim(coalesce(endpoint_name,'')), '.', 1))
                            ) STORED,
        entity_type         TEXT,
        entity_value        JSONB,
        ips                 TEXT[],
        ingested_at         TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE INDEX IF NOT EXISTS idx_tm_ah_alert
        ON public.trendmicro_alert_host(alert_id);
    CREATE INDEX IF NOT EXISTS idx_tm_ah_agent
        ON public.trendmicro_alert_host(agent_guid);
    CREATE INDEX IF NOT EXISTS idx_tm_ah_name_norm
        ON public.trendmicro_alert_host(endpoint_name_norm);
    CREATE INDEX IF NOT EXISTS idx_tm_ah_ips_gin
        ON public.trendmicro_alert_host USING GIN (ips);
    """

    cur.execute(create_table_query)
    print("The table 'trendmicro_alert_host' was created or already exists")

    cur.close()
    conn.close()


def check_create_table_trendmicro_oat_detection(host, port, user, password, database):
    """
    Creates table for TrendMicro OAT (Observed Attack Techniques) detections.
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS public.trendmicro_oat_detection (
        uuid                TEXT        PRIMARY KEY,
        agent_guid          TEXT,
        endpoint_name       TEXT,
        endpoint_name_norm  TEXT GENERATED ALWAYS AS (
                              lower(split_part(trim(coalesce(endpoint_name,'')), '.', 1))
                            ) STORED,
        endpoint_ip         TEXT[],
        source              TEXT,
        entity_type         TEXT,
        detected_at         TIMESTAMPTZ,
        ingested_at_api     TIMESTAMPTZ,
        filter_ids          TEXT[],
        filter_names        TEXT[],
        filter_risk_level   TEXT,
        mitre_tactic_ids    TEXT[],
        mitre_technique_ids TEXT[],
        process_name        TEXT,
        process_cmd         TEXT,
        process_user        TEXT,
        process_file_sha256 TEXT,
        object_name         TEXT,
        object_cmd          TEXT,
        event_name          TEXT,
        logon_user          TEXT[],
        raw_detail          JSONB,
        ingested_at         TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE INDEX IF NOT EXISTS idx_tm_oat_agent
        ON public.trendmicro_oat_detection(agent_guid);
    CREATE INDEX IF NOT EXISTS idx_tm_oat_name_norm
        ON public.trendmicro_oat_detection(endpoint_name_norm);
    CREATE INDEX IF NOT EXISTS idx_tm_oat_detected
        ON public.trendmicro_oat_detection(detected_at DESC);
    CREATE INDEX IF NOT EXISTS idx_tm_oat_risk
        ON public.trendmicro_oat_detection(filter_risk_level);
    CREATE INDEX IF NOT EXISTS idx_tm_oat_mitre_gin
        ON public.trendmicro_oat_detection USING GIN (mitre_technique_ids);
    CREATE INDEX IF NOT EXISTS idx_tm_oat_sha256
        ON public.trendmicro_oat_detection(process_file_sha256)
        WHERE process_file_sha256 IS NOT NULL;
    CREATE INDEX IF NOT EXISTS idx_tm_oat_raw_gin
        ON public.trendmicro_oat_detection USING GIN (raw_detail);
    """

    cur.execute(create_table_query)
    print("The table 'trendmicro_oat_detection' was created or already exists")

    cur.close()
    conn.close()


# ============================================================================
# RAPID7 INSIGHTVM INTEGRATION TABLES
# ============================================================================

def check_create_table_rapid7_etl_runs(host, port, user, password, database):
    """
    Creates table for tracking Rapid7 InsightVM ETL runs.
    Must be created first due to FK dependencies from rapid7_asset,
    rapid7_vuln_finding and rapid7_remediation.
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS public.rapid7_etl_runs (
        run_id            BIGSERIAL   PRIMARY KEY,
        started_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
        finished_at       TIMESTAMPTZ,
        status            TEXT        NOT NULL DEFAULT 'running'
                                      CHECK (status IN ('running','success','partial','error')),
        api_base_url      TEXT,
        region            TEXT,
        rows_assets       INTEGER     NOT NULL DEFAULT 0,
        rows_vulns        INTEGER     NOT NULL DEFAULT 0,
        rows_remediations INTEGER     NOT NULL DEFAULT 0,
        error_message     TEXT,
        error_detail      TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_r7_etl_runs_started
        ON public.rapid7_etl_runs(started_at DESC);
    """

    cur.execute(create_table_query)
    print("The table 'rapid7_etl_runs' was created or already exists")

    cur.close()
    conn.close()


def check_create_table_rapid7_asset(host, port, user, password, database):
    """
    Creates table for Rapid7 InsightVM asset inventory.
    Depends on rapid7_etl_runs — create that first.
    Must be created before rapid7_vuln_finding and rapid7_remediation.
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS public.rapid7_asset (
        asset_id              TEXT        PRIMARY KEY,
        last_run_id           BIGINT
                                REFERENCES public.rapid7_etl_runs(run_id)
                                ON DELETE SET NULL,
        org_id                TEXT,
        agent_id              TEXT,
        aws_instance_id       TEXT,
        azure_resource_id     TEXT,
        gcp_object_id         TEXT,
        mac                   TEXT,
        ip                    TEXT,
        host_name             TEXT,
        host_name_norm        TEXT GENERATED ALWAYS AS (
                                lower(split_part(trim(coalesce(host_name,'')), '.', 1))
                              ) STORED,
        os_architecture       TEXT,
        os_family             TEXT,
        os_product            TEXT,
        os_vendor             TEXT,
        os_version            TEXT,
        os_type               TEXT,
        os_description        TEXT,
        risk_score            NUMERIC(12,4),
        sites                 TEXT[]   NOT NULL DEFAULT '{}',
        asset_groups          TEXT[]   NOT NULL DEFAULT '{}',
        tags                  TEXT[]   NOT NULL DEFAULT '{}',
        vuln_finding_count    INTEGER  NOT NULL DEFAULT 0,
        unique_vuln_id_count  INTEGER  NOT NULL DEFAULT 0,
        unique_cve_count      INTEGER  NOT NULL DEFAULT 0,
        cves                  TEXT[]   NOT NULL DEFAULT '{}',
        ingested_at           TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE INDEX IF NOT EXISTS idx_r7_asset_host_name_norm
        ON public.rapid7_asset(host_name_norm);
    CREATE INDEX IF NOT EXISTS idx_r7_asset_ip
        ON public.rapid7_asset(ip);
    CREATE INDEX IF NOT EXISTS idx_r7_asset_os_family
        ON public.rapid7_asset(os_family);
    CREATE INDEX IF NOT EXISTS idx_r7_asset_risk_score
        ON public.rapid7_asset(risk_score DESC);
    CREATE INDEX IF NOT EXISTS idx_r7_asset_cves_gin
        ON public.rapid7_asset USING GIN (cves);
    CREATE INDEX IF NOT EXISTS idx_r7_asset_sites_gin
        ON public.rapid7_asset USING GIN (sites);
    """

    cur.execute(create_table_query)
    print("The table 'rapid7_asset' was created or already exists")

    cur.close()
    conn.close()


def check_create_table_rapid7_vuln_finding(host, port, user, password, database):
    """
    Creates table for Rapid7 InsightVM vulnerability findings.
    Depends on rapid7_asset and rapid7_etl_runs — create those first.
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS public.rapid7_vuln_finding (
        finding_id            BIGSERIAL   PRIMARY KEY,
        asset_id              TEXT        NOT NULL
                                REFERENCES public.rapid7_asset(asset_id)
                                ON DELETE CASCADE,
        run_id                BIGINT
                                REFERENCES public.rapid7_etl_runs(run_id)
                                ON DELETE SET NULL,
        vuln_id               TEXT        NOT NULL,
        port                  INTEGER,
        protocol              TEXT,
        nic                   TEXT,
        severity              TEXT,
        severity_rank         INTEGER,
        severity_score        INTEGER,
        risk_score            NUMERIC(12,4),
        risk_score_v2         NUMERIC(12,4),
        cvss_score            NUMERIC(5,2),
        cvss_v3_score         NUMERIC(5,2),
        cvss_v3_severity      TEXT,
        cvss_v3_severity_rank INTEGER,
        cvss_v3_attack_vector         TEXT,
        cvss_v3_attack_complexity     TEXT,
        cvss_v3_privileges_required   TEXT,
        cvss_v3_user_interaction      TEXT,
        cvss_v3_scope                 TEXT,
        cvss_v3_confidentiality       TEXT,
        cvss_v3_integrity             TEXT,
        cvss_v3_availability          TEXT,
        epss_score            NUMERIC(8,6),
        epss_percentile       NUMERIC(8,6),
        has_exploits          BOOLEAN,
        threat_feed_exists    BOOLEAN,
        pci_compliant         BOOLEAN,
        pci_severity          INTEGER,
        skill_level           TEXT,
        skill_level_rank      INTEGER,
        title                 TEXT,
        description           TEXT,
        first_found_at        TIMESTAMPTZ,
        date_published        TIMESTAMPTZ,
        date_added            TIMESTAMPTZ,
        date_modified         TIMESTAMPTZ,
        cves                  TEXT[]   NOT NULL DEFAULT '{}',
        tags                  TEXT[]   NOT NULL DEFAULT '{}',
        ingested_at           TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE UNIQUE INDEX IF NOT EXISTS uidx_r7_vf_dedup
        ON public.rapid7_vuln_finding
        (asset_id, run_id, vuln_id,
         COALESCE(port,-1), COALESCE(protocol,''), COALESCE(nic,''));

    CREATE INDEX IF NOT EXISTS idx_r7_vf_asset
        ON public.rapid7_vuln_finding(asset_id);
    CREATE INDEX IF NOT EXISTS idx_r7_vf_run
        ON public.rapid7_vuln_finding(run_id);
    CREATE INDEX IF NOT EXISTS idx_r7_vf_vuln_id
        ON public.rapid7_vuln_finding(vuln_id);
    CREATE INDEX IF NOT EXISTS idx_r7_vf_severity
        ON public.rapid7_vuln_finding(severity, severity_rank);
    CREATE INDEX IF NOT EXISTS idx_r7_vf_cvss_v3
        ON public.rapid7_vuln_finding(cvss_v3_score DESC NULLS LAST);
    CREATE INDEX IF NOT EXISTS idx_r7_vf_epss
        ON public.rapid7_vuln_finding(epss_score DESC NULLS LAST);
    CREATE INDEX IF NOT EXISTS idx_r7_vf_has_exploits
        ON public.rapid7_vuln_finding(has_exploits)
        WHERE has_exploits = true;
    CREATE INDEX IF NOT EXISTS idx_r7_vf_cves_gin
        ON public.rapid7_vuln_finding USING GIN (cves);
    """

    cur.execute(create_table_query)
    print("The table 'rapid7_vuln_finding' was created or already exists")

    cur.close()
    conn.close()


def check_create_table_rapid7_remediation(host, port, user, password, database):
    """
    Creates table for Rapid7 InsightVM remediation records.
    Depends on rapid7_asset and rapid7_etl_runs — create those first.
    """
    db_params = {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'database': database
    }

    conn = psycopg2.connect(**db_params)
    conn.autocommit = True
    cur = conn.cursor()

    create_table_query = """
    CREATE TABLE IF NOT EXISTS public.rapid7_remediation (
        remediation_id    BIGSERIAL   PRIMARY KEY,
        asset_id          TEXT        NOT NULL
                            REFERENCES public.rapid7_asset(asset_id)
                            ON DELETE CASCADE,
        run_id            BIGINT
                            REFERENCES public.rapid7_etl_runs(run_id)
                            ON DELETE SET NULL,
        vuln_id           TEXT        NOT NULL,
        cve_id            TEXT,
        title             TEXT,
        description       TEXT,
        proof             TEXT,
        first_found_at    TIMESTAMPTZ,
        last_detected_at  TIMESTAMPTZ,
        last_removed_at   TIMESTAMPTZ,
        reintroduced_at   TIMESTAMPTZ,
        ingested_at       TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE UNIQUE INDEX IF NOT EXISTS uidx_r7_rem_dedup
        ON public.rapid7_remediation
        (asset_id, run_id, vuln_id, COALESCE(cve_id,''));

    CREATE INDEX IF NOT EXISTS idx_r7_rem_asset
        ON public.rapid7_remediation(asset_id);
    CREATE INDEX IF NOT EXISTS idx_r7_rem_vuln
        ON public.rapid7_remediation(vuln_id);
    CREATE INDEX IF NOT EXISTS idx_r7_rem_cve
        ON public.rapid7_remediation(cve_id)
        WHERE cve_id IS NOT NULL;
    """

    cur.execute(create_table_query)
    print("The table 'rapid7_remediation' was created or already exists")

    cur.close()
    conn.close()


# ============================================================================
# MASTER FUNCTION TO CREATE ALL EXTERNAL INTEGRATION TABLES
# ============================================================================

def check_create_all_external_integration_tables(host, port, user, password, database):
    """
    Creates all external integration tables in the correct order
    (respecting foreign key dependencies within each integration group).
    """
    ct = datetime.now()
    print(str(ct) + " Creating all external integration tables...")

    # Tenable tables
    print("\n--- Creating Tenable tables ---")
    check_create_table_tenable_assets_current(host, port, user, password, database)
    check_create_table_tenable_findings_current(host, port, user, password, database)
    check_create_table_tenable_finding_evidence_current(host, port, user, password, database)
    check_create_table_tenable_finding_ports(host, port, user, password, database)
    check_create_table_tenable_findings_history(host, port, user, password, database)
    check_create_table_tenable_ingest_runs(host, port, user, password, database)
    check_create_table_tenable_plugin_cve_map(host, port, user, password, database)

    # CrowdStrike Falcon Spotlight tables
    print("\n--- Creating CrowdStrike Falcon Spotlight tables ---")
    check_create_table_falcon_spotlight_dim_hosts(host, port, user, password, database)
    check_create_table_falcon_spotlight_dim_vulnerabilities(host, port, user, password, database)
    check_create_table_falcon_spotlight_dim_evaluation_logic(host, port, user, password, database)
    check_create_table_falcon_spotlight_dim_remediations(host, port, user, password, database)
    check_create_table_falcon_spotlight_fact_vulnerability_instances(host, port, user, password, database)
    check_create_table_falcon_spotlight_rel_apps(host, port, user, password, database)
    check_create_table_falcon_spotlight_rel_evaluation_logic(host, port, user, password, database)

    # Qualys tables (order matters due to foreign keys)
    print("\n--- Creating Qualys tables ---")
    check_create_table_qualys_asset(host, port, user, password, database)
    check_create_table_qualys_asset_open_port(host, port, user, password, database)
    check_create_table_qualys_qid_kb(host, port, user, password, database)
    check_create_table_qualys_finding(host, port, user, password, database)
    check_create_table_qualys_finding_evidence(host, port, user, password, database)

    # ServiceNow tables
    print("\n--- Creating ServiceNow tables ---")
    check_create_table_snow_problem_vuln_tickets(host, port, user, password, database)

    # Microsoft Defender for Endpoint (MDE) tables
    print("\n--- Creating Microsoft Defender for Endpoint (MDE) tables ---")
    check_create_table_mde_etl_runs(host, port, user, password, database)
    check_create_table_mde_asset(host, port, user, password, database)
    check_create_table_mde_cve(host, port, user, password, database)
    check_create_table_mde_asset_vuln(host, port, user, password, database)

    # Automox tables (order matters due to foreign keys)
    print("\n--- Creating Automox tables ---")
    check_create_table_automox_etl_runs(host, port, user, password, database)
    check_create_table_automox_assets_inventory(host, port, user, password, database)
    check_create_table_automox_pending_software(host, port, user, password, database)
    check_create_table_automox_asset_cves(host, port, user, password, database)

    # Wiz tables — VM/software pipeline (order matters due to foreign keys)
    print("\n--- Creating Wiz tables ---")
    check_create_table_wiz_etl_runs(host, port, user, password, database)
    check_create_table_wiz_assets(host, port, user, password, database)
    check_create_table_wiz_cves(host, port, user, password, database)
    check_create_table_wiz_software_vulnerable(host, port, user, password, database)

    # Wiz tables — Cloud/CSPM pipeline (order matters due to foreign keys)
    check_create_table_wiz_cloud_etl_runs(host, port, user, password, database)
    check_create_table_wiz_cloud_asset(host, port, user, password, database)
    check_create_table_wiz_cloud_vuln_finding(host, port, user, password, database)
    check_create_table_wiz_cloud_cfg_finding(host, port, user, password, database)
    check_create_table_wiz_cloud_issue(host, port, user, password, database)
    check_create_table_wiz_cloud_resource_type_probe(host, port, user, password, database)

    # SentinelOne tables (order matters due to foreign keys)
    print("\n--- Creating SentinelOne tables ---")
    check_create_table_sentinelone_etl_runs(host, port, user, password, database)
    check_create_table_sentinelone_agent(host, port, user, password, database)
    check_create_table_sentinelone_installed_app(host, port, user, password, database)
    check_create_table_sentinelone_cve(host, port, user, password, database)
    check_create_table_sentinelone_vuln_finding(host, port, user, password, database)

    # TrendMicro Vision One tables (order matters due to foreign keys)
    print("\n--- Creating TrendMicro Vision One tables ---")
    check_create_table_trendmicro_etl_runs(host, port, user, password, database)
    check_create_table_trendmicro_endpoint(host, port, user, password, database)
    check_create_table_trendmicro_endpoint_iface(host, port, user, password, database)
    check_create_table_trendmicro_alert(host, port, user, password, database)
    check_create_table_trendmicro_alert_host(host, port, user, password, database)
    check_create_table_trendmicro_oat_detection(host, port, user, password, database)

    # Rapid7 InsightVM tables (order matters due to foreign keys)
    print("\n--- Creating Rapid7 InsightVM tables ---")
    check_create_table_rapid7_etl_runs(host, port, user, password, database)
    check_create_table_rapid7_asset(host, port, user, password, database)
    check_create_table_rapid7_vuln_finding(host, port, user, password, database)
    check_create_table_rapid7_remediation(host, port, user, password, database)

    ct = datetime.now()
    print("\n" + str(ct) + " All external integration tables created successfully!")
