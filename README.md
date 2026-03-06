# vAnalyzer - Enterprise Vulnerability Reporting Platform

[![Version](https://img.shields.io/badge/version-1.4-blue)](https://github.com/vanalyzer/vanalyzer)
[![Docker](https://img.shields.io/badge/docker-ready-brightgreen)](https://www.docker.com/)

## Overview

vAnalyzer integrates with Vicarius vRx to provide enterprise vulnerability reporting and analysis. It enriches vulnerability data with threat intelligence from CISA KEV, FIRST EPSS, and optional advanced threat intelligence integration.

### Key Features
- **Threat Intelligence Integration**: Combines multiple threat intelligence sources for comprehensive analysis
- **Automated Enrichment**: Integration with CISA KEV, FIRST EPSS, and optional threat intelligence
- **Docker Swarm Deployment**: Containerized architecture with automatic orchestration
- **Analytics Dashboard**: Metabase-powered visualizations and custom reporting

---

## System Requirements

### Hardware
- **CPU**: 4+ cores recommended
- **RAM**: 8GB minimum, 16GB recommended
- **Storage**: 50GB minimum

### Software
- **OS**: Linux (Ubuntu 20.04+, RHEL 8+, Rocky Linux 8+)
- **Docker**: Version 20.10+ (installer will handle if not present)

### Required Credentials
- Vicarius Dashboard URL or ID (e.g., `company.vicarius.cloud` or `company`)
- Vicarius API Key (from Settings → API Keys)
- Root or sudo privileges for installation

---

## Quick Start

### 1. Install Docker (if needed)
```bash
sudo ./vanalyzer install
```

### 2. Configure vAnalyzer
```bash
sudo ./vanalyzer init
```

**Configuration prompts:**
- **Hostname**: FQDN for SSL certificate (e.g., `vanalyzer.company.com`)
- **Dashboard ID**: Vicarius instance (e.g., `company` or full URL)
- **API Key**: Vicarius API authentication key
- **Database User**: PostgreSQL username (default: `vanalyzer`)
- **Database Name**: PostgreSQL database (default: `vanalyzer`)
- **Database Password**: Strong password required
- **Sync Interval**: Hours between data refresh (default: `6`)
- **External Data**: Enable CISA KEV + FIRST EPSS (optional)
- **Threat Intelligence**: Enable advanced threat intelligence API (optional)

### 3. Deploy Stack
```bash
sudo ./vanalyzer deploy
```

Deployment includes:
- PostgreSQL database with optimized indexes
- Python data sync engine
- Metabase analytics dashboard
- Traefik reverse proxy with SSL

**Expected time**: 5-10 minutes

### 4. Configure DNS
Add to your hosts file:
- **Linux/Mac**: `/etc/hosts`
- **Windows**: `C:\Windows\System32\drivers\etc\hosts`

```
YOUR_SERVER_IP your-hostname
```

### 5. Access Dashboard
1. Navigate to: `https://[your-hostname]`
2. Accept self-signed certificate warning
3. Login with default credentials:
   ```
   Username: vrxadmin@vrxadmin.com
   Password: Vicarius123!@#
   ```
4. **Change password immediately** in Settings → Account settings
5. Configure database connection in Settings → Admin Settings → Databases:
   - Database Name: Your configured database name
   - Username: Database user from configuration
   - Password: Database password from configuration
6. Verify data sync completes (15-30 minutes)

---

## Daily Operations

### Monitoring
```bash
sudo ./vanalyzer status     # Check service status
sudo ./vanalyzer health     # Run health checks
sudo ./vanalyzer validate   # Validate configuration
```

### Log Management
```bash
sudo ./vanalyzer logs app       # Application logs
sudo ./vanalyzer logs appdb     # Database logs
sudo ./vanalyzer logs metabase  # Dashboard logs
```

### Data Management
```bash
sudo ./vanalyzer backup                    # Create backup
sudo ./vanalyzer restore <backup_dir>      # Restore all databases
sudo ./vanalyzer restore-metabase <backup> # Restore Metabase only
sudo ./vanalyzer update                    # Force data sync
```

### Data Synchronization
- **Automatic**: Runs at configured interval (default: 6 hours)
- **Manual**: `sudo ./vanalyzer update`
- **Monitor**: `sudo ./vanalyzer logs app | grep -i sync`

---

## Offline Deployment

### Create Bundle (Internet-Connected)
```bash
sudo ./vanalyzer deploy
sudo ./vanalyzer bundle
```

### Deploy Offline (Air-Gapped)
```bash
sudo ./vanalyzer import
sudo ./vanalyzer init
sudo ./vanalyzer deploy
```

**Note**: Offline deployments won't receive external threat intelligence updates.

---

## Troubleshooting

### Quick Diagnostics
```bash
sudo ./vanalyzer health     # Full system check
sudo ./vanalyzer validate   # Configuration check
sudo ./vanalyzer status     # Service status
```

### Common Issues

**No Data in Dashboards**
```bash
# Check sync status
sudo ./vanalyzer logs app | grep -i sync

# Force manual sync
sudo ./vanalyzer update

# Wait 15-30 minutes for initial population
```

**Cannot Access Website**
- Check services: `sudo ./vanalyzer status`
- Verify hostname in hosts file
- Try IP address: `https://YOUR_SERVER_IP`

**Login Issues**
- Use default credentials: `vrxadmin@vrxadmin.com` / `Vicarius123!@#`
- Wait 5 minutes after deployment

**Certificate Warning**
- Normal for self-signed certificates
- Click "Advanced" → "Proceed"

---

## Command Reference

### Setup & Deployment
```bash
sudo ./vanalyzer install    # Install Docker
sudo ./vanalyzer init       # Configure system
sudo ./vanalyzer deploy     # Deploy stack
sudo ./vanalyzer update     # Update data
```

### Monitoring
```bash
sudo ./vanalyzer status     # Service status
sudo ./vanalyzer health     # Health checks
sudo ./vanalyzer validate   # Configuration check
sudo ./vanalyzer logs <service>  # View logs (app/appdb/metabase/traefik)
```

### Data Management
```bash
sudo ./vanalyzer backup                    # Backup all databases
sudo ./vanalyzer restore <backup>          # Restore all databases
sudo ./vanalyzer restore-metabase <backup> # Restore Metabase only
```

### Maintenance
```bash
sudo ./vanalyzer clean-logs    # Clean log files
sudo ./vanalyzer clean-docker  # Clean Docker resources
sudo ./vanalyzer purge         # Remove everything (WARNING: deletes all data)
```

### Offline Deployment
```bash
sudo ./vanalyzer bundle     # Create offline bundle
sudo ./vanalyzer import     # Import offline bundle
```

### Utilities
```bash
sudo ./vanalyzer certs      # Manage SSL certificates
sudo ./vanalyzer version    # Show version
sudo ./vanalyzer help       # Show help
```

---

## Security

### SSL Certificates
- Default: Self-signed certificates (browser warning expected)
- Custom certificates: Place in `traefik/config/certs/` directory

### Backup Strategy
```bash
# Manual backup
sudo ./vanalyzer backup

# Backups stored in: ./backups/backup_YYYYMMDD_HHMMSS/
```

### Complete Removal
```bash
sudo ./vanalyzer purge    # WARNING: Deletes all data and services
```

---

## Post-Installation Checklist

- [ ] Changed default Metabase admin password
- [ ] Configured database connection in Metabase
- [ ] Verified data sync completed (15-30 minutes)
- [ ] Set up backup schedule
- [ ] Configured DNS for custom hostname
- [ ] Tested threat intelligence integration (if enabled)
- [ ] Reviewed vulnerability data in dashboard

---

## Best Practices

### Operations
- Schedule regular backups using cron
- Monitor disk usage for database growth
- Review sync logs weekly
- Test restore procedures quarterly

### Performance
- Allocate sufficient RAM for large datasets
- Use SSD storage for database
- Adjust sync interval based on data volume

### Dashboard Usage
- Create custom dashboards for different teams
- Set up automated reports
- Use filters for critical assets
- Export data for compliance reporting

---

**Version**: 1.4.1 | **Last Updated**: 2025-09-30
