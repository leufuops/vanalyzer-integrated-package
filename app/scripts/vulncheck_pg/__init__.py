"""
VulncheckDB - PostgreSQL CVE Enrichment Module

Simple, reliable PostgreSQL CVE enrichment using vulncheck data.
Copy this folder into any project to add vulnerability intelligence to your CVE database.

Usage:
    from vulncheck_pg import VulncheckDB
    
    db = VulncheckDB(your_db_connection)
    db.sync()  # Download + enrich CVEs
"""

from .main import VulncheckDB

__version__ = "1.0.0"
__author__ = "Vulncheck Integration Team"
__description__ = "PostgreSQL CVE enrichment with vulncheck data"

__all__ = ["VulncheckDB"]