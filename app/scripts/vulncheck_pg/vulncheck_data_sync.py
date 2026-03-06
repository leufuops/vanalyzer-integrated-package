#!/usr/bin/env python3
"""
VulncheckDataSync - Integration module for vulnerability data synchronization
Designed to be integrated into existing vulnerability analysis tools
"""

import os
import sys
import logging
import requests
from datetime import datetime
from pathlib import Path
from typing import List, Optional
from dotenv import load_dotenv
import vulncheck_sdk
from vulncheck_sdk.rest import ApiException

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(f'vulncheck_{datetime.now().strftime("%Y%m%d")}.log')
    ]
)
logger = logging.getLogger(__name__)

# API Configuration
DEFAULT_HOST = "https://api.vulncheck.com"
DEFAULT_API = DEFAULT_HOST + "/v3"

class VulncheckDataSync:
    """Integration module for synchronizing vulnerability data from Vulncheck API"""
    
    def __init__(self, api_token=None, download_dir=None, selected_indexes=None, logger=None):
        """
        Initialize the VulncheckDataSync module
        
        Args:
            api_token: API token (if None, reads from VULNCHECK_API_TOKEN env var)
            download_dir: Directory for downloads (if None, uses ./vulncheck_data)
            selected_indexes: List of indexes to sync (if None, reads from env)
            self.logger: Custom logger instance (if None, creates default logger)
        """
        self.token = api_token or os.environ.get("VULNCHECK_API_TOKEN")
        if not self.token:
            self.logger.error("VULNCHECK_API_TOKEN not found in environment variables")
            raise ValueError("Please set VULNCHECK_API_TOKEN in .env file")
        
        self.configuration = vulncheck_sdk.Configuration(host=DEFAULT_API)
        self.configuration.api_key["Bearer"] = self.token
        
        # Parse index list from parameter or environment
        if selected_indexes is not None:
            self.selected_indexes = selected_indexes if isinstance(selected_indexes, list) else [selected_indexes]
        else:
            self.selected_indexes = self._parse_index_list()
        
        # Create download directory
        if download_dir:
            self.download_dir = Path(download_dir)
        else:
            self.download_dir = Path(os.environ.get("VULNCHECK_DOWNLOAD_DIR", "vulncheck_data"))
        self.download_dir.mkdir(exist_ok=True)
        
        # Use provided logger or create default
        self.logger = logger or logging.getLogger(__name__)
        
        self.logger.info(f"Initialized VulncheckDataSync with {len(self.selected_indexes)} selected indexes")
    
    def _parse_index_list(self) -> List[str]:
        """Parse the comma-separated list of indexes from environment"""
        index_string = os.environ.get("VULNCHECK_INDEXES", "")
        if not index_string:
            return []
        
        # Clean and split the index list
        indexes = [idx.strip() for idx in index_string.split(",") if idx.strip()]
        return indexes
    
    def list_all_indexes(self, save_to_file: bool = False) -> List[str]:
        """
        List all available indexes from the API
        
        Args:
            save_to_file: If True, saves the list to available_indexes.txt
            
        Returns:
            List of available index names
        """
        logger.info("Fetching all available indexes...")
        try:
            with vulncheck_sdk.ApiClient(self.configuration) as api_client:
                endpoints_client = vulncheck_sdk.EndpointsApi(api_client)
                api_response = endpoints_client.index_get()
                
                indexes = [index.name for index in api_response.data]
                self.logger.info(f"Found {len(indexes)} available indexes")
                
                if save_to_file:
                    self.save_index_list(indexes)
                
                return indexes
        
        except ApiException as e:
            self.logger.error(f"API Exception: {e.status} - {e.reason}")
            return []
        except Exception as e:
            self.logger.error(f"Unexpected error: {str(e)}")
            return []
    
    def save_index_list(self, indexes: List[str]) -> str:
        """
        Save the list of indexes to a file for reference
        
        Args:
            indexes: List of index names to save
            
        Returns:
            Path to the saved file
        """
        from datetime import datetime
        
        filename = f"available_indexes_{datetime.now().strftime('%Y%m%d')}.txt"
        filepath = Path(filename)
        
        with open(filepath, 'w') as f:
            f.write("# Vulncheck Available Indexes\n")
            f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# Total: {len(indexes)} indexes\n")
            f.write("#\n")
            f.write("# Copy the index names you want to sync to your .env file\n")
            f.write("# Example: VULNCHECK_INDEXES=initial-access,cisa-kev,exploits\n")
            f.write("#\n")
            f.write("# Popular/Important Indexes:\n")
            f.write("#   initial-access    - Initial access vulnerabilities\n")
            f.write("#   cisa-kev         - CISA Known Exploited Vulnerabilities\n")
            f.write("#   exploits         - Available exploits\n")
            f.write("#   nist-nvd2        - NIST National Vulnerability Database\n")
            f.write("#   mitre-cvelist-v5 - MITRE CVE List\n")
            f.write("#   exploit-chains   - Exploit chains\n")
            f.write("#   ransomware       - Ransomware vulnerabilities\n")
            f.write("#\n")
            f.write("-" * 60 + "\n\n")
            
            # Write all indexes in alphabetical order
            f.write("## All Available Indexes (Alphabetical)\n\n")
            for index in sorted(indexes):
                f.write(f"{index}\n")
        
        self.logger.info(f"Index list saved to {filepath}")
        print(f"\nIndex list saved to: {filepath}")
        print(f"Review this file to select indexes for your .env configuration")
        
        return str(filepath)
    
    def download_index(self, index_name: str, force: bool = False) -> bool:
        """
        Download a specific index backup
        
        Args:
            index_name: Name of the index to download
            force: Force download even if file exists
        
        Returns:
            True if successful, False otherwise
        """
        file_path = self.download_dir / f"{index_name}.zip"
        
        # Check if file already exists
        if file_path.exists() and not force:
            self.logger.info(f"Index '{index_name}' already downloaded at {file_path}")
            return True
        
        logger.info(f"Downloading index: {index_name}")
        
        try:
            with vulncheck_sdk.ApiClient(self.configuration) as api_client:
                endpoints_client = vulncheck_sdk.EndpointsApi(api_client)
                
                # Get backup URL
                api_response = endpoints_client.backup_index_get(index_name)
                
                if not api_response.data:
                    self.logger.error(f"No backup data available for index '{index_name}'")
                    return False
                
                backup_url = api_response.data[0].url
                self.logger.info(f"Fetching backup from: {backup_url[:50]}...")
                
                # Download the file
                response = requests.get(backup_url, stream=True)
                response.raise_for_status()
                
                # Save to file with progress indication
                total_size = int(response.headers.get('content-length', 0))
                
                with open(file_path, "wb") as file:
                    downloaded = 0
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            file.write(chunk)
                            downloaded += len(chunk)
                            if total_size > 0:
                                progress = (downloaded / total_size) * 100
                                print(f"\rDownloading {index_name}: {progress:.1f}%", end="", flush=True)
                
                print()  # New line after progress
                file_size_mb = file_path.stat().st_size / (1024 * 1024)
                self.logger.info(f"Downloaded '{index_name}' ({file_size_mb:.2f} MB) to {file_path}")
                return True
        
        except ApiException as e:
            self.logger.error(f"API Exception for '{index_name}': {e.status} - {e.reason}")
            return False
        except requests.RequestException as e:
            self.logger.error(f"Download error for '{index_name}': {str(e)}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error downloading '{index_name}': {str(e)}")
            return False
    
    def sync_indexes(self, indexes=None, force: bool = False) -> dict:
        """
        Synchronize vulnerability data indexes
        
        Args:
            indexes: List of indexes to sync (if None, uses selected_indexes)
            force: Force re-download even if files exist
        
        Returns:
            Dictionary with sync results
        """
        indexes_to_sync = indexes or self.selected_indexes
        
        if not indexes_to_sync:
            self.logger.warning("No indexes specified for synchronization")
            return {"success": [], "failed": [], "skipped": []}
        
        self.logger.info(f"Starting synchronization of {len(indexes_to_sync)} indexes")
        results = {"success": [], "failed": [], "skipped": []}
        
        for index in indexes_to_sync:
            result = self.download_index(index, force=force)
            if result:
                results["success"].append(index)
            else:
                results["failed"].append(index)
        
        return results
    
    def download_selected_indexes(self, force: bool = False) -> dict:
        """
        Download all indexes specified in VULNCHECK_INDEXES environment variable
        
        Args:
            force: Force download even if files exist
        
        Returns:
            Dictionary with download results
        """
        if not self.selected_indexes:
            self.logger.warning("No indexes selected in VULNCHECK_INDEXES environment variable")
            return {"success": [], "failed": [], "skipped": []}
        
        logger.info(f"Starting download of {len(self.selected_indexes)} selected indexes")
        results = {"success": [], "failed": [], "skipped": []}
        
        for index in self.selected_indexes:
            result = self.download_index(index, force=force)
            if result:
                results["success"].append(index)
            else:
                results["failed"].append(index)
        
        return results
    
    def test_connection(self) -> bool:
        """Test API connection and authentication"""
        logger.info("Testing API connection...")
        try:
            with vulncheck_sdk.ApiClient(self.configuration) as api_client:
                endpoints_client = vulncheck_sdk.EndpointsApi(api_client)
                api_response = endpoints_client.index_get()
                self.logger.info("API connection successful")
                return True
        except Exception as e:
            self.logger.error(f"API connection failed: {str(e)}")
            return False


def main():
    """Main function with CLI interface"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Vulncheck SDK Tool")
    parser.add_argument("action", choices=["list", "download", "test", "download-selected"],
                       help="Action to perform")
    parser.add_argument("--index", "-i", help="Specific index name for download")
    parser.add_argument("--force", "-f", action="store_true", 
                       help="Force download even if file exists")
    parser.add_argument("--verbose", "-v", action="store_true",
                       help="Enable verbose output")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        client = VulncheckDataSync()
        
        if args.action == "test":
            success = client.test_connection()
            sys.exit(0 if success else 1)
        
        elif args.action == "list":
            indexes = client.list_all_indexes(save_to_file=True)
            if indexes:
                print("\nAvailable Indexes:")
                print("-" * 40)
                for i, index in enumerate(indexes, 1):
                    print(f"{i:3}. {index}")
                print(f"\nTotal: {len(indexes)} indexes")
            else:
                print("Failed to retrieve indexes")
                sys.exit(1)
        
        elif args.action == "download":
            if not args.index:
                print("Error: --index is required for download action")
                sys.exit(1)
            
            success = client.download_index(args.index, force=args.force)
            sys.exit(0 if success else 1)
        
        elif args.action == "download-selected":
            if not client.selected_indexes:
                print("No indexes configured in VULNCHECK_INDEXES environment variable")
                print("Add indexes to .env file, e.g.:")
                print('VULNCHECK_INDEXES="initial-access,cisa-kev,exploits"')
                sys.exit(1)
            
            print(f"Downloading {len(client.selected_indexes)} configured indexes...")
            results = client.download_selected_indexes(force=args.force)
            
            print("\n" + "=" * 50)
            print("DOWNLOAD SUMMARY")
            print("=" * 50)
            if results["success"]:
                print(f"Success ({len(results['success'])}): {', '.join(results['success'])}")
            if results["failed"]:
                print(f"Failed ({len(results['failed'])}): {', '.join(results['failed'])}")
            
            success_rate = len(results["success"]) / len(client.selected_indexes) * 100
            print(f"\nTotal: {len(results['success'])}/{len(client.selected_indexes)} ({success_rate:.0f}%)")
            
            sys.exit(0 if not results["failed"] else 1)
    
    except ValueError as e:
        logger.error(str(e))
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("\nOperation interrupted by user")
        sys.exit(1)


if __name__ == "__main__":
    main()