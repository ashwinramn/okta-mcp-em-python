"""
S3 Client for CSV file retrieval from AWS S3 buckets.
Supports multiple authentication methods and file caching.
"""
import os
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from dotenv import load_dotenv

# Load .env from project root
PROJECT_ROOT = Path(__file__).resolve().parent
load_dotenv(PROJECT_ROOT / ".env")

logger = logging.getLogger("okta_mcp")

class S3Client:
    """Manages S3 operations for CSV file retrieval."""
    
    def __init__(self):
        self.enabled = os.environ.get("S3_ENABLED", "false").lower() == "true"
        self.bucket_name = os.environ.get("S3_BUCKET_NAME")
        self.prefix = os.environ.get("S3_PREFIX", "")
        # Parse allowed paths list if present (split by comma and strip whitespace)
        allowed_paths_str = os.environ.get("S3_ALLOWED_PATHS", "")
        self.allowed_paths = [p.strip() for p in allowed_paths_str.split(",") if p.strip()]
        
        self.region = os.environ.get("AWS_REGION", "us-east-1")
        
        if self.enabled and not self.bucket_name:
            logger.warning("S3_ENABLED is true but S3_BUCKET_NAME not set")
            self.enabled = False
        
        self.client = None
        if self.enabled:
            try:
                self.client = boto3.client('s3', region_name=self.region)
                logger.info(f"S3 client initialized for bucket: {self.bucket_name}")
            except Exception as e:
                logger.error(f"Failed to initialize S3 client: {e}")
                self.enabled = False
    
    async def list_csv_files(self) -> List[str]:
        """
        List all CSV files in the S3 bucket.
        Returns: List of full S3 keys (paths) to the files.
        """
        if not self.enabled or not self.client:
            return []
        
        search_paths = self.allowed_paths if self.allowed_paths else [self.prefix]
        files = []
        
        try:
            for path in search_paths:
                # Ensure path ends with slash if it's a folder, unless it's empty (root)
                prefix = path
                if prefix and not prefix.endswith('/') and not prefix.endswith('.csv'):
                     prefix += '/'
                
                response = self.client.list_objects_v2(
                    Bucket=self.bucket_name,
                    Prefix=prefix
                )
                
                for obj in response.get('Contents', []):
                    key = obj['Key']
                    if key.endswith('.csv'):
                        # Return full key so we can distinguish files in different folders
                        files.append(key)
            
            # Deduplicate and sort
            return sorted(list(set(files)))
            
        except ClientError as e:
            logger.error(f"Error listing S3 files: {e}")
            return []
    
    async def download_file(self, s3_key: str, local_path: Path) -> bool:
        """Download a CSV file from S3 using its key to a local path."""
        if not self.enabled or not self.client:
            return False
        
        try:
            # Ensure local parent dir exists (for nested keys)
            local_path.parent.mkdir(parents=True, exist_ok=True)
            
            self.client.download_file(
                Bucket=self.bucket_name,
                Key=s3_key,
                Filename=str(local_path)
            )
            
            logger.info(f"Downloaded {s3_key} from S3 to {local_path}")
            return True
        except ClientError as e:
            logger.error(f"Error downloading {s3_key} from S3: {e}")
            return False
    
    async def sync_to_local(self, local_folder: Path) -> Dict[str, Any]:
        """Sync all CSV files from S3 to local folder."""
        if not self.enabled:
            return {"synced": 0, "errors": []}
        
        files = await self.list_csv_files()
        synced = 0
        errors = []
        
        for key in files:
            # Mirror S3 directory structure locally
            # If key is "data/report.csv", local path is local_folder/data/report.csv
            local_path = local_folder / key
            
            success = await self.download_file(key, local_path)
            if success:
                synced += 1
            else:
                errors.append(key)
        
        return {"synced": synced, "errors": errors, "total": len(files)}

# Global instance
s3_client = S3Client()
