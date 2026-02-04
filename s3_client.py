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
        """List all CSV files in the S3 bucket."""
        if not self.enabled or not self.client:
            return []
        
        try:
            response = self.client.list_objects_v2(
                Bucket=self.bucket_name,
                Prefix=self.prefix
            )
            
            files = []
            for obj in response.get('Contents', []):
                key = obj['Key']
                if key.endswith('.csv'):
                    filename = Path(key).name
                    files.append(filename)
            
            return sorted(files)
        except ClientError as e:
            logger.error(f"Error listing S3 files: {e}")
            return []
    
    async def download_file(self, filename: str, local_path: Path) -> bool:
        """Download a CSV file from S3 to local path."""
        if not self.enabled or not self.client:
            return False
        
        try:
            s3_key = f"{self.prefix}/{filename}" if self.prefix else filename
            
            self.client.download_file(
                Bucket=self.bucket_name,
                Key=s3_key,
                Filename=str(local_path)
            )
            
            logger.info(f"Downloaded {filename} from S3 to {local_path}")
            return True
        except ClientError as e:
            logger.error(f"Error downloading {filename} from S3: {e}")
            return False
    
    async def sync_to_local(self, local_folder: Path) -> Dict[str, Any]:
        """Sync all CSV files from S3 to local folder."""
        if not self.enabled:
            return {"synced": 0, "errors": []}
        
        files = await self.list_csv_files()
        synced = 0
        errors = []
        
        for filename in files:
            local_path = local_folder / filename
            success = await self.download_file(filename, local_path)
            if success:
                synced += 1
            else:
                errors.append(filename)
        
        return {"synced": synced, "errors": errors, "total": len(files)}

# Global instance
s3_client = S3Client()
