"""
S3 Client for CSV file retrieval from AWS S3 buckets.
Supports multiple authentication methods and file caching.

Uses aioboto3 for true async operations to avoid blocking the event loop.
"""
import os
import logging
import asyncio
from pathlib import Path
from typing import Optional, List, Dict, Any

import aioboto3
from botocore.exceptions import ClientError, NoCredentialsError
from dotenv import load_dotenv

# Load .env from project root
PROJECT_ROOT = Path(__file__).resolve().parent
load_dotenv(PROJECT_ROOT / ".env")

logger = logging.getLogger("okta_mcp")


class S3Client:
    """Manages S3 operations for CSV file retrieval using async operations."""
    
    def __init__(self):
        self.enabled = os.environ.get("S3_ENABLED", "false").lower() == "true"
        self.bucket_name = os.environ.get("S3_BUCKET_NAME")
        self.prefix = os.environ.get("S3_PREFIX", "")
        self.region = os.environ.get("AWS_REGION", "us-east-1")
        
        if self.enabled and not self.bucket_name:
            logger.warning("S3_ENABLED is true but S3_BUCKET_NAME not set")
            self.enabled = False
        
        # Create session for aioboto3 (client created per-request)
        self.session = aioboto3.Session() if self.enabled else None
        
        if self.enabled:
            logger.info(f"S3 client initialized for bucket: {self.bucket_name}")
    
    async def list_csv_files(self) -> List[str]:
        """List all CSV files in the S3 bucket (truly async).
        
        Returns full S3 keys relative to the bucket root (not just filenames),
        so they can be used directly for download operations.
        """
        if not self.enabled or not self.session:
            return []
        
        try:
            async with self.session.client('s3', region_name=self.region) as client:
                # Handle pagination for large buckets
                files = []
                paginator_params = {'Bucket': self.bucket_name}
                if self.prefix:
                    paginator_params['Prefix'] = self.prefix
                
                response = await client.list_objects_v2(**paginator_params)
                
                for obj in response.get('Contents', []):
                    key = obj['Key']
                    if key.endswith('.csv'):
                        # Return full key for download, not just filename
                        files.append(key)
                
                # Handle pagination if there are more files
                while response.get('IsTruncated'):
                    response = await client.list_objects_v2(
                        **paginator_params,
                        ContinuationToken=response['NextContinuationToken']
                    )
                    for obj in response.get('Contents', []):
                        key = obj['Key']
                        if key.endswith('.csv'):
                            files.append(key)
                
                return sorted(files)
        except ClientError as e:
            logger.error(f"Error listing S3 files: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error listing S3 files: {e}")
            return []
    
    async def download_file(self, s3_key: str, local_path: Path) -> bool:
        """Download a CSV file from S3 to local path (truly async).
        
        Args:
            s3_key: Full S3 key (as returned by list_csv_files)
            local_path: Local path to save the file
        """
        if not self.enabled or not self.session:
            return False
        
        try:
            async with self.session.client('s3', region_name=self.region) as client:
                # Use get_object for async download
                response = await client.get_object(
                    Bucket=self.bucket_name,
                    Key=s3_key
                )
                
                # Read the body asynchronously
                async with response['Body'] as stream:
                    data = await stream.read()
                
                # Write to local file
                local_path.parent.mkdir(parents=True, exist_ok=True)
                with open(local_path, 'wb') as f:
                    f.write(data)
            
            logger.info(f"Downloaded {s3_key} from S3 to {local_path}")
            return True
        except ClientError as e:
            logger.error(f"Error downloading {s3_key} from S3: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error downloading {s3_key}: {e}")
            return False
    
    async def sync_to_local(self, local_folder: Path) -> Dict[str, Any]:
        """Sync all CSV files from S3 to local folder (concurrent downloads).
        
        Preserves folder structure from S3 in the local folder.
        """
        if not self.enabled:
            return {"synced": 0, "errors": [], "total": 0}
        
        files = await self.list_csv_files()
        
        if not files:
            return {"synced": 0, "errors": [], "total": 0}
        
        # Download files concurrently (max 5 at a time)
        semaphore = asyncio.Semaphore(5)
        results = {"synced": 0, "errors": [], "total": len(files)}
        
        async def download_with_semaphore(s3_key: str):
            async with semaphore:
                # Preserve folder structure locally
                local_path = local_folder / s3_key
                success = await self.download_file(s3_key, local_path)
                if success:
                    results["synced"] += 1
                else:
                    results["errors"].append(s3_key)
        
        # Run all downloads concurrently
        await asyncio.gather(*[download_with_semaphore(f) for f in files])
        
        return results


# Global instance
s3_client = S3Client()
