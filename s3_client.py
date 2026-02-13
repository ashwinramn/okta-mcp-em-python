"""
S3 Client for CSV file retrieval from AWS S3 buckets.
Supports multiple authentication methods and file caching.

Uses boto3 (synchronous) with asyncio.to_thread() wrappers to avoid blocking
the event loop while keeping the async interface for callers.
"""
import os
import logging
import asyncio
from pathlib import Path
from typing import List, Dict, Any

import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from dotenv import load_dotenv

# Load .env from project root
PROJECT_ROOT = Path(__file__).resolve().parent
load_dotenv(PROJECT_ROOT / ".env", override=True)

logger = logging.getLogger("okta_mcp")


class S3Client:
    """Manages S3 operations for CSV file retrieval using boto3."""

    def __init__(self):
        self.enabled = os.environ.get("S3_ENABLED", "false").lower() == "true"
        self.bucket_name = os.environ.get("S3_BUCKET_NAME")
        self.prefix = os.environ.get("S3_PREFIX", "")
        self.region = os.environ.get("AWS_REGION", "us-east-1")

        if self.enabled and not self.bucket_name:
            logger.warning("S3_ENABLED is true but S3_BUCKET_NAME not set")
            self.enabled = False

        if self.enabled:
            logger.info(f"S3 client initialized for bucket: {self.bucket_name}")

    def _get_client(self):
        """Create a boto3 S3 client with current credentials."""
        if not self.enabled:
            return None
        return boto3.client('s3', region_name=self.region)

    def _list_csv_files_sync(self) -> List[str]:
        """Synchronous implementation: list all CSV files in the S3 bucket."""
        client = self._get_client()
        if not client:
            return []

        try:
            files = []
            paginator_params = {'Bucket': self.bucket_name}
            if self.prefix:
                paginator_params['Prefix'] = self.prefix

            paginator = client.get_paginator('list_objects_v2')
            for page in paginator.paginate(**paginator_params):
                for obj in page.get('Contents', []):
                    key = obj['Key']
                    if key.endswith('.csv'):
                        files.append(key)

            return sorted(files)
        except ClientError as e:
            logger.error(f"Error listing S3 files: {e}")
            return []
        except NoCredentialsError as e:
            logger.error(f"AWS credentials not configured: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error listing S3 files: {e}")
            return []

    def _download_file_sync(self, s3_key: str, local_path: Path) -> bool:
        """Synchronous implementation: download a CSV file from S3."""
        client = self._get_client()
        if not client:
            return False

        try:
            local_path.parent.mkdir(parents=True, exist_ok=True)
            client.download_file(self.bucket_name, s3_key, str(local_path))
            logger.info(f"Downloaded {s3_key} from S3 to {local_path}")
            return True
        except ClientError as e:
            logger.error(f"Error downloading {s3_key} from S3: {e}")
            return False
        except NoCredentialsError as e:
            logger.error(f"AWS credentials not configured: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error downloading {s3_key}: {e}")
            return False

    def _sync_to_local_sync(self, local_folder: Path) -> Dict[str, Any]:
        """Synchronous implementation: sync all CSV files from S3 to local folder."""
        if not self.enabled:
            return {"synced": 0, "errors": [], "total": 0}

        files = self._list_csv_files_sync()

        if not files:
            return {"synced": 0, "errors": [], "total": 0}

        results = {"synced": 0, "errors": [], "total": len(files)}

        for s3_key in files:
            local_path = local_folder / s3_key
            success = self._download_file_sync(s3_key, local_path)
            if success:
                results["synced"] += 1
            else:
                results["errors"].append(s3_key)

        return results

    # ------------------------------------------------------------------
    # Async wrappers — these are what callers use
    # ------------------------------------------------------------------

    async def list_csv_files(self) -> List[str]:
        """List all CSV files in the S3 bucket.

        Returns full S3 keys relative to the bucket root (not just filenames),
        so they can be used directly for download operations.
        """
        return await asyncio.to_thread(self._list_csv_files_sync)

    async def download_file(self, s3_key: str, local_path: Path) -> bool:
        """Download a CSV file from S3 to local path.

        Args:
            s3_key: Full S3 key (as returned by list_csv_files)
            local_path: Local path to save the file
        """
        return await asyncio.to_thread(self._download_file_sync, s3_key, local_path)

    async def sync_to_local(self, local_folder: Path) -> Dict[str, Any]:
        """Sync all CSV files from S3 to local folder."""
        return await asyncio.to_thread(self._sync_to_local_sync, local_folder)

    # ------------------------------------------------------------------
    # Synchronous direct-call methods for non-async contexts
    # ------------------------------------------------------------------

    def download_file_sync(self, s3_key: str, local_path: Path) -> bool:
        """Download a file synchronously. Use from non-async code paths."""
        return self._download_file_sync(s3_key, local_path)


# Global instance
s3_client = S3Client()
