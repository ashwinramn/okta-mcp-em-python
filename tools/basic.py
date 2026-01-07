"""
Basic tools for CSV handling, file management, and Okta connection testing.
"""
import os
import json
import csv
import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

from client import okta_client
from s3_client import s3_client

# Constants - resolve paths relative to this file
# File is in: okta-mcp-em-python/tools/basic.py
# Root is:    okta-mcp-em-python/
PROJECT_ROOT = Path(__file__).resolve().parent.parent
CSV_FOLDER = PROJECT_ROOT / "csv"
PROCESSED_FOLDER = CSV_FOLDER / "processed"
PROCESSED_ASSIGNED_FOLDER = CSV_FOLDER / "processed_and_assigned"

# ============================================
# CSV Cache for sharing between analyze and process
# ============================================
_csv_cache: Dict[str, Dict[str, Any]] = {}

def get_cached_csv(filename: str) -> Optional[Dict[str, Any]]:
    """Retrieve cached CSV analysis data."""
    return _csv_cache.get(filename)

def set_cached_csv(filename: str, data: Dict[str, Any]):
    """Cache CSV analysis data for later use."""
    _csv_cache[filename] = data

def clear_csv_cache(filename: str = None):
    """Clear CSV cache. If filename provided, clear only that entry."""
    global _csv_cache
    if filename:
        _csv_cache.pop(filename, None)
    else:
        _csv_cache = {}

def ensure_dirs():
    CSV_FOLDER.mkdir(parents=True, exist_ok=True)
    PROCESSED_FOLDER.mkdir(parents=True, exist_ok=True)
    PROCESSED_ASSIGNED_FOLDER.mkdir(parents=True, exist_ok=True)

async def okta_test(args: Dict[str, Any]) -> str:
    # 1. Check Okta Env
    if not okta_client.domain or not okta_client.token:
        return json.dumps({
            "success": False,
            "message": "Environment variables not loaded",
            "details": {
                "OKTA_DOMAIN": "SET" if okta_client.domain else "MISSING",
                "OKTA_API_TOKEN": "SET" if okta_client.token else "MISSING"
            }
        }, indent=2)

    # 2. Call /api/v1/users/me
    result = await okta_client.execute_request("GET", "/api/v1/users/me")
    
    if not result["success"]:
        return json.dumps({
            "success": False,
            "message": "❌ Failed to connect to Okta tenant",
            "error": result.get("error") or str(result.get("response")),
            "httpCode": result.get("httpCode"),
            "details": {
                "domain": okta_client.domain,
                "tokenPreview": f"***{okta_client.token[-4:] if okta_client.token else 'None'}"
            }
        }, indent=2)
    
    user_info = result["response"]
    profile = user_info.get("profile", {})
    
    # 3. Check S3 Connection
    s3_status = "❌ Not Connected"
    s3_details = {}
    s3_instructions = ""
    
    if s3_client.enabled:
        try:
            s3_files = await s3_client.list_csv_files()
            s3_status = f"✅ Connected ({len(s3_files)} CSV files found)"
            s3_details = {
                "bucket": s3_client.bucket_name,
                "prefix": s3_client.prefix or "(root)",
                "region": s3_client.region,
                "files_found": len(s3_files)
            }
            
            if s3_files:
                file_list = "\n".join([f"      - {f}" for f in s3_files[:10]])
                if len(s3_files) > 10:
                    file_list += f"\n      ... and {len(s3_files) - 10} more"
                
                s3_instructions = (
                    f"\n\n📦 **S3 Bucket Contents**"
                    f"\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                    f"\n   Bucket: s3://{s3_client.bucket_name}/{s3_client.prefix or ''}"
                    f"\n   Files found: {len(s3_files)}"
                    f"\n\n{file_list}"
                    f"\n\n💡 **What would you like to do?**"
                    f"\n   • List all files: 'Show me all S3 files'"
                    f"\n   • View specific location: 'Show files at s3://bucket/path/'"
                    f"\n   • Sync to local: 'Sync S3 files'"
                    f"\n   • Process a file: 'analyze_csv_for_entitlements(\"filename.csv\")'"
                )
        except Exception as e:
            s3_status = f"⚠️ Connection Error"
            s3_details = {
                "error": str(e),
                "bucket": s3_client.bucket_name,
                "enabled": True
            }
            s3_instructions = (
                f"\n\n⚠️ **S3 Connection Failed**"
                f"\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                f"\nError: {str(e)}"
                f"\n\nPlease check your AWS credentials and bucket configuration."
            )
    else:
        s3_details = {"enabled": False}
        s3_instructions = (
            "\n\n📦 **S3 Integration Not Enabled**"
            "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            "\n\n**To connect your S3 bucket for CSV storage:**"
            "\n\n**Step 1: Get AWS Credentials via IAM Identity Center**"
            "\n   1. Go to your AWS Access Portal"
            "\n   2. Login and select your AWS account"
            "\n   3. Click 'Access keys' next to your account/role"
            "\n   4. Choose **Option 1: Set AWS environment variables**"
            "\n   5. Copy the three export commands shown"
            "\n"
            "\n**Step 2: Update Your .env File**"
            "\n   Add these lines to your .env file:"
            "\n   ```"
            "\n   S3_ENABLED=true"
            "\n   S3_BUCKET_NAME=your-bucket-name"
            "\n   S3_PREFIX=csv-files/"
            "\n   AWS_REGION=us-east-1"
            "\n   AWS_ACCESS_KEY_ID=ASIA..."
            "\n   AWS_SECRET_ACCESS_KEY=..."
            "\n   AWS_SESSION_TOKEN=..."
            "\n   ```"
            "\n"
            "\n**Step 3: Test Connection**"
            "\n   Run `okta_test()` again to verify S3 connectivity"
        )
    
    # 4. List Local CSV Files
    ensure_dirs()
    local_files = get_all_local_csvs()
    if local_files:
        file_list = "\n".join([f"      - {f}" for f in local_files])
        csv_msg = f"\n{file_list}"
    else:
        csv_msg = "      (None found locally)"

    menu = (
         "\n\n🤖 **MCP MAIN MENU**"
         "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
         "\n1️⃣  **CSV Processing**"
         f"\n   Local files:{csv_msg}"
         "\n   > Action: `analyze_csv_for_entitlements('filename.csv')`"
         "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    )

    return json.dumps({
        "success": True,
        "message": f"✅ Okta tenant connected successfully!{s3_instructions}{menu}",
        "details": {
            "okta": {
                "domain": okta_client.domain,
                "user": profile.get("email") or profile.get("login") or "authenticated",
                "status": user_info.get("status", "active"),
                "tokenPreview": f"***{okta_client.token[-4:]}"
            },
            "s3": {
                "status": s3_status,
                **s3_details
            },
            "local_csv_files": len(local_files)
        }
    }, indent=2)

def get_all_local_csvs() -> List[str]:
    """Recursively list all CSV files in CSV_FOLDER, returning paths relative to it."""
    csvs = []
    if not CSV_FOLDER.exists():
        return []
        
    for root, _, files in os.walk(CSV_FOLDER):
        for f in files:
            if f.endswith(".csv"):
                # Get relative path from CSV_FOLDER (e.g., "folder/file.csv")
                full_path = Path(root) / f
                rel_path = full_path.relative_to(CSV_FOLDER)
                csvs.append(str(rel_path))
    return sorted(csvs)

async def list_csv_files(args: Dict[str, Any]) -> str:
    ensure_dirs()
    
    local_files = get_all_local_csvs()
    
    s3_files = []
    if s3_client.enabled:
        s3_files = await s3_client.list_csv_files()
    
    # Merge unique paths
    all_files = sorted(set(local_files + s3_files))
    
    if not all_files:
        msg = "No CSV files found"
        if s3_client.enabled:
            msg += f" in local folder or S3 bucket ({s3_client.bucket_name})"
        else:
            msg += " in csv/ folder"
        return msg + ". Please add CSV files to process."
    
    file_list = []
    for i, f in enumerate(all_files):
        source = ""
        if f in local_files and f in s3_files:
            source = " [local + S3]"
        elif f in s3_files:
            source = " [S3]"
        file_list.append(f"{i+1}. {f}{source}")
    
    file_list_str = "\n".join(file_list)
    
    return (f"Available CSV files:\n\n{file_list_str}\n\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "⚠️  REQUIRED: Please provide the Okta App ID to process these files.\n"
            "   Example: \"The App ID is 0oa1234567890ABCDEF\"\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

def get_csv_path(file_identifier: str) -> Optional[Path]:
    """
    Resolves a CSV path from a filename/path OR a list index number (string).
    Auto-downloads from S3 if not found locally.
    """
    import logging
    logger = logging.getLogger("okta_mcp")
    
    # 1. Try by Index
    if file_identifier.isdigit():
        idx = int(file_identifier) - 1
        # Start with all known files (local + S3) to respect the list order
        # Note: This list generation might be slow if S3 is slow, but necessary for consistent indexing
        # For efficiency, we might just look at local files if we assume user is picking from local list?
        # But list_csv_files shows mixed list. We must re-fetch or assume state.
        # To avoid async call in sync function, we'll just scan local for now. 
        # Ideally this tool usage passes the full filename.
        local_files = get_all_local_csvs()
        if 0 <= idx < len(local_files):
             return CSV_FOLDER / local_files[idx]
             
    # 2. Try by Path (Relative to CSV_FOLDER)
    potential_path = CSV_FOLDER / file_identifier
    if potential_path.exists() and potential_path.is_file():
        return potential_path
    
    # 3. Try appending .csv
    if not file_identifier.lower().endswith(".csv"):
        file_identifier_csv = f"{file_identifier}.csv"
        potential_path = CSV_FOLDER / file_identifier_csv
        if potential_path.exists() and potential_path.is_file():
            return potential_path
    else:
        file_identifier_csv = file_identifier
    
    # 4. Try S3 Download (if enabled)
    # logic: if we have a key "folder/file.csv", we try to download it.
    if s3_client.enabled:
        logger.info(f"File {file_identifier_csv} not found locally, attempting S3 download")
        import asyncio
        # We assume file_identifier_csv is the S3 key relative to bucket root 
        # (or whatever list_csv_files returned)
        target_local_path = CSV_FOLDER / file_identifier_csv
        success = asyncio.run(s3_client.download_file(file_identifier_csv, target_local_path))
        if success:
            return target_local_path
    
    return None

async def read_csv_file(args: Dict[str, Any]) -> str:
    ensure_dirs()
    file_identifier = args.get("file")
    if not file_identifier:
        raise ValueError("File argument is required")
    
    file_path = get_csv_path(file_identifier)
    
    if not file_path:
         return f"❌ File not found: {file_identifier} (Checked index and filename in {CSV_FOLDER})"

    try:
        size_bytes = file_path.stat().st_size
        creation_time = datetime.datetime.fromtimestamp(file_path.stat().st_ctime).replace(microsecond=0)
        filename = file_path.name
    except FileNotFoundError:
        return f"❌ File not found: {file_identifier}"
    except Exception as e:
        return f"❌ Error accessing file {file_identifier}: {e}"
    
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    lines = content.strip().split('\n')
    row_count = len(lines) - 1
    columns = lines[0].split(',') if lines else []
    
    return (f"📄 File: {filename}\n"
            f"📊 Rows: {row_count} | Columns: {len(columns)}\n"
            f"📝 Columns: {', '.join(columns)}\n\n"
            f"{content}\n\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            "⚠️  REQUIRED: Please provide the Okta App ID to process this file.\n"
            "   Example: \"The App ID is 0oa1234567890ABCDEF\"\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

async def move_to_processed(args: Dict[str, Any]) -> str:
    ensure_dirs()
    filename = args.get("filename")
    dest = args.get("destination", "processed")
    
    if not filename:
        return "❌ Error: filename required"

    src = CSV_FOLDER / filename
    destination_folder = PROCESSED_ASSIGNED_FOLDER if dest == "processed_and_assigned" else PROCESSED_FOLDER
    dst = destination_folder / filename
    
    if not src.exists():
        return f"❌ Error: File {filename} not found in {CSV_FOLDER}"
    
    try:
        src.rename(dst)
        clear_csv_cache(filename)
        return f"✅ File moved to {dest}: {filename}"
    except Exception as e:
        return f"❌ Error moving file: {str(e)}"

async def sync_s3_files(args: Dict[str, Any]) -> str:
    """Manually sync all CSV files from S3 to local folder."""
    if not s3_client.enabled:
        return "❌ S3 integration is not enabled. Set S3_ENABLED=true in .env"
    
    ensure_dirs()
    result = await s3_client.sync_to_local(CSV_FOLDER)
    
    if result["errors"]:
        return (f"⚠️ Synced {result['synced']}/{result['total']} files from S3\n"
                f"Errors: {', '.join(result['errors'])}")
    
    return f"✅ Successfully synced {result['synced']} CSV files from S3 bucket: {s3_client.bucket_name}"

async def validate_csv_preflight(args: Dict[str, Any]) -> str:
    """Validate a CSV file for common errors before Okta processing."""
    import pandas as pd
    ensure_dirs()
    file_identifier = args.get("file")
    if not file_identifier:
        return "❌ Error: file identifier required"
    
    file_path = get_csv_path(file_identifier)
    if not file_path:
        return f"❌ Error: File {file_identifier} not found"
    
    try:
        df = pd.read_csv(file_path)
        issues = []
        
        # 1. Check required columns
        required = ["Email"]
        missing = [col for col in required if col not in df.columns]
        if missing:
            issues.append(f"Missing required columns: {', '.join(missing)}")
        
        # 2. Check for empty values in critical columns
        if "Email" in df.columns:
            empty_emails = df["Email"].isna().sum()
            if empty_emails > 0:
                issues.append(f"Found {empty_emails} rows with empty Email values")
        
        # 3. Check for obvious duplicate emails (if single grant per user expected)
        # Note: Some CSVs allow multiple rows per user, so this is just a warning
        duplicate_emails = df["Email"].duplicated().sum()
        if duplicate_emails > 0:
            issues.append(f"ℹ️ Info: Found {duplicate_emails} duplicate email entries (may be intended for multi-role assignment)")
            
        # 4. Check for potential entitlement columns
        entitlement_keywords = ["Role", "Permission", "Group", "Entitlement", "Access"]
        found_entitlements = [col for col in df.columns if any(kw in col for kw in entitlement_keywords)]
        if not found_entitlements:
            issues.append("Warning: No obvious entitlement columns found (Role, Permission, etc.)")
            
        if not issues:
            return f"✅ Pre-flight check passed for {file_path.name}! Ready for analysis."
        
        issues_str = "\n".join([f"- {i}" for i in issues])
        return f"📊 Pre-flight check results for {file_path.name}:\n\n{issues_str}"
        
    except Exception as e:
        return f"❌ Error validating CSV: {str(e)}"

