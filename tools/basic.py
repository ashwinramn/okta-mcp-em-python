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
    local_files = sorted([f for f in os.listdir(CSV_FOLDER) if f.endswith(".csv")])
    if local_files:
        file_list = "\n".join([f"      - {f}" for f in local_files])
        csv_msg = f"\n{file_list}"
    else:
        csv_msg = "      (None found locally)"

    # Fetch live dashboard menu
    from tools import menu as _menu
    menu_result_str = await _menu.show_workflow_menu({})

    return json.dumps({
        "success": True,
        "message": f"Okta tenant connected successfully!{s3_instructions}",
        "details": {
            "okta": {
                "domain": okta_client.domain,
                "user": profile.get("email") or profile.get("login") or "authenticated",
                "status": user_info.get("status", "active"),
            },
            "s3": {
                "status": s3_status,
                **s3_details
            },
            "local_csv_files": len(local_files)
        },
        "menu": json.loads(menu_result_str)
    }, indent=2)

async def list_csv_files(args: Dict[str, Any]) -> str:
    ensure_dirs()
    
    local_files = sorted([f for f in os.listdir(CSV_FOLDER) if f.endswith(".csv")])
    
    s3_files = []
    if s3_client.enabled:
        s3_files = await s3_client.list_csv_files()
    
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
    Resolves a CSV path from a filename OR a list index number (string).
    Searches CSV_FOLDER and all subdirectories recursively.
    Auto-downloads from S3 if not found locally.
    """
    import logging
    logger = logging.getLogger("okta_mcp")

    def _is_safe_path(resolved_path: Path, base_path: Path) -> bool:
        """
        Verify that resolved_path is within base_path (no directory traversal).
        Returns True only if resolved_path is within base_path hierarchy.
        """
        try:
            # Resolve both paths to absolute, normalized form
            resolved_abs = resolved_path.resolve()
            base_abs = base_path.resolve()

            # Check if resolved path is within base path
            resolved_abs.relative_to(base_abs)
            return True
        except ValueError:
            # relative_to raises ValueError if not under base_path
            return False

    # Sanitize filename to prevent directory traversal
    file_identifier = file_identifier.strip()

    # Block obvious traversal attempts
    if ".." in file_identifier or file_identifier.startswith("/"):
        logger.warning(f"Blocked suspicious path identifier: {file_identifier}")
        return None

    if file_identifier.isdigit():
        idx = int(file_identifier) - 1
        files = sorted([f for f in CSV_FOLDER.glob("*.csv") if f.is_file()])
        if 0 <= idx < len(files):
            return files[idx]
    
    # Check direct path first
    potential_path = CSV_FOLDER / file_identifier
    if potential_path.exists() and potential_path.is_file():
        if _is_safe_path(potential_path, CSV_FOLDER):
            return potential_path
        else:
            logger.warning(f"Blocked path traversal attempt: {potential_path}")
            return None
    
    # Add .csv extension if not present
    if not file_identifier.lower().endswith(".csv"):
        file_identifier_csv = f"{file_identifier}.csv"
    else:
        file_identifier_csv = file_identifier
    
    potential_path = CSV_FOLDER / file_identifier_csv
    if potential_path.exists() and potential_path.is_file():
        if _is_safe_path(potential_path, CSV_FOLDER):
            return potential_path
        else:
            logger.warning(f"Blocked path traversal attempt: {potential_path}")
            return None

    # Search recursively in all subdirectories
    for match in CSV_FOLDER.rglob(file_identifier_csv):
        if match.is_file():
            if _is_safe_path(match, CSV_FOLDER):
                logger.info(f"Found CSV in subdirectory: {match}")
                return match
            else:
                logger.warning(f"Blocked path traversal attempt: {match}")
                continue  # Skip to next match
    
    # Also try without extension in subdirectories
    if file_identifier != file_identifier_csv:
        for match in CSV_FOLDER.rglob(file_identifier):
            if match.is_file():
                if _is_safe_path(match, CSV_FOLDER):
                    logger.info(f"Found CSV in subdirectory: {match}")
                    return match
                else:
                    logger.warning(f"Blocked path traversal attempt: {match}")
                    continue  # Skip to next match

    # Try S3 download as last resort
    if s3_client.enabled:
        logger.info(f"File {file_identifier_csv} not found locally, attempting S3 download")
        import asyncio
        success = asyncio.run(s3_client.download_file(file_identifier_csv, CSV_FOLDER / file_identifier_csv))
        if success:
            downloaded_path = CSV_FOLDER / file_identifier_csv
            if _is_safe_path(downloaded_path, CSV_FOLDER):
                return downloaded_path
            else:
                logger.warning(f"Downloaded file is outside CSV folder: {downloaded_path}")
                return None
    
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


# ============================================
# CSV Analysis for Entitlements
# ============================================

# Known column patterns for classification
IDENTIFIER_COLUMNS = {'username', 'email', 'user_id', 'userid', 'login', 'employee_id', 'employeeid', 'samaccountname'}
AUDIT_COLUMNS = {'access_date', 'action_type', 'effective_access', 'last_used', 'timestamp', 'created_at', 'updated_at'}
DATE_PATTERNS = {'date', 'expir', 'valid_until', 'start_date', 'end_date'}
# Resource column is ignored because each CSV represents one application
IGNORE_COLUMNS = {'resource', 'application', 'app', 'system', 'target_app', 'target_system'}


def _classify_column(col_name: str, unique_values: int, total_rows: int, max_per_user: int, sample_values: List[str]) -> Dict[str, Any]:
    """Classify a column as entitlement, attribute, identifier, or audit."""
    col_lower = col_name.lower().replace(' ', '_').replace('-', '_')
    
    # Check if it's a user identifier
    if col_lower in IDENTIFIER_COLUMNS:
        return {
            "type": "user_identifier",
            "description": "Used to match CSV users to Okta users",
            "action": "match_users"
        }
    
    # Check if it's an ignored column (e.g., Resource - since each CSV = one app)
    if col_lower in IGNORE_COLUMNS:
        return {
            "type": "ignored",
            "description": "Ignored - each CSV represents one application",
            "action": "ignore"
        }
    
    # Check if it's an audit/analytics column
    if col_lower in AUDIT_COLUMNS or any(audit in col_lower for audit in ['action', 'timestamp', 'log']):
        return {
            "type": "audit",
            "description": "Audit/analytics data - not used for provisioning",
            "action": "ignore"
        }
    
    # Check if it's a date field (potential app attribute)
    if any(pattern in col_lower for pattern in DATE_PATTERNS):
        return {
            "type": "app_attribute",
            "value_type": "single",
            "description": "Date field - application profile attribute",
            "action": "add_to_app_profile_schema"
        }
    
    # Determine if it's entitlement or attribute based on cardinality
    # Low cardinality (few unique values) = likely entitlement
    # High cardinality (many unique values) = likely attribute
    cardinality_ratio = unique_values / total_rows if total_rows > 0 else 0
    
    if unique_values <= 50 and cardinality_ratio < 0.1:
        # Low cardinality - this is an entitlement
        value_type = "multi" if max_per_user > 1 else "single"
        return {
            "type": "entitlement",
            "value_type": value_type,
            "description": f"Entitlement ({value_type}-value) - {unique_values} unique values",
            "action": "create_entitlement_type"
        }
    else:
        # High cardinality - this is an attribute
        return {
            "type": "app_attribute",
            "value_type": "single",
            "description": f"Application attribute - {unique_values} unique values",
            "action": "add_to_app_profile_schema"
        }


def _detect_data_quality_issues(df, columns: List[str]) -> List[Dict[str, Any]]:
    """Detect data quality issues in the CSV."""
    issues = []
    
    for col in columns:
        # Check for missing values
        null_count = df[col].isna().sum()
        if null_count > 0:
            issues.append({
                "column": col,
                "issue": "missing_values",
                "count": int(null_count),
                "percentage": f"{(null_count / len(df)) * 100:.1f}%"
            })
        
        # Check for whitespace issues
        if df[col].dtype == 'object':
            whitespace_count = df[col].astype(str).str.contains(r'^\s+|\s+$', regex=True, na=False).sum()
            if whitespace_count > 0:
                issues.append({
                    "column": col,
                    "issue": "leading_trailing_whitespace",
                    "count": int(whitespace_count)
                })
        
        # Check for inconsistent casing (for categorical columns)
        if df[col].dtype == 'object':
            unique_vals = df[col].dropna().unique()
            if len(unique_vals) <= 50:  # Only check low-cardinality columns
                lower_unique = set(str(v).lower() for v in unique_vals)
                if len(lower_unique) < len(unique_vals):
                    issues.append({
                        "column": col,
                        "issue": "inconsistent_casing",
                        "example": f"{len(unique_vals)} values reduce to {len(lower_unique)} when lowercased"
                    })
    
    return issues


async def analyze_csv_for_entitlements(args: Dict[str, Any]) -> str:
    """
    Analyze a CSV file and classify columns for entitlement management.
    
    Returns:
    - Column classification (entitlement/attribute/identifier/audit)
    - Data quality issues
    - Sample users with their access
    - Confirmation prompt
    """
    import pandas as pd
    
    ensure_dirs()
    file_identifier = args.get("file")
    if not file_identifier:
        return "❌ Error: 'file' argument is required"
    
    file_path = get_csv_path(file_identifier)
    if not file_path:
        return f"❌ File not found: {file_identifier}"
    
    # Load CSV
    try:
        df = pd.read_csv(file_path)
    except Exception as e:
        return f"❌ Error reading CSV: {e}"
    
    filename = file_path.name
    columns = list(df.columns)
    
    # Build analysis result
    output_lines = []
    output_lines.append("=" * 70)
    output_lines.append(f"📊 CSV ANALYSIS: {filename}")
    output_lines.append("=" * 70)
    output_lines.append(f"\n📁 Basic Info: {len(df):,} rows | {len(columns)} columns")
    
    # ========== SECTION 1: Column Classification ==========
    output_lines.append("\n" + "─" * 70)
    output_lines.append("1️⃣  COLUMN CLASSIFICATION")
    output_lines.append("─" * 70)
    
    column_analysis = {}
    user_id_column = None
    
    for col in columns:
        unique_values = df[col].nunique()
        sample_values = df[col].dropna().unique()[:5].tolist()
        
        # Calculate max values per user (need to identify user column first)
        # For now, assume first identifier-like column is the user key
        if user_id_column is None:
            col_lower = col.lower().replace(' ', '_').replace('-', '_')
            if col_lower in IDENTIFIER_COLUMNS:
                user_id_column = col
        
        max_per_user = 1
        if user_id_column and col != user_id_column:
            try:
                max_per_user = df.groupby(user_id_column)[col].nunique().max()
            except:
                max_per_user = 1
        
        classification = _classify_column(col, unique_values, len(df), max_per_user, sample_values)
        classification["unique_values"] = unique_values
        classification["sample_values"] = [str(v) for v in sample_values]
        column_analysis[col] = classification
        
        # Format output
        type_emoji = {
            "entitlement": "🎫",
            "app_attribute": "📝",
            "user_identifier": "🔑",
            "audit": "📊",
            "ignored": "🚫"
        }.get(classification["type"], "❓")
        
        value_type_str = ""
        if classification.get("value_type"):
            value_type_str = f" ({classification['value_type']}-value)"
        
        output_lines.append(f"\n{type_emoji} {col}")
        output_lines.append(f"   Type: {classification['type'].upper()}{value_type_str}")
        output_lines.append(f"   Unique Values: {unique_values}")
        output_lines.append(f"   Sample: {classification['sample_values'][:3]}")
        output_lines.append(f"   Action: {classification['action']}")
    
    # ========== SECTION 2: Data Quality Issues ==========
    output_lines.append("\n" + "─" * 70)
    output_lines.append("2️⃣  DATA QUALITY ISSUES")
    output_lines.append("─" * 70)
    
    issues = _detect_data_quality_issues(df, columns)
    
    if issues:
        for issue in issues:
            output_lines.append(f"\n⚠️  {issue['column']}: {issue['issue']}")
            if 'count' in issue:
                output_lines.append(f"   Count: {issue['count']}")
            if 'percentage' in issue:
                output_lines.append(f"   Percentage: {issue['percentage']}")
            if 'example' in issue:
                output_lines.append(f"   Details: {issue['example']}")
    else:
        output_lines.append("\n✅ No data quality issues detected")
    
    # ========== SECTION 3: Sample Users ==========
    output_lines.append("\n" + "─" * 70)
    output_lines.append("3️⃣  SAMPLE USERS (3 users with all their access)")
    output_lines.append("─" * 70)
    
    if user_id_column:
        sample_users = df[user_id_column].unique()[:3]
        
        for user in sample_users:
            user_rows = df[df[user_id_column] == user]
            output_lines.append(f"\n👤 {user}")
            
            for col in columns:
                if col == user_id_column:
                    continue
                classification = column_analysis[col]
                if classification["type"] in ["entitlement", "app_attribute"]:
                    values = user_rows[col].dropna().unique().tolist()
                    if len(values) == 1:
                        output_lines.append(f"   {col}: {values[0]}")
                    elif len(values) > 1:
                        output_lines.append(f"   {col}: {values}")
    else:
        output_lines.append("\n⚠️  Could not identify user column - showing first 3 rows")
        output_lines.append(df.head(3).to_string(index=False))
    
    # ========== SECTION 4: Summary & Confirmation ==========
    output_lines.append("\n" + "─" * 70)
    output_lines.append("4️⃣  SUMMARY")
    output_lines.append("─" * 70)
    
    entitlements = [c for c, a in column_analysis.items() if a["type"] == "entitlement"]
    attributes = [c for c, a in column_analysis.items() if a["type"] == "app_attribute"]
    identifiers = [c for c, a in column_analysis.items() if a["type"] == "user_identifier"]
    
    output_lines.append(f"\n🎫 Entitlements to create: {len(entitlements)}")
    for e in entitlements:
        a = column_analysis[e]
        output_lines.append(f"   • {e} ({a['value_type']}-value) - {a['unique_values']} values")
    
    output_lines.append(f"\n📝 App attributes to add: {len(attributes)}")
    for attr in attributes:
        output_lines.append(f"   • {attr}")
    
    output_lines.append(f"\n🔑 User identifier: {identifiers[0] if identifiers else 'NOT FOUND'}")
    
    # Cache the analysis for later use
    cache_data = {
        "filename": filename,
        "file_path": str(file_path),
        "row_count": len(df),
        "columns": columns,
        "column_analysis": column_analysis,
        "user_id_column": user_id_column,
        "issues": issues,
        "entitlements": entitlements,
        "attributes": attributes
    }
    set_cached_csv(filename, cache_data)
    
    # Confirmation prompt
    output_lines.append("\n" + "=" * 70)
    output_lines.append("⚠️  CONFIRMATION REQUIRED")
    output_lines.append("=" * 70)
    output_lines.append("\nPlease review the analysis above and confirm:")
    output_lines.append("  • Are the column classifications correct?")
    output_lines.append("  • Should any entitlements be attributes instead (or vice versa)?")
    output_lines.append("  • Are there data quality issues that need fixing first?")
    output_lines.append("\nReply with:")
    output_lines.append("  ✅ 'Confirmed' - to proceed with this analysis")
    output_lines.append("  🔄 'Change X to Y' - to reclassify a column")
    output_lines.append("  ❌ 'Cancel' - to abort")
    
    return "\n".join(output_lines)


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
