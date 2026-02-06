"""
Okta IGA Entitlement Workflow Module

WORKFLOW STAGES:
1. analyze_csv_for_entitlements(filename) 
   - Caches CSV data
   - Analyzes entitlements, attributes, issues
   - Prompts for App ID

2. prepare_entitlement_structure(filename, appId)
   - Checks app's existing entitlements
   - If NONE: Creates structure automatically
   - If SOME: Asks user to replace or update

3. execute_user_grants(filename, appId)
   - Retrieves entitlement IDs
   - Searches users concurrently
   - Assigns users to application (if not already assigned)
   - Grants entitlements concurrently
   - Returns summary with assignment and grant statistics
"""
import logging
import asyncio
import csv
import json
import codecs
from pathlib import Path
from typing import Dict, Any, List, Set, Tuple, Optional
import time

from client import okta_client, tracker
from tools import basic, api, batch

# Re-use constants and helpers from basic
from tools.basic import get_csv_path, CSV_FOLDER, PROCESSED_ASSIGNED_FOLDER, get_cached_csv, set_cached_csv, clear_csv_cache

logger = logging.getLogger("okta_mcp")


# ============================================
# Helper Functions
# ============================================

def safe_json_loads(json_str: str, context: str = "") -> Tuple[bool, Any]:
    """Safely parse JSON string with detailed error handling."""
    if not json_str:
        return True, []
    
    if isinstance(json_str, (list, dict)):
        return True, json_str
    
    try:
        data = json.loads(json_str)
        return True, data
    except json.JSONDecodeError as e:
        logger.error(f"[{context}] JSON decode error: {e}")
        logger.error(f"[{context}] Raw content (first 500 chars): {json_str[:500]}")
        return False, {"error": str(e), "raw_content": json_str[:500]}


def generate_entitlement_description(name: str) -> str:
    """Generate a simple description for an entitlement."""
    name_clean = name.replace("_", " ").replace("-", " ").title()
    return f"{name_clean} access"


def generate_value_description(entitlement_name: str, value: str) -> str:
    """Generate a simple description for an entitlement value."""
    val_clean = value.replace("_", " ").replace("-", " ").title()
    return f"{val_clean}"


# ============================================
# STAGE 1: Analyze CSV
# ============================================

async def analyze_csv_for_entitlements(args: Dict[str, Any]) -> str:
    """
    STAGE 1: Analyze CSV for entitlements, attributes, and issues.
    """
    filename = args.get("filename")
    filepath = get_csv_path(filename)
    
    if not filepath:
        return json.dumps({"status": "FAILED", "error": f"File not found: {filename}"})
    
    import pandas as pd
    
    try:
        df = pd.read_csv(filepath, dtype=str).fillna("")
        
        # Known user profile columns (lookup only - do NOT create)
        USER_PROFILE_COLUMNS = {
            # Identity columns (used to find users in Okta)
            "User_Email", "Email", "email", "User", "Username", "Login",
            "user.login", "Person_Id", "Employee_Number", "User_ID", "employee_id",
            "okta_id", "samaccountname", "upn", "user_principal_name",
            # Common profile fields
            "firstName", "First Name", "first_name", "First_Name",
            "lastName", "Last Name", "last_name", "Last_Name",
            "Full Name", "full_name", "fullName", "displayName", "Display_Name",
            "Manager", "manager_email", "Manager_Email", "manager_name",
            "Title", "Job_Title", "job_title", "Position",
            "phone", "Phone", "mobile", "Mobile", "telephone",
            "Department", "department", "Dept", "dept",
        }

        # Known app profile columns (app-specific metadata -> create via App Schema API)
        APP_PROFILE_COLUMNS = {
            "Last_Login", "Last Login", "Access_Date", "Access Date", "AccessDate",
            "Effective_Access", "Date", "Created_Date", "Updated_Date", "Action_Type", "Action_Date", "Timestamp", "Modified_Date",
        }

        # Classify columns into three types: User Profile Attribute, App Profile Attribute, Entitlement
        column_classification: Dict[str, str] = {}
        user_profile_cols: List[str] = []
        app_profile_cols: List[str] = []
        ent_cols: List[str] = []

        for c in df.columns:
            c_lower = c.lower()
            if c_lower in {x.lower() for x in USER_PROFILE_COLUMNS}:
                column_classification[c] = "User Profile Attribute"
                user_profile_cols.append(c)
            elif c_lower in {x.lower() for x in APP_PROFILE_COLUMNS}:
                column_classification[c] = "App Profile Attribute"
                app_profile_cols.append(c)
            else:
                # Default to Entitlement for anything not recognized as a profile column
                column_classification[c] = "Entitlement"
                ent_cols.append(c)

        # Ensure email-like columns are marked as user profile attributes
        for candidate in ("email", "Email", "User_Email", "User", "Username", "Login", "user.login"):
            if candidate in df.columns and candidate not in user_profile_cols:
                column_classification[candidate] = "User Profile Attribute"
                user_profile_cols.append(candidate)
        
        # Look for email column - prioritize columns with actual email addresses
        # Priority: columns named "email" > columns containing @ symbols > other candidates
        email_col = None
        # First priority: exact "email" column name
        if "email" in df.columns:
            email_col = "email"
        elif "Email" in df.columns:
            email_col = "Email"
        elif "User_Email" in df.columns:
            email_col = "User_Email"
        else:
            # Fallback to other candidates
            email_candidates = ["User", "Username", "Login", "user.login"]
            email_col = next((c for c in df.columns if c in email_candidates or c.lower() in [e.lower() for e in email_candidates]), None)
        
        issues = []
        
        if not email_col:
            issues.append("❌ CRITICAL: No email column found (User_Email, Email, User, Username, or Login)")
        else:
            missing_emails = df[df[email_col] == ""].index.tolist()
            if missing_emails:
                rows = [str(i+2) for i in missing_emails[:5]]
                issues.append(f"⚠️ Missing emails in {len(missing_emails)} rows (e.g., rows {', '.join(rows)})")
        
        if not ent_cols:
            issues.append("❌ CRITICAL: No entitlement columns detected")
        
        if "Effective_Access" in df.columns:
            permitted_df = df[df["Effective_Access"] == "Permitted"]
            total_rows = len(df)
            permitted_rows = len(permitted_df)
        else:
            permitted_df = df
            total_rows = len(df)
            permitted_rows = total_rows
        
        entitlements = {}
        entitlement_details = {}  # Enhanced details with multiValue detection
        
        for col in ent_cols:
            unique_vals = set()
            has_multi_value = False  # Track if any row has comma-separated values
            
            for v in permitted_df[col].unique():
                if not v: 
                    continue
                # Check if this value contains commas (multi-value indicator)
                items = v.split(',')
                if len(items) > 1:
                    has_multi_value = True
                for item in items:
                    if item.strip():
                        unique_vals.add(item.strip())
            
            entitlements[col] = sorted(list(unique_vals))
            entitlement_details[col] = {
                "values": sorted(list(unique_vals)),
                "value_count": len(unique_vals),
                "multiValue": has_multi_value,
                "multiValue_reason": "Detected comma-separated values in CSV" if has_multi_value else "Single value per user per row"
            }
            
            if not unique_vals:
                issues.append(f"⚠️ Column '{col}' has no values for permitted users")
        
        unique_users = []
        if email_col:
            unique_users = sorted(list(set(
                permitted_df[email_col].str.strip().unique()
            ) - {""}))
        
        # Build sample user previews (2-3 users showing what they'll look like in Okta)
        sample_user_previews = []
        sample_rows = permitted_df.head(3).to_dict('records')
        for row in sample_rows:
            user_email = row.get(email_col, "").strip()
            if not user_email:
                continue
            
            user_entitlements = {}
            for ent_col in ent_cols:
                val = row.get(ent_col, "").strip()
                if val:
                    # Parse comma-separated values
                    parsed_values = [v.strip() for v in val.split(',') if v.strip()]
                    user_entitlements[ent_col] = {
                        "values": parsed_values,
                        "multiValue": len(parsed_values) > 1
                    }
            
            sample_user_previews.append({
                "email": user_email,
                "okta_preview": {
                    "user": f"<Okta User ID for {user_email}>",
                    "app_assignment": "User will be assigned to application",
                    "entitlements_granted": user_entitlements
                }
            })
        
        cache_data = {
            "filepath": str(filepath),
            "filename": filepath.name,
            "email_column": email_col,
            "entitlement_columns": ent_cols,
            "user_profile_columns": user_profile_cols,
            "app_profile_columns": app_profile_cols,
            "column_classification": column_classification,
            "entitlements": entitlements,
            "entitlement_details": entitlement_details,
            "unique_users": unique_users,
            "total_rows": total_rows,
            "permitted_rows": permitted_rows,
            "has_effective_access": "Effective_Access" in df.columns,
            "sample_user_previews": sample_user_previews
        }
        set_cached_csv(filepath.name, cache_data)
        
        ent_summary = []
        for col, vals in entitlements.items():
            ent_summary.append(f"  • {col}: {', '.join(vals[:10])}{'...' if len(vals) > 10 else ''} ({len(vals)} values)")
        
        # Build human-readable output
        output_lines = [
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
            "📊 STAGE 1 COMPLETE: CSV Analysis",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
            "",
            f"📁 File: {filepath.name}",
            f"   Total rows: {total_rows}",
            f"   Permitted rows: {permitted_rows}",
            f"   Unique users: {len(unique_users)}",
            "",
            "📋 Column Classification:",
            "─────────────────────────────────────────────────────────────────────────────────",
        ]

        # Add classification listing
        for col, cls in column_classification.items():
            output_lines.append(f"  • {col} → {cls}")

        output_lines.extend([
            "",
            "📋 ENTITLEMENTS TO CREATE:",
            "─────────────────────────────────────────────────────────────────────────────────"
        ])
        
        for ent_name, details in entitlement_details.items():
            multi_indicator = "✅ MULTI-VALUE" if details["multiValue"] else "◻️  Single-value"
            output_lines.append(f"")
            output_lines.append(f"   🏷️  {ent_name}")
            output_lines.append(f"       Type: {multi_indicator}")
            output_lines.append(f"       Reason: {details['multiValue_reason']}")
            output_lines.append(f"       Values ({details['value_count']}): {', '.join(details['values'][:8])}{'...' if details['value_count'] > 8 else ''}")
        
        output_lines.append("")
        output_lines.append("─────────────────────────────────────────────────────────────────────────────────")
        output_lines.append("")
        output_lines.append("👥 SAMPLE USER PREVIEWS (What they'll look like in Okta):")
        output_lines.append("─────────────────────────────────────────────────────────────────────────────────")
        
        for i, preview in enumerate(sample_user_previews[:3], 1):
            user_email = preview.get("email", "")
            user_ents = preview.get("okta_preview", {}).get("entitlements_granted", {})
            output_lines.append(f"")
            output_lines.append(f"   👤 User {i}: {user_email}")
            for ent_name, ent_data in user_ents.items():
                vals = ent_data.get("values", [])
                multi = "🔹" if ent_data.get("multiValue") else "▪️"
                output_lines.append(f"       {multi} {ent_name}: {', '.join(vals)}")
        
        if issues and issues != ["✅ No issues detected"]:
            output_lines.append("")
            output_lines.append("⚠️  DATA ISSUES:")
            for issue in issues:
                output_lines.append(f"   {issue}")
        
        output_lines.extend([
            "",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
            "🔜 NEXT STEP: Provide the Okta App ID",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
            "",
            "   Once you have the App ID, I will call:",
            "   prepare_entitlement_structure(filename, appId)",
            "",
            "   This will CREATE the entitlement structure in Okta.",
            "",
            "   💡 Example: 'The App ID is 0oa1234567890ABCDEF'",
            "",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        ])
        
        return "\n".join(output_lines)

    except Exception as e:
        logger.error(f"CSV analysis failed: {e}", exc_info=True)
        return f"❌ FAILED: Error analyzing CSV: {str(e)}"


# ============================================
# STAGE 2: Prepare Entitlement Structure
# ============================================

async def _ensure_app_schema_attributes(app_id: str, attributes: List[str]) -> Tuple[bool, str]:
    """
    Ensure that app schema has attributes for all provided app-level attributes.
    This should be used only for App Profile Attributes (not entitlements).
    Returns (success, message)
    """
    try:
        # Get current app schema
        schema_url = f"https://{okta_client.domain}/api/v1/meta/schemas/apps/{app_id}/default"
        result = await okta_client.execute_request("GET", schema_url)
        
        if not result["success"]:
            return False, f"Failed to retrieve app schema: {result.get('response', {})}"
        
        schema = result.get("response", {})
        existing_custom = schema.get("definitions", {}).get("custom", {}).get("properties", {})
        
        # Check which attributes are missing in the app schema
        missing_attrs = [name for name in attributes if name not in existing_custom]
        
        if not missing_attrs:
            logger.info(f"✅ All entitlement attributes already exist in app schema")
            return True, "All attributes exist"
        
        # Create missing attributes
        logger.info(f"Creating {len(missing_attrs)} missing app schema attributes: {missing_attrs}")
        
        new_custom_properties = existing_custom.copy()
        for attr_name in missing_attrs:
            new_custom_properties[attr_name] = {
                "title": attr_name,
                "type": "string",
                "scope": "NONE"
            }
        
        update_body = {
            "definitions": {
                "custom": {
                    "id": "#custom",
                    "type": "object",
                    "properties": new_custom_properties
                }
            }
        }
        
        update_result = await okta_client.execute_request("POST", schema_url, body=update_body)
        
        if update_result["success"]:
            logger.info(f"✅ Successfully created app schema attributes: {missing_attrs}")
            return True, f"Created {len(missing_attrs)} attributes"
        else:
            error_msg = update_result.get("response", {}).get("errorSummary", "Unknown error")
            logger.error(f"❌ Failed to create app schema attributes: {error_msg}")
            return False, f"Failed to create attributes: {error_msg}"
            
    except Exception as e:
        logger.error(f"Exception ensuring app schema attributes: {e}", exc_info=True)
        return False, f"Exception: {str(e)}"


async def prepare_entitlement_structure(args: Dict[str, Any]) -> str:
    """
    STAGE 2: Evaluate app's entitlements and create structure.
    """
    filename = args.get("filename")
    app_id = args.get("appId")
    mode = args.get("mode", "auto")
    
    if not app_id:
        return json.dumps({"status": "FAILED", "error": "App ID is required"})
    
    cached = get_cached_csv(filename)
    if not cached:
        return json.dumps({
            "status": "FAILED", 
            "error": f"CSV '{filename}' not found in cache. Please run analyze_csv_for_entitlements first."
        })
    
    csv_entitlements = cached.get("entitlements", {})
    entitlement_details = cached.get("entitlement_details", {})
    sample_user_previews = cached.get("sample_user_previews", [])
    
    if not csv_entitlements:
        return json.dumps({"status": "FAILED", "error": "No entitlements found in cached CSV data"})
    
    try:
        logger.info(f"Checking existing entitlements for app {app_id}")
        
        existing_ents_json = await api.okta_iga_list_entitlements({"appId": app_id})
        success, existing_ents = safe_json_loads(existing_ents_json, "list_entitlements")
        
        if not success:
            return json.dumps({
                "status": "FAILED",
                "error": f"Failed to retrieve app entitlements: {existing_ents.get('error', 'Unknown')}"
            })
        
        if isinstance(existing_ents, dict) and existing_ents.get("error"):
            return json.dumps({
                "status": "FAILED",
                "error": f"API error: {existing_ents.get('error')}"
            })
        
        if not isinstance(existing_ents, list):
            existing_ents = existing_ents.get("data", []) if isinstance(existing_ents, dict) else []
        
        existing_names = {e.get('name'): e for e in existing_ents if isinstance(e, dict) and e.get('name')}
        
        logger.info(f"Found {len(existing_names)} existing entitlements: {list(existing_names.keys())}")
        
        if len(existing_names) == 0:
            logger.info("No existing entitlements found. Creating structure automatically.")
            
            # First, ensure app schema has attributes for any App Profile Attributes
            app_profile_attrs = cached.get("app_profile_columns", [])
            schema_success, schema_msg = await _ensure_app_schema_attributes(app_id, app_profile_attrs)
            if not schema_success:
                return json.dumps({
                    "status": "FAILED",
                    "error": f"Failed to ensure app schema attributes: {schema_msg}"
                })
            
            return await _create_entitlement_structure(app_id, csv_entitlements, entitlement_details, sample_user_previews, mode="create")
        
        else:
            csv_ent_names = set(csv_entitlements.keys())
            app_ent_names = set(existing_names.keys())
            
            common = csv_ent_names & app_ent_names
            new_in_csv = csv_ent_names - app_ent_names
            only_in_app = app_ent_names - csv_ent_names
            
            if mode == "auto":
                # Build human-readable output for existing entitlements
                output_lines = [
                    "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
                    "⚠️  EXISTING ENTITLEMENTS FOUND",
                    "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
                    "",
                    f"📱 App ID: {app_id}",
                    "",
                    "📋 EXISTING ENTITLEMENTS IN APP:",
                    "─────────────────────────────────────────────────────────────────────────────────"
                ]
                
                for ent in existing_ents:
                    output_lines.append(f"   🏷️  {ent.get('name')} (ID: {ent.get('id')})")
                
                output_lines.append("")
                output_lines.append("📋 ENTITLEMENTS IN CSV:")
                output_lines.append("─────────────────────────────────────────────────────────────────────────────────")
                for name in csv_ent_names:
                    output_lines.append(f"   🏷️  {name}")
                
                output_lines.append("")
                output_lines.append("🔍 COMPARISON:")
                output_lines.append("─────────────────────────────────────────────────────────────────────────────────")
                if common:
                    output_lines.append(f"   ✅ Matching: {', '.join(common)}")
                if new_in_csv:
                    output_lines.append(f"   🆕 New in CSV: {', '.join(new_in_csv)}")
                if only_in_app:
                    output_lines.append(f"   📱 Only in App: {', '.join(only_in_app)}")
                
                output_lines.extend([
                    "",
                    "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
                    "🤔 WHAT WOULD YOU LIKE TO DO?",
                    "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
                    "",
                    "   • 'Update' - Add new entitlements from CSV, keep existing ones",
                    "   • 'Replace' - Delete ALL existing entitlements and recreate from CSV",
                    "",
                    "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                ])
                
                return "\n".join(output_lines)
            
            elif mode == "update":
                new_ents = {k: v for k, v in csv_entitlements.items() if k in new_in_csv}
                new_ent_details = {k: v for k, v in entitlement_details.items() if k in new_in_csv}
                if not new_ents:
                    return (
                        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                        "✅ NO CHANGES NEEDED\n"
                        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                        "\n"
                        "All entitlements from CSV already exist in the app.\n"
                        f"Existing entitlements: {', '.join(app_ent_names)}\n"
                        "\n"
                        "Ready to proceed with granting users their entitlements?\n"
                        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                    )
                return await _create_entitlement_structure(app_id, new_ents, new_ent_details, sample_user_previews, mode="update")
            
            elif mode == "replace":
                return await _replace_entitlement_structure(app_id, existing_ents, csv_entitlements, entitlement_details, sample_user_previews)
            
            else:
                return f"❌ FAILED: Unknown mode: {mode}"
    
    except Exception as e:
        logger.error(f"Entitlement structure preparation failed: {e}", exc_info=True)
        return f"❌ FAILED: {str(e)}"


async def _create_entitlement_structure(
    app_id: str, 
    entitlements: Dict[str, List[str]], 
    entitlement_details: Dict[str, Dict] = None,
    sample_user_previews: List[Dict] = None,
    mode: str = "create"
) -> str:
    """Internal: Create entitlement definitions and values via the Governance Entitlements API.
    
    API Documentation: https://developer.okta.com/docs/api/iga/openapi/governance.api/tag/Entitlements/
    Endpoint: POST /governance/api/v1/entitlements
    
    All entitlements are created as multi-value by default (multiValue: true).
    Per the API docs: "If multiValue is true, then the dataType property is set to array."
    
    Request Body Schema (from API docs):
    - name (required): string[1..255] - The display name for an entitlement property
    - externalValue (required): string[1..255] - The value of an entitlement property
    - dataType (required): string - The data type ("string" for single/multi-value)
    - multiValue (required): boolean - If true, entitlement can hold multiple values
    - parent (required): object - {externalId: app_id, type: "APPLICATION"}
    - values: Array of objects - Collection of entitlement values
      - name: value name
      - description: description for the value
      - externalValue: external identifier
    - description: string[1..1000] - The description of an entitlement property
    
    Example from API docs:
    {
        "name": "License Entitlement",
        "externalValue": "license_entitlement",
        "description": "Some license entitlement",
        "parent": {"externalId": "0oafxqCAJWWGELFTYASJ", "type": "APPLICATION"},
        "multiValue": true,
        "dataType": "string",
        "values": [
            {"name": "value1", "description": "description for value1", "externalValue": "value_1"},
            {"name": "value2", "description": "description for value2", "externalValue": "value_2"}
        ]
    }
    """
    created = []
    errors = []
    entitlement_details = entitlement_details or {}
    sample_user_previews = sample_user_previews or []
    
    for ent_name, values in entitlements.items():
        try:
            description = generate_entitlement_description(ent_name)
            
            # Build ALL values at once - each value needs name, description, externalValue
            # API Doc: values array contains objects with name, description, externalValue
            values_payload = [
                {
                    "name": val,
                    "description": generate_value_description(ent_name, val),
                    "externalValue": val
                }
                for val in values
            ]
            
            # API Doc: POST /governance/api/v1/entitlements
            # https://developer.okta.com/docs/api/iga/openapi/governance.api/tag/Entitlements/#tag/Entitlements/operation/createEntitlement
            url = f"https://{okta_client.domain}/governance/api/v1/entitlements"
            
            # Request body per API documentation
            # Note: dataType is "string" (not "string[]"), multiValue: true makes it multi-value
            # API Doc: "If this property [multiValue] is true, then the dataType property is set to array"
            body = {
                "name": ent_name,
                "externalValue": ent_name,
                "description": description,
                "parent": {
                    "externalId": app_id,
                    "type": "APPLICATION"
                },
                "multiValue": True,  # Always create as multi-value per requirements
                "dataType": "string",  # API uses "string" - multiValue:true handles array behavior
                "values": values_payload
            }
            
            logger.info(f"Creating entitlement: {ent_name} with {len(values)} values (multiValue=True)")
            logger.debug(f"Entitlement body: {json.dumps(body, indent=2)}")
            
            result = await okta_client.execute_request("POST", url, body=body)
            
            if result["success"]:
                response_data = result.get("response", {})
                created.append({
                    "name": ent_name,
                    "id": response_data.get("id"),
                    "multiValue": True,
                    "values": values,
                    "value_count": len(values),
                    "description": description,
                    "created_values": len(response_data.get("values", []))
                })
                logger.info(f"✅ Created entitlement '{ent_name}' with {len(values)} values (multiValue=True)")
            else:
                error_msg = result.get("response", {}).get("errorSummary", str(result.get("response")))
                errors.append({"name": ent_name, "error": error_msg})
                logger.error(f"❌ Failed to create entitlement '{ent_name}': {error_msg}")
            
            await asyncio.sleep(0.5)
            
        except Exception as e:
            errors.append({"name": ent_name, "error": str(e)})
            logger.error(f"❌ Exception creating entitlement '{ent_name}': {e}", exc_info=True)
    
    status = "SUCCESS" if not errors else ("PARTIAL_SUCCESS" if created else "FAILED")
    
    # Build human-readable output
    output_lines = [
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"{'✅' if status == 'SUCCESS' else '⚠️'} STAGE 2 COMPLETE: Entitlement Structure Created",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        "",
        f"📱 App ID: {app_id}",
        f"   Mode: {mode}",
        "",
        "📋 ENTITLEMENTS CREATED IN OKTA:",
        "─────────────────────────────────────────────────────────────────────────────────"
    ]
    
    for ent in created:
        multi_indicator = "✅ MULTI-VALUE" if ent["multiValue"] else "◻️  Single-value"
        output_lines.append(f"")
        output_lines.append(f"   🏷️  {ent['name']}")
        output_lines.append(f"       Entitlement ID: {ent['id']}")
        output_lines.append(f"       Type: {multi_indicator}")
        output_lines.append(f"       Values ({ent['value_count']}): {', '.join(ent['values'][:8])}{'...' if ent['value_count'] > 8 else ''}")
    
    if errors:
        output_lines.append("")
        output_lines.append("❌ ERRORS:")
        for err in errors:
            output_lines.append(f"   • {err['name']}: {err['error']}")
    
    output_lines.append("")
    output_lines.append("─────────────────────────────────────────────────────────────────────────────────")
    output_lines.append("")
    output_lines.append("👥 SAMPLE GRANTS PREVIEW (What will be created for each user):")
    output_lines.append("─────────────────────────────────────────────────────────────────────────────────")
    
    for preview in sample_user_previews[:3]:
        user_email = preview.get("email", "")
        user_ents = preview.get("okta_preview", {}).get("entitlements_granted", {})
        output_lines.append(f"")
        output_lines.append(f"   👤 {user_email}")
        for ent_name, ent_data in user_ents.items():
            vals = ent_data.get("values", [])
            # Find the entitlement ID
            created_ent = next((c for c in created if c["name"] == ent_name), None)
            ent_id = created_ent.get("id", "???") if created_ent else "???"
            multi = "🔹" if ent_data.get("multiValue") else "▪️"
            output_lines.append(f"       {multi} {ent_name} ({ent_id}): {', '.join(vals)}")
    
    output_lines.extend([
        "",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        "🔜 NEXT STEP: Grant entitlements to users",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        "",
        "   Ready to proceed? I will call:",
        "   execute_user_grants(filename, appId)",
        "",
        "   This will grant the entitlements above to all users in the CSV.",
        "",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    ])
    
    return "\n".join(output_lines)


async def _replace_entitlement_structure(
    app_id: str, 
    existing_ents: List[Dict], 
    csv_entitlements: Dict[str, List[str]],
    entitlement_details: Dict[str, Dict] = None,
    sample_user_previews: List[Dict] = None
) -> str:
    """Internal: Delete existing entitlements and recreate from CSV."""
    deleted = []
    delete_errors = []
    entitlement_details = entitlement_details or {}
    sample_user_previews = sample_user_previews or []
    
    for ent in existing_ents:
        ent_id = ent.get("id")
        ent_name = ent.get("name")
        if not ent_id:
            continue
            
        try:
            url = f"https://{okta_client.domain}/governance/api/v1/entitlements/{ent_id}"
            result = await okta_client.execute_request("DELETE", url)
            
            if result["success"] or result.get("httpCode") == "204":
                deleted.append(ent_name)
            else:
                delete_errors.append({"name": ent_name, "error": result.get("response")})
            
            await asyncio.sleep(0.3)
            
        except Exception as e:
            delete_errors.append({"name": ent_name, "error": str(e)})
    
    logger.info(f"Deleted {len(deleted)} entitlements, {len(delete_errors)} errors")
    
    create_result_str = await _create_entitlement_structure(app_id, csv_entitlements, entitlement_details, sample_user_previews, mode="replace")
    
    # Build human-readable output for replace mode
    output_lines = [
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        "🔄 STAGE 2 COMPLETE: Entitlements Replaced",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        "",
        f"🗑️  DELETED: {len(deleted)} existing entitlements",
    ]
    
    if deleted:
        output_lines.append(f"   • {', '.join(deleted)}")
    
    if delete_errors:
        output_lines.append(f"   ❌ Errors: {len(delete_errors)}")
        for err in delete_errors:
            output_lines.append(f"      • {err['name']}: {err['error']}")
    
    output_lines.append("")
    output_lines.append(create_result_str)
    
    return "\n".join(output_lines)


# ============================================
# STAGE 3: Execute User Grants
# ============================================

async def collect_app_entitlement_ids(app_id: str) -> Dict[str, Any]:
    """
    Collect all entitlement IDs and value IDs for an application upfront.
    
    Returns:
        {
            "success": True/False,
            "ent_id_map": {entitlement_name: entitlement_schema_id},
            "ent_value_map": {entitlement_name: {value_name: value_id}},
            "entitlement_details": [{name, id, values: [{name, id}]}],
            "error": "..." (if failed)
        }
    """
    result = {
        "success": False,
        "ent_id_map": {},
        "ent_value_map": {},
        "entitlement_details": []
    }
    
    # Step 1: Get all entitlements for the app
    existing_ents_json = await api.okta_iga_list_entitlements({"appId": app_id})
    success, existing_ents = safe_json_loads(existing_ents_json, "list_entitlements")
    
    if not success or not isinstance(existing_ents, list):
        result["error"] = "Failed to retrieve entitlements from app"
        return result
    
    if not existing_ents:
        result["error"] = "No entitlements found in app. Please run prepare_entitlement_structure first."
        return result
    
    # Build entitlement ID map
    ent_id_map = {}
    for e in existing_ents:
        if isinstance(e, dict) and 'name' in e and 'id' in e:
            ent_id_map[e['name']] = e['id']
    
    result["ent_id_map"] = ent_id_map
    
    # Step 2: Get all values for each entitlement
    ent_value_map = {}
    entitlement_details = []
    
    for ent_name, ent_id in ent_id_map.items():
        values_json = await api.okta_iga_list_entitlement_values({"entitlementId": ent_id})
        success, values_data = safe_json_loads(values_json, f"list_values_{ent_name}")
        
        if not success or not isinstance(values_data, list):
            values_data = []
        
        # Build map of value name -> value ID
        value_id_map = {}
        value_details = []
        for v in values_data:
            if isinstance(v, dict) and 'name' in v and 'id' in v:
                value_id_map[v['name']] = v['id']
                value_details.append({"name": v['name'], "id": v['id']})
        
        ent_value_map[ent_name] = value_id_map
        entitlement_details.append({
            "name": ent_name,
            "id": ent_id,
            "values": value_details
        })
        
        await asyncio.sleep(0.1)  # Small delay between API calls
    
    result["success"] = True
    result["ent_value_map"] = ent_value_map
    result["entitlement_details"] = entitlement_details
    
    return result


async def execute_user_grants(args: Dict[str, Any]) -> str:
    """
    STAGE 3: Grant entitlements to users from CSV.
    
    WORKFLOW:
    1. Collects all entitlement IDs and value IDs upfront (from app)
    2. Searches for all unique users in Okta (concurrent)
    3. Assigns found users to the application (concurrent)
    4. Builds and creates entitlement grants (concurrent, rate-limited)
    
    Returns detailed summary with assignment and grant statistics.
    """
    filename = args.get("filename")
    app_id = args.get("appId")
    
    if not app_id:
        return json.dumps({"status": "FAILED", "error": "App ID is required"})
    
    cached = get_cached_csv(filename)
    if not cached:
        return json.dumps({
            "status": "FAILED",
            "error": f"CSV '{filename}' not found in cache. Please run analyze_csv_for_entitlements first."
        })
    
    csv_entitlements = cached.get("entitlements", {})
    unique_users = cached.get("unique_users", [])
    email_col = cached.get("email_column")
    filepath = cached.get("filepath")
    
    if not unique_users:
        return json.dumps({"status": "FAILED", "error": "No users found in cached CSV data"})
    
    progress = []
    start_time = time.time()
    
    try:
        # STEP 1: Collect all entitlement IDs upfront
        progress.append(f"[1/4] Collecting entitlement IDs for app {app_id}")
        
        ent_data = await collect_app_entitlement_ids(app_id)
        
        if not ent_data["success"]:
            return json.dumps({
                "status": "FAILED",
                "error": ent_data.get("error", "Failed to collect entitlement IDs")
            })
        
        ent_id_map = ent_data["ent_id_map"]
        ent_value_map = ent_data["ent_value_map"]
        entitlement_details = ent_data["entitlement_details"]
        
        progress.append(f"   ✅ Found {len(ent_id_map)} entitlements: {list(ent_id_map.keys())}")
        for ent in entitlement_details:
            progress.append(f"      • {ent['name']}: {len(ent['values'])} values")
        
        # STEP 2: Search for users in Okta
        progress.append(f"[2/4] Searching for {len(unique_users)} users in Okta (concurrent)")
        
        search_inputs = [{"attribute": "email", "value": email} for email in unique_users]
        
        search_result_str = await batch.okta_batch_user_search({
            "searches": search_inputs,
            "concurrency": 10
        })
        success, search_result = safe_json_loads(search_result_str, "batch_user_search")
        
        if not success:
            return json.dumps({
                "status": "FAILED",
                "error": f"User search failed: {search_result.get('error', 'Unknown')}"
            })
        
        found_users = {item['value']: item['userId'] for item in search_result.get('found', [])}
        not_found_users = [item['value'] for item in search_result.get('not_found', [])]
        
        all_searched = set(found_users.keys()) | set(not_found_users)
        missing = set(unique_users) - all_searched
        not_found_users.extend(list(missing))
        
        progress.append(f"   ✅ Found: {len(found_users)} users")
        if not_found_users:
            progress.append(f"   ⚠️ Not found (will be skipped): {len(not_found_users)} users")
            progress.append(f"      Examples: {not_found_users[:5]}{'...' if len(not_found_users) > 5 else ''}")
        
        if not found_users:
            not_found_sample = not_found_users[:10]
            return (
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                "❌ NO USERS FOUND IN OKTA\n"
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                "\n"
                f"All {len(not_found_users)} users in the CSV do not exist in your Okta tenant.\n"
                "\n"
                "Sample users not found:\n" +
                "\n".join([f"   • {email}" for email in not_found_sample]) +
                ("\n   ... and more" if len(not_found_users) > 10 else "") +
                "\n\n"
                "💡 HINT: Verify that users exist in Okta with matching email addresses,\n"
                "   or create them first before running this workflow.\n"
                "\n"
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            )
        
        # STEP 3: Assign users to application
        progress.append(f"[3/4] Assigning {len(found_users)} users to application (concurrent)")
        
        user_ids_to_assign = list(found_users.values())
        
        assign_result_str = await batch.okta_batch_assign_users({
            "appId": app_id,
            "userIds": user_ids_to_assign,
            "concurrency": 10
        })
        success, assign_result = safe_json_loads(assign_result_str, "batch_assign_users")
        
        if not success:
            return json.dumps({
                "status": "FAILED",
                "error": f"User assignment failed: {assign_result.get('error', 'Unknown')}",
                "progress": progress
            })
        
        assigned_count = assign_result.get("summary", {}).get("assigned", 0)
        already_assigned = assign_result.get("summary", {}).get("already_assigned", 0)
        assignment_failed = assign_result.get("failed", [])
        
        progress.append(f"   ✅ Newly assigned: {assigned_count} users")
        if already_assigned > 0:
            progress.append(f"   ℹ️  Already assigned: {already_assigned} users")
        if assignment_failed:
            progress.append(f"   ⚠️ Assignment failed: {len(assignment_failed)} users")
            # Log failed assignments but continue - they might have been assigned previously
            for failure in assignment_failed[:5]:
                logger.warning(f"Failed to assign user {failure.get('userId')}: {failure.get('error')}")
        
        # STEP 4: Build and execute grant requests
        progress.append("[4/4] Building grant requests from CSV data")
        
        # Group grants by user to consolidate multiple entitlements per user
        user_grants = {}  # {user_id: {entitlement_id: [value_ids]}}
        skipped = []
        
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            for row in reader:
                effective_access = row.get("Effective_Access", "Permitted")
                if effective_access != "Permitted":
                    continue
                    
                email = row.get(email_col, "").strip()
                if not email or email not in found_users:
                    continue
                
                user_id = found_users[email]
                
                if user_id not in user_grants:
                    user_grants[user_id] = {}
                
                # Process each entitlement column for this user
                for ent_name in csv_entitlements.keys():
                    values_str = row.get(ent_name, "")
                    if not values_str:
                        continue
                    
                    ent_id = ent_id_map.get(ent_name)
                    if not ent_id:
                        skipped.append({"email": email, "entitlement": ent_name, "reason": "entitlement_not_found"})
                        continue
                    
                    # Split comma-separated values
                    for val in values_str.split(","):
                        val = val.strip()
                        if not val:
                            continue
                        
                        # Get the value ID
                        value_id = ent_value_map.get(ent_name, {}).get(val)
                        if not value_id:
                            skipped.append({
                                "email": email, 
                                "entitlement": ent_name, 
                                "value": val,
                                "reason": "entitlement_value_not_found"
                            })
                            continue
                        
                        # Add to user's entitlements
                        if user_id not in user_grants:
                            user_grants[user_id] = {}
                        if ent_id not in user_grants[user_id]:
                            user_grants[user_id][ent_id] = []
                        user_grants[user_id][ent_id].append(value_id)
        
        # Build grant requests - one grant per user with all their entitlements
        grant_inputs = []
        
        for user_id, entitlements_map in user_grants.items():
            # CORRECT GRANT STRUCTURE (from working Node.js project)
            entitlements_array = []
            for ent_id, value_ids in entitlements_map.items():
                entitlements_array.append({
                    "id": ent_id,
                    "values": [{"id": vid} for vid in value_ids]
                })
            
            grant_body = {
                "grantType": "CUSTOM",
                "actor": "ADMIN",  # Who is creating the grant (ADMIN = administrative action)
                "target": {
                    "externalId": app_id,  # Application ID
                    "type": "APPLICATION"
                },
                "targetPrincipal": {
                    "externalId": user_id,  # User ID
                    "type": "OKTA_USER"
                },
                "entitlements": entitlements_array
            }
            
            grant_inputs.append({"userId": user_id, "grantBody": grant_body})
        
        progress.append(f"   ✅ Prepared {len(grant_inputs)} grants for {len(user_grants)} users (skipped: {len(skipped)})")
        
        if not grant_inputs:
            return (
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                "⚠️  NO GRANTS TO CREATE\n"
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                "\n"
                "No grants could be created. This usually means:\n"
                "• Users in CSV don't exist in Okta\n"
                "• Entitlement values in CSV don't match created entitlements\n"
                "\n"
                f"Skipped: {len(skipped)} rows\n"
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            )
        
        progress.append(f"[6/6] Creating {len(grant_inputs)} grants (concurrent, rate-limited)")
        
        grant_result_str = await batch.okta_batch_create_grants({
            "grants": grant_inputs,
            "concurrency": 5
        })
        success, grant_result = safe_json_loads(grant_result_str, "batch_create_grants")
        
        if not success:
            return json.dumps({
                "status": "FAILED",
                "error": f"Grant creation failed: {grant_result.get('error', 'Unknown')}",
                "progress": progress
            })
        
        successful_grants = grant_result.get("successful", 0)
        failed_grants = grant_result.get("failed", [])
        created_grants = grant_result.get("created", [])
        
        progress.append(f"   ✅ Successfully created: {successful_grants} grants")
        if failed_grants:
            progress.append(f"   ⚠️ Failed: {len(failed_grants)} grants")
        
        elapsed = time.time() - start_time
        rate_status = tracker.get_status()
        
        await basic.move_to_processed({"filename": Path(filepath).name, "destination": "processed_and_assigned"})
        
        # Build sample user previews showing what was actually created in Okta
        sample_users_in_okta = []
        for grant_info in created_grants[:3]:  # Show first 3 successful grants
            user_id = grant_info.get("userId")
            grant_id = grant_info.get("grantId")
            grant_status = grant_info.get("grantStatus")
            entitlements_granted = grant_info.get("entitlements", [])
            
            # Find the email for this user
            user_email = next((email for email, uid in found_users.items() if uid == user_id), user_id)
            
            sample_users_in_okta.append({
                "user_email": user_email,
                "okta_user_id": user_id,
                "grant_id": grant_id,
                "grant_status": grant_status,
                "entitlements_in_okta": entitlements_granted
            })
        
        # Build human-readable output
        output_lines = [
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
            "🚀 STAGE 3 COMPLETE: Entitlements Granted!",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
            "",
            "📊 SUMMARY:",
            "─────────────────────────────────────────────────────────────────────────────────",
            f"   👥 Users searched:      {len(unique_users)}",
            f"   ✅ Users found:         {len(found_users)}",
            f"   ❌ Users not found:     {len(not_found_users)}",
            "",
            f"   📱 Users assigned:      {assigned_count} (new) + {already_assigned} (already assigned)",
            "",
            f"   🎫 Grants created:      {successful_grants}",
            f"   ❌ Grants failed:       {len(failed_grants)}",
            f"   ⏭️  Grants skipped:      {len(skipped)}",
            "",
            f"   ⏱️  Time elapsed:        {round(elapsed, 2)} seconds",
            "",
            "─────────────────────────────────────────────────────────────────────────────────"
        ]
        
        if sample_users_in_okta:
            output_lines.append("")
            output_lines.append("👥 SAMPLE USERS NOW IN OKTA:")
            output_lines.append("─────────────────────────────────────────────────────────────────────────────────")
            
            for user in sample_users_in_okta:
                output_lines.append(f"")
                output_lines.append(f"   👤 {user['user_email']}")
                output_lines.append(f"       Okta User ID: {user['okta_user_id']}")
                output_lines.append(f"       Grant ID: {user['grant_id']}")
                output_lines.append(f"       Grant Status: {user['grant_status']}")
                
                if user['entitlements_in_okta']:
                    output_lines.append(f"       Entitlements:")
                    for ent in user['entitlements_in_okta']:
                        ent_id = ent.get('id', '???')
                        values = ent.get('values', [])
                        value_names = [v.get('id', '???') for v in values]
                        output_lines.append(f"         • {ent_id}: {', '.join(value_names)}")
                
                output_lines.append(f"       🔗 View in Okta: https://{okta_client.domain}/admin/user/profile/view/{user['okta_user_id']}#tab-applications")
        
        if not_found_users:
            output_lines.append("")
            output_lines.append("⚠️  USERS NOT FOUND IN OKTA (skipped):")
            output_lines.append("─────────────────────────────────────────────────────────────────────────────────")
            for email in not_found_users[:10]:
                output_lines.append(f"   • {email}")
            if len(not_found_users) > 10:
                output_lines.append(f"   ... and {len(not_found_users) - 10} more")
        
        if failed_grants:
            output_lines.append("")
            output_lines.append("❌ FAILED GRANTS:")
            output_lines.append("─────────────────────────────────────────────────────────────────────────────────")
            for fail in failed_grants[:5]:
                output_lines.append(f"   • User {fail.get('userId', '???')}: {fail.get('error', 'Unknown error')}")
        
        output_lines.extend([
            "",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
            "✅ WORKFLOW COMPLETE",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
            "",
            f"   📁 CSV file moved to: processed_and_assigned/",
            "",
            f"   📈 Rate Limits:",
            f"       • Requests last minute: {rate_status.get('requestsLastMinute', 0)}",
            f"       • Total requests: {rate_status.get('stats', {}).get('totalRequests', 0)}",
            "",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        ])
        
        return "\n".join(output_lines)
    
    except Exception as e:
        logger.error(f"User grants failed: {e}", exc_info=True)
        return f"❌ FAILED: {str(e)}\n\nProgress:\n" + "\n".join(progress)


# ============================================
# Legacy Wrapper (for backwards compatibility)
# ============================================

async def process_entitlements_workflow(args: Dict[str, Any]) -> str:
    """Legacy wrapper that routes to the new staged workflow."""
    stage = args.get("stage", "full")
    
    if stage == "analyze":
        return await analyze_csv_for_entitlements(args)
    
    elif stage == "create_structure":
        return await prepare_entitlement_structure(args)
    
    elif stage == "grant_users":
        return await execute_user_grants(args)
    
    elif stage == "full":
        filename = args.get("filename")
        app_id = args.get("appId")
        
        cached = get_cached_csv(filename)
        if not cached:
            analysis_result = await analyze_csv_for_entitlements({"filename": filename})
            analysis = json.loads(analysis_result)
            if analysis.get("status") != "analysis_complete":
                return analysis_result
        
        mode = "replace" if args.get("confirm_new_entitlements") else "auto"
        structure_result = await prepare_entitlement_structure({
            "filename": filename,
            "appId": app_id,
            "mode": mode
        })
        structure = json.loads(structure_result)
        
        if structure.get("status") == "EXISTING_ENTITLEMENTS_FOUND":
            return structure_result
        
        return await execute_user_grants({
            "filename": filename,
            "appId": app_id
        })
    
    else:
        return json.dumps({"status": "FAILED", "error": f"Unknown stage: {stage}"})
