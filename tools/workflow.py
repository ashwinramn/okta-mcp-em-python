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
    
    # Normalize filename to basename for consistent caching
    cache_key = Path(filename).name if filename else None
    
    if not filepath:
        return json.dumps({"status": "FAILED", "error": f"File not found: {filename}"})
    
    import pandas as pd
    
    try:
        df = pd.read_csv(filepath, dtype=str).fillna("")
        
        IGNORED_COLUMNS = {
            "User_Email", "Email", "User", "Username", "Login", "Person_Id", 
            "Employee_Number", "User_ID", "First Name", "Last Name", "Full Name",
            "Department", "Manager", "Title", "Cost Center", "Division",
            "Effective_Access", "Last_Login", "Date", "Created_Date", 
            "Updated_Date", "Status", "Active", "Access_Date", "Action_Type", "Action_Date"
        }
        
        ignored_lower = {k.lower() for k in IGNORED_COLUMNS}
        
        attr_cols = [c for c in df.columns if c in IGNORED_COLUMNS or c.lower() in ignored_lower]
        ent_cols = [c for c in df.columns if c not in attr_cols]
        
        email_col = next((c for c in ["User_Email", "Email", "User"] if c in df.columns), None)
        
        issues = []
        
        if not email_col:
            issues.append("❌ CRITICAL: No email column found (User_Email, Email, or User)")
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
        for col in ent_cols:
            unique_vals = set()
            for v in permitted_df[col].unique():
                if not v: 
                    continue
                for item in v.split(','):
                    if item.strip():
                        unique_vals.add(item.strip())
            
            entitlements[col] = sorted(list(unique_vals))
            
            if not unique_vals:
                issues.append(f"⚠️ Column '{col}' has no values for permitted users")
        
        unique_users = []
        if email_col:
            unique_users = sorted(list(set(
                permitted_df[email_col].str.strip().unique()
            ) - {""}))
        
        cache_data = {
            "filepath": str(filepath),
            "filename": filepath.name,
            "email_column": email_col,
            "entitlement_columns": ent_cols,
            "attribute_columns": attr_cols,
            "entitlements": entitlements,
            "unique_users": unique_users,
            "total_rows": total_rows,
            "permitted_rows": permitted_rows,
            "has_effective_access": "Effective_Access" in df.columns
        }
        set_cached_csv(cache_key, cache_data)
        
        ent_summary = []
        for col, vals in entitlements.items():
            ent_summary.append(f"  • {col}: {', '.join(vals[:10])}{'...' if len(vals) > 10 else ''} ({len(vals)} values)")
        
        return json.dumps({
            "status": "analysis_complete",
            "csv_name": filepath.name,
            "summary": {
                "total_rows": total_rows,
                "permitted_rows": permitted_rows,
                "unique_users": len(unique_users),
                "entitlement_types": len(ent_cols),
                "total_entitlement_values": sum(len(v) for v in entitlements.values())
            },
            "entitlements_found": entitlements,
            "entitlement_columns": ent_cols,
            "application_attributes": attr_cols,
            "issues": issues if issues else ["✅ No issues detected"],
            "cached": True,
            "next_step": "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                        "📋 WORKFLOW STEP 1 COMPLETE - CSV Analyzed\n"
                        "\n"
                        "🔜 NEXT REQUIRED STEP:\n"
                        "   Once you have the App ID, call:\n"
                        "   prepare_entitlement_structure(filename, appId)\n"
                        "\n"
                        "   This will CREATE the entitlement structure in Okta.\n"
                        "   DO NOT skip to execute_user_grants - it will fail!\n"
                        "\n"
                        "⚠️  Please provide the Okta App ID to continue.\n"
                        "   Example: 'The App ID is 0oa1234567890ABCDEF'\n"
                        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        }, indent=2)

    except Exception as e:
        logger.error(f"CSV analysis failed: {e}", exc_info=True)
        return json.dumps({"status": "FAILED", "error": f"Error analyzing CSV: {str(e)}"})


# ============================================
# STAGE 2: Prepare Entitlement Structure
# ============================================

async def _ensure_app_schema_attributes(app_id: str, entitlement_names: List[str]) -> Tuple[bool, str]:
    """
    Ensure that app schema has attributes for all entitlements.
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
        
        # Check which entitlement attributes are missing
        missing_attrs = [name for name in entitlement_names if name not in existing_custom]
        
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
    
    # Normalize filename to basename for consistent caching
    cache_key = Path(filename).name if filename else None
    cached = get_cached_csv(cache_key)
    if not cached:
        return json.dumps({
            "status": "FAILED", 
            "error": f"CSV '{filename}' not found in cache. Please run analyze_csv_for_entitlements first."
        })
    
    csv_entitlements = cached.get("entitlements", {})
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
            
            # First, ensure app schema has attributes for all entitlements
            schema_success, schema_msg = await _ensure_app_schema_attributes(app_id, list(csv_entitlements.keys()))
            if not schema_success:
                return json.dumps({
                    "status": "FAILED",
                    "error": f"Failed to ensure app schema attributes: {schema_msg}"
                })
            
            return await _create_entitlement_structure(app_id, csv_entitlements, mode="create")
        
        else:
            csv_ent_names = set(csv_entitlements.keys())
            app_ent_names = set(existing_names.keys())
            
            common = csv_ent_names & app_ent_names
            new_in_csv = csv_ent_names - app_ent_names
            only_in_app = app_ent_names - csv_ent_names
            
            if mode == "auto":
                return json.dumps({
                    "status": "EXISTING_ENTITLEMENTS_FOUND",
                    "message": "⚠️ The application already has entitlements configured.",
                    "comparison": {
                        "in_app": list(app_ent_names),
                        "in_csv": list(csv_ent_names),
                        "matching": list(common),
                        "new_in_csv": list(new_in_csv),
                        "only_in_app": list(only_in_app)
                    },
                    "existing_entitlements": [
                        {"name": e.get("name"), "id": e.get("id"), "description": e.get("description", "")}
                        for e in existing_ents
                    ],
                    "options": {
                        "update": "Add new entitlements from CSV, keep existing ones",
                        "replace": "Delete all existing entitlements and recreate from CSV"
                    },
                    "next_step": "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                                "🔄 What would you like to do?\n"
                                "   • 'Update' - Add new entitlements, keep existing\n"
                                "   • 'Replace' - Delete all and recreate from CSV\n"
                                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                }, indent=2)
            
            elif mode == "update":
                new_ents = {k: v for k, v in csv_entitlements.items() if k in new_in_csv}
                if not new_ents:
                    return json.dumps({
                        "status": "NO_CHANGES_NEEDED",
                        "message": "✅ All entitlements from CSV already exist in the app.",
                        "existing_entitlements": list(app_ent_names),
                        "next_step": "Ready to proceed with granting users their entitlements?"
                    }, indent=2)
                return await _create_entitlement_structure(app_id, new_ents, mode="update")
            
            elif mode == "replace":
                return await _replace_entitlement_structure(app_id, existing_ents, csv_entitlements)
            
            else:
                return json.dumps({"status": "FAILED", "error": f"Unknown mode: {mode}"})
    
    except Exception as e:
        logger.error(f"Entitlement structure preparation failed: {e}", exc_info=True)
        return json.dumps({"status": "FAILED", "error": str(e)})


async def _create_entitlement_structure(app_id: str, entitlements: Dict[str, List[str]], mode: str = "create") -> str:
    """Internal: Create entitlement definitions and values.
    
    CORRECT API STRUCTURE (learned from manual testing):
    - app: {"id": app_id}
    - attribute: entitlement name (must match app schema attribute)
    - dataType: "string"
    - displayName: display name for the entitlement
    - description: generated description
    - externalValue: external identifier (usually same as name)
    - multiValue: false (single-select entitlement)
    - name: internal name
    - parent: {"externalId": app_id, "type": "APPLICATION"}
    - values: array of value objects, each with:
      - name: value name
      - displayName: display name (can be same as name)
      - externalValue: external identifier
      - description: generated description for this value
    """
    created = []
    errors = []
    
    for ent_name, values in entitlements.items():
        try:
            description = generate_entitlement_description(ent_name)
            
            # Build ALL values at once - each value needs name, displayName, externalValue, description
            values_payload = [
                {
                    "name": val,
                    "displayName": val,
                    "externalValue": val,
                    "description": generate_value_description(ent_name, val)
                }
                for val in values
            ]
            
            url = f"https://{okta_client.domain}/governance/api/v1/entitlements"
            
            # CORRECT STRUCTURE - all required fields based on API testing
            body = {
                "app": {
                    "id": app_id
                },
                "attribute": ent_name,  # Must match app schema attribute name
                "dataType": "string",
                "displayName": ent_name,
                "description": description,
                "externalValue": ent_name,
                "multiValue": False,  # Single-select entitlement
                "name": ent_name,
                "parent": {
                    "externalId": app_id,  # Note: externalId, not id
                    "type": "APPLICATION"   # Must be uppercase
                },
                "values": values_payload  # ALL values created in one API call
            }
            
            logger.info(f"Creating entitlement: {ent_name} with {len(values)} values")
            logger.debug(f"Entitlement body: {json.dumps(body, indent=2)}")
            
            result = await okta_client.execute_request("POST", url, body=body)
            
            if result["success"]:
                response_data = result.get("response", {})
                created.append({
                    "name": ent_name,
                    "values": values,
                    "value_count": len(values),
                    "description": description,
                    "id": response_data.get("id"),
                    "created_values": len(response_data.get("values", []))
                })
                logger.info(f"✅ Created entitlement '{ent_name}' with {len(values)} values")
            else:
                error_msg = result.get("response", {}).get("errorSummary", str(result.get("response")))
                errors.append({"name": ent_name, "error": error_msg})
                logger.error(f"❌ Failed to create entitlement '{ent_name}': {error_msg}")
            
            await asyncio.sleep(0.5)
            
        except Exception as e:
            errors.append({"name": ent_name, "error": str(e)})
            logger.error(f"❌ Exception creating entitlement '{ent_name}': {e}", exc_info=True)
    
    status = "SUCCESS" if not errors else ("PARTIAL_SUCCESS" if created else "FAILED")
    
    return json.dumps({
        "status": status,
        "mode": mode,
        "message": f"✅ Created {len(created)} entitlement(s)" + (f", {len(errors)} failed" if errors else ""),
        "created": created,
        "errors": errors if errors else [],
        "next_step": "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                    "✅ WORKFLOW STEP 2 COMPLETE - Entitlement Structure Created\n"
                    "\n"
                    "🔜 NEXT REQUIRED STEP:\n"
                    "   Call: execute_user_grants(filename, appId)\n"
                    "\n"
                    "   This will grant entitlements to users from the CSV.\n"
                    "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    }, indent=2)


async def _replace_entitlement_structure(app_id: str, existing_ents: List[Dict], csv_entitlements: Dict[str, List[str]]) -> str:
    """Internal: Delete existing entitlements and recreate from CSV."""
    deleted = []
    delete_errors = []
    
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
    
    create_result_str = await _create_entitlement_structure(app_id, csv_entitlements, mode="replace")
    create_result = json.loads(create_result_str)
    
    return json.dumps({
        "status": create_result.get("status"),
        "mode": "replace",
        "deleted": {
            "count": len(deleted),
            "names": deleted,
            "errors": delete_errors
        },
        "created": create_result.get("created", []),
        "errors": create_result.get("errors", []),
        "next_step": create_result.get("next_step")
    }, indent=2)


# ============================================
# STAGE 3: Execute User Grants
# ============================================

async def execute_user_grants(args: Dict[str, Any]) -> str:
    """
    STAGE 3: Grant entitlements to users from CSV.
    
    WORKFLOW:
    1. Retrieves entitlement IDs from the application
    2. Retrieves entitlement value IDs for all entitlements
    3. Searches for all unique users in Okta (concurrent)
    4. Assigns found users to the application
    5. Builds grant requests from CSV data (one grant per user with all entitlements)
    6. Creates entitlement grants (concurrent, rate-limited)
    
    Returns detailed summary with assignment and grant statistics.
    """
    filename = args.get("filename")
    app_id = args.get("appId")
    
    if not app_id:
        return json.dumps({"status": "FAILED", "error": "App ID is required"})
    
    # Normalize filename to basename for consistent caching
    cache_key = Path(filename).name if filename else None
    cached = get_cached_csv(cache_key)
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
        progress.append(f"[1/5] Retrieving entitlement IDs for app {app_id}")
        
        existing_ents_json = await api.okta_iga_list_entitlements({"appId": app_id})
        success, existing_ents = safe_json_loads(existing_ents_json, "list_entitlements")
        
        if not success or not isinstance(existing_ents, list):
            existing_ents = []
        
        ent_id_map = {e['name']: e['id'] for e in existing_ents if isinstance(e, dict) and 'name' in e and 'id' in e}
        
        if not ent_id_map:
            return json.dumps({
                "status": "FAILED",
                "error": "No entitlements found in app. Please run prepare_entitlement_structure first."
            })
        
        progress.append(f"   ✅ Found {len(ent_id_map)} entitlements: {list(ent_id_map.keys())}")
        
        # NEW: Get entitlement value IDs for all entitlements
        progress.append(f"[2/5] Retrieving entitlement value IDs")
        
        ent_value_map = {}  # {entitlement_name: {value_name: value_id}}
        
        for ent_name, ent_id in ent_id_map.items():
            values_json = await api.okta_iga_list_entitlement_values({"entitlementId": ent_id})
            success, values_data = safe_json_loads(values_json, f"list_values_{ent_name}")
            
            if not success or not isinstance(values_data, list):
                values_data = []
            
            # Build map of value name -> value ID
            value_id_map = {}
            for v in values_data:
                if isinstance(v, dict) and 'name' in v and 'id' in v:
                    value_id_map[v['name']] = v['id']
            
            ent_value_map[ent_name] = value_id_map
            
            await asyncio.sleep(0.2)  # Small delay between API calls
        
        progress.append(f"   ✅ Retrieved value IDs for all entitlements")
        
        progress.append(f"[3/5] Searching for {len(unique_users)} users in Okta (concurrent)")
        
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
            return json.dumps({
                "status": "FAILED",
                "error": "No users found in Okta",
                "not_found_users": not_found_users[:20],
                "progress": progress
            })
        
        # NEW STEP: Assign users to application first
        progress.append(f"[4/5] Assigning {len(found_users)} users to application (concurrent)")
        
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
        
        progress.append("[5/5] Building grant requests from CSV data")
        
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
                        if ent_id not in user_grants[user_id]:
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
            return json.dumps({
                "status": "NO_GRANTS",
                "message": "No grants to create",
                "skipped": skipped[:20],
                "progress": progress
            })
        
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
        
        progress.append(f"   ✅ Successfully created: {successful_grants} grants")
        if failed_grants:
            progress.append(f"   ⚠️ Failed: {len(failed_grants)} grants")
        
        elapsed = time.time() - start_time
        rate_status = tracker.get_status()
        
        await basic.move_to_processed({"filename": Path(filepath).name, "destination": "processed_and_assigned"})
        
        return json.dumps({
            "status": "SUCCESS",
            "message": "🚀 Entitlement granting completed!",
            "summary": {
                "users_searched": len(unique_users),
                "users_found": len(found_users),
                "users_not_found": len(not_found_users),
                "users_assigned": assigned_count,
                "users_already_assigned": already_assigned,
                "assignment_failures": len(assignment_failed),
                "grants_attempted": len(grant_inputs),
                "grants_successful": successful_grants,
                "grants_failed": len(failed_grants),
                "grants_skipped": len(skipped),
                "elapsed_seconds": round(elapsed, 2)
            },
            "not_found_users": not_found_users[:20] if not_found_users else [],
            "assignment_failures": assignment_failed[:10] if assignment_failed else [],
            "failed_grants": failed_grants[:10] if failed_grants else [],
            "progress": progress,
            "rate_limits": {
                "requests_last_minute": rate_status.get("requestsLastMinute", 0),
                "total_requests": rate_status.get("stats", {}).get("totalRequests", 0),
                "throttled": rate_status.get("stats", {}).get("throttledRequests", 0)
            },
            "file_status": f"Moved to processed_and_assigned/"
        }, indent=2)
    
    except Exception as e:
        logger.error(f"User grants failed: {e}", exc_info=True)
        return json.dumps({
            "status": "FAILED",
            "error": str(e),
            "progress": progress
        })


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
