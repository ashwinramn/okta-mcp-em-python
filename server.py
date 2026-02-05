"""
Okta MCP Server - Model Context Protocol server for Okta Entitlements & Grants

This is the main entry point for the MCP server.
"""
import sys
import os
from pathlib import Path
from typing import Any, Dict, List

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel

# Ensure the project root is in sys.path for imports
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools import basic, api, batch, workflow

# Initialize FastMCP
mcp = FastMCP("okta-mcp-em-python")

# --- BATCH INPUT MODELS ---
class SearchItem(BaseModel):
    attribute: str
    value: str

class GrantBody(BaseModel):
    grantType: str
    actor: Dict[str, Any]
    action: str
    targetResourceOrn: str = None
    target: Dict[str, Any]
    targetPrincipal: Dict[str, Any]
    entitlements: List[Dict[str, Any]] = None

class GrantItem(BaseModel):
    userId: str
    grantBody: Any

# ===========================================
# BASIC TOOLS
# ===========================================

@mcp.tool()
async def okta_test() -> str:
    """Test connection to Okta tenant by verifying environment variables and making an API call to /api/v1/users/me."""
    return await basic.okta_test({})

@mcp.tool()
async def list_csv_files() -> str:
    """List all CSV files available in the csv/ folder for processing."""
    return await basic.list_csv_files({})

@mcp.tool()
async def read_csv_file(file: str) -> str:
    """Read the contents of a CSV file. Accepts either the filename or a number from the list."""
    return await basic.read_csv_file({"file": file})

@mcp.tool()
async def move_to_processed(filename: str, destination: str = "processed") -> str:
    """Move a CSV file to the processed/ subfolder after successful entitlement creation.
    destination can be 'processed' or 'processed_and_assigned'.
    """
    return await basic.move_to_processed({"filename": filename, "destination": destination})

@mcp.tool()
async def sync_s3_files() -> str:
    """Sync CSV files from S3 bucket to local folder for processing."""
    return await basic.sync_s3_files({})

# ===========================================
# API TOOLS
# ===========================================

@mcp.tool()
async def execute_okta_api_call(method: str, url: str, headers: dict = None, body: Any = None, description: str = None) -> str:
    """Execute an Okta API call. LLM constructs the request, MCP adds headers.
    
    Args:
        method: HTTP method (GET, POST, etc.)
        url: Full URL
        headers: Optional headers (Auth added automatically)
        body: Request body
        description: Description for logging
    """
    return await api.execute_okta_api_call({
        "method": method, 
        "url": url, 
        "headers": headers, 
        "body": body, 
        "description": description
    })

@mcp.tool()
async def okta_iga_list_entitlements(appId: str) -> str:
    """List all entitlements for a specific Okta application."""
    return await api.okta_iga_list_entitlements({"appId": appId})

@mcp.tool()
async def okta_iga_list_entitlement_values(entitlementId: str) -> str:
    """List all values for a specific entitlement."""
    return await api.okta_iga_list_entitlement_values({"entitlementId": entitlementId})

@mcp.tool()
async def okta_user_search(attribute: str, value: str) -> str:
    """Search for an Okta user by attribute (email, login, employeeNumber)."""
    return await api.okta_user_search({"attribute": attribute, "value": value})

@mcp.tool()
async def okta_assign_user_to_app(appId: str, userId: str) -> str:
    """Assign a user to an Okta application."""
    return await api.okta_assign_user_to_app({"appId": appId, "userId": userId})

@mcp.tool()
async def okta_iga_create_custom_grant(grantBody: Dict[str, Any]) -> str:
    """
    Create a CUSTOM governance grant to assign entitlements to a user.
    
    API Doc: https://developer.okta.com/docs/api/iga/openapi/governance.api/tag/Grants/#tag/Grants/operation/createGrant
    
    grantBody must be the complete JSON body with structure:
    {
        "grantType": "CUSTOM",
        "target": {"externalId": "APP_ID", "type": "APPLICATION"},
        "targetPrincipal": {"externalId": "USER_ID", "type": "OKTA_USER"},
        "entitlements": [
            {"id": "ENTITLEMENT_ID", "values": [{"id": "VALUE_ID"}, {"id": "VALUE_ID_2"}]}
        ]
    }
    
    Expected success response includes: id, status="ACTIVE", entitlements array
    """
    return await api.okta_iga_create_custom_grant({"grantBody": grantBody})

@mcp.tool()
async def okta_iga_list_grants(filter: str) -> str:
    """List grants for a user/app using a filter expression."""
    return await api.okta_iga_list_grants({"filter": filter})

@mcp.tool()
async def okta_get_rate_status() -> str:
    """Get current rate limit status for tracked endpoints."""
    return await api.okta_get_rate_status({})

@mcp.tool()
async def okta_create_app_attributes(appId: str, attributes: Dict[str, Dict[str, str]]) -> str:
    """
    Create application profile attributes (schema properties) for an Okta app.
    
    USE THIS FOR: Non-entitlement attributes like User_ID, Last_Login, Department, etc.
    DO NOT USE FOR: Entitlements (Role, Permission_Set) - use prepare_entitlement_structure instead!
    
    Args:
        appId: Okta Application ID
        attributes: Dict of attribute definitions, e.g.:
            {
                "User_ID": {"type": "string", "description": "User identifier"},
                "Last_Login": {"type": "string", "description": "Last login date"},
                "Department": {"type": "string", "description": "User department"}
            }
    
    Example:
        okta_create_app_attributes(
            "0oaXXXXXXXXXXXXX",
            {
                "Employee_Number": {"type": "string", "description": "Employee ID"},
                "Access_Date": {"type": "string", "description": "Date of access"}
            }
        )
    """
    return await api.okta_create_app_attributes({"appId": appId, "attributes": attributes})

# ===========================================
# BATCH TOOLS
# ===========================================

@mcp.tool()
async def okta_batch_user_search(searches: List[Dict[str, str]], concurrency: int = 5) -> str:
    """Search for multiple Okta users in parallel. 
    searches: List of objects with 'attribute' and 'value'.
    """
    return await batch.okta_batch_user_search({"searches": searches, "concurrency": concurrency})

@mcp.tool()
async def okta_batch_assign_users(appId: str, userIds: List[str], concurrency: int = 5) -> str:
    """Assign multiple users to an application in parallel."""
    return await batch.okta_batch_assign_users({"appId": appId, "userIds": userIds, "concurrency": concurrency})

@mcp.tool()
async def okta_batch_create_grants(grants: List[Dict[str, Any]], concurrency: int = 5) -> str:
    """
    Create multiple governance grants in parallel.
    
    API Doc: https://developer.okta.com/docs/api/iga/openapi/governance.api/tag/Grants/#tag/Grants/operation/createGrant
    
    grants: List of objects with:
        - userId: The Okta user ID (for tracking)
        - grantBody: The complete grant request body:
            {
                "grantType": "CUSTOM",
                "target": {"externalId": "APP_ID", "type": "APPLICATION"},
                "targetPrincipal": {"externalId": "USER_ID", "type": "OKTA_USER"},
                "entitlements": [{"id": "ENT_ID", "values": [{"id": "VALUE_ID"}]}]
            }
    
    Returns: Summary with successful grants (including grantId, grantStatus, entitlements) and failures
    """
    return await batch.okta_batch_create_grants({"grants": grants, "concurrency": concurrency})

# ===========================================
# WORKFLOW TOOLS (STAGED)
# ===========================================

@mcp.tool()
async def analyze_csv_for_entitlements(filename: str) -> str:
    """
    STAGE 1 of 3: Analyze a CSV file to identify users and entitlements.
    
    WORKFLOW ORDER: analyze_csv_for_entitlements -> prepare_entitlement_structure -> execute_user_grants
    
    This tool:
    - Caches the CSV data for subsequent workflow steps
    - Identifies entitlement types and their values
    - Identifies application attributes (user info columns)
    - Reports any data quality issues
    - Prompts for the Okta App ID to continue
    
    NEXT STEP: After user provides App ID, call prepare_entitlement_structure(filename, appId)
    DO NOT call execute_user_grants directly - the entitlement structure must be created first!
    """
    return await workflow.analyze_csv_for_entitlements({"filename": filename})

@mcp.tool()
async def prepare_entitlement_structure(filename: str, appId: str, mode: str = "auto") -> str:
    """
    STAGE 2 of 3: Create the entitlement structure in Okta using the Entitlements API.
    
    WORKFLOW ORDER: analyze_csv_for_entitlements -> prepare_entitlement_structure -> execute_user_grants
    
    THIS IS THE CRITICAL STEP that creates entitlements in Okta!
    Uses: POST /governance/api/v1/entitlements
    
    This tool:
    - Checks if the app has existing entitlements
    - If NONE exist: Creates the structure automatically with generated descriptions
    - If SOME exist: Returns comparison and asks user to choose 'update' or 'replace'
    
    Args:
        filename: CSV filename (must be analyzed first with analyze_csv_for_entitlements)
        appId: Okta Application ID
        mode: 'auto' (check and ask), 'update' (add new only), or 'replace' (delete all and recreate)
    
    REQUIRES: Run analyze_csv_for_entitlements first to cache the CSV data.
    NEXT STEP: After structure is created, call execute_user_grants(filename, appId)
    """
    return await workflow.prepare_entitlement_structure({
        "filename": filename,
        "appId": appId,
        "mode": mode
    })

@mcp.tool()
async def execute_user_grants(filename: str, appId: str) -> str:
    """
    STAGE 3 of 3 (FINAL): Grant entitlements to users from the CSV.
    
    WORKFLOW ORDER: analyze_csv_for_entitlements -> prepare_entitlement_structure -> execute_user_grants
    
    WARNING: This tool will FAIL if prepare_entitlement_structure was not run first!
    The entitlement structure MUST exist in Okta before grants can be created.
    
    This tool:
    - Retrieves entitlement IDs from the application (will fail if none exist)
    - Searches for all unique users in CSV (concurrent, rate-limited)
    - Reports users not found in Okta (skips them)
    - Creates entitlement grants for found users (concurrent, rate-limited)
    - Returns detailed summary with timing and rate limit info
    
    Args:
        filename: CSV filename (must be analyzed first)
        appId: Okta Application ID
    
    REQUIRES (in order):
    1. analyze_csv_for_entitlements(filename) - to cache CSV data
    2. prepare_entitlement_structure(filename, appId) - to create entitlements in Okta
    """
    return await workflow.execute_user_grants({
        "filename": filename,
        "appId": appId
    })

# ===========================================
# LEGACY WORKFLOW TOOL (Backwards Compatibility)
# ===========================================

@mcp.tool()
async def process_entitlements_workflow(
    filename: str, 
    appId: str, 
    entitlementColumns: List[str] = None,
    entitlementDescriptions: Dict[str, str] = None,
    confirm_new_entitlements: bool = False,
    stage: str = "full"
) -> str:
    """
    [LEGACY] Full entitlement provisioning workflow.
    
    For better control, use the staged tools instead:
    1. analyze_csv_for_entitlements(filename)
    2. prepare_entitlement_structure(filename, appId, mode)
    3. execute_user_grants(filename, appId)
    
    STAGES:
    - 'full': Runs everything (default behavior)
    - 'analyze': Same as analyze_csv_for_entitlements
    - 'create_structure': Same as prepare_entitlement_structure
    - 'grant_users': Same as execute_user_grants
    """
    return await workflow.process_entitlements_workflow({
        "filename": filename, 
        "appId": appId, 
        "entitlementColumns": entitlementColumns,
        "descriptions": entitlementDescriptions,
        "confirm_new_entitlements": confirm_new_entitlements,
        "stage": stage
    })


def main():
    mcp.run()

if __name__ == "__main__":
    main()
