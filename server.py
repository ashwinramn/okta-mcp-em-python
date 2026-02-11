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

from tools import basic, api, batch, workflow, bundle, menu, sod, governance

def validate_environment_variables() -> None:
    """
    Validate required environment variables before MCP server starts.
    Exits with code 1 if validation fails.
    """
    import logging
    logger = logging.getLogger("okta_mcp")

    okta_domain = os.environ.get("OKTA_DOMAIN")
    okta_token = os.environ.get("OKTA_API_TOKEN")

    if not okta_domain:
        logger.error("CRITICAL: OKTA_DOMAIN environment variable is not set")
        print("❌ ERROR: OKTA_DOMAIN environment variable is required")
        print("Create a .env file with: OKTA_DOMAIN=your-domain.okta.com")
        sys.exit(1)

    if not okta_token:
        logger.error("CRITICAL: OKTA_API_TOKEN environment variable is not set")
        print("❌ ERROR: OKTA_API_TOKEN environment variable is required")
        print("Create a .env file with: OKTA_API_TOKEN=your-api-token")
        sys.exit(1)

    logger.info(f"Environment validation passed: OKTA_DOMAIN={okta_domain}")

validate_environment_variables()

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
async def show_workflow_menu() -> str:
    """Display the main workflow menu. Call this after okta_test succeeds to see available workflows.
    
    Shows two workflow options:
    1. Import CSV → Okta: Import access data from CSV files into Okta as entitlements
    2. Mine Patterns → Bundles: Analyze existing entitlements to create access bundles
    """
    return await menu.show_workflow_menu({})

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
async def okta_iga_list_grants_for_app(appId: str, userId: str = None) -> str:
    """
    List all governance grants for a specific application.

    This tool handles the correct filter format for the Grants API automatically.
    No need to construct filter expressions manually.

    Args:
        appId: Required. The Okta application ID.
        userId: Optional. Filter to a specific user's grants.

    Returns: JSON with grants list, counts, and unique user stats.
    """
    return await api.okta_iga_list_grants_for_app({"appId": appId, "userId": userId})

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


# ===========================================
# BUNDLE GENERATION TOOLS
# ===========================================

@mcp.tool()
async def analyze_entitlement_patterns(
    appId: str,
    profileAttributes: List[str] = None,
    threshold: float = 75,
    includeMultiAttribute: bool = True,
    multiAttributeDepth: int = 2
) -> str:
    """
    Analyze entitlement patterns for an application.
    
    Discovers patterns between user profile attributes and their entitlements.
    For example: "90% of users in department=Engineering have Role=Developer"
    
    Args:
        appId: Required. The Okta application ID to analyze.
        profileAttributes: Optional. Profile attributes to analyze.
            Default: ["department", "title", "employeeType", "costCenter"]
        threshold: Optional. Minimum percentage for pattern inclusion (50-100).
            Default: 75.
        includeMultiAttribute: Optional. Analyze multi-attribute combinations.
            Default: True.
        multiAttributeDepth: Optional. Max attributes to combine (2-3).
            Default: 2.
    
    Returns analysis results with discovered patterns, cached for bundle creation.
    Use the analysis_id and pattern_id with preview_bundle_creation to see bundle details.
    """
    return await bundle.analyze_entitlement_patterns({
        "appId": appId,
        "profileAttributes": profileAttributes,
        "threshold": threshold,
        "includeMultiAttribute": includeMultiAttribute,
        "multiAttributeDepth": multiAttributeDepth
    })


@mcp.tool()
async def preview_bundle_creation(
    analysisId: str,
    patternId: str,
    bundleName: str = None,
    description: str = None
) -> str:
    """
    Preview bundle creation from a discovered pattern (dry run).
    
    Shows exactly what would be created without making any changes.
    Run analyze_entitlement_patterns first to get the analysisId and patternId.
    
    Args:
        analysisId: Required. The analysis ID from analyze_entitlement_patterns.
        patternId: Required. The pattern ID to create a bundle from.
        bundleName: Optional. Custom name for the bundle.
        description: Optional. Custom description for the bundle.
    
    Returns preview of the bundle including the API payload that would be sent.
    """
    return await bundle.preview_bundle_creation({
        "analysisId": analysisId,
        "patternId": patternId,
        "bundleName": bundleName,
        "description": description
    })


@mcp.tool()
async def create_bundle_from_pattern(
    analysisId: str,
    patternId: str,
    bundleName: str,
    description: str = None,
    confirmCreation: bool = False,
    allowSodOverride: bool = False
) -> str:
    """
    Create an entitlement bundle from a discovered pattern (SoD-safe).

    This will create a real bundle in Okta. Use preview_bundle_creation first
    to see what will be created.

    SoD SAFETY: Before creating the bundle, this tool checks for separation of
    duties conflicts against existing risk rules, the knowledge base, and ISACA
    duty category pairings. If conflicts are found, creation is BLOCKED unless
    allowSodOverride=true is explicitly passed.

    Args:
        analysisId: Required. The analysis ID from analyze_entitlement_patterns.
        patternId: Required. The pattern ID to create a bundle from.
        bundleName: Required. Name for the bundle.
        description: Optional. Description for the bundle.
        confirmCreation: Required. Must be true to confirm bundle creation.
        allowSodOverride: Optional. Set to true to create bundle despite SoD conflicts.
            Default: false. When true, the bundle is created but logged as an override.

    Returns the created bundle details, SoD check status, or conflict details if blocked.
    """
    return await bundle.create_bundle_from_pattern({
        "analysisId": analysisId,
        "patternId": patternId,
        "bundleName": bundleName,
        "description": description,
        "confirmCreation": confirmCreation,
        "allowSodOverride": allowSodOverride,
    })


@mcp.tool()
async def create_entitlement_bundle(
    appId: str,
    bundleName: str,
    entitlements: list,
    description: str = "",
    checkSod: bool = True,
    allowSodOverride: bool = False
) -> str:
    """
    Create an entitlement bundle directly from entitlement value names.

    Use this when you know which entitlements to bundle together without needing
    pattern analysis first. Resolves entitlement value names to IDs, checks for
    SoD conflicts, and creates the bundle via the Okta API.

    Args:
        appId: Required. Okta application ID.
        bundleName: Required. Name for the bundle.
        entitlements: Required. List of entitlement value names to include.
        description: Optional. Description for the bundle.
        checkSod: Optional. Check for SoD conflicts before creation. Default: true.
        allowSodOverride: Optional. Create despite SoD conflicts. Default: false.

    Returns the created bundle details or error/conflict information.
    """
    return await bundle.create_entitlement_bundle({
        "appId": appId,
        "bundleName": bundleName,
        "entitlements": entitlements,
        "description": description,
        "checkSod": checkSod,
        "allowSodOverride": allowSodOverride,
    })


# ===========================================
# SEPARATION OF DUTIES (SoD) TOOLS
# ===========================================

@mcp.tool()
async def analyze_sod_context(appId: str) -> str:
    """
    Gather SoD analysis context for an application.

    Returns structured data for LLM to analyze separation of duties risks:
    - Application info (name, label, status)
    - All entitlements and their values
    - Known toxic patterns from knowledge base (if app is recognized)
    - ISACA duty categories and toxic pairing rules
    - Compliance framework references (NIST AC-5, SOX 404, SOC2)

    The LLM uses this context to:
    1. Map entitlement values to duty categories (authorization, custody, recording, verification)
    2. Identify toxic combinations using ISACA rules
    3. Cross-reference with known patterns for the app type
    4. Recommend SoD rules with compliance justification

    Args:
        appId: Required. The Okta application ID to analyze.

    After analysis, use create_sod_risk_rule to create enforcement rules.
    """
    return await sod.analyze_sod_context({"appId": appId})


@mcp.tool()
async def create_sod_risk_rule(
    appId: str,
    ruleName: str,
    list1: List[str],
    list2: List[str],
    description: str = "",
    notes: str = ""
) -> str:
    """
    Create an Okta IGA Risk Rule for separation of duties enforcement.

    API: POST /governance/api/v1/risk-rules
    API Doc: https://developer.okta.com/docs/api/iga/openapi/governance.api/tag/Risk-Rules/#tag/Risk-Rules/operation/createRiskRule

    This tool automatically:
    1. Retrieves the app ORN (required for resources array)
    2. Resolves value names to entitlement IDs
    3. Builds the correct ENTITLEMENTS-shaped conflictCriteria
    4. Creates the rule with type: "SEPARATION_OF_DUTIES"

    Args:
        appId: Required. Okta application ID.
        ruleName: Required. Name for the SoD rule (e.g., "Admin + Auditor Conflict").
        list1: Required. First list of entitlement value names that conflict with list2.
        list2: Required. Second list of entitlement value names that conflict with list1.
        description: Longer compliance text explaining the risk (SOX, NIST AC-5, etc.).
        notes: Short UI-friendly audit note (what the requester sees).

    Example:
        create_sod_risk_rule(
            appId="0oa123abc",
            ruleName="Admin + Action Write Conflict",
            list1=["admin"],
            list2=["action_write_enabled"],
            description="Admin approval + ability to write actions enables approval+execution. Compliance: NIST AC-5 / ISACA.",
            notes="Admin plus action-write lets one person approve and execute changes."
        )
    """
    return await sod.create_sod_risk_rule({
        "appId": appId,
        "ruleName": ruleName,
        "description": description,
        "notes": notes,
        "list1": list1,
        "list2": list2
    })


@mcp.tool()
async def list_sod_risk_rules(appId: str = None) -> str:
    """
    List existing SoD Risk Rules.

    Args:
        appId: Optional. Filter rules by application ID.

    Returns list of Risk Rules with their configuration.
    """
    return await sod.list_sod_risk_rules({"appId": appId})


@mcp.tool()
async def get_entitlement_ids_for_values(appId: str, valueNames: List[str]) -> str:
    """
    Resolve entitlement value names to their IDs for use in API calls.

    Use this helper when you need to construct Risk Rule API calls manually
    via execute_okta_api_call. It returns the entitlementId, entitlementName,
    valueId, and valueName for each value name.

    Args:
        appId: Required. Okta application ID.
        valueNames: Required. List of entitlement value names to resolve.

    Returns:
        JSON mapping of value names to their full info (IDs and names).

    Example:
        get_entitlement_ids_for_values(
            appId="0oa123abc",
            valueNames=["admin", "action_write_enabled"]
        )
    """
    return await sod.get_entitlement_ids_for_values({
        "appId": appId,
        "valueNames": valueNames
    })


@mcp.tool()
async def test_sod_risk_rule(userId: str, appId: str = None) -> str:
    """
    Test Risk Rules by running a risk assessment for a user.

    API: POST /governance/api/v1/risk-rule-assessments

    This generates a risk assessment to verify if any rules detect
    SoD conflicts for a specific user.

    Args:
        userId: Required. Okta user ID to assess.
        appId: Optional. Filter assessment to specific application.

    Returns:
        JSON with risk assessment results. Check 'violations' array
        for any SoD conflicts detected.
    """
    return await sod.test_sod_risk_rule({
        "userId": userId,
        "appId": appId
    })


# ===========================================
# GOVERNANCE SUMMARY TOOLS
# ===========================================

@mcp.tool()
async def generate_governance_summary(appId: str) -> str:
    """
    Generate a comprehensive governance posture report and scorecard for an application.

    This is a one-shot tool that pulls data from multiple Okta APIs and produces:
    - Entitlement inventory (schemas, values, types)
    - Access grant statistics (total grants, active, unique users)
    - Separation of Duties coverage (rules created vs toxic pairs known)
    - Bundle/role-based access adoption ratio
    - Compliance readiness checks (NIST AC-5, SOX 404, SOC2 CC6.1, CC6.3)
    - Overall governance score (0-100) with letter grade
    - Prioritized recommendations for improvement

    Use this after completing a workflow (CSV import, pattern mining, or SoD analysis)
    to show the governance posture improvement. Ideal for before/after comparisons.

    Args:
        appId: Required. The Okta application ID to assess.

    Returns:
        Formatted governance scorecard with metrics, compliance status, and next steps.
    """
    return await governance.generate_governance_summary({"appId": appId})


def main():
    mcp.run()

if __name__ == "__main__":
    main()
