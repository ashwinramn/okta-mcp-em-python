"""
Okta API tools for entitlements, grants, and user management.
"""
import json
import logging
from typing import Dict, Any, List, Tuple
from urllib.parse import quote

from client import okta_client, tracker, RATE_LIMIT_CONFIG

logger = logging.getLogger("okta_mcp")

# ============================================
# Description Generators for Entitlements
# ============================================

def generate_entitlement_description(entitlement_name: str, app_name: str = None) -> str:
    """Generate a meaningful description for an entitlement based on its name."""
    name_clean = entitlement_name.replace("_", " ").replace("-", " ")
    if app_name:
        return f"{name_clean} entitlement for {app_name} access control"
    return f"{name_clean} entitlement for application access control"

def generate_value_description(entitlement_name: str, value_name: str) -> str:
    """Generate a description for an entitlement value."""
    ent_clean = entitlement_name.replace("_", " ").replace("-", " ")
    val_clean = value_name.replace("_", " ").replace("-", " ")
    return f"{val_clean} - {ent_clean} assignment"


# ============================================
# Safe JSON Parsing Helper
# ============================================

def safe_parse_response(response: Any, context: str = "") -> Tuple[bool, Any]:
    """Safely parse API response, handling empty responses and JSON errors."""
    if response is None:
        logger.debug(f"[{context}] Response is None, returning empty list")
        return True, []
    
    if isinstance(response, (list, dict)):
        return True, response
    
    if isinstance(response, str):
        if not response.strip():
            logger.debug(f"[{context}] Empty string response, returning empty list")
            return True, []
        try:
            return True, json.loads(response)
        except json.JSONDecodeError as e:
            logger.error(f"[{context}] JSON parse error: {e}. Raw content: {response[:200]}")
            return False, {"error": f"JSON parse error: {e}", "raw": response[:500]}
    
    return True, response


# ============================================
# Internal API Functions (return raw data)
# ============================================

async def _list_entitlements_raw(app_id: str) -> Dict[str, Any]:
    """
    Internal function to list entitlements - returns raw data structure.
    
    API Doc: https://developer.okta.com/docs/api/iga/openapi/governance.api/tag/Entitlements/#tag/Entitlements/operation/listEntitlements
    Endpoint: GET /governance/api/v1/entitlements
    
    Filter format: parent.externalId eq "{appId}" AND parent.type eq "APPLICATION"
    """
    filter_expr = f'parent.externalId eq "{app_id}" AND parent.type eq "APPLICATION"'
    # API Doc: GET /governance/api/v1/entitlements?filter=...
    url = f"/governance/api/v1/entitlements?filter={quote(filter_expr)}"
    
    result = await okta_client.execute_request("GET", url)
    
    if result["success"]:
        response = result.get("response", [])
        success, data = safe_parse_response(response, f"list_entitlements({app_id})")
        
        if isinstance(data, dict):
            if "data" in data:
                return {"success": True, "data": data["data"], "raw_response": data}
            return {"success": True, "data": [data] if data else [], "raw_response": data}
        elif isinstance(data, list):
            return {"success": True, "data": data, "raw_response": data}
        else:
            return {"success": True, "data": [], "raw_response": data}
    else:
        return {
            "success": False, 
            "data": [], 
            "error": result.get("response", {}).get("errorSummary", "Unknown error"),
            "httpCode": result.get("httpCode")
        }

async def _create_entitlement_raw(app_id: str, name: str, description: str = None, values: List[Dict] = None) -> Dict[str, Any]:
    """
    Internal function to create an entitlement definition.
    
    API Doc: https://developer.okta.com/docs/api/iga/openapi/governance.api/tag/Entitlements/#tag/Entitlements/operation/createEntitlement
    Endpoint: POST /governance/api/v1/entitlements
    
    Request Body Schema (from official docs):
    - name (required): string[1..255] - Display name
    - externalValue (required): string[1..255] - External identifier
    - dataType (required): string - Always "string" (NOT "string[]")
    - multiValue (required): boolean - true for multi-value entitlements
    - parent (required): {externalId: app_id, type: "APPLICATION"}
    - description: string[1..1000]
    - values: Array of {name, description, externalValue}
    
    Note: Per API docs, "If multiValue is true, then the dataType property is set to array" internally.
    """
    # API Doc: POST /governance/api/v1/entitlements
    url = f"https://{okta_client.domain}/governance/api/v1/entitlements"
    
    # Request body per official Okta API documentation
    body = {
        "name": name,
        "externalValue": name,  # Per API docs: required field
        "description": description or generate_entitlement_description(name),
        "dataType": "string",  # Per API docs: always "string", NOT "string[]"
        "multiValue": True,    # Per API docs: this makes it multi-value
        "parent": {
            "type": "APPLICATION",
            "externalId": app_id  # Per API docs: use externalId, not id
        }
    }
    
    if values:
        body["values"] = values
    
    result = await okta_client.execute_request("POST", url, body=body)
    
    if result["success"]:
        return {"success": True, "data": result.get("response", {})}
    else:
        error_msg = "Unknown error"
        if isinstance(result.get("response"), dict):
            error_msg = result["response"].get("errorSummary", str(result["response"]))
        return {
            "success": False,
            "data": {},
            "error": error_msg,
            "httpCode": result.get("httpCode")
        }

async def _create_entitlement_value_raw(entitlement_id: str, value: str, description: str = None, entitlement_name: str = None) -> Dict[str, Any]:
    """
    Internal function to create an entitlement value.
    
    API Doc: https://developer.okta.com/docs/api/iga/openapi/governance.api/tag/Entitlements/#tag/Entitlements/operation/updateEntitlement
    Endpoint: PATCH /governance/api/v1/entitlements/{entitlementId}
    
    Note: Values can also be created during entitlement creation via POST.
    This function uses the update endpoint to add values to existing entitlements.
    
    Value object schema:
    - name: string - Display name for the value
    - externalValue: string - External identifier
    - description: string - Description of the value
    """
    # API Doc: POST to values endpoint (alternative to PATCH)
    url = f"https://{okta_client.domain}/governance/api/v1/entitlements/{entitlement_id}/values"
    
    # Value object per API documentation
    body = {
        "name": value,
        "externalValue": value,
        "description": description or generate_value_description(entitlement_name or "Entitlement", value)
    }
    
    result = await okta_client.execute_request("POST", url, body=body)
    
    if result["success"]:
        return {"success": True, "data": result.get("response", {})}
    else:
        error_msg = "Unknown error"
        if isinstance(result.get("response"), dict):
            error_msg = result["response"].get("errorSummary", str(result["response"]))
        return {
            "success": False,
            "data": {},
            "error": error_msg,
            "httpCode": result.get("httpCode")
        }


# ============================================
# Tool-Facing API Functions (return formatted strings)
# ============================================

async def execute_okta_api_call(args: Dict[str, Any]) -> str:
    method = args.get("method")
    url = args.get("url")
    headers = args.get("headers", {})
    body = args.get("body")
    description = args.get("description")
    
    result = await okta_client.execute_request(method, url, headers, body)
    
    report = f"\n{'='*60}\nAPI CALL RESULT\n{'='*60}\n\n"
    if description:
        report += f"Description: {description}\n"
    report += f"Method: {method}\nURL: {url}\n"
    report += f"HTTP Code: {result['httpCode']}\n"
    report += f"Success: {'✅' if result['success'] else '❌'}\n"
    report += f"\n{'='*60}\n\n"

    if result["success"]:
        report += "✅ RESPONSE:\n\n"
        report += json.dumps(result["response"], indent=2)
    else:
        report += "❌ ERROR RESPONSE:\n\n"
        report += json.dumps(result["response"], indent=2)
        report += f"\n\n{'='*60}\nORIGINAL REQUEST:\n\n"
        req_debug = {
            "method": method, 
            "url": url, 
            "headers": headers, 
            "body": body
        }
        report += json.dumps(req_debug, indent=2)
        
        if result.get("error"):
             report += f"\n\n{'='*60}\nERROR MESSAGE: {result['error']}\n"
        
        report += "\n\n💡 TIP: Consult the Okta Governance API docs to fix the request:\n"
        if '/grants' in url:
            report += "- Grants API: https://developer.okta.com/docs/api/iga/openapi/governance.api/tag/Grants/\n"
        if '/entitlements' in url:
             report += "- Entitlements API: https://developer.okta.com/docs/api/iga/openapi/governance.api/tag/Entitlements/\n"

    report += f"\n{'='*60}\n"
    return report

async def okta_iga_list_entitlements(args: Dict[str, Any]) -> str:
    """List entitlements for an app - returns JSON string for workflow compatibility."""
    app_id = args.get("appId")
    result = await _list_entitlements_raw(app_id)
    
    if result["success"]:
        return json.dumps(result["data"])
    else:
        return json.dumps({"error": result.get("error"), "data": []})

async def okta_iga_list_entitlement_values(args: Dict[str, Any]) -> str:
    """
    List values for an entitlement - handles paginated API response.
    
    API Doc: https://developer.okta.com/docs/api/iga/openapi/governance.api/tag/Entitlements/#tag/Entitlements/operation/listEntitlementValues
    Endpoint: GET /governance/api/v1/entitlements/{entitlementId}/values
    
    Response format: {"data": [...], "_links": {...}, "metadata": {...}}
    """
    ent_id = args.get("entitlementId")
    # API Doc: GET /governance/api/v1/entitlements/{entitlementId}/values
    url = f"/governance/api/v1/entitlements/{ent_id}/values"
    
    result = await okta_client.execute_request("GET", url)
    
    if result["success"]:
        response = result.get("response", [])
        # Handle paginated response: {"data": [...], "_links": {...}}
        if isinstance(response, dict) and "data" in response:
            return json.dumps(response["data"])
        # Handle direct array response
        return json.dumps(response)
    else:
        return json.dumps({"error": result.get("response", {}).get("errorSummary", "Unknown error"), "data": []})

async def okta_user_search(args: Dict[str, Any]) -> str:
    attr = args.get("attribute")
    val = args.get("value")
    search_query = f'profile.{attr} eq "{val}"'
    url = f"/api/v1/users?search={quote(search_query)}"
    
    result = await okta_client.execute_request("GET", url)
    
    if result["success"]:
        users = result["response"]
        if isinstance(users, list) and len(users) > 0:
             return f"✅ Found {len(users)} user(s)\n\n{json.dumps(users, indent=2)}"
        else:
             return f"⚠️ No users found with {attr} = \"{val}\""
    else:
        return f"❌ Failed to search users\nHTTP {result['httpCode']}\n\n{json.dumps(result['response'], indent=2)}"

async def okta_assign_user_to_app(args: Dict[str, Any]) -> str:
    app_id = args.get("appId")
    user_id = args.get("userId")
    url = f"/api/v1/apps/{app_id}/users"
    
    result = await okta_client.execute_request("POST", url, body={"id": user_id})
    
    if result["success"]:
         return f"✅ Successfully assigned user {user_id} to app {app_id}\n\n{json.dumps(result['response'], indent=2)}"
    elif result["httpCode"] == "409":
         return f"⚠️ User {user_id} is already assigned to app {app_id}"
    else:
         return f"❌ Failed to assign user to app\nHTTP {result['httpCode']}\n\n{json.dumps(result['response'], indent=2)}"

async def okta_iga_create_custom_grant(args: Dict[str, Any]) -> str:
    """
    Create a governance grant for a user on an application.
    
    API Doc: https://developer.okta.com/docs/api/iga/openapi/governance.api/tag/Grants/#tag/Grants/operation/createGrant
    
    Grant Types:
    - CUSTOM: Assign specific entitlements with values
    - POLICY: Grant based on policy rules  
    - ENTITLEMENT-BUNDLE: Grant a bundle of entitlements
    
    Args:
        grantBody: The grant request body with structure:
            {
                "grantType": "CUSTOM",
                "target": {"externalId": "APP_ID", "type": "APPLICATION"},
                "targetPrincipal": {"externalId": "USER_ID", "type": "OKTA_USER"},
                "entitlements": [
                    {"id": "ENTITLEMENT_ID", "values": [{"id": "VALUE_ID"}]}
                ]
            }
    
    Expected Success Response:
        {
            "id": "0ggb0oNGTSWTBKOLGLNR",
            "grantType": "CUSTOM",
            "status": "ACTIVE",
            "target": {"externalId": "APP_ID", "type": "APPLICATION"},
            "targetPrincipal": {"externalId": "USER_ID", "type": "OKTA_USER"},
            "entitlements": [...],
            ...
        }
    """
    grant_body = args.get("grantBody")
    url = "/governance/api/v1/grants"
    
    result = await okta_client.execute_request("POST", url, body=grant_body)
    
    if result["success"]:
        response = result["response"]
        grant_id = response.get("id")
        grant_status = response.get("status")
        
        # Validate response per official Okta documentation
        validation_notes = []
        if not grant_id:
            validation_notes.append("⚠️ WARNING: No grant ID in response")
        if grant_status != "ACTIVE":
            validation_notes.append(f"⚠️ WARNING: Grant status is '{grant_status}' (expected 'ACTIVE')")
        
        validation_str = "\n".join(validation_notes) + "\n\n" if validation_notes else ""
        
        return f"✅ Successfully created grant (ID: {grant_id}, Status: {grant_status})\n\n{validation_str}{json.dumps(response, indent=2)}"
    else:
        return (f"❌ Failed to create grant\nHTTP {result['httpCode']}\n\n"
                f"Request Body:\n{json.dumps(grant_body, indent=2)}\n\n"
                f"Error Response:\n{json.dumps(result['response'], indent=2)}")

async def okta_iga_list_grants(args: Dict[str, Any]) -> str:
    """
    List grants for a user/resource.
    
    API Doc: https://developer.okta.com/docs/api/iga/openapi/governance.api/tag/Grants/
    
    Args:
        filter: SCIM filter expression, e.g.:
            target.externalId eq "APP_ID" AND target.type eq "APPLICATION" AND 
            targetPrincipal.externalId eq "USER_ID" AND targetPrincipal.type eq "OKTA_USER"
    """
    filter_expr = args.get("filter")
    url = f"/governance/api/v1/grants?filter={quote(filter_expr)}"
    
    result = await okta_client.execute_request("GET", url)
    
    if result["success"]:
         return f"✅ Successfully retrieved grants\n\n{json.dumps(result['response'], indent=2)}"
    else:
         return f"❌ Failed to list grants\nHTTP {result['httpCode']}\n\n{json.dumps(result['response'], indent=2)}"


async def okta_iga_get_principal_entitlements(args: Dict[str, Any]) -> str:
    """
    Retrieve the effective entitlements for a user on a resource.
    
    This is the API to verify what entitlements a user actually has after 
    all grants are evaluated.
    
    API Doc: https://developer.okta.com/docs/api/iga/openapi/governance.api/tag/Principal-Entitlements/
    
    Args:
        appId: The application ID
        userId: The Okta user ID
    
    Returns:
        List of effective entitlements with their values
    """
    app_id = args.get("appId")
    user_id = args.get("userId")
    
    if not app_id or not user_id:
        return json.dumps({
            "status": "FAILED",
            "error": "Both appId and userId are required"
        })
    
    # Build the filter expression per the API docs
    filter_expr = (
        f'parent.externalId eq "{app_id}" AND parent.type eq "APPLICATION" AND '
        f'targetPrincipal.externalId eq "{user_id}" AND targetPrincipal.type eq "OKTA_USER"'
    )
    url = f"/governance/api/v1/principal-entitlements?filter={quote(filter_expr)}"
    
    result = await okta_client.execute_request("GET", url)
    
    if result["success"]:
        response = result.get("response", {})
        data = response.get("data", []) if isinstance(response, dict) else response
        
        if not data:
            return json.dumps({
                "status": "NO_ENTITLEMENTS",
                "message": f"No effective entitlements found for user {user_id} on app {app_id}",
                "appId": app_id,
                "userId": user_id
            }, indent=2)
        
        # Format the entitlements nicely
        entitlements_summary = []
        for ent in data:
            ent_info = {
                "name": ent.get("name"),
                "id": ent.get("id"),
                "multiValue": ent.get("multiValue", False),
                "values": [
                    {"value": v.get("value"), "displayName": v.get("displayName")}
                    for v in ent.get("values", [])
                ]
            }
            entitlements_summary.append(ent_info)
        
        return json.dumps({
            "status": "SUCCESS",
            "appId": app_id,
            "userId": user_id,
            "entitlementCount": len(entitlements_summary),
            "entitlements": entitlements_summary,
            "raw_response": response
        }, indent=2)
    else:
        return json.dumps({
            "status": "FAILED",
            "error": result.get("response", {}).get("errorSummary", "Unknown error"),
            "httpCode": result.get("httpCode"),
            "appId": app_id,
            "userId": user_id
        }, indent=2)

async def okta_get_rate_status(args: Dict[str, Any]) -> str:
    status = tracker.get_status()
    
    report = f"📊 OKTA API RATE LIMIT STATUS\n{'='*50}\n\n"
    
    conc = status['concurrent']
    report += f"🔄 CONCURRENT REQUESTS:\n   Active: {conc['active']}/{conc['limit']}\n   Available: {conc['available']}\n\n"
    
    stats = status['stats']
    report += f"📈 SESSION STATISTICS:\n   Total Requests: {stats['totalRequests']}\n   Throttled: {stats['throttledRequests']}\n   Rate Limit Hits (429s): {stats['rateLimitHits']}\n   Requests (last minute): {status['requestsLastMinute']}\n\n"
    
    endpoints = status['endpoints']
    if endpoints:
        report += "🎯 ENDPOINT RATE LIMITS:\n"
        for cat, info in endpoints.items():
            emoji = '⚠️' if float(info['percentUsed'].strip('%')) > 50 else '✅'
            report += f"   {emoji} {cat}:\n      Remaining: {info['remaining']}/{info['limit']} ({info['percentUsed']} used)\n      Resets in: {info['resetsIn']}\n"
    else:
        report += "ℹ️ No endpoint rate limits tracked yet.\n   (Limits are captured from API response headers)\n"
    
    report += f"\n💡 Configuration:\n   Safety Threshold: {status['config']['safetyThreshold']*100}%\n   Concurrent Limit: {status['config']['concurrentLimit']}\n   Default Endpoint Limit: {status['config']['defaultLimit']}/min\n"
    
    return report


# ============================================
# Application Schema Management
# ============================================

async def okta_create_app_attributes(args: Dict[str, Any]) -> str:
    """
    Create application profile attributes (custom properties).
    
    API Doc: https://developer.okta.com/docs/api/openapi/okta-management/management/tag/ApplicationUsers/
    
    This is for NON-ENTITLEMENT attributes like:
    - User_ID, Employee_Number (user identifiers)
    - Access_Date, Last_Login (temporal fields)
    - Department, Manager (organizational fields)
    - Status, Active (status flags)
    
    ⚠️ DO NOT use this for entitlements! 
    Entitlements (like Role, Permission_Set) should be created using:
    - prepare_entitlement_structure() which calls /governance/api/v1/entitlements
    
    App user profile attributes are sent to the application during SSO/provisioning.
    Entitlements are managed through Okta Identity Governance for access control.
    
    Args:
        appId: The Okta application ID
        attributes: Dict of attribute definitions, e.g.:
            {
                "User_ID": {"type": "string", "description": "User identifier"},
                "Last_Login": {"type": "string", "description": "Last login date"}
            }
    
    Returns:
        Formatted report of created attributes
    """
    app_id = args.get("appId")
    attributes = args.get("attributes", {})
    
    if not app_id or not attributes:
        return json.dumps({
            "status": "FAILED",
            "error": "Both appId and attributes are required"
        })
    
    # First, get the current schema
    schema_url = f"/api/v1/meta/schemas/apps/{app_id}/default"
    result = await okta_client.execute_request("GET", schema_url)
    
    if not result["success"]:
        return json.dumps({
            "status": "FAILED",
            "error": f"Failed to retrieve app schema: {result.get('response', {}).get('errorSummary', 'Unknown error')}"
        })
    
    current_schema = result.get("response", {})
    existing_custom = current_schema.get("definitions", {}).get("custom", {}).get("properties", {})
    
    # Build the new custom properties
    new_custom_properties = existing_custom.copy()
    
    created = []
    skipped = []
    
    for attr_name, attr_config in attributes.items():
        if attr_name in existing_custom:
            skipped.append(attr_name)
            continue
        
        attr_type = attr_config.get("type", "string")
        attr_desc = attr_config.get("description", f"{attr_name} - Application attribute")
        
        new_custom_properties[attr_name] = {
            "title": attr_name,
            "type": attr_type,
            "scope": "NONE"
        }
        
        if attr_desc:
            new_custom_properties[attr_name]["description"] = attr_desc
        
        created.append(attr_name)
    
    if not created:
        return json.dumps({
            "status": "NO_CHANGES",
            "message": "All requested attributes already exist",
            "existing_attributes": list(existing_custom.keys()),
            "skipped": skipped
        }, indent=2)
    
    # Update the schema with new attributes
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
        return json.dumps({
            "status": "SUCCESS",
            "message": f"✅ Created {len(created)} application attribute(s)",
            "created": created,
            "skipped": skipped,
            "total_attributes": len(new_custom_properties),
            "schema_updated": True
        }, indent=2)
    else:
        error_msg = update_result.get("response", {}).get("errorSummary", "Unknown error")
        return json.dumps({
            "status": "FAILED",
            "error": f"Failed to update schema: {error_msg}",
            "attempted_to_create": created,
            "httpCode": update_result.get("httpCode")
        }, indent=2)

