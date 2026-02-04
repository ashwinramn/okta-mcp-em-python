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
    """Internal function to list entitlements - returns raw data structure."""
    filter_expr = f'parent.externalId eq "{app_id}" AND parent.type eq "APPLICATION"'
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
    """Internal function to create an entitlement definition."""
    url = f"https://{okta_client.domain}/governance/api/v1/entitlements"
    
    body = {
        "name": name,
        "displayName": name,
        "description": description or generate_entitlement_description(name),
        "dataType": "string",
        "parent": {
            "type": "APPLICATION",
            "id": app_id
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
    """Internal function to create an entitlement value."""
    url = f"https://{okta_client.domain}/governance/api/v1/entitlements/{entitlement_id}/values"
    
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
    ent_id = args.get("entitlementId")
    url = f"/governance/api/v1/entitlements/{ent_id}/values"
    
    result = await okta_client.execute_request("GET", url)
    
    if result["success"]:
        return json.dumps(result.get("response", []))
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
    grant_body = args.get("grantBody")
    url = "/governance/api/v1/grants"
    
    result = await okta_client.execute_request("POST", url, body=grant_body)
    
    if result["success"]:
        return f"✅ Successfully created grant\n\n{json.dumps(result['response'], indent=2)}"
    else:
        return (f"❌ Failed to create grant\nHTTP {result['httpCode']}\n\n"
                f"Request Body:\n{json.dumps(grant_body, indent=2)}\n\n"
                f"Error Response:\n{json.dumps(result['response'], indent=2)}")

async def okta_iga_list_grants(args: Dict[str, Any]) -> str:
    filter_expr = args.get("filter")
    url = f"/governance/api/v1/grants?filter={quote(filter_expr)}"
    
    result = await okta_client.execute_request("GET", url)
    
    if result["success"]:
         return f"✅ Successfully retrieved grants\n\n{json.dumps(result['response'], indent=2)}"
    else:
         return f"❌ Failed to list grants\nHTTP {result['httpCode']}\n\n{json.dumps(result['response'], indent=2)}"

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
    
    This is for NON-ENTITLEMENT attributes like:
    - User_ID, Employee_Number (user identifiers)
    - Access_Date, Last_Login (temporal fields)
    - Department, Manager (organizational fields)
    - Status, Active (status flags)
    
    DO NOT use this for entitlements! Entitlements (like Role, Permission_Set) 
    should be created using prepare_entitlement_structure().
    
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

