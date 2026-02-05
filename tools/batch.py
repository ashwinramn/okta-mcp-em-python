"""
Batch Operations for Okta API

All functions return JSON strings that can be parsed by workflow tools.
"""
import json
import logging
from typing import Dict, Any, List
from urllib.parse import quote

from client import okta_client, tracker
from batch import ParallelEngine, BatchedTask

logger = logging.getLogger("okta_mcp")


async def okta_batch_user_search(args: Dict[str, Any]) -> str:
    """Search for multiple Okta users in parallel."""
    searches = args.get("searches", [])
    concurrency = args.get("concurrency", 5)

    if not searches:
        return json.dumps({"error": "'searches' must be a non-empty array", "found": [], "not_found": []})
    
    tasks = []
    for s in searches:
        attr = s.get("attribute", "email")
        val = s.get("value", "")
        
        if not val:
            continue
        
        async def execute_search(attr=attr, val=val):
            search_query = f'profile.{attr} eq "{val}"'
            url = f"/api/v1/users?search={quote(search_query)}"
            result = await okta_client.execute_request("GET", url)
            
            if not result["success"]:
                err_msg = result.get("error") or str(result.get("response", {}))
                raise Exception(f"HTTP {result['httpCode']}: {err_msg}")
            
            users = result["response"]
            if isinstance(users, list) and len(users) > 0:
                u = users[0]
                return {
                     "found": True,
                     "userId": u["id"],
                     "attribute": attr,
                     "value": val,
                     "user": {
                         "id": u["id"],
                         "email": u.get("profile", {}).get("email"),
                         "login": u.get("profile", {}).get("login"),
                         "firstName": u.get("profile", {}).get("firstName"),
                         "lastName": u.get("profile", {}).get("lastName"),
                         "status": u.get("status")
                     }
                }
            else:
                 return {
                     "found": False,
                     "attribute": attr,
                     "value": val
                 }

        tasks.append(BatchedTask(
            id=f"{attr}:{val}",
            execute=execute_search,
            url="/api/v1/users"
        ))

    if not tasks:
        return json.dumps({"found": [], "not_found": [], "errors": [], "summary": "No valid searches"})

    results = await ParallelEngine.execute_parallel(tasks, concurrency=concurrency)
    
    found = []
    not_found = []
    errors = []
    
    for r in results["succeeded"]:
        result_data = r["result"]
        if result_data["found"]:
            found.append({
                "attribute": result_data["attribute"],
                "value": result_data["value"],
                "userId": result_data["userId"],
                "user": result_data["user"]
            })
        else:
            not_found.append({
                "attribute": result_data["attribute"],
                "value": result_data["value"]
            })
    
    for r in results["failed"]:
        parts = r["id"].split(":", 1)
        errors.append({
            "attribute": parts[0] if len(parts) > 0 else "unknown",
            "value": parts[1] if len(parts) > 1 else r["id"],
            "error": r["error"]
        })
    
    return json.dumps({
        "found": found,
        "not_found": not_found,
        "errors": errors,
        "summary": {
            "total": len(searches),
            "found": len(found),
            "not_found": len(not_found),
            "errors": len(errors)
        },
        "timing": {
            "totalDuration": results["totalDuration"],
            "averagePerTask": results["averagePerTask"],
            "throughput": results["throughput"]
        }
    })


async def okta_batch_assign_users(args: Dict[str, Any]) -> str:
    """Assign multiple users to an application in parallel."""
    app_id = args.get("appId")
    user_ids = args.get("userIds", [])
    concurrency = args.get("concurrency", 5)
    
    if not app_id or not user_ids:
        return json.dumps({"error": "'appId' and 'userIds' are required", "assigned": [], "failed": []})

    tasks = []
    
    for uid in user_ids:
        async def execute_assign(user_id=uid):
             url = f"/api/v1/apps/{app_id}/users"
             result = await okta_client.execute_request("POST", url, body={"id": user_id})
             
             if result["success"]:
                 return {"status": "assigned", "userId": user_id}
             elif result["httpCode"] == "409":
                 return {"status": "already_assigned", "userId": user_id}
             else:
                 err = result.get("error") or str(result.get("response"))
                 raise Exception(f"HTTP {result['httpCode']}: {err}")

        tasks.append(BatchedTask(
            id=uid,
            execute=execute_assign,
            url=f"/api/v1/apps/{app_id}/users"
        ))

    results = await ParallelEngine.execute_parallel(tasks, concurrency=concurrency)
    
    assigned = []
    already_assigned = []
    failed = []
    
    for r in results["succeeded"]:
        if r["result"]["status"] == "assigned":
            assigned.append(r["result"]["userId"])
        else:
            already_assigned.append(r["result"]["userId"])
    
    for r in results["failed"]:
        failed.append({"userId": r["id"], "error": r["error"]})
    
    return json.dumps({
        "appId": app_id,
        "assigned": assigned,
        "already_assigned": already_assigned,
        "failed": failed,
        "summary": {
            "total": len(user_ids),
            "assigned": len(assigned),
            "already_assigned": len(already_assigned),
            "failed": len(failed)
        },
        "timing": {
            "totalDuration": results["totalDuration"],
            "throughput": results["throughput"]
        }
    })


async def okta_batch_create_grants(args: Dict[str, Any]) -> str:
    """
    Create multiple governance grants in parallel.
    
    API Doc: https://developer.okta.com/docs/api/iga/openapi/governance.api/tag/Grants/#tag/Grants/operation/createGrant
    
    Expected Response Structure (per official docs):
    {
        "id": "0ggb0oNGTSWTBKOLGLNR",
        "grantType": "CUSTOM",
        "status": "ACTIVE",  # MUST be ACTIVE for success
        "target": {"externalId": "APP_ID", "type": "APPLICATION"},
        "targetPrincipal": {"externalId": "USER_ID", "type": "OKTA_USER"},
        "entitlements": [{"id": "...", "values": [{"id": "..."}]}],
        ...
    }
    """
    grants = args.get("grants", [])
    concurrency = args.get("concurrency", 5)
    
    if not grants:
        return json.dumps({"error": "'grants' must be a non-empty array", "successful": 0, "failed": []})
    
    tasks = []
    
    for i, g in enumerate(grants):
        user_id = g.get("userId")
        body = g.get("grantBody")
        
        if not user_id or not body:
            continue
        
        async def execute_grant(b=body, u=user_id, idx=i):
            url = "/governance/api/v1/grants"
            result = await okta_client.execute_request("POST", url, body=b)
            
            if result["success"]:
                response = result["response"]
                grant_id = response.get("id")
                grant_status = response.get("status")
                
                # Validate response per official documentation
                # A successful grant MUST have an id and status should be ACTIVE
                if not grant_id:
                    e = Exception(f"Grant created but no ID returned. Response: {response}")
                    e.response = response
                    raise e
                
                # Log warning if status is not ACTIVE (but don't fail)
                if grant_status and grant_status != "ACTIVE":
                    logger.warning(f"Grant {grant_id} created with status '{grant_status}' (expected ACTIVE)")
                
                return {
                    "status": "created",
                    "userId": u,
                    "grantId": grant_id,
                    "grantStatus": grant_status,
                    "entitlements": response.get("entitlements", []),
                    "index": idx
                }
            else:
                err = result.get("response", {})
                error_msg = err.get("errorSummary", str(err)) if isinstance(err, dict) else str(err)
                e = Exception(f"HTTP {result['httpCode']}: {error_msg}")
                e.response = err
                raise e
        
        tasks.append(BatchedTask(
            id=f"{user_id}:{i}",
            execute=execute_grant,
            url="/governance/api/v1/grants"
        ))

    if not tasks:
        return json.dumps({"successful": 0, "failed": [], "summary": "No valid grants to create"})

    results = await ParallelEngine.execute_parallel(tasks, concurrency=concurrency)
    
    created = []
    failed = []
    
    for r in results["succeeded"]:
        created.append({
            "userId": r["result"]["userId"],
            "grantId": r["result"]["grantId"],
            "grantStatus": r["result"].get("grantStatus", "UNKNOWN"),
            "entitlements": r["result"].get("entitlements", [])
        })
    
    for r in results["failed"]:
        parts = r["id"].split(":", 1)
        failed.append({
            "userId": parts[0] if parts else r["id"],
            "error": r["error"]
        })
    
    return json.dumps({
        "successful": len(created),
        "created": created,
        "failed": failed,
        "summary": {
            "total": len(grants),
            "successful": len(created),
            "failed": len(failed)
        },
        "timing": {
            "totalDuration": results["totalDuration"],
            "throughput": results["throughput"]
        }
    })
