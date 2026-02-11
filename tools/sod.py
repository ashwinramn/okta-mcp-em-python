"""
Separation of Duties (SoD) Tools for Okta Identity Governance.

This module provides tools for:
1. Analyzing SoD context for an application (entitlements + knowledge base)
2. Creating SoD Risk Rules via the Okta IGA Risk Rules API

Tools leverage existing entitlement APIs and the app_knowledge knowledge base
to provide structured context for LLM-driven SoD analysis.

API Documentation References:
- Risk Rules API: https://developer.okta.com/docs/api/iga/openapi/governance.api/tag/Risk-Rules/#tag/Risk-Rules/operation/createRiskRule
- Entitlements API: https://developer.okta.com/docs/api/iga/openapi/governance.api/tag/Entitlements/

Key API Learnings:
- type MUST be "SEPARATION_OF_DUTIES"
- resources array is REQUIRED with resourceOrn (app ORN, not app ID)
- conflictCriteria uses ENTITLEMENTS shape with nested structure
- Get app ORN from: GET /api/v1/apps/{appId} -> "orn" field
"""

import json
import logging
from typing import Dict, Any, List, Optional

from client import okta_client
from tools.api import _list_entitlements_raw, okta_iga_list_entitlement_values
from tools.app_knowledge import (
    SUPPORTED_EM_APPS,
    DUTY_CATEGORIES,
    COMPLIANCE_FRAMEWORKS,
    ISACA_TOXIC_PAIRINGS,
    lookup_app_by_name,
    get_duty_for_entitlement,
    get_authoritative_sod_sources,
)

logger = logging.getLogger("okta_mcp")

# =============================================================================
# API Documentation References
# =============================================================================
# These URLs are provided so the LLM can study the API documentation
# and construct correct API calls when needed.

RISK_RULES_API_DOC = "https://developer.okta.com/docs/api/iga/openapi/governance.api/tag/Risk-Rules/#tag/Risk-Rules/operation/createRiskRule"
ENTITLEMENTS_API_DOC = "https://developer.okta.com/docs/api/iga/openapi/governance.api/tag/Entitlements/"

# API Endpoints
RISK_RULES_ENDPOINT = "/governance/api/v1/risk-rules"
RISK_ASSESSMENTS_ENDPOINT = "/governance/api/v1/risk-rule-assessments"


# =============================================================================
# Tool 1: analyze_sod_context
# =============================================================================

async def analyze_sod_context(args: Dict[str, Any]) -> str:
    """
    Gather SoD analysis context for an application.

    This tool collects all information needed for the LLM to analyze
    separation of duties risks:
    - Application info from Okta (including ORN for Risk Rules API)
    - All entitlements and their values WITH THEIR IDs
    - Known toxic patterns from the knowledge base
    - ISACA duty mappings
    - Compliance framework references (NIST, SOX, SOC2)

    The LLM uses this context to:
    1. Map entitlements to duty categories
    2. Identify toxic combinations using ISACA rules
    3. Cross-reference with known patterns for the app type
    4. Recommend SoD rules with compliance justification

    IMPORTANT: The entitlement IDs and app ORN returned here are required
    for creating Risk Rules via create_sod_risk_rule.

    Args:
        appId: Okta application ID

    Returns:
        Structured JSON context for LLM analysis including:
        - app_orn: Required for Risk Rules API
        - entitlement_value_lookup: Maps value names to IDs
    """
    app_id = args.get("appId")

    if not app_id:
        return json.dumps({
            "status": "ERROR",
            "error": "appId is required"
        }, indent=2)

    result = {
        "status": "SUCCESS",
        "appId": app_id,
        "app_orn": None,  # Critical for Risk Rules API
        "app_info": None,
        "entitlements": [],
        "entitlement_value_lookup": {},  # Quick lookup: value_name -> {entitlementId, valueId, names}
        "knowledge_base": None,
        "authoritative_sources": get_authoritative_sod_sources(),
        "duty_categories": DUTY_CATEGORIES,
        "analysis_guidance": [],
        "api_references": {
            "risk_rules_api": RISK_RULES_API_DOC,
            "entitlements_api": ENTITLEMENTS_API_DOC,
            "risk_rules_endpoint": RISK_RULES_ENDPOINT
        }
    }

    # Step 1: Get application info from Okta (including ORN)
    app_url = f"/api/v1/apps/{app_id}"
    app_result = await okta_client.execute_request("GET", app_url)

    if app_result["success"]:
        app_data = app_result.get("response", {})

        # Extract the ORN - critical for Risk Rules API
        app_orn = app_data.get("orn") or app_data.get("_links", {}).get("self", {}).get("href", "")
        result["app_orn"] = app_orn

        result["app_info"] = {
            "id": app_data.get("id"),
            "name": app_data.get("name"),
            "label": app_data.get("label"),
            "status": app_data.get("status"),
            "signOnMode": app_data.get("signOnMode"),
            "created": app_data.get("created"),
            "orn": app_orn  # Include ORN in app_info too
        }

        if app_orn:
            result["analysis_guidance"].append(
                f"App ORN retrieved: {app_orn} (required for Risk Rules)"
            )
        else:
            result["analysis_guidance"].append(
                "WARNING: Could not retrieve app ORN. Risk Rule creation may fail."
            )

        # Try to match to knowledge base by app label/name
        app_label = app_data.get("label", "")
        app_name = app_data.get("name", "")
        kb_match = lookup_app_by_name(app_label) or lookup_app_by_name(app_name)

        if kb_match:
            result["knowledge_base"] = {
                "matched_app": kb_match.get("label"),
                "risk_category": kb_match.get("risk_category"),
                "data_classification": kb_match.get("data_classification"),
                "known_entitlement_types": kb_match.get("okta_entitlements"),
                "duty_mapping": kb_match.get("duty_mapping"),
                "known_toxic_pairs": kb_match.get("known_toxic_pairs"),
                "reference_urls": kb_match.get("reference_urls")
            }
            result["analysis_guidance"].append(
                f"Knowledge base match found: {kb_match.get('label')} "
                f"(Risk: {kb_match.get('risk_category')})"
            )
        else:
            result["analysis_guidance"].append(
                "No knowledge base match found. Use ISACA duty model for analysis."
            )
    else:
        result["app_info"] = {
            "id": app_id,
            "error": "Failed to fetch app details",
            "httpCode": app_result.get("httpCode")
        }

    # Step 2: Get all entitlements for the app
    ent_result = await _list_entitlements_raw(app_id)

    if ent_result["success"]:
        entitlements_data = ent_result.get("data", [])
        result["analysis_guidance"].append(
            f"Found {len(entitlements_data)} entitlement schema(s)"
        )

        # Get values for each entitlement
        for ent in entitlements_data:
            ent_id = ent.get("id")
            ent_name = ent.get("name")

            ent_info = {
                "id": ent_id,
                "name": ent_name,
                "description": ent.get("description"),
                "dataType": ent.get("dataType"),
                "multiValue": ent.get("multiValue"),
                "values": [],
                "duty_mappings": []
            }

            # Fetch values
            if ent_id:
                values_json = await okta_iga_list_entitlement_values({"entitlementId": ent_id})
                try:
                    values = json.loads(values_json)
                    if isinstance(values, list):
                        for val in values:
                            val_id = val.get("id")
                            val_name = val.get("name", val.get("externalValue", ""))
                            val_external = val.get("externalValue", "")

                            val_info = {
                                "id": val_id,
                                "name": val_name,
                                "externalValue": val_external,
                                "description": val.get("description"),
                                "entitlementId": ent_id,
                                "entitlementName": ent_name
                            }

                            # Try to map to duty category from knowledge base
                            if result.get("knowledge_base"):
                                duty_mapping = result["knowledge_base"].get("duty_mapping", {})
                                if val_name in duty_mapping:
                                    val_info["inferred_duty"] = duty_mapping[val_name]
                                    ent_info["duty_mappings"].append({
                                        "value": val_name,
                                        "duty": duty_mapping[val_name]
                                    })

                            ent_info["values"].append(val_info)

                            # Add to quick lookup map (includes names for API)
                            if val_name:
                                result["entitlement_value_lookup"][val_name] = {
                                    "entitlementId": ent_id,
                                    "entitlementName": ent_name,
                                    "valueId": val_id,
                                    "valueName": val_name
                                }
                            if val_external and val_external != val_name:
                                result["entitlement_value_lookup"][val_external] = {
                                    "entitlementId": ent_id,
                                    "entitlementName": ent_name,
                                    "valueId": val_id,
                                    "valueName": val_external
                                }

                except json.JSONDecodeError:
                    ent_info["values_error"] = "Failed to parse values"

            result["entitlements"].append(ent_info)
    else:
        result["entitlements_error"] = ent_result.get("error", "Failed to fetch entitlements")
        result["analysis_guidance"].append("Warning: Could not fetch entitlements")

    # Step 3: Add ISACA toxic pairing rules for reference
    result["isaca_toxic_rules"] = [
        {
            "pair": list(p["pair"]),
            "risk": p["risk"],
            "severity": p["severity"]
        }
        for p in ISACA_TOXIC_PAIRINGS
    ]

    # Step 4: Add analysis instructions for the LLM
    result["llm_instructions"] = """
ANALYSIS STEPS:
1. For each entitlement value, determine its duty category:
   - authorization: Approvals, user management, config changes
   - custody: Data access, asset control, transactions
   - recording: Creating records, reports, logs
   - verification: Auditing, reconciliation, compliance review

2. Identify toxic combinations using ISACA rules:
   - authorization + custody = Embezzlement risk
   - custody + recording = Undetected theft
   - authorization + recording = Fraud concealment
   - Any duty + verification = Detection failure

3. Cross-reference with known_toxic_pairs from knowledge base if available

4. For each identified toxic pair, use entitlement_value_lookup to get:
   - entitlementId and entitlementName
   - valueId and valueName
   - These are ALL required for the Risk Rules API

5. Create Risk Rules using create_sod_risk_rule:
   - The tool will use app_orn and entitlement IDs automatically
   - Default to AUDIT enforcement mode
   - Include compliance justification in description
   - Use notes for short UI-friendly text

IMPORTANT: The Risk Rules API requires:
- app_orn (not app ID) in resources array
- ENTITLEMENTS-shaped conflictCriteria with both IDs and names
- type: "SEPARATION_OF_DUTIES"
"""

    return json.dumps(result, indent=2)


# =============================================================================
# Tool 2: create_sod_risk_rule
# =============================================================================

async def create_sod_risk_rule(args: Dict[str, Any]) -> str:
    """
    Create an Okta IGA Risk Rule for separation of duties enforcement.

    API Documentation: https://developer.okta.com/docs/api/iga/openapi/governance.api/tag/Risk-Rules/#tag/Risk-Rules/operation/createRiskRule

    Endpoint: POST /governance/api/v1/risk-rules
    Required Scope: okta.governance.riskRule.manage

    This tool:
    1. Retrieves the app ORN (required for resources array)
    2. Retrieves all entitlements and values with IDs and names
    3. Resolves value names to the full ENTITLEMENTS structure
    4. Constructs the correct conflictCriteria shape
    5. Creates the Risk Rule

    Args:
        appId: Okta application ID
        ruleName: Name for the SoD rule
        description: Description explaining the risk (longer compliance text)
        notes: Short audit note for UI (what requester sees)
        list1: First list of entitlement values (conflict with list2)
        list2: Second list of entitlement values (conflict with list1)

    Returns:
        JSON result with created rule details or error with fallback guidance
    """
    app_id = args.get("appId")
    rule_name = args.get("ruleName")
    description = args.get("description", "")
    notes = args.get("notes", "")
    list1 = args.get("list1", [])
    list2 = args.get("list2", [])

    # Validation
    errors = []
    if not app_id:
        errors.append("appId is required")
    if not rule_name:
        errors.append("ruleName is required")
    if not list1 or not isinstance(list1, list):
        errors.append("list1 must be a non-empty array of entitlement values")
    if not list2 or not isinstance(list2, list):
        errors.append("list2 must be a non-empty array of entitlement values")

    if errors:
        return json.dumps({
            "status": "VALIDATION_ERROR",
            "errors": errors,
            "api_documentation": RISK_RULES_API_DOC
        }, indent=2)

    # Step 1: Get app info to retrieve ORN
    app_url = f"/api/v1/apps/{app_id}"
    app_result = await okta_client.execute_request("GET", app_url)

    if not app_result["success"]:
        return json.dumps({
            "status": "ERROR",
            "error": "Failed to fetch app details",
            "httpCode": app_result.get("httpCode"),
            "hint": "Cannot create Risk Rule without app ORN"
        }, indent=2)

    app_data = app_result.get("response", {})
    app_orn = app_data.get("orn")

    if not app_orn:
        return json.dumps({
            "status": "ERROR",
            "error": "App ORN not found in app response",
            "hint": "The app may not have an ORN assigned. Check app details.",
            "app_response": app_data
        }, indent=2)

    # Step 2: Get entitlements for the app to resolve value IDs and names
    ent_result = await _list_entitlements_raw(app_id)

    if not ent_result["success"]:
        return json.dumps({
            "status": "ERROR",
            "error": "Failed to fetch entitlements for the application",
            "details": ent_result.get("error"),
            "httpCode": ent_result.get("httpCode"),
            "api_documentation": ENTITLEMENTS_API_DOC
        }, indent=2)

    entitlements = ent_result.get("data", [])

    if not entitlements:
        return json.dumps({
            "status": "ERROR",
            "error": "No entitlements found for this application. "
                     "Entitlements must be defined before creating SoD rules.",
            "api_documentation": ENTITLEMENTS_API_DOC
        }, indent=2)

    # Step 3: Build a map of value name -> full info (including names)
    # Structure: { valueName: { entitlementId, entitlementName, valueId, valueName } }
    value_map: Dict[str, Dict[str, str]] = {}

    for ent in entitlements:
        ent_id = ent.get("id")
        ent_name = ent.get("name")

        if not ent_id:
            continue

        values_json = await okta_iga_list_entitlement_values({"entitlementId": ent_id})
        try:
            values = json.loads(values_json)
            if isinstance(values, list):
                for val in values:
                    val_id = val.get("id")
                    val_name = val.get("name", val.get("externalValue", ""))
                    val_external = val.get("externalValue", "")

                    info = {
                        "entitlementId": ent_id,
                        "entitlementName": ent_name,
                        "valueId": val_id,
                        "valueName": val_name
                    }

                    if val_name:
                        value_map[val_name] = info
                    if val_external and val_external != val_name:
                        value_map[val_external] = info
        except json.JSONDecodeError:
            logger.warning(f"Failed to parse values for entitlement {ent_id}")

    # Step 4: Resolve list1 and list2 values and group by entitlement
    def resolve_and_group(value_names: List[str]) -> tuple:
        """
        Resolve value names and group by entitlement for the ENTITLEMENTS shape.
        Returns: (grouped_entitlements, unresolved_names)

        grouped_entitlements structure:
        {
            entitlementId: {
                "id": entitlementId,
                "name": entitlementName,
                "values": [{"id": valueId, "name": valueName}, ...]
            }
        }
        """
        grouped: Dict[str, Dict] = {}
        unresolved = []

        for name in value_names:
            info = None

            # Try exact match
            if name in value_map:
                info = value_map[name]
            else:
                # Try case-insensitive match
                for key, val_info in value_map.items():
                    if key.lower() == name.lower():
                        info = val_info
                        break

            if info:
                ent_id = info["entitlementId"]
                if ent_id not in grouped:
                    grouped[ent_id] = {
                        "id": ent_id,
                        "name": info["entitlementName"],
                        "values": []
                    }
                grouped[ent_id]["values"].append({
                    "id": info["valueId"],
                    "name": info["valueName"]
                })
            else:
                unresolved.append(name)

        return grouped, unresolved

    list1_grouped, list1_unresolved = resolve_and_group(list1)
    list2_grouped, list2_unresolved = resolve_and_group(list2)

    # Report unresolved values
    if list1_unresolved or list2_unresolved:
        available_values = list(value_map.keys())
        return json.dumps({
            "status": "VALUE_RESOLUTION_ERROR",
            "error": "Some entitlement values could not be found",
            "list1_unresolved": list1_unresolved,
            "list2_unresolved": list2_unresolved,
            "available_values": available_values[:100],
            "hint": "Value names must match exactly. Use analyze_sod_context to see available values.",
            "api_documentation": RISK_RULES_API_DOC
        }, indent=2)

    if not list1_grouped:
        return json.dumps({
            "status": "ERROR",
            "error": "list1 resolved to empty - no valid entitlement values found",
            "api_documentation": RISK_RULES_API_DOC
        }, indent=2)

    if not list2_grouped:
        return json.dumps({
            "status": "ERROR",
            "error": "list2 resolved to empty - no valid entitlement values found",
            "api_documentation": RISK_RULES_API_DOC
        }, indent=2)

    # Step 5: Build the conflictCriteria in ENTITLEMENTS shape
    # This is the correct structure that works with the API
    conflict_criteria = {
        "and": [
            {
                "name": "list1",
                "attribute": "principal.effective_grants",
                "operation": "CONTAINS_ONE",
                "value": {
                    "type": "ENTITLEMENTS",
                    "value": list(list1_grouped.values())
                }
            },
            {
                "name": "list2",
                "attribute": "principal.effective_grants",
                "operation": "CONTAINS_ONE",
                "value": {
                    "type": "ENTITLEMENTS",
                    "value": list(list2_grouped.values())
                }
            }
        ]
    }

    # Step 6: Build the complete Risk Rule request body
    risk_rule_body = {
        "name": rule_name,
        "description": description,
        "type": "SEPARATION_OF_DUTIES",
        "resources": [
            {"resourceOrn": app_orn}
        ],
        "conflictCriteria": conflict_criteria
    }

    # Add notes if provided
    if notes:
        risk_rule_body["notes"] = notes

    # Step 7: Create the Risk Rule via API
    url = f"https://{okta_client.domain}{RISK_RULES_ENDPOINT}"

    logger.info(f"Creating SoD Risk Rule: {rule_name}")
    result = await okta_client.execute_request("POST", url, body=risk_rule_body)

    if result["success"]:
        response = result.get("response", {})
        return json.dumps({
            "status": "SUCCESS",
            "message": f"SoD Risk Rule '{rule_name}' created successfully",
            "rule": {
                "id": response.get("id"),
                "name": response.get("name"),
                "type": response.get("type"),
                "status": response.get("status")
            },
            "full_response": response
        }, indent=2)
    else:
        error_response = result.get("response", {})
        http_code = result.get("httpCode")

        # Build detailed fallback guidance
        fallback_guidance = {
            "status": "API_ERROR",
            "error": f"Risk Rule API call failed with HTTP {http_code}",
            "httpCode": http_code,
            "error_response": error_response,
            "api_documentation": RISK_RULES_API_DOC,
            "app_orn": app_orn,
            "attempted_request_body": risk_rule_body,
            "resolved_data": {
                "list1_entitlements": list(list1_grouped.values()),
                "list2_entitlements": list(list2_grouped.values())
            },
            "llm_fallback_instructions": f"""
The create_sod_risk_rule tool failed. To debug:

1. Check the error_response for specific validation errors.

2. Common issues:
   - 400 missing resources → Verify resourceOrn is correct
   - 400 invalid conflict shape → Check conflictCriteria structure
   - 400 duplicate name → Rule with this name may already exist
   - 500 internal → Retry once, verify entitlement/value IDs

3. The app ORN used: {app_orn}

4. You can use execute_okta_api_call to try a corrected request.
   The resolved entitlement data is in resolved_data above.

5. To verify the rule was created (or find existing rules):
   GET {RISK_RULES_ENDPOINT}?filter=name sw "{rule_name}"
""",
            "endpoint": RISK_RULES_ENDPOINT
        }

        return json.dumps(fallback_guidance, indent=2)


# =============================================================================
# Tool 3: list_sod_risk_rules
# =============================================================================

async def list_sod_risk_rules(args: Dict[str, Any]) -> str:
    """
    List existing SoD Risk Rules for an application.

    API Documentation: https://developer.okta.com/docs/api/iga/openapi/governance.api/tag/Risk-Rules/

    Args:
        appId: Optional - filter by application ID (will convert to ORN filter)
        ruleName: Optional - filter by rule name (uses "sw" startswith)

    Returns:
        JSON list of Risk Rules
    """
    app_id = args.get("appId")
    rule_name = args.get("ruleName")

    url = f"https://{okta_client.domain}{RISK_RULES_ENDPOINT}"

    # Build filter if provided
    filters = []

    if rule_name:
        filters.append(f'name sw "{rule_name}"')

    if filters:
        from urllib.parse import quote
        filter_str = " and ".join(filters)
        url += f"?filter={quote(filter_str)}"

    result = await okta_client.execute_request("GET", url)

    if result["success"]:
        response = result.get("response", {})
        rules = response.get("data", response) if isinstance(response, dict) else response

        # If appId provided, filter results by resourceOrn containing the appId
        if app_id and isinstance(rules, list):
            filtered_rules = []
            for rule in rules:
                resources = rule.get("resources", [])
                for res in resources:
                    if app_id in res.get("resourceOrn", ""):
                        filtered_rules.append(rule)
                        break
            rules = filtered_rules

        return json.dumps({
            "status": "SUCCESS",
            "count": len(rules) if isinstance(rules, list) else 1,
            "rules": rules,
            "api_documentation": RISK_RULES_API_DOC
        }, indent=2)
    else:
        return json.dumps({
            "status": "ERROR",
            "error": "Failed to list Risk Rules",
            "httpCode": result.get("httpCode"),
            "response": result.get("response"),
            "api_documentation": RISK_RULES_API_DOC
        }, indent=2)


# =============================================================================
# Tool 4: get_entitlement_ids_for_values
# =============================================================================

async def get_entitlement_ids_for_values(args: Dict[str, Any]) -> str:
    """
    Resolve entitlement value names to their IDs for use in API calls.

    This helper returns the entitlementId, entitlementName, valueId, and valueName
    for given value names. Use this when constructing Risk Rule API calls.

    Args:
        appId: Okta application ID
        valueNames: List of entitlement value names to resolve

    Returns:
        JSON mapping of value names to their full info (IDs and names)
    """
    app_id = args.get("appId")
    value_names = args.get("valueNames", [])

    if not app_id:
        return json.dumps({
            "status": "ERROR",
            "error": "appId is required"
        }, indent=2)

    if not value_names:
        return json.dumps({
            "status": "ERROR",
            "error": "valueNames is required (list of value names to resolve)"
        }, indent=2)

    # Get app ORN first
    app_url = f"/api/v1/apps/{app_id}"
    app_result = await okta_client.execute_request("GET", app_url)
    app_orn = None
    if app_result["success"]:
        app_orn = app_result.get("response", {}).get("orn")

    # Get entitlements
    ent_result = await _list_entitlements_raw(app_id)

    if not ent_result["success"]:
        return json.dumps({
            "status": "ERROR",
            "error": "Failed to fetch entitlements",
            "httpCode": ent_result.get("httpCode")
        }, indent=2)

    entitlements = ent_result.get("data", [])

    # Build value map
    value_map: Dict[str, Dict[str, str]] = {}

    for ent in entitlements:
        ent_id = ent.get("id")
        ent_name = ent.get("name")

        if not ent_id:
            continue

        values_json = await okta_iga_list_entitlement_values({"entitlementId": ent_id})
        try:
            values = json.loads(values_json)
            if isinstance(values, list):
                for val in values:
                    val_id = val.get("id")
                    val_name = val.get("name", val.get("externalValue", ""))
                    val_external = val.get("externalValue", "")

                    info = {
                        "entitlementId": ent_id,
                        "entitlementName": ent_name,
                        "valueId": val_id,
                        "valueName": val_name
                    }

                    if val_name:
                        value_map[val_name] = info
                    if val_external and val_external != val_name:
                        value_map[val_external] = info
        except json.JSONDecodeError:
            pass

    # Resolve requested values
    resolved = {}
    unresolved = []

    for name in value_names:
        if name in value_map:
            resolved[name] = value_map[name]
        else:
            # Try case-insensitive
            found = False
            for key, val_info in value_map.items():
                if key.lower() == name.lower():
                    resolved[name] = val_info
                    found = True
                    break
            if not found:
                unresolved.append(name)

    return json.dumps({
        "status": "SUCCESS" if not unresolved else "PARTIAL",
        "appId": app_id,
        "appOrn": app_orn,
        "resolved": resolved,
        "unresolved": unresolved,
        "available_values": list(value_map.keys()) if unresolved else None,
        "api_documentation": RISK_RULES_API_DOC,
        "usage_hint": "Use entitlementId/entitlementName and valueId/valueName in the ENTITLEMENTS-shaped conflictCriteria."
    }, indent=2)


# =============================================================================
# Tool 5: test_sod_risk_rule (Risk Assessment)
# =============================================================================

async def test_sod_risk_rule(args: Dict[str, Any]) -> str:
    """
    Test a Risk Rule by running a risk assessment for a user.

    API: POST /governance/api/v1/risk-rule-assessments

    This generates a risk assessment to verify if a rule would detect
    conflicts for a specific user.

    Args:
        userId: Okta user ID to assess
        appId: Optional - filter assessment to specific app

    Returns:
        JSON with risk assessment results
    """
    user_id = args.get("userId")
    app_id = args.get("appId")

    if not user_id:
        return json.dumps({
            "status": "ERROR",
            "error": "userId is required"
        }, indent=2)

    url = f"https://{okta_client.domain}{RISK_ASSESSMENTS_ENDPOINT}"

    body = {
        "principalId": user_id,
        "principalType": "USER"
    }

    if app_id:
        # Get app ORN
        app_url = f"/api/v1/apps/{app_id}"
        app_result = await okta_client.execute_request("GET", app_url)
        if app_result["success"]:
            app_orn = app_result.get("response", {}).get("orn")
            if app_orn:
                body["resourceOrn"] = app_orn

    result = await okta_client.execute_request("POST", url, body=body)

    if result["success"]:
        response = result.get("response", {})
        return json.dumps({
            "status": "SUCCESS",
            "assessment": response,
            "hint": "Check 'violations' array for any SoD conflicts detected."
        }, indent=2)
    else:
        return json.dumps({
            "status": "ERROR",
            "error": "Failed to run risk assessment",
            "httpCode": result.get("httpCode"),
            "response": result.get("response")
        }, indent=2)
