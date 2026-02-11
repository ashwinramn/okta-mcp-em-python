"""
Menu and Workflow Navigation Tools for Okta Entitlement Manager

Provides:
1. Live-context dashboard with tenant stats
2. Outcome-oriented workflow selection
3. Step-by-step guidance through workflows
"""
import json
import logging
from typing import Dict, Any, List, Optional
from urllib.parse import quote

from client import okta_client

logger = logging.getLogger("okta_mcp")

# ============================================
# Workflow Definitions
# ============================================

WORKFLOWS = {
    "csv_import": {
        "name": "Import CSV → Okta",
        "description": "Import access data from CSV files into Okta as entitlements",
        "steps": [
            {
                "id": "list_files",
                "name": "List CSV Files",
                "tool": "list_csv_files",
                "description": "View available CSV files (syncs from S3 if configured)",
                "prompt": "Which file would you like to process? Enter the filename or number."
            },
            {
                "id": "analyze",
                "name": "Analyze CSV",
                "tool": "analyze_csv_for_entitlements",
                "description": "Analyze the CSV to identify entitlements and users",
                "prompt": "Are these entitlements correct?\n• If YES → Enter the Okta App ID\n• If NO → Provide corrections"
            },
            {
                "id": "prepare",
                "name": "Prepare Structure",
                "tool": "prepare_entitlement_structure",
                "description": "Create the entitlement schema in Okta",
                "prompt": "Review the entitlement structure above. Type 'confirm' to create in Okta."
            },
            {
                "id": "execute",
                "name": "Execute Grants",
                "tool": "execute_user_grants",
                "description": "Assign entitlements to users",
                "prompt": "Ready to assign entitlements to users. Type 'confirm' to proceed."
            },
            {
                "id": "complete",
                "name": "Complete",
                "tool": None,
                "description": "Workflow complete",
                "prompt": "Move CSV to processed folder? (yes/no)\nOr type 'menu' to return to the main menu."
            }
        ]
    },
    "role_discovery": {
        "name": "Discover & Create Roles",
        "description": "Mine patterns, check SoD conflicts, and create access bundles",
        "steps": [
            {
                "id": "get_app",
                "name": "Select Application",
                "tool": None,
                "description": "Choose the application to analyze",
                "prompt": "Enter the Okta App ID to analyze, or type 'search' to find an app."
            },
            {
                "id": "analyze",
                "name": "Analyze Patterns",
                "tool": "analyze_entitlement_patterns",
                "description": "Discover entitlement patterns from user profiles",
                "prompt": "Select a pattern to create a bundle from. Enter the pattern number or ID."
            },
            {
                "id": "preview",
                "name": "Preview Bundle",
                "tool": "preview_bundle_creation",
                "description": "Review the bundle and SoD conflict check before creation",
                "prompt": "Review the bundle preview and SoD check above.\n• Type 'create' to create this bundle\n• Type 'back' to select a different pattern"
            },
            {
                "id": "create",
                "name": "Create Bundle",
                "tool": "create_bundle_from_pattern",
                "description": "Create the SoD-safe bundle in Okta",
                "prompt": "Bundle created! Would you like to:\n• Create another bundle? (type pattern # or ID)\n• Return to menu? (type 'menu')"
            },
            {
                "id": "complete",
                "name": "Complete",
                "tool": None,
                "description": "Workflow complete",
                "prompt": "Type 'menu' to return to the main menu."
            }
        ]
    },
    "sod_enforcement": {
        "name": "Enforce Compliance",
        "description": "Find toxic combinations and create separation of duties rules",
        "steps": [
            {
                "id": "get_app",
                "name": "Select Application",
                "tool": None,
                "description": "Choose the application to analyze for SoD risks",
                "prompt": "Enter the Okta App ID to analyze, or type 'search' to find an app."
            },
            {
                "id": "analyze",
                "name": "Analyze SoD Context",
                "tool": "analyze_sod_context",
                "description": "Gather entitlements and identify toxic combinations",
                "prompt": "Review the analysis above. I'll identify toxic combinations based on ISACA duty segregation and compliance requirements."
            },
            {
                "id": "review",
                "name": "Review Toxic Pairs",
                "tool": None,
                "description": "Review identified toxic combinations",
                "prompt": "Review the toxic combinations above.\n• Type 'create all' to create rules for all identified pairs\n• Type a number to create a rule for a specific pair"
            },
            {
                "id": "create",
                "name": "Create SoD Rules",
                "tool": "create_sod_risk_rule",
                "description": "Create Risk Rules in Okta IGA",
                "prompt": "Rule created. Would you like to:\n• Create the next rule? (type 'next')\n• View created rules? (type 'list')\n• Return to menu? (type 'menu')"
            },
            {
                "id": "complete",
                "name": "Complete",
                "tool": None,
                "description": "SoD analysis complete",
                "prompt": "SoD rules created.\n• Review in Okta Admin → Identity Governance → Risk Rules\n• Type 'menu' to return to the main menu."
            }
        ]
    },
    "governance_report": {
        "name": "Governance Scorecard",
        "description": "Generate a compliance scorecard for an application",
        "steps": [
            {
                "id": "get_app",
                "name": "Select Application",
                "tool": None,
                "description": "Choose the application to assess",
                "prompt": "Enter the Okta App ID to assess."
            },
            {
                "id": "report",
                "name": "Generate Report",
                "tool": "generate_governance_summary",
                "description": "Pull data and score governance posture",
                "prompt": "Report complete. Type 'menu' to return."
            }
        ]
    }
}


# ============================================
# Live Tenant Stats
# ============================================

async def _fetch_tenant_stats() -> Dict[str, Any]:
    """Fetch live stats from the Okta tenant for the dashboard.

    Makes lightweight API calls to populate the menu header.
    Falls back gracefully if any call fails.
    """
    stats = {
        "apps_governed": "?",
        "sod_rules_active": "?",
        "csv_files_ready": "?",
        "entitlement_bundles": "?",
        "users_with_grants": "?",
    }

    # Fetch entitlement count (proxy for "apps governed")
    try:
        ent_url = "/governance/api/v1/entitlements?limit=1"
        ent_result = await okta_client.execute_request("GET", ent_url)
        if ent_result["success"]:
            response = ent_result.get("response", {})
            if isinstance(response, dict):
                # Use metadata total if available, otherwise count parent apps
                metadata = response.get("metadata", {})
                if metadata.get("totalCount") is not None:
                    stats["apps_governed"] = metadata["totalCount"]
                else:
                    data = response.get("data", response)
                    if isinstance(data, list):
                        # Count unique parent app IDs
                        app_ids = set()
                        for e in data:
                            parent = e.get("parent", {})
                            if parent.get("externalId"):
                                app_ids.add(parent["externalId"])
                        stats["apps_governed"] = len(app_ids) if app_ids else len(data)
            elif isinstance(response, list):
                app_ids = set()
                for e in response:
                    parent = e.get("parent", {})
                    if parent.get("externalId"):
                        app_ids.add(parent["externalId"])
                stats["apps_governed"] = len(app_ids) if app_ids else len(response)
    except Exception:
        pass

    # Fetch SoD rules count
    try:
        rules_url = f"https://{okta_client.domain}/governance/api/v1/risk-rules"
        rules_result = await okta_client.execute_request("GET", rules_url)
        if rules_result["success"]:
            response = rules_result.get("response", {})
            rules = response.get("data", response) if isinstance(response, dict) else response
            stats["sod_rules_active"] = len(rules) if isinstance(rules, list) else 0
    except Exception:
        pass

    # Fetch bundle count
    try:
        bundle_url = "/governance/api/v1/entitlement-bundles"
        bundle_result = await okta_client.execute_request("GET", bundle_url)
        if bundle_result["success"]:
            response = bundle_result.get("response", {})
            bundles = response.get("data", response) if isinstance(response, dict) else response
            stats["entitlement_bundles"] = len(bundles) if isinstance(bundles, list) else 0
    except Exception:
        pass

    # Count CSV files ready
    try:
        import os
        csv_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "csv")
        if os.path.isdir(csv_dir):
            csv_count = sum(1 for f in os.listdir(csv_dir) if f.endswith(".csv"))
            stats["csv_files_ready"] = csv_count
    except Exception:
        pass

    return stats


# ============================================
# Menu Formatting
# ============================================

def _format_dashboard(stats: Dict[str, Any]) -> str:
    """Format the main dashboard menu with live tenant stats."""
    domain = okta_client.domain or "unknown"

    menu = f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  OKTA GOVERNANCE AUTOPILOT                              {domain}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  YOUR TENANT                              QUICK STATS
  Apps governed:    {str(stats['apps_governed']):4s}                     SoD rules active:      {str(stats['sod_rules_active']):>4s}
  CSV files ready:  {str(stats['csv_files_ready']):4s}                     Entitlement bundles:   {str(stats['entitlement_bundles']):>4s}

  ──────────────────────────────────────────────────────────────────────────

  [1] MIGRATE LEGACY ACCESS                    CSV --> Entitlements --> Grants
      "I have a spreadsheet of who              Analyze --> Structure --> Grant
       has access in our old system"

  [2] DISCOVER & CREATE ROLES              Patterns --> SoD Check --> Bundles
      "Build role-based access from             Analyze --> Conflict Check
       existing patterns - SoD-safe"             --> Preview --> Create

  [3] ENFORCE COMPLIANCE                         Analysis --> Risk Rules
      "Find toxic combinations and               ISACA + NIST AC-5 + SOX 404
       create separation of duties rules"

  [4] GOVERNANCE SCORECARD                       Full Posture Report
      "How well-governed is this app?            Score 0-100 + Compliance
       Show me what's missing"

  ──────────────────────────────────────────────────────────────────────────
  Select 1-4, or describe what you need in plain English.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
    return menu.strip()


def _format_step_header(workflow_id: str, step_index: int) -> str:
    """Format the step header showing progress."""
    workflow = WORKFLOWS.get(workflow_id)
    if not workflow:
        return ""

    total_steps = len(workflow["steps"])
    step = workflow["steps"][step_index]
    workflow_name = workflow["name"].upper()

    # Build progress indicator
    progress_parts = []
    for i, s in enumerate(workflow["steps"]):
        if i < step_index:
            progress_parts.append("[done]")
        elif i == step_index:
            progress_parts.append("[>>]")
        else:
            progress_parts.append("[ ]")

    progress_bar = " ".join(progress_parts)

    header = f"""
  {workflow_name} - Step {step_index + 1} of {total_steps}: {step['name']}
  {progress_bar}
"""
    return header.strip()


def _format_next_step_prompt(workflow_id: str, step_index: int) -> str:
    """Format the next step prompt."""
    workflow = WORKFLOWS.get(workflow_id)
    if not workflow or step_index >= len(workflow["steps"]):
        return ""

    step = workflow["steps"][step_index]

    lines = [
        f"  NEXT: {step['name']}",
        f"  {step['description']}",
        "",
    ]
    for line in step.get("prompt", "").split("\n"):
        lines.append(f"  {line}")

    return "\n".join(lines)


# ============================================
# MCP Tool Functions
# ============================================

async def show_workflow_menu(args: Dict[str, Any]) -> str:
    """
    Display the main workflow dashboard with live tenant stats.

    Call this after okta_test succeeds to see available workflows.

    Returns:
        The formatted dashboard with workflow options and tenant context.
    """
    stats = await _fetch_tenant_stats()
    menu = _format_dashboard(stats)

    return json.dumps({
        "success": True,
        "menu": menu,
        "tenant_stats": stats,
        "workflows": {
            "1": {
                "id": "csv_import",
                "name": WORKFLOWS["csv_import"]["name"],
                "description": WORKFLOWS["csv_import"]["description"],
                "first_step": "list_csv_files"
            },
            "2": {
                "id": "role_discovery",
                "name": WORKFLOWS["role_discovery"]["name"],
                "description": WORKFLOWS["role_discovery"]["description"],
                "first_step": "Enter App ID or search for app"
            },
            "3": {
                "id": "sod_enforcement",
                "name": WORKFLOWS["sod_enforcement"]["name"],
                "description": WORKFLOWS["sod_enforcement"]["description"],
                "first_step": "analyze_sod_context"
            },
            "4": {
                "id": "governance_report",
                "name": WORKFLOWS["governance_report"]["name"],
                "description": WORKFLOWS["governance_report"]["description"],
                "first_step": "generate_governance_summary"
            }
        },
        "instructions": "Type '1' to import CSV data, '2' to discover and create roles (SoD-safe), '3' to enforce compliance, '4' for a governance scorecard, or describe what you need."
    }, indent=2)


def get_workflow_step(workflow_id: str, step_id: str) -> Optional[Dict[str, Any]]:
    """Get step details by workflow and step ID."""
    workflow = WORKFLOWS.get(workflow_id)
    if not workflow:
        return None

    for i, step in enumerate(workflow["steps"]):
        if step["id"] == step_id:
            return {
                "index": i,
                "step": step,
                "total_steps": len(workflow["steps"]),
                "is_last": i == len(workflow["steps"]) - 1
            }
    return None


def get_next_step(workflow_id: str, current_step_id: str) -> Optional[Dict[str, Any]]:
    """Get the next step in a workflow."""
    workflow = WORKFLOWS.get(workflow_id)
    if not workflow:
        return None

    for i, step in enumerate(workflow["steps"]):
        if step["id"] == current_step_id:
            if i + 1 < len(workflow["steps"]):
                next_step = workflow["steps"][i + 1]
                return {
                    "index": i + 1,
                    "step": next_step,
                    "header": _format_step_header(workflow_id, i + 1),
                    "prompt": next_step.get("prompt", "")
                }
    return None


def format_step_guidance(
    workflow_id: str,
    step_id: str,
    result_summary: str = ""
) -> str:
    """Format guidance output for a workflow step."""
    step_info = get_workflow_step(workflow_id, step_id)
    if not step_info:
        return result_summary

    header = _format_step_header(workflow_id, step_info["index"])

    next_info = get_next_step(workflow_id, step_id)

    output = header + "\n"

    if result_summary:
        output += f"\n{result_summary}\n"

    if next_info:
        output += _format_next_step_prompt(workflow_id, next_info["index"])

    return output
