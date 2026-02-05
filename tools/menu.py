"""
Menu and Workflow Navigation Tools for Okta Entitlement Manager

This module provides:
1. Main workflow menu display
2. Step-by-step guidance through workflows
3. Context-aware next step suggestions
"""
import json
import logging
from typing import Dict, Any, List, Optional

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
                "prompt": "Are these entitlements correct?\n• If YES → Enter the Okta App ID\n• If NO → Provide corrections (e.g., \"Role and Permission are entitlements, Support_Group is not\")"
            },
            {
                "id": "prepare",
                "name": "Prepare Structure",
                "tool": "prepare_entitlement_structure",
                "description": "Create the entitlement schema in Okta",
                "prompt": "Review the entitlement structure above. Type 'confirm' to create in Okta, or describe changes needed."
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
    "bundle_mining": {
        "name": "Mine Patterns → Bundles",
        "description": "Analyze existing entitlements to create access bundles",
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
                "description": "Review the bundle before creation",
                "prompt": "Review the bundle preview above.\n• Type 'create' to create this bundle\n• Type 'edit name: <new name>' to change the name\n• Type 'back' to select a different pattern"
            },
            {
                "id": "create",
                "name": "Create Bundle",
                "tool": "create_bundle_from_pattern",
                "description": "Create the bundle in Okta",
                "prompt": "Bundle created! Would you like to:\n• Create another bundle from this analysis? (type pattern # or ID)\n• Start a new analysis? (type 'new')\n• Return to menu? (type 'menu')"
            },
            {
                "id": "complete",
                "name": "Complete",
                "tool": None,
                "description": "Workflow complete",
                "prompt": "Type 'menu' to return to the main menu."
            }
        ]
    }
}


# ============================================
# Menu Formatting
# ============================================

def _format_main_menu() -> str:
    """Format the main workflow selection menu."""
    menu = """
┌────────────────────────────────────────────────────────────────────────────┐
│                    🎯 OKTA ENTITLEMENT MANAGER                             │
│                                                                            │
│  Choose a workflow:                                                        │
│                                                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ 1️⃣  IMPORT CSV → OKTA                                               │   │
│  │     Import access data from CSV files into Okta as entitlements     │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                            │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ 2️⃣  MINE PATTERNS → BUNDLES                                         │   │
│  │     Analyze existing entitlements to create access bundles          │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                            │
│  Type "1" or "2" to begin, or describe what you want to do.               │
└────────────────────────────────────────────────────────────────────────────┘
"""
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
            progress_parts.append("✅")
        elif i == step_index:
            progress_parts.append("📍")
        else:
            progress_parts.append("⬜")
    
    progress_bar = " ".join(progress_parts)
    
    header = f"""
┌────────────────────────────────────────────────────────────────────────────┐
│  📍 {workflow_name} → Step {step_index + 1} of {total_steps}: {step['name']:<40} │
│  {progress_bar:<70} │
└────────────────────────────────────────────────────────────────────────────┘
"""
    return header.strip()


def _format_next_step_prompt(workflow_id: str, step_index: int) -> str:
    """Format the next step prompt."""
    workflow = WORKFLOWS.get(workflow_id)
    if not workflow or step_index >= len(workflow["steps"]):
        return ""
    
    step = workflow["steps"][step_index]
    next_tool = step.get("tool", "")
    prompt = step.get("prompt", "")
    
    footer = f"""
├────────────────────────────────────────────────────────────────────────────┤
│  ➡️  NEXT STEP: {step['name']:<55} │
│                                                                            │
│  {step['description']:<70} │
│                                                                            │
│  💬 {prompt.split(chr(10))[0]:<68} │"""
    
    # Add additional prompt lines if multi-line
    for line in prompt.split('\n')[1:]:
        footer += f"\n│     {line:<67} │"
    
    footer += """
└────────────────────────────────────────────────────────────────────────────┘"""
    
    return footer


# ============================================
# MCP Tool Functions
# ============================================

async def show_workflow_menu(args: Dict[str, Any]) -> str:
    """
    Display the main workflow menu.
    
    Call this after okta_test succeeds to see available workflows.
    
    Args:
        None required.
    
    Returns:
        The formatted menu with workflow options.
    """
    menu = _format_main_menu()
    
    return json.dumps({
        "success": True,
        "menu": menu,
        "workflows": {
            "1": {
                "id": "csv_import",
                "name": WORKFLOWS["csv_import"]["name"],
                "description": WORKFLOWS["csv_import"]["description"],
                "first_step": "list_csv_files"
            },
            "2": {
                "id": "bundle_mining",
                "name": WORKFLOWS["bundle_mining"]["name"],
                "description": WORKFLOWS["bundle_mining"]["description"],
                "first_step": "Enter App ID or search for app"
            }
        },
        "instructions": "Type '1' to import CSV data, '2' to mine patterns for bundles, or describe what you want to do."
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
    """
    Format guidance output for a workflow step.
    
    Args:
        workflow_id: The workflow identifier
        step_id: Current step ID
        result_summary: Summary of results from the current step
    
    Returns:
        Formatted string with header, results, and next step prompt
    """
    step_info = get_workflow_step(workflow_id, step_id)
    if not step_info:
        return result_summary
    
    header = _format_step_header(workflow_id, step_info["index"])
    
    # Get next step info for the prompt
    next_info = get_next_step(workflow_id, step_id)
    
    output = header + "\n"
    
    if result_summary:
        output += f"\n{result_summary}\n"
    
    if next_info:
        output += _format_next_step_prompt(workflow_id, next_info["index"])
    
    return output
