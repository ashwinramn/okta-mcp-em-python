"""
Governance Summary Tool for Okta Identity Governance.

Provides a comprehensive governance posture report for an application:
- Entitlement inventory (counts, types, coverage)
- Grant statistics (users, active grants, coverage %)
- SoD rule coverage (rules created, toxic pairs covered vs uncovered)
- Bundle coverage (role-based vs ad-hoc access)
- Compliance readiness scoring against NIST AC-5, SOX 404, SOC2

Designed for hackathon demos: one tool call produces a full governance scorecard.
"""

import json
import logging
import time
from typing import Dict, Any, List

from client import okta_client
from tools.api import _list_entitlements_raw, okta_iga_list_entitlement_values
from tools.app_knowledge import (
    COMPLIANCE_FRAMEWORKS,
    ISACA_TOXIC_PAIRINGS,
    DUTY_CATEGORIES,
    lookup_app_by_name,
)

logger = logging.getLogger("okta_mcp")


async def generate_governance_summary(args: Dict[str, Any]) -> str:
    """
    Generate a comprehensive governance posture report for an application.

    Pulls data from multiple Okta APIs and scores the governance maturity:
    - Entitlement structure completeness
    - User grant coverage
    - SoD rule enforcement
    - Bundle/role-based access adoption
    - Overall compliance readiness

    Args:
        appId: Required. The Okta application ID.

    Returns:
        Formatted governance scorecard with metrics, findings, and recommendations.
    """
    app_id = args.get("appId")

    if not app_id:
        return json.dumps({"status": "ERROR", "error": "appId is required"})

    start_time = time.time()
    report = {
        "app": {},
        "entitlements": {},
        "grants": {},
        "sod": {},
        "bundles": {},
        "compliance": {},
        "score": {},
        "recommendations": [],
    }

    # ── Step 1: Application info ────────────────────────────────────
    app_url = f"/api/v1/apps/{app_id}"
    app_result = await okta_client.execute_request("GET", app_url)

    app_label = "Unknown"
    app_orn = None
    if app_result["success"]:
        app_data = app_result.get("response", {})
        app_label = app_data.get("label", app_data.get("name", "Unknown"))
        app_orn = app_data.get("orn")
        report["app"] = {
            "id": app_id,
            "label": app_label,
            "status": app_data.get("status"),
            "signOnMode": app_data.get("signOnMode"),
            "orn": app_orn,
        }
    else:
        report["app"] = {"id": app_id, "error": "Could not fetch app details"}

    # ── Step 2: Entitlement inventory ───────────────────────────────
    ent_result = await _list_entitlements_raw(app_id)
    entitlements = []
    total_values = 0
    multi_value_count = 0

    if ent_result["success"]:
        entitlements = ent_result.get("data", [])

        for ent in entitlements:
            ent_id = ent.get("id")
            if not ent_id:
                continue
            values_json = await okta_iga_list_entitlement_values({"entitlementId": ent_id})
            try:
                values = json.loads(values_json)
                if isinstance(values, list):
                    total_values += len(values)
            except (json.JSONDecodeError, TypeError):
                pass
            if ent.get("multiValue"):
                multi_value_count += 1

    report["entitlements"] = {
        "total_schemas": len(entitlements),
        "total_values": total_values,
        "multi_value_schemas": multi_value_count,
        "single_value_schemas": len(entitlements) - multi_value_count,
        "entitlement_names": [e.get("name") for e in entitlements],
    }

    # ── Step 3: Grant statistics ────────────────────────────────────
    # Query grants for this app
    from urllib.parse import quote

    grant_filter = f'target.externalId eq "{app_id}" AND target.type eq "APPLICATION"'
    grant_url = f"/governance/api/v1/grants?filter={quote(grant_filter)}"
    grant_result = await okta_client.execute_request("GET", grant_url)

    grants = []
    if grant_result["success"]:
        response = grant_result.get("response", {})
        if isinstance(response, dict) and "data" in response:
            grants = response["data"]
        elif isinstance(response, list):
            grants = response

    active_grants = [g for g in grants if g.get("status") == "ACTIVE"]
    unique_users = set()
    grant_types = {}
    for g in grants:
        principal = g.get("targetPrincipal", {})
        if principal.get("externalId"):
            unique_users.add(principal["externalId"])
        gt = g.get("grantType", "UNKNOWN")
        grant_types[gt] = grant_types.get(gt, 0) + 1

    report["grants"] = {
        "total_grants": len(grants),
        "active_grants": len(active_grants),
        "unique_users_with_grants": len(unique_users),
        "grant_types": grant_types,
    }

    # ── Step 4: SoD rule coverage ───────────────────────────────────
    rules_url = f"https://{okta_client.domain}/governance/api/v1/risk-rules"
    rules_result = await okta_client.execute_request("GET", rules_url)

    sod_rules = []
    if rules_result["success"]:
        response = rules_result.get("response", {})
        all_rules = response.get("data", response) if isinstance(response, dict) else response
        if isinstance(all_rules, list) and app_orn:
            for rule in all_rules:
                resources = rule.get("resources", [])
                for res in resources:
                    if app_id in res.get("resourceOrn", ""):
                        sod_rules.append(rule)
                        break

    # Estimate toxic pair coverage from knowledge base
    kb_match = lookup_app_by_name(app_label)
    known_toxic_pairs = []
    if kb_match:
        known_toxic_pairs = kb_match.get("known_toxic_pairs", [])

    total_possible_toxic_pairs = len(known_toxic_pairs) if known_toxic_pairs else len(ISACA_TOXIC_PAIRINGS)
    covered_pairs = len(sod_rules)

    report["sod"] = {
        "rules_created": len(sod_rules),
        "rule_names": [r.get("name") for r in sod_rules],
        "known_toxic_pairs": len(known_toxic_pairs) if known_toxic_pairs else "N/A (app not in knowledge base)",
        "isaca_toxic_pair_categories": len(ISACA_TOXIC_PAIRINGS),
        "coverage_estimate": f"{min(covered_pairs, total_possible_toxic_pairs)}/{total_possible_toxic_pairs} pairs covered" if total_possible_toxic_pairs > 0 else "No baseline available",
        "knowledge_base_match": kb_match.get("label") if kb_match else None,
    }

    # ── Step 5: Bundle analysis ─────────────────────────────────────
    bundle_url = f"/governance/api/v1/entitlement-bundles?filter={quote(f'resources.externalId eq \"{app_id}\"')}"
    bundle_result = await okta_client.execute_request("GET", bundle_url)

    bundles = []
    if bundle_result["success"]:
        response = bundle_result.get("response", {})
        if isinstance(response, dict) and "data" in response:
            bundles = response["data"]
        elif isinstance(response, list):
            bundles = response

    bundle_grants = sum(1 for g in grants if g.get("grantType") == "ENTITLEMENT-BUNDLE")
    custom_grants = sum(1 for g in grants if g.get("grantType") == "CUSTOM")
    total_grants = len(grants) if grants else 1  # avoid division by zero

    report["bundles"] = {
        "total_bundles": len(bundles),
        "bundle_names": [b.get("name") for b in bundles[:10]],
        "bundle_based_grants": bundle_grants,
        "custom_grants": custom_grants,
        "role_based_access_ratio": f"{(bundle_grants / total_grants * 100):.0f}%" if total_grants > 0 else "0%",
    }

    # ── Step 6: Compliance scoring ──────────────────────────────────
    scores = {}

    # Entitlement Structure Score (0-25)
    ent_score = 0
    if len(entitlements) > 0:
        ent_score += 10  # Has entitlements defined
    if total_values > 0:
        ent_score += 10  # Has values defined
    if multi_value_count > 0:
        ent_score += 5   # Uses multi-value (flexible)
    scores["entitlement_structure"] = ent_score

    # Access Governance Score (0-25)
    access_score = 0
    if len(active_grants) > 0:
        access_score += 10  # Has active grants
    if len(unique_users) >= 3:
        access_score += 5   # Multiple users governed
    if bundle_grants > 0:
        access_score += 10  # Uses role-based bundles
    scores["access_governance"] = access_score

    # SoD Score (0-25)
    sod_score = 0
    if len(sod_rules) > 0:
        sod_score += 10  # Has SoD rules
    if len(sod_rules) >= 3:
        sod_score += 10  # Good SoD coverage
    if kb_match:
        sod_score += 5   # Using known patterns
    scores["sod_enforcement"] = sod_score

    # Operational Maturity Score (0-25)
    ops_score = 0
    if app_orn:
        ops_score += 5   # App properly configured with ORN
    if grant_types.get("CUSTOM", 0) > 0 or grant_types.get("ENTITLEMENT-BUNDLE", 0) > 0:
        ops_score += 10  # Programmatic grant management
    if len(bundles) > 0:
        ops_score += 10  # Bundle-based access management
    scores["operational_maturity"] = ops_score

    total_score = sum(scores.values())
    max_score = 100

    # Grade
    if total_score >= 80:
        grade = "A"
        grade_label = "Excellent"
    elif total_score >= 60:
        grade = "B"
        grade_label = "Good"
    elif total_score >= 40:
        grade = "C"
        grade_label = "Needs Improvement"
    elif total_score >= 20:
        grade = "D"
        grade_label = "Significant Gaps"
    else:
        grade = "F"
        grade_label = "Not Governed"

    report["score"] = {
        "total": total_score,
        "max": max_score,
        "grade": grade,
        "grade_label": grade_label,
        "breakdown": scores,
    }

    # ── Step 7: Recommendations ─────────────────────────────────────
    recs = []

    if len(entitlements) == 0:
        recs.append({
            "priority": "CRITICAL",
            "area": "Entitlements",
            "action": "Define entitlement schemas for this application",
            "impact": "Cannot govern access without entitlement definitions",
            "compliance": "NIST AC-5, SOX 404",
        })

    if len(active_grants) == 0 and len(entitlements) > 0:
        recs.append({
            "priority": "HIGH",
            "area": "Access Grants",
            "action": "Create grants linking users to their entitlements",
            "impact": "Entitlements exist but no users are governed",
            "compliance": "SOC2 CC6.1",
        })

    if len(sod_rules) == 0 and len(entitlements) > 0:
        recs.append({
            "priority": "HIGH",
            "area": "Separation of Duties",
            "action": "Create SoD risk rules to enforce duty segregation",
            "impact": "No toxic combination detection or enforcement",
            "compliance": "NIST AC-5, SOX 404, ISACA SoD",
        })

    if len(bundles) == 0 and len(entitlements) > 0:
        recs.append({
            "priority": "MEDIUM",
            "area": "Role-Based Access",
            "action": "Create entitlement bundles for standardized access patterns",
            "impact": "All access is ad-hoc; no role-based governance",
            "compliance": "NIST AC-2, SOC2 CC6.3",
        })

    if bundle_grants == 0 and custom_grants > 0:
        recs.append({
            "priority": "MEDIUM",
            "area": "Access Standardization",
            "action": "Migrate custom grants to bundle-based grants where possible",
            "impact": f"{custom_grants} custom grants could be consolidated into role bundles",
            "compliance": "SOC2 CC6.1",
        })

    if not kb_match and len(entitlements) > 0:
        recs.append({
            "priority": "LOW",
            "area": "Knowledge Base",
            "action": "Map entitlement values to ISACA duty categories for better SoD analysis",
            "impact": "SoD analysis would be more precise with duty category mappings",
            "compliance": "ISACA SoD Implementation Guide",
        })

    report["recommendations"] = recs

    elapsed = time.time() - start_time

    # ── Build human-readable output ─────────────────────────────────
    lines = [
        "",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        "                    OKTA GOVERNANCE POSTURE REPORT",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        "",
        f"   Application:  {app_label}",
        f"   App ID:       {app_id}",
        f"   Status:       {report['app'].get('status', 'Unknown')}",
        "",
    ]

    # Score banner
    score_bar_filled = int(total_score / max_score * 20)
    score_bar = "[" + "#" * score_bar_filled + "-" * (20 - score_bar_filled) + "]"
    lines.extend([
        "  ╔═══════════════════════════════════════════════════════════════╗",
        f"  ║   GOVERNANCE SCORE:  {total_score}/{max_score}  {score_bar}  Grade: {grade} ({grade_label})",
        "  ╚═══════════════════════════════════════════════════════════════╝",
        "",
    ])

    # Score breakdown
    lines.append("   SCORE BREAKDOWN:")
    lines.append("   ─────────────────────────────────────────────────────────────")
    for category, score in scores.items():
        cat_label = category.replace("_", " ").title()
        bar = "#" * int(score / 25 * 10) + "-" * (10 - int(score / 25 * 10))
        lines.append(f"   {cat_label:25s}  {score:2d}/25  [{bar}]")
    lines.append("")

    # Entitlements
    lines.extend([
        "   ENTITLEMENT INVENTORY",
        "   ─────────────────────────────────────────────────────────────",
        f"   Entitlement Schemas:    {len(entitlements)}",
        f"   Total Values:           {total_values}",
        f"   Multi-Value Schemas:    {multi_value_count}",
    ])
    if entitlements:
        lines.append(f"   Schemas:                {', '.join(e.get('name', '?') for e in entitlements[:5])}")
    lines.append("")

    # Grants
    lines.extend([
        "   ACCESS GRANT STATISTICS",
        "   ─────────────────────────────────────────────────────────────",
        f"   Total Grants:           {len(grants)}",
        f"   Active Grants:          {len(active_grants)}",
        f"   Unique Users Governed:  {len(unique_users)}",
        f"   Grant Types:            {', '.join(f'{k}: {v}' for k, v in grant_types.items()) if grant_types else 'None'}",
    ])
    lines.append("")

    # SoD
    lines.extend([
        "   SEPARATION OF DUTIES",
        "   ─────────────────────────────────────────────────────────────",
        f"   SoD Rules Created:      {len(sod_rules)}",
    ])
    if sod_rules:
        for rule in sod_rules[:5]:
            lines.append(f"     - {rule.get('name', 'Unnamed')}")
    if kb_match:
        lines.append(f"   Knowledge Base Match:   {kb_match.get('label')} (Risk: {kb_match.get('risk_category', 'Unknown')})")
    lines.append(f"   Coverage:               {report['sod']['coverage_estimate']}")
    lines.append("")

    # Bundles
    lines.extend([
        "   ROLE-BASED ACCESS (BUNDLES)",
        "   ─────────────────────────────────────────────────────────────",
        f"   Entitlement Bundles:    {len(bundles)}",
        f"   Bundle-Based Grants:    {bundle_grants}",
        f"   Custom (Ad-Hoc) Grants: {custom_grants}",
        f"   Role-Based Ratio:       {report['bundles']['role_based_access_ratio']}",
    ])
    lines.append("")

    # Compliance readiness
    lines.extend([
        "   COMPLIANCE READINESS",
        "   ─────────────────────────────────────────────────────────────",
    ])
    # NIST AC-5
    nist_status = "PASS" if len(sod_rules) > 0 and len(entitlements) > 0 else "FAIL"
    nist_icon = "PASS" if nist_status == "PASS" else "FAIL"
    lines.append(f"   [{nist_icon}]  NIST AC-5 (Separation of Duties)")
    # SOX 404
    sox_status = "PASS" if len(sod_rules) > 0 and len(active_grants) > 0 else "FAIL"
    sox_icon = "PASS" if sox_status == "PASS" else "FAIL"
    lines.append(f"   [{sox_icon}]  SOX Section 404 (Internal Controls)")
    # SOC2 CC6.1
    soc_status = "PASS" if len(active_grants) > 0 and len(entitlements) > 0 else "FAIL"
    soc_icon = "PASS" if soc_status == "PASS" else "FAIL"
    lines.append(f"   [{soc_icon}]  SOC 2 CC6.1 (Logical Access Controls)")
    # SOC2 CC6.3
    soc3_status = "PASS" if len(bundles) > 0 else "FAIL"
    soc3_icon = "PASS" if soc3_status == "PASS" else "FAIL"
    lines.append(f"   [{soc3_icon}]  SOC 2 CC6.3 (Role-Based Access)")
    lines.append("")

    # Recommendations
    if recs:
        lines.extend([
            "   RECOMMENDATIONS",
            "   ─────────────────────────────────────────────────────────────",
        ])
        for i, rec in enumerate(recs, 1):
            lines.append(f"   {i}. [{rec['priority']}] {rec['action']}")
            lines.append(f"      Impact: {rec['impact']}")
            lines.append(f"      Compliance: {rec['compliance']}")
            lines.append("")

    lines.extend([
        f"   Report generated in {elapsed:.2f}s",
        "",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
    ])

    # Attach the raw data as JSON at the end for LLM consumption
    lines.extend([
        "",
        "RAW DATA (for further analysis):",
        json.dumps(report, indent=2, default=str),
    ])

    return "\n".join(lines)
