"""
Bundle Generation Tools for Okta Entitlement Management

This module provides tools for:
1. Analyzing entitlement patterns across users
2. Generating bundle suggestions based on patterns
3. Creating entitlement bundles in Okta

API References:
- Entitlement Bundles: https://developer.okta.com/docs/api/iga/openapi/governance.api/tag/Entitlement-Bundles/
- Grants API: https://developer.okta.com/docs/api/iga/openapi/governance.api/tag/Grants/
- Application Users: https://developer.okta.com/docs/api/openapi/okta-management/management/tag/ApplicationUsers/
"""
import json
import logging
import os
import hashlib
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Optional, Tuple, Set
from urllib.parse import quote
from itertools import combinations
from collections import defaultdict

from client import okta_client

logger = logging.getLogger("okta_mcp")

# ============================================
# Constants
# ============================================

DEFAULT_PROFILE_ATTRIBUTES = ["department", "title", "employeeType", "costCenter"]
DEFAULT_THRESHOLD = 75
PATTERN_STRENGTH_THRESHOLDS = {
    "strong": 90,    # ≥90% - Almost universal
    "moderate": 75,  # 75-89% - Most users
    "weak": 50       # 50-74% - About half
}

# Cache directory
ANALYSIS_CACHE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "csv", "analysis_cache")


# ============================================
# Data Classes
# ============================================

@dataclass
class Pattern:
    """Represents a discovered entitlement pattern."""
    id: str
    attributes: Dict[str, str]  # e.g., {"department": "Engineering"}
    entitlements: Dict[str, List[str]]  # e.g., {"Role": ["Admin", "User"]}
    entitlement_ids: Dict[str, Dict[str, str]]  # Maps name -> {value_name: value_id}
    user_count: int
    total_users: int
    percentage: float
    strength: str  # "strong", "moderate", "weak"
    matching_user_ids: List[str]  # User IDs that match this pattern


# ============================================
# Internal Helpers - Data Fetching
# ============================================

async def _get_app_users_with_profiles(app_id: str) -> Tuple[List[Dict], List[str]]:
    """
    Fetch all app users with embedded Okta profiles using expand=user.
    
    Uses pagination to get all users.
    Returns: (list of user data, list of progress messages)
    
    API: GET /api/v1/apps/{appId}/users?expand=user&limit=200
    """
    progress = []
    all_users = []
    after = None
    page = 0
    limit = 200  # Max allowed
    
    progress.append(f"   📥 Fetching app users with profiles (expand=user)...")
    
    while True:
        page += 1
        url = f"/api/v1/apps/{app_id}/users?expand=user&limit={limit}"
        if after:
            url += f"&after={after}"
        
        result = await okta_client.execute_request("GET", url)
        
        if not result["success"]:
            error_msg = result.get("response", {}).get("errorSummary", str(result.get("response")))
            progress.append(f"   ❌ Failed to fetch app users: {error_msg}")
            return [], progress
        
        users = result.get("response", [])
        if not users:
            break
        
        # Extract user data with embedded profile
        for app_user in users:
            embedded_user = app_user.get("_embedded", {}).get("user", {})
            if embedded_user:
                user_data = {
                    "userId": embedded_user.get("id"),
                    "status": embedded_user.get("status"),
                    "profile": embedded_user.get("profile", {}),
                    "appUserStatus": app_user.get("status"),
                }
                all_users.append(user_data)
        
        progress.append(f"   📄 Page {page}: fetched {len(users)} users (total: {len(all_users)})")
        
        # Check for next page - look for 'after' in Link header or response
        # Okta uses cursor-based pagination
        if len(users) < limit:
            break
        
        # Get the last user's ID as cursor for next page
        after = users[-1].get("id") if users else None
        if not after:
            break
    
    progress.append(f"   ✅ Total users fetched: {len(all_users)}")
    return all_users, progress


async def _get_app_grants_with_entitlements(app_id: str) -> Tuple[List[Dict], List[str]]:
    """
    Fetch all grants for an application with full entitlement details.
    
    Uses pagination and the required filter.
    Returns: (list of grants, list of progress messages)
    
    API: GET /governance/api/v1/grants?filter=...&include=full_entitlements
    """
    progress = []
    all_grants = []
    after = None
    page = 0
    limit = 200  # Max allowed for IGA APIs
    
    # Build filter - must be URL encoded
    filter_expr = f'target.externalId eq "{app_id}" AND target.type eq "APPLICATION"'
    encoded_filter = quote(filter_expr)
    
    progress.append(f"   📥 Fetching grants for app (include=full_entitlements)...")
    
    while True:
        page += 1
        url = f"/governance/api/v1/grants?filter={encoded_filter}&include=full_entitlements&limit={limit}"
        if after:
            url += f"&after={after}"
        
        result = await okta_client.execute_request("GET", url)
        
        if not result["success"]:
            error_msg = result.get("response", {}).get("errorSummary", str(result.get("response")))
            # Check if it's a "no grants found" vs actual error
            if result.get("httpCode") == "404":
                progress.append(f"   ⚠️ No grants found for this application")
                return [], progress
            progress.append(f"   ❌ Failed to fetch grants: {error_msg}")
            return [], progress
        
        response = result.get("response", {})
        
        # Handle paginated response format: {"data": [...], "_links": {...}}
        grants = response.get("data", []) if isinstance(response, dict) else response
        
        if not grants:
            break
        
        # Extract grant data with entitlements
        for grant in grants:
            if grant.get("status") != "ACTIVE":
                continue  # Skip inactive grants
            
            principal = grant.get("targetPrincipal", {})
            user_id = principal.get("externalId")
            
            if not user_id:
                continue
            
            # Extract entitlements with names and IDs
            entitlements = []
            for ent in grant.get("entitlements", []):
                ent_data = {
                    "id": ent.get("id"),
                    "name": ent.get("name"),
                    "values": []
                }
                for val in ent.get("values", []):
                    ent_data["values"].append({
                        "id": val.get("id"),
                        "name": val.get("name") or val.get("externalValue")
                    })
                entitlements.append(ent_data)
            
            grant_data = {
                "grantId": grant.get("id"),
                "userId": user_id,
                "grantType": grant.get("grantType"),
                "entitlements": entitlements
            }
            all_grants.append(grant_data)
        
        progress.append(f"   📄 Page {page}: fetched {len(grants)} grants (total: {len(all_grants)})")
        
        # Check for next page
        links = response.get("_links", {}) if isinstance(response, dict) else {}
        next_link = links.get("next", {}).get("href")
        
        if not next_link or len(grants) < limit:
            break
        
        # Extract after cursor from next link
        if "after=" in next_link:
            after = next_link.split("after=")[1].split("&")[0]
        else:
            break
    
    progress.append(f"   ✅ Total grants fetched: {len(all_grants)}")
    return all_grants, progress


def _join_users_and_grants(
    users: List[Dict], 
    grants: List[Dict]
) -> Tuple[Dict[str, Dict], List[str]]:
    """
    Join user profiles with their entitlements by userId.
    
    Returns: (joined data dict, progress messages)
    
    Structure:
    {
        "userId": {
            "profile": {...},
            "entitlements": {
                "Role": ["Admin", "User"],
                "Permission": ["Read", "Write"]
            },
            "entitlement_ids": {
                "Role": {"Admin": "ent123", "User": "ent456"},
                "Permission": {"Read": "ent789"}
            }
        }
    }
    """
    progress = []
    
    # Build user profile lookup
    user_profiles = {u["userId"]: u["profile"] for u in users if u.get("userId")}
    progress.append(f"   📊 Users with profiles: {len(user_profiles)}")
    
    # Build grants lookup by user
    # Using a regular dict with explicit initialization for type safety
    user_grants: Dict[str, Dict[str, Any]] = {}
    
    for grant in grants:
        user_id = grant.get("userId")
        if not user_id:
            continue
        
        # Initialize user entry if not exists
        if user_id not in user_grants:
            user_grants[user_id] = {
                "entitlements": {},
                "entitlement_ids": {}
            }
        
        for ent in grant.get("entitlements", []):
            ent_name = ent.get("name")
            ent_schema_id = ent.get("id")  # This is the entitlement schema ID
            if not ent_name:
                continue
            
            # Initialize entitlement lists if not exists
            if ent_name not in user_grants[user_id]["entitlements"]:
                user_grants[user_id]["entitlements"][ent_name] = []
                user_grants[user_id]["entitlement_ids"][ent_name] = {}
            
            # Store the schema ID with a special key
            if ent_schema_id:
                user_grants[user_id]["entitlement_ids"][ent_name]["_schema_id"] = ent_schema_id
            
            for val in ent.get("values", []):
                val_name = val.get("name")
                val_id = val.get("id")
                if val_name:
                    if val_name not in user_grants[user_id]["entitlements"][ent_name]:
                        user_grants[user_id]["entitlements"][ent_name].append(val_name)
                    if val_id:
                        user_grants[user_id]["entitlement_ids"][ent_name][val_name] = val_id
    
    progress.append(f"   📊 Users with grants: {len(user_grants)}")
    
    # Join - only include users who have BOTH profile AND grants
    joined = {}
    users_with_both = set(user_profiles.keys()) & set(user_grants.keys())
    
    for user_id in users_with_both:
        joined[user_id] = {
            "profile": user_profiles[user_id],
            "entitlements": dict(user_grants[user_id]["entitlements"]),
            "entitlement_ids": dict(user_grants[user_id]["entitlement_ids"])
        }
    
    users_no_grants = set(user_profiles.keys()) - set(user_grants.keys())
    grants_no_profile = set(user_grants.keys()) - set(user_profiles.keys())
    
    progress.append(f"   ✅ Users with both profile and grants: {len(joined)}")
    if users_no_grants:
        progress.append(f"   ⚠️ Users assigned but no grants: {len(users_no_grants)}")
    if grants_no_profile:
        progress.append(f"   ⚠️ Grants for users not in app: {len(grants_no_profile)}")
    
    return joined, progress


# ============================================
# Internal Helpers - Pattern Analysis
# ============================================

def _calculate_pattern_strength(percentage: float) -> str:
    """Determine pattern strength based on percentage threshold."""
    if percentage >= PATTERN_STRENGTH_THRESHOLDS["strong"]:
        return "strong"
    elif percentage >= PATTERN_STRENGTH_THRESHOLDS["moderate"]:
        return "moderate"
    elif percentage >= PATTERN_STRENGTH_THRESHOLDS["weak"]:
        return "weak"
    return "none"


def _generate_pattern_id(attributes: Dict[str, str]) -> str:
    """Generate a unique, descriptive pattern ID."""
    # Build descriptive part
    parts = []
    for attr, val in sorted(attributes.items()):
        # Sanitize value for ID (remove spaces, special chars)
        safe_val = "".join(c for c in val if c.isalnum())[:20]
        parts.append(f"{attr}_{safe_val}")
    
    descriptive = "_".join(parts)
    
    # Add short hash for uniqueness
    hash_input = json.dumps(attributes, sort_keys=True)
    short_hash = hashlib.md5(hash_input.encode()).hexdigest()[:6]
    
    return f"pattern_{descriptive}_{short_hash}"


def _find_common_entitlements(
    user_ids: List[str],
    joined_data: Dict[str, Dict],
    min_percentage: float
) -> Tuple[Dict[str, List[str]], Dict[str, Dict[str, str]], float]:
    """
    Find entitlements that are common among a set of users.
    
    Uses "has at least" logic - an entitlement value is included if
    at least min_percentage of users have it.
    
    Returns: (common_entitlements, entitlement_ids, min_coverage_percentage)
        entitlement_ids includes "_schema_id" key for each entitlement name
        min_coverage_percentage is the minimum coverage across all entitlement values
    """
    if not user_ids:
        return {}, {}, 0.0
    
    total_users = len(user_ids)
    
    # Count entitlement values across users
    ent_value_counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    ent_value_ids: Dict[str, Dict[str, str]] = defaultdict(dict)
    
    for user_id in user_ids:
        user_data = joined_data.get(user_id, {})
        user_ents = user_data.get("entitlements", {})
        user_ent_ids = user_data.get("entitlement_ids", {})
        
        for ent_name, values in user_ents.items():
            # Capture schema ID (stored with _schema_id key)
            if ent_name in user_ent_ids and "_schema_id" in user_ent_ids[ent_name]:
                ent_value_ids[ent_name]["_schema_id"] = user_ent_ids[ent_name]["_schema_id"]
            
            for val in values:
                ent_value_counts[ent_name][val] += 1
                # Capture the entitlement value ID
                if ent_name in user_ent_ids and val in user_ent_ids[ent_name]:
                    ent_value_ids[ent_name][val] = user_ent_ids[ent_name][val]
    
    # Filter to common entitlements (above threshold)
    common_ents: Dict[str, List[str]] = {}
    common_ent_ids: Dict[str, Dict[str, str]] = {}
    coverage_percentages: List[float] = []
    
    for ent_name, value_counts in ent_value_counts.items():
        common_values = []
        for val, count in value_counts.items():
            percentage = (count / total_users) * 100
            if percentage >= min_percentage:
                common_values.append(val)
                coverage_percentages.append(percentage)
        
        if common_values:
            common_ents[ent_name] = sorted(common_values)
            # Include schema ID and value IDs
            common_ent_ids[ent_name] = {}
            if "_schema_id" in ent_value_ids.get(ent_name, {}):
                common_ent_ids[ent_name]["_schema_id"] = ent_value_ids[ent_name]["_schema_id"]
            for v in common_values:
                if v in ent_value_ids.get(ent_name, {}):
                    common_ent_ids[ent_name][v] = ent_value_ids[ent_name][v]
    
    # Return minimum coverage percentage (conservative estimate of pattern strength)
    min_coverage = min(coverage_percentages) if coverage_percentages else 0.0
    
    return common_ents, common_ent_ids, min_coverage


def _analyze_single_attribute_patterns(
    joined_data: Dict[str, Dict],
    attributes: List[str],
    threshold: float
) -> List[Pattern]:
    """
    Find patterns based on single profile attributes.
    
    Example: department=Engineering → [Role: Admin, Permission: Deploy]
    """
    patterns = []
    total_users = len(joined_data)
    
    if total_users == 0:
        return patterns
    
    for attr in attributes:
        # Group users by attribute value
        attr_groups: Dict[str, List[str]] = defaultdict(list)
        
        for user_id, user_data in joined_data.items():
            profile = user_data.get("profile", {})
            attr_value = profile.get(attr)
            
            if attr_value:  # Skip users without this attribute
                attr_groups[attr_value].append(user_id)
        
        # Analyze each group
        for attr_value, user_ids in attr_groups.items():
            group_size = len(user_ids)
            percentage = (group_size / total_users) * 100
            
            # Skip very small groups (less than 3 users or less than 5% of total)
            if group_size < 3 or percentage < 5:
                continue
            
            # Find common entitlements for this group
            common_ents, ent_ids, coverage_pct = _find_common_entitlements(
                user_ids, joined_data, threshold
            )
            
            if not common_ents:
                continue
            
            # Create pattern
            pattern_attrs = {attr: attr_value}
            pattern = Pattern(
                id=_generate_pattern_id(pattern_attrs),
                attributes=pattern_attrs,
                entitlements=common_ents,
                entitlement_ids=ent_ids,
                user_count=group_size,
                total_users=total_users,
                percentage=round(percentage, 1),
                strength=_calculate_pattern_strength(coverage_pct),
                matching_user_ids=user_ids
            )
            patterns.append(pattern)
    
    return patterns


def _analyze_multi_attribute_patterns(
    joined_data: Dict[str, Dict],
    attributes: List[str],
    threshold: float,
    depth: int = 2
) -> List[Pattern]:
    """
    Find patterns based on combinations of profile attributes.
    
    Example: department=Engineering + title=Senior → [Role: Admin]
    """
    patterns = []
    total_users = len(joined_data)
    
    if total_users == 0 or depth < 2:
        return patterns
    
    # Generate attribute combinations (2 to depth)
    for combo_size in range(2, min(depth + 1, len(attributes) + 1)):
        for attr_combo in combinations(attributes, combo_size):
            # Group users by combination of attribute values
            combo_groups: Dict[tuple, List[str]] = defaultdict(list)
            
            for user_id, user_data in joined_data.items():
                profile = user_data.get("profile", {})
                
                # Get values for all attributes in combo
                combo_values = []
                skip = False
                for attr in attr_combo:
                    val = profile.get(attr)
                    if not val:
                        skip = True
                        break
                    combo_values.append((attr, val))
                
                if not skip:
                    combo_groups[tuple(combo_values)].append(user_id)
            
            # Analyze each group
            for combo_values, user_ids in combo_groups.items():
                group_size = len(user_ids)
                percentage = (group_size / total_users) * 100
                
                # Skip very small groups
                if group_size < 3 or percentage < 3:
                    continue
                
                # Find common entitlements for this group
                common_ents, ent_ids, coverage_pct = _find_common_entitlements(
                    user_ids, joined_data, threshold
                )
                
                if not common_ents:
                    continue
                
                # Create pattern
                pattern_attrs = dict(combo_values)
                pattern = Pattern(
                    id=_generate_pattern_id(pattern_attrs),
                    attributes=pattern_attrs,
                    entitlements=common_ents,
                    entitlement_ids=ent_ids,
                    user_count=group_size,
                    total_users=total_users,
                    percentage=round(percentage, 1),
                    strength=_calculate_pattern_strength(coverage_pct),
                    matching_user_ids=user_ids
                )
                patterns.append(pattern)
    
    return patterns


# ============================================
# Internal Helpers - Caching & Utilities
# ============================================

def _ensure_cache_dir() -> str:
    """Ensure cache directory exists and return path."""
    os.makedirs(ANALYSIS_CACHE_DIR, exist_ok=True)
    return ANALYSIS_CACHE_DIR


def _save_analysis_cache(
    app_id: str,
    app_name: str,
    analysis_data: Dict[str, Any]
) -> str:
    """
    Save analysis results to cache file.
    
    Returns: analysis_id (filename without extension)
    """
    cache_dir = _ensure_cache_dir()
    
    # Create app-specific subdirectory
    app_cache_dir = os.path.join(cache_dir, app_id)
    os.makedirs(app_cache_dir, exist_ok=True)
    
    # Generate analysis ID with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    analysis_id = f"{app_id}_{timestamp}"
    
    # Prepare cache data
    cache_data = {
        "analysis_id": analysis_id,
        "app_id": app_id,
        "app_name": app_name,
        "timestamp": datetime.now().isoformat(),
        "data": analysis_data
    }
    
    # Save to file
    cache_file = os.path.join(app_cache_dir, f"{timestamp}_analysis.json")
    with open(cache_file, "w") as f:
        json.dump(cache_data, f, indent=2, default=str)
    
    logger.info(f"Saved analysis cache: {cache_file}")
    return analysis_id


def _get_cached_analysis(analysis_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve cached analysis by ID.
    
    Returns: cached data or None if not found
    """
    cache_dir = _ensure_cache_dir()
    
    # Parse app_id from analysis_id (format: {app_id}_{timestamp})
    parts = analysis_id.rsplit("_", 2)
    if len(parts) < 3:
        logger.warning(f"Invalid analysis_id format: {analysis_id}")
        return None
    
    app_id = parts[0]
    timestamp = f"{parts[1]}_{parts[2]}"
    
    # Look for cache file
    app_cache_dir = os.path.join(cache_dir, app_id)
    cache_file = os.path.join(app_cache_dir, f"{timestamp}_analysis.json")
    
    if not os.path.exists(cache_file):
        logger.warning(f"Cache file not found: {cache_file}")
        return None
    
    try:
        with open(cache_file, "r") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load cache file: {e}")
        return None


def _generate_bundle_names(app_name: str, pattern: Pattern) -> List[str]:
    """
    Generate suggested bundle names based on pattern attributes.
    
    Returns: List of 3 suggested names
    """
    # Build attribute description - focus on the pattern attributes
    attr_parts = []
    for attr, val in pattern.attributes.items():
        # Use clean value directly for title, add short prefix for others
        attr_short = {
            "department": "Dept",
            "title": "",  # Use value directly
            "employeeType": "Type",
            "costCenter": "CC"
        }.get(attr, attr[:4].capitalize())
        
        clean_val = "".join(c for c in val if c.isalnum() or c in " -")[:25].strip()
        if attr_short:
            attr_parts.append(f"{attr_short} {clean_val}")
        else:
            attr_parts.append(clean_val)
    
    attr_desc = " - ".join(attr_parts)
    
    # Generate cleaner suggestions (no app name, no "Bundle" suffix)
    suggestions = [
        f"{attr_desc} Access",
        f"{attr_desc} Standard",
        f"{attr_desc} Entitlements"
    ]
    
    # Clean up names (remove double dashes/spaces, etc.)
    cleaned = []
    for name in suggestions:
        name = name.replace("--", "-").replace("  ", " ").strip("-").strip()
        cleaned.append(name[:255])  # Okta limit is 255 chars
    
    return cleaned


def _build_bundle_payload(
    app_id: str,
    pattern: Pattern,
    bundle_name: str,
    description: Optional[str] = None,
    app_name: str = ""
) -> Dict[str, Any]:
    """
    Build the API payload for creating an entitlement bundle.
    
    API: POST /governance/api/v1/entitlement-bundles
    """
    # Build entitlements array with IDs
    entitlements_payload = []
    
    for ent_name, values in pattern.entitlements.items():
        ent_ids = pattern.entitlement_ids.get(ent_name, {})
        
        # We need the entitlement schema ID - this is tricky
        # The pattern stores value IDs but we need schema ID too
        # For now, we'll need to look this up or store it during analysis
        
        values_payload = []
        for val in values:
            val_id = ent_ids.get(val)
            if val_id:
                values_payload.append({"id": val_id})
        
        if values_payload:
            # Note: We need entitlement schema ID here
            # This will be populated during analysis
            entitlements_payload.append({
                "id": ent_ids.get("_schema_id", ""),  # Schema ID stored with special key
                "values": values_payload
            })
    
    # Generate description if not provided
    if not description:
        description = _generate_bundle_description(pattern, app_name)
    
    payload = {
        "name": bundle_name,
        "description": description[:1000],  # Okta limit
        "target": {
            "externalId": app_id,
            "type": "APPLICATION"
        },
        "entitlements": entitlements_payload
    }
    
    return payload


def _generate_bundle_description(pattern: Pattern, app_name: str = "") -> str:
    """
    Generate a meaningful bundle description that helps requesters and auditors.
    
    Written in natural language for business users, not IT jargon.
    """
    # Build natural "who" description
    who_parts = []
    for attr, val in pattern.attributes.items():
        if attr == "title":
            who_parts.append(f"{val}s")  # e.g., "Finance Specialists"
        elif attr == "department":
            who_parts.append(f"the {val} department")
        elif attr == "employeeType":
            who_parts.append(f"{val} employees")
        elif attr == "costCenter":
            who_parts.append(f"cost center {val}")
        else:
            who_parts.append(f"{val}")
    
    # Join with natural language
    if len(who_parts) == 1:
        who_desc = who_parts[0]
    elif len(who_parts) == 2:
        who_desc = f"{who_parts[0]} in {who_parts[1]}" if "department" in pattern.attributes else f"{who_parts[0]} and {who_parts[1]}"
    else:
        who_desc = ", ".join(who_parts[:-1]) + f", and {who_parts[-1]}"
    
    # Build natural "what" description - focus on capabilities, not technical names
    access_parts = []
    for ent_name, values in pattern.entitlements.items():
        # Make entitlement names more readable
        ent_readable = ent_name.replace("_", " ")
        if len(values) == 1:
            access_parts.append(f"{values[0]} {ent_readable.lower()}")
        elif len(values) <= 2:
            access_parts.append(f"{' and '.join(values)} {ent_readable.lower()}s")
        else:
            access_parts.append(f"multiple {ent_readable.lower()}s ({', '.join(values[:2])}, etc.)")
    
    # Join access parts naturally
    if len(access_parts) == 1:
        access_desc = access_parts[0]
    elif len(access_parts) == 2:
        access_desc = f"{access_parts[0]} with {access_parts[1]}"
    else:
        access_desc = ", ".join(access_parts[:-1]) + f", and {access_parts[-1]}"
    
    # Build the description
    description = f"Standard access for {who_desc}. Grants {access_desc}."
    
    # Add guidance based on strength
    if pattern.strength == "strong":
        description += " This is the typical access for this role."
    elif pattern.strength == "moderate":
        description += " Most people in this role have this access."
    else:
        description += " Some people in this role have this access."
    
    return description


def _get_app_name(app_id: str) -> str:
    """Get app name from app ID (sync helper for naming)."""
    # This would ideally be fetched from the API
    # For now, return a placeholder that will be updated during analysis
    return f"App-{app_id[:8]}"


# ============================================
# MCP Tool Functions
# ============================================

async def analyze_entitlement_patterns(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze entitlement patterns for an application.
    
    Discovers patterns between user profile attributes and their entitlements.
    For example: "90% of users in department=Engineering have Role=Developer"
    
    Args:
        appId (str): Required. The Okta application ID to analyze.
        profileAttributes (list): Optional. Profile attributes to analyze.
            Default: ["department", "title", "employeeType", "costCenter"]
        threshold (float): Optional. Minimum percentage for pattern inclusion.
            Default: 75. Range: 50-100.
        includeMultiAttribute (bool): Optional. Analyze multi-attribute combinations.
            Default: True.
        multiAttributeDepth (int): Optional. Max attributes to combine.
            Default: 2. Range: 2-3.
    
    Returns:
        Analysis results with discovered patterns, cached for bundle creation.
    """
    # Extract and validate arguments
    app_id = args.get("appId")
    if not app_id:
        return {
            "success": False,
            "error": "Missing required parameter: appId"
        }
    
    profile_attributes = args.get("profileAttributes", DEFAULT_PROFILE_ATTRIBUTES)
    threshold = args.get("threshold", DEFAULT_THRESHOLD)
    include_multi = args.get("includeMultiAttribute", True)
    multi_depth = args.get("multiAttributeDepth", 2)
    
    # Validate threshold
    if not (50 <= threshold <= 100):
        return {
            "success": False,
            "error": f"threshold must be between 50 and 100, got {threshold}"
        }
    
    # Validate depth
    if not (2 <= multi_depth <= 3):
        multi_depth = max(2, min(3, multi_depth))
    
    progress_log = []
    progress_log.append(f"🔍 Starting entitlement pattern analysis for app: {app_id}")
    progress_log.append(f"   📊 Analyzing attributes: {profile_attributes}")
    progress_log.append(f"   📊 Threshold: {threshold}%")
    progress_log.append(f"   📊 Multi-attribute analysis: {include_multi} (depth: {multi_depth})")
    
    try:
        # Step 1: Get app details for naming
        progress_log.append("\n📥 Step 1: Fetching application details...")
        app_result = await okta_client.execute_request("GET", f"/api/v1/apps/{app_id}")
        if not app_result["success"]:
            error_msg = app_result.get("response", {}).get("errorSummary", "Unknown error")
            return {
                "success": False,
                "error": f"Failed to fetch app details: {error_msg}",
                "progress": progress_log
            }
        
        app_data = app_result.get("response", {})
        app_name = app_data.get("label", app_data.get("name", f"App-{app_id[:8]}"))
        progress_log.append(f"   ✅ App: {app_name}")
        
        # Step 2: Fetch users with profiles
        progress_log.append("\n📥 Step 2: Fetching app users with profiles...")
        users, user_progress = await _get_app_users_with_profiles(app_id)
        progress_log.extend(user_progress)
        
        if not users:
            return {
                "success": False,
                "error": "No users found for this application",
                "progress": progress_log
            }
        
        # Step 3: Fetch grants with entitlements
        progress_log.append("\n📥 Step 3: Fetching grants with entitlements...")
        grants, grant_progress = await _get_app_grants_with_entitlements(app_id)
        progress_log.extend(grant_progress)
        
        if not grants:
            return {
                "success": False,
                "error": "No grants found for this application. Ensure the app has entitlements configured.",
                "progress": progress_log
            }
        
        # Step 4: Join users and grants
        progress_log.append("\n📥 Step 4: Joining user profiles with entitlements...")
        joined_data, join_progress = _join_users_and_grants(users, grants)
        progress_log.extend(join_progress)
        
        if not joined_data:
            return {
                "success": False,
                "error": "No users with both profiles and grants found",
                "progress": progress_log
            }
        
        # Step 5: Analyze single-attribute patterns
        progress_log.append("\n🔬 Step 5: Analyzing single-attribute patterns...")
        single_patterns = _analyze_single_attribute_patterns(
            joined_data, profile_attributes, threshold
        )
        progress_log.append(f"   ✅ Found {len(single_patterns)} single-attribute patterns")
        
        # Step 6: Analyze multi-attribute patterns (if enabled)
        multi_patterns = []
        if include_multi:
            progress_log.append(f"\n🔬 Step 6: Analyzing multi-attribute patterns (depth: {multi_depth})...")
            multi_patterns = _analyze_multi_attribute_patterns(
                joined_data, profile_attributes, threshold, multi_depth
            )
            progress_log.append(f"   ✅ Found {len(multi_patterns)} multi-attribute patterns")
        
        # Combine and sort patterns
        all_patterns = single_patterns + multi_patterns
        all_patterns.sort(key=lambda p: (-p.user_count, -p.percentage))
        
        progress_log.append(f"\n✅ Analysis complete! Found {len(all_patterns)} total patterns")
        
        # Step 7: Save to cache
        analysis_data = {
            "app_id": app_id,
            "app_name": app_name,
            "threshold": threshold,
            "profile_attributes": profile_attributes,
            "total_users_analyzed": len(joined_data),
            "total_patterns": len(all_patterns),
            "patterns": [asdict(p) for p in all_patterns],
            "analysis_timestamp": datetime.now().isoformat()
        }
        
        analysis_id = _save_analysis_cache(app_id, app_name, analysis_data)
        progress_log.append(f"   💾 Analysis cached with ID: {analysis_id}")
        
        # Format output
        patterns_output = []
        for i, pattern in enumerate(all_patterns[:20], 1):  # Top 20 patterns
            # Format attributes
            attr_str = " AND ".join(f"{k}={v}" for k, v in pattern.attributes.items())
            
            # Format entitlements
            ent_parts = []
            for ent_name, values in pattern.entitlements.items():
                if len(values) <= 3:
                    ent_parts.append(f"{ent_name}: {', '.join(values)}")
                else:
                    ent_parts.append(f"{ent_name}: {', '.join(values[:3])} (+{len(values)-3} more)")
            ent_str = "; ".join(ent_parts)
            
            # Strength indicator
            strength_emoji = {"strong": "🟢", "moderate": "🟡", "weak": "🟠"}.get(pattern.strength, "⚪")
            
            patterns_output.append({
                "rank": i,
                "pattern_id": pattern.id,
                "attributes": attr_str,
                "entitlements": ent_str,
                "user_count": pattern.user_count,
                "percentage": f"{pattern.percentage}%",
                "strength": f"{strength_emoji} {pattern.strength.capitalize()}"
            })
        
        # Summary stats
        strong_count = sum(1 for p in all_patterns if p.strength == "strong")
        moderate_count = sum(1 for p in all_patterns if p.strength == "moderate")
        weak_count = sum(1 for p in all_patterns if p.strength == "weak")
        
        return {
            "success": True,
            "app_name": app_name,
            "app_id": app_id,
            "analysis_id": analysis_id,
            "summary": {
                "total_users_analyzed": len(joined_data),
                "total_patterns_found": len(all_patterns),
                "strong_patterns": strong_count,
                "moderate_patterns": moderate_count,
                "weak_patterns": weak_count,
                "threshold_used": f"{threshold}%"
            },
            "top_patterns": patterns_output,
            "progress": progress_log,
            "next_steps": [
                f"Use preview_bundle_creation with analysis_id='{analysis_id}' and pattern_id='<pattern_id>' to preview bundle creation",
                f"Use create_bundle_from_pattern to create a bundle from a discovered pattern"
            ]
        }
        
    except Exception as e:
        logger.exception("Error during pattern analysis")
        return {
            "success": False,
            "error": f"Analysis failed: {str(e)}",
            "progress": progress_log
        }


async def preview_bundle_creation(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Preview bundle creation from a discovered pattern (dry run).
    
    Shows exactly what would be created without making any changes.
    
    Args:
        analysisId (str): Required. The analysis ID from analyze_entitlement_patterns.
        patternId (str): Required. The pattern ID to create a bundle from.
        bundleName (str): Optional. Custom name for the bundle.
        description (str): Optional. Custom description for the bundle.
    
    Returns:
        Preview of the bundle that would be created, including the API payload.
    """
    analysis_id = args.get("analysisId")
    pattern_id = args.get("patternId")
    bundle_name = args.get("bundleName")
    description = args.get("description")
    
    if not analysis_id:
        return {
            "success": False,
            "error": "Missing required parameter: analysisId"
        }
    
    if not pattern_id:
        return {
            "success": False,
            "error": "Missing required parameter: patternId"
        }
    
    # Load cached analysis
    cached = _get_cached_analysis(analysis_id)
    if not cached:
        return {
            "success": False,
            "error": f"Analysis not found: {analysis_id}. Run analyze_entitlement_patterns first."
        }
    
    # Get the actual analysis data (stored in 'data' key)
    analysis_data = cached.get("data", cached)  # Fallback to cached if no 'data' key
    
    # Find the pattern
    pattern_data = None
    for p in analysis_data.get("patterns", []):
        if p.get("id") == pattern_id:
            pattern_data = p
            break
    
    if not pattern_data:
        available_patterns = [p.get("id") for p in analysis_data.get("patterns", [])[:10]]
        return {
            "success": False,
            "error": f"Pattern not found: {pattern_id}",
            "available_patterns": available_patterns
        }
    
    # Reconstruct Pattern object
    pattern = Pattern(
        id=pattern_data["id"],
        attributes=pattern_data["attributes"],
        entitlements=pattern_data["entitlements"],
        entitlement_ids=pattern_data["entitlement_ids"],
        user_count=pattern_data["user_count"],
        total_users=pattern_data["total_users"],
        percentage=pattern_data["percentage"],
        strength=pattern_data["strength"],
        matching_user_ids=pattern_data["matching_user_ids"]
    )
    
    app_id = cached.get("app_id")
    app_name = cached.get("app_name", "Application")
    
    if not app_id:
        return {
            "success": False,
            "error": "Cached analysis is missing app_id. Please re-run analyze_entitlement_patterns."
        }
    
    # Generate bundle name suggestions if not provided
    if not bundle_name:
        name_suggestions = _generate_bundle_names(app_name, pattern)
        bundle_name = name_suggestions[0]  # Use first suggestion
    else:
        name_suggestions = [bundle_name]
    
    # Build the payload
    payload = _build_bundle_payload(app_id, pattern, bundle_name, description, app_name)
    
    # Format entitlements for display
    entitlements_display = []
    for ent_name, values in pattern.entitlements.items():
        ent_ids = pattern.entitlement_ids.get(ent_name, {})
        schema_id = ent_ids.get("_schema_id", "N/A")
        
        values_display = []
        for val in values:
            val_id = ent_ids.get(val, "N/A")
            values_display.append(f"  - {val} (ID: {val_id})")
        
        entitlements_display.append({
            "name": ent_name,
            "schema_id": schema_id,
            "values": values_display
        })
    
    # Format attributes for display
    attr_display = " AND ".join(f"{k}={v}" for k, v in pattern.attributes.items())
    
    return {
        "success": True,
        "preview": {
            "bundle_name": bundle_name,
            "description": payload.get("description"),
            "target_app": f"{app_name} ({app_id})",
            "pattern_attributes": attr_display,
            "pattern_strength": pattern.strength,
            "coverage": f"{pattern.user_count} users ({pattern.percentage}%)",
            "entitlements": entitlements_display
        },
        "name_suggestions": name_suggestions,
        "api_payload": payload,
        "api_endpoint": "POST /governance/api/v1/entitlement-bundles",
        "warnings": _get_bundle_warnings(pattern, payload),
        "next_step": f"Use create_bundle_from_pattern with analysisId='{analysis_id}', patternId='{pattern_id}' to create this bundle"
    }


def _get_bundle_warnings(pattern: Pattern, payload: Dict) -> List[str]:
    """Generate warnings about potential issues with bundle creation."""
    warnings = []
    
    # Check for missing entitlement IDs
    for ent in payload.get("entitlements", []):
        if not ent.get("id"):
            warnings.append("⚠️ Missing entitlement schema ID - bundle creation may fail")
            break
        for val in ent.get("values", []):
            if not val.get("id"):
                warnings.append("⚠️ Some entitlement values are missing IDs")
                break
    
    # Warn about weak patterns
    if pattern.strength == "weak":
        warnings.append("⚠️ This is a weak pattern (50-74% coverage) - consider using a stronger pattern")
    
    # Warn about small user groups
    if pattern.user_count < 5:
        warnings.append("⚠️ Small user group - this pattern may not be representative")
    
    return warnings


async def create_bundle_from_pattern(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create an entitlement bundle from a discovered pattern.
    
    This will create a real bundle in Okta. Use preview_bundle_creation first
    to see what will be created.
    
    Args:
        analysisId (str): Required. The analysis ID from analyze_entitlement_patterns.
        patternId (str): Required. The pattern ID to create a bundle from.
        bundleName (str): Required. Name for the bundle.
        description (str): Optional. Description for the bundle.
        confirmCreation (bool): Required. Must be true to confirm bundle creation.
    
    Returns:
        The created bundle details or error information.
    """
    analysis_id = args.get("analysisId")
    pattern_id = args.get("patternId")
    bundle_name = args.get("bundleName")
    description = args.get("description")
    confirm = args.get("confirmCreation", False)
    
    # Validate required parameters
    if not analysis_id:
        return {
            "success": False,
            "error": "Missing required parameter: analysisId"
        }
    
    if not pattern_id:
        return {
            "success": False,
            "error": "Missing required parameter: patternId"
        }
    
    if not bundle_name:
        return {
            "success": False,
            "error": "Missing required parameter: bundleName"
        }
    
    if not confirm:
        return {
            "success": False,
            "error": "Bundle creation requires confirmCreation=true. Use preview_bundle_creation first to review what will be created."
        }
    
    # Load cached analysis
    cached = _get_cached_analysis(analysis_id)
    if not cached:
        return {
            "success": False,
            "error": f"Analysis not found: {analysis_id}. Run analyze_entitlement_patterns first."
        }
    
    # Get the actual analysis data (stored in 'data' key)
    analysis_data = cached.get("data", cached)  # Fallback to cached if no 'data' key
    
    # Find the pattern
    pattern_data = None
    for p in analysis_data.get("patterns", []):
        if p.get("id") == pattern_id:
            pattern_data = p
            break
    
    if not pattern_data:
        return {
            "success": False,
            "error": f"Pattern not found: {pattern_id}"
        }
    
    # Reconstruct Pattern object
    pattern = Pattern(
        id=pattern_data["id"],
        attributes=pattern_data["attributes"],
        entitlements=pattern_data["entitlements"],
        entitlement_ids=pattern_data["entitlement_ids"],
        user_count=pattern_data["user_count"],
        total_users=pattern_data["total_users"],
        percentage=pattern_data["percentage"],
        strength=pattern_data["strength"],
        matching_user_ids=pattern_data["matching_user_ids"]
    )
    
    app_id = cached.get("app_id")
    app_name = cached.get("app_name", "Application")
    
    if not app_id:
        return {
            "success": False,
            "error": "Cached analysis is missing app_id. Please re-run analyze_entitlement_patterns."
        }
    
    # Build the payload
    payload = _build_bundle_payload(app_id, pattern, bundle_name, description, app_name)
    
    # Validate payload has required IDs
    for ent in payload.get("entitlements", []):
        if not ent.get("id"):
            return {
                "success": False,
                "error": "Cannot create bundle: Missing entitlement schema ID. The entitlement data may be incomplete."
            }
        for val in ent.get("values", []):
            if not val.get("id"):
                return {
                    "success": False,
                    "error": "Cannot create bundle: Missing entitlement value ID. The entitlement data may be incomplete."
                }
    
    # Create the bundle
    try:
        result = await okta_client.execute_request(
            "POST",
            "/governance/api/v1/entitlement-bundles",
            {},  # headers
            payload  # body
        )
        
        if not result["success"]:
            error_response = result.get("response", {})
            error_msg = error_response.get("errorSummary", str(error_response))
            return {
                "success": False,
                "error": f"Failed to create bundle: {error_msg}",
                "api_response": error_response
            }
        
        created_bundle = result.get("response", {})
        
        return {
            "success": True,
            "message": f"✅ Bundle '{bundle_name}' created successfully!",
            "bundle": {
                "id": created_bundle.get("id"),
                "name": created_bundle.get("name"),
                "description": created_bundle.get("description"),
                "status": created_bundle.get("status"),
                "target_app": f"{app_name} ({app_id})",
                "entitlements_count": len(created_bundle.get("entitlements", []))
            },
            "pattern_info": {
                "attributes": pattern.attributes,
                "coverage": f"{pattern.user_count} users ({pattern.percentage}%)",
                "strength": pattern.strength
            },
            "api_response": created_bundle
        }
        
    except Exception as e:
        logger.exception("Error creating bundle")
        return {
            "success": False,
            "error": f"Bundle creation failed: {str(e)}"
        }