# Okta API Reference Guide

This document maps the MCP tools to their corresponding Okta API documentation.

## Identity Governance APIs (IGA)

These APIs are for **entitlement management** - managing what access users have to applications.

### Entitlements API
- **Endpoint**: `GET/POST /governance/api/v1/entitlements`
- **Purpose**: Define entitlements (access types) for an application
- **Doc URL**: https://developer.okta.com/docs/api/iga/openapi/governance.api/tag/Entitlements/
- **MCP Tool**: `prepare_entitlement_structure()`
- **Example**: Create "Role" entitlement with values like "Admin", "User", "Viewer"

### Grants API
- **Endpoint**: `POST /governance/api/v1/grants`
- **Purpose**: Assign entitlements to users
- **Doc URL**: https://developer.okta.com/docs/api/iga/openapi/governance.api/tag/Grants/
- **MCP Tool**: `okta_iga_create_custom_grant()`, `execute_user_grants()`
- **Grant Types**:
  - `CUSTOM` - Assign specific entitlements with values
  - `POLICY` - Grant based on policy rules
  - `ENTITLEMENT-BUNDLE` - Grant a bundle of entitlements

### Principal Entitlements API
- **Endpoint**: `GET /governance/api/v1/principal-entitlements`
- **Purpose**: View effective entitlements for a user on a resource
- **Doc URL**: https://developer.okta.com/docs/api/iga/openapi/governance.api/tag/Principal-Entitlements/
- **MCP Tool**: `okta_iga_get_principal_entitlements()`
- **Use Case**: Verify what entitlements a user actually has after grants are applied

## Application Management APIs

These APIs are for **application configuration** - not for entitlements.

### Application Users API
- **Endpoint**: `GET/POST /api/v1/apps/{appId}/users`
- **Purpose**: Assign users to apps, manage app user profiles
- **Doc URL**: https://developer.okta.com/docs/api/openapi/okta-management/management/tag/ApplicationUsers/
- **MCP Tool**: `okta_assign_user_to_app()`, `okta_batch_assign_users()`
- **Profile Attributes**: Things like `userName`, `email`, `User_ID` - NOT entitlements

### Application Grants API (OAuth)
- **Endpoint**: `GET/POST /api/v1/apps/{appId}/grants`
- **Purpose**: Manage OAuth 2.0 scope consent grants for apps
- **Doc URL**: https://developer.okta.com/docs/api/openapi/okta-management/management/tag/ApplicationGrants/
- **NOT for**: User entitlements - this is for OAuth scopes like `okta.users.read`

## Key Distinction

| Concept | API | Purpose |
|---------|-----|---------|
| **Entitlements** | `/governance/api/v1/entitlements` | Define access types (Role, Permission_Set) |
| **Grants** | `/governance/api/v1/grants` | Assign entitlements to users |
| **Principal Entitlements** | `/governance/api/v1/principal-entitlements` | View user's effective entitlements |
| **App User Profile** | `/api/v1/apps/{appId}/users/{userId}` | User attributes sent to app (User_ID, email) |
| **OAuth Grants** | `/api/v1/apps/{appId}/grants` | OAuth scope permissions for the app itself |

## Common Mistakes

❌ **Wrong**: Putting Role/Permission_Set in app user profile
```python
# DON'T DO THIS - entitlements don't belong in app user profile
POST /api/v1/apps/{appId}/users/{userId}
{"profile": {"Role": "Admin"}}  # WRONG!
```

✅ **Correct**: Use Governance Grants API for entitlements
```python
# DO THIS - use IGA Grants API
POST /governance/api/v1/grants
{
    "grantType": "CUSTOM",
    "actor": "ADMIN",  # Who is creating the grant
    "target": {"externalId": "APP_ID", "type": "APPLICATION"},
    "targetPrincipal": {"externalId": "USER_ID", "type": "OKTA_USER"},
    "entitlements": [
        {"id": "ENTITLEMENT_SCHEMA_ID", "values": [{"id": "VALUE_ID"}]}
    ]
}

# Response includes:
{
    "id": "gra17atqzjv6mM17J1d7",  # Grant ID
    "status": "ACTIVE",
    "grantType": "CUSTOM",
    "action": "ALLOW",
    "actor": "ADMIN",
    "targetPrincipalOrn": "orn:oktapreview:directory:ORG_ID:users:USER_ID",
    "targetResourceOrn": "orn:oktapreview:idp:ORG_ID:apps:APP_NAME:APP_ID",
    "entitlements": [{"id": "...", "values": [{"id": "..."}]}],
    "_links": {"self": {"href": "...grants/GRANT_ID"}}
}
```

## Grant API Deep Dive

### Request Fields
| Field | Required | Description |
|-------|----------|-------------|
| `grantType` | ✅ | `CUSTOM`, `POLICY`, or `ENTITLEMENT-BUNDLE` |
| `actor` | ✅ | Who creates the grant: `ADMIN`, `USER`, `SYSTEM` |
| `target` | ✅ | Application: `{externalId: APP_ID, type: "APPLICATION"}` |
| `targetPrincipal` | ✅ | User: `{externalId: USER_ID, type: "OKTA_USER"}` |
| `entitlements` | ✅ | Array of entitlement schemas with values |

### Response Fields
| Field | Description |
|-------|-------------|
| `id` | Unique grant ID (e.g., `gra17atqzjv6mM17J1d7`) |
| `status` | Grant status: `ACTIVE`, `REVOKED`, etc. |
| `action` | `ALLOW` (grant permits access) |
| `targetPrincipalOrn` | Okta Resource Name for user |
| `targetResourceOrn` | Okta Resource Name for app |
| `created` | ISO timestamp of creation |
| `createdBy` | ID of principal who created grant |
| `_links.self.href` | Direct URL to this grant |

### Entitlements Array Structure
```json
"entitlements": [
    {
        "id": "esp17ar5arh0wp3Vr1d7",  // Entitlement Schema ID (Access_Level)
        "values": [
            {"id": "ent17ar5atLo7RTkL1d7"}  // Entitlement Value ID (Approve)
        ]
    },
    {
        "id": "esp17ar5ajlHT0H2U1d7",  // Entitlement Schema ID (Role)
        "values": [
            {"id": "ent17ar5anXF5KOll1d7"}  // Entitlement Value ID (Clerk)
        ]
    }
]
```

### Multiple Entitlements Per Grant
A single grant can include multiple entitlement schemas (e.g., both Role AND Access_Level):
- More efficient (1 API call vs N calls)
- Atomic operation (all or nothing)
- Easier to audit (single grant ID)

## Workflow Summary

1. **Create Entitlements**: `POST /governance/api/v1/entitlements` - Define Role, Permission_Set, etc.
2. **Assign Users to App**: `POST /api/v1/apps/{appId}/users` - Basic app assignment
3. **Grant Entitlements**: `POST /governance/api/v1/grants` - Assign entitlement values to users
4. **Verify**: `GET /governance/api/v1/principal-entitlements` - Check effective entitlements
