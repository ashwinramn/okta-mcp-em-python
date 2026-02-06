# Okta API Reference Guide

This document maps the MCP tools to their corresponding Okta API documentation.

---

## ⚠️ API Documentation Guidelines for Contributors

**IMPORTANT: When creating or modifying any API calls in this codebase:**

1. **Always reference the official Okta API documentation** before implementing
2. **Add API doc URL as a comment** above any API call
3. **Include request/response schema** from the official docs in docstrings
4. **Copy exact field names and types** from the documentation
5. **Test against the actual API** to verify behavior

Example of properly documented API call:
```python
# API Doc: POST /governance/api/v1/entitlements
# https://developer.okta.com/docs/api/iga/openapi/governance.api/tag/Entitlements/#tag/Entitlements/operation/createEntitlement
url = f"https://{domain}/governance/api/v1/entitlements"
body = {
    "name": "Role",
    "externalValue": "role",
    "dataType": "string",  # Per API docs - NOT "string[]"
    "multiValue": True,    # This makes it multi-value
    ...
}
```

---

## Identity Governance APIs (IGA)

These APIs are for **entitlement management** - managing what access users have to applications.

### Entitlements API
- **Endpoint**: `GET/POST /governance/api/v1/entitlements`
- **Purpose**: Define entitlements (access types) for an application
- **Doc URL**: https://developer.okta.com/docs/api/iga/openapi/governance.api/tag/Entitlements/
- **MCP Tool**: `prepare_entitlement_structure()`
- **Example**: Create "Role" entitlement with values like "Admin", "User", "Viewer"

#### Create Entitlement - POST /governance/api/v1/entitlements
```json
// Request Body Schema (from official docs):
{
    "name": "License Entitlement",           // required: string[1..255]
    "externalValue": "license_entitlement",  // required: string[1..255]
    "description": "Some license entitlement", // optional: string[1..1000]
    "parent": {                              // required: object
        "externalId": "0oafxqCAJWWGELFTYASJ", // App ID
        "type": "APPLICATION"
    },
    "multiValue": true,                      // required: boolean
    "dataType": "string",                    // required: string (NOT "string[]")
    "values": [                              // optional: array of value objects
        {
            "name": "value1",
            "description": "description for value1",
            "externalValue": "value_1"
        },
        {
            "name": "value2", 
            "description": "description for value2",
            "externalValue": "value_2"
        }
    ]
}

// Response (201):
{
    "id": "esp2lr1lavoGDYw5U8g6",
    "name": "License Entitlement",
    "externalValue": "license_entitlement",
    "description": "Some license entitlement",
    "parentResourceOrn": "orn:okta:idp:00o11edPwGqbUrsDm0g4:apps:salesforce:0oafxqCAJWWGELFTYASJ",
    "parent": {"externalId": "0oafxqCAJWWGELFTYASJ", "type": "APPLICATION"},
    "multiValue": true,
    "required": false,
    "dataType": "string",
    "values": [
        {"id": "ent148fuJDGTsvYjP0g4", "name": "value1", ...},
        {"id": "ent148gF8aZoRfFsh0g4", "name": "value2", ...}
    ]
}
```

**⚠️ IMPORTANT**: 
- `dataType` is always `"string"` (NOT `"string[]"`)
- `multiValue: true` is what enables multiple values per user
- Per API docs: "If multiValue is true, then the dataType property is set to array" (internally)

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

---

## Entitlement Bundles API

Bundles allow you to group multiple entitlements together for easier assignment.

- **Doc URL**: https://developer.okta.com/docs/api/iga/openapi/governance.api/tag/Entitlement-Bundles/
- **MCP Tools**: `analyze_entitlement_patterns()`, `preview_bundle_creation()`, `create_bundle_from_pattern()`

### Create Entitlement Bundle
```
POST /governance/api/v1/entitlement-bundles

Request Body:
{
    "name": "Engineering Standard Access",
    "description": "Standard entitlements for Engineering department",
    "target": {
        "externalId": "{appId}",
        "type": "APPLICATION"
    },
    "entitlements": [
        {
            "id": "{entitlementSchemaId}",
            "values": [
                {"id": "{entitlementValueId}"}
            ]
        }
    ]
}

Response (201):
{
    "id": "enbo3j1lwErh6dn701d6",
    "name": "Engineering Standard Access",
    "description": "Standard entitlements for Engineering department",
    "orn": "orn:okta:idp:{orgId}:entitlement-bundles:enbo3j1lwErh6dn701d6",
    "status": "ACTIVE",
    "targetResourceOrn": "orn:okta:idp:{orgId}:apps:{appType}:{appId}",
    "target": {"externalId": "{appId}", "type": "APPLICATION"},
    "entitlements": [...],
    "_links": {"self": {"href": "..."}}
}
```

### List Entitlement Bundles
```
GET /governance/api/v1/entitlement-bundles

Query Parameters:
- filter: SCIM filter (e.g., target.externalId eq "{appId}")
- include: "full_entitlements" to include entitlement details
- limit: 1-200 (default 20)
- after: pagination cursor
```

### Grant a Bundle to User
```
POST /governance/api/v1/grants
{
    "grantType": "ENTITLEMENT-BUNDLE",
    "entitlementBundleId": "{bundleId}",
    "actor": "ACCESS_REQUEST",
    "targetPrincipal": {
        "externalId": "{userId}",
        "type": "OKTA_USER"
    }
}
```

---

## Grants API - List Grants (for Pattern Mining)

Used to retrieve all grants for an application to analyze entitlement patterns.

### List All Grants for an Application
```
GET /governance/api/v1/grants?filter={filter}&include=full_entitlements

Required Filter (URL encoded):
filter=target.externalId eq "{appId}" AND target.type eq "APPLICATION"

Query Parameters:
- include: "full_entitlements" - Returns complete entitlement details with names
- limit: 1-200 (default 20)
- after: pagination cursor

Response:
{
    "data": [
        {
            "id": "0ggb0oNGTSWTBKOLGLNR",
            "grantType": "CUSTOM",
            "status": "ACTIVE",
            "targetPrincipal": {
                "externalId": "{userId}",
                "type": "OKTA_USER"
            },
            "targetPrincipalOrn": "orn:okta:directory:{orgId}:users:{userId}",
            "entitlements": [
                {
                    "id": "{entitlementSchemaId}",
                    "name": "Role",
                    "values": [
                        {"id": "{valueId}", "name": "Admin"}
                    ]
                }
            ]
        }
    ],
    "_links": {
        "self": {"href": "..."},
        "next": {"href": "..."}  // If more pages exist
    }
}
```

---

## Application Users API - With User Profile Expansion

Used to get app users with their full Okta profile in a single call.

### List App Users with Embedded User Profiles
```
GET /api/v1/apps/{appId}/users?expand=user&limit=200

Query Parameters:
- expand: "user" - Embeds full Okta user object in _embedded.user
- limit: 1-500 (default 50)
- after: pagination cursor

Response:
[
    {
        "id": "{appUserId}",
        "scope": "USER",
        "status": "PROVISIONED",
        "credentials": {"userName": "user@example.com"},
        "profile": {...},  // App-specific profile
        "_embedded": {
            "user": {
                "id": "{oktaUserId}",
                "status": "ACTIVE",
                "profile": {
                    "login": "user@example.com",
                    "email": "user@example.com",
                    "firstName": "John",
                    "lastName": "Doe",
                    "department": "Engineering",
                    "title": "Senior Engineer",
                    "employeeType": "Full-Time",
                    "costCenter": "CC-1234",
                    "division": "R&D",
                    "organization": "Acme Corp",
                    "manager": "manager@example.com",
                    "employeeNumber": "EMP001",
                    // ... any custom attributes
                }
            }
        }
    }
]
```

**Key Optimization**: Using `expand=user` eliminates the need to make separate 
`GET /api/v1/users/{userId}` calls for each user, dramatically reducing API calls.

---

## Okta Resource Name (ORN) Format

ORNs are used to identify Okta resources in governance APIs.

### ORN Structure
```
orn:{partition}:{service}:{orgId}:{objectType}:{objectId}
```

### Components
| Component | Description | Examples |
|-----------|-------------|----------|
| `partition` | Environment | `okta` (production), `oktapreview` (preview) |
| `service` | Okta service | `directory`, `idp`, `governance` |
| `orgId` | Your org ID | `00o11edPwGqbUrsDm0g4` |
| `objectType` | Resource type | `users`, `apps`, `groups`, `entitlement-bundles` |
| `objectId` | Resource ID | Varies by type |

### Common ORN Patterns
| Resource | ORN Format |
|----------|------------|
| User | `orn:{partition}:directory:{orgId}:users:{userId}` |
| Application | `orn:{partition}:idp:{orgId}:apps:{appType}:{appId}` |
| Group | `orn:{partition}:directory:{orgId}:groups:{groupId}` |
| Entitlement Bundle | `orn:{partition}:governance:{orgId}:entitlement-bundles:{bundleId}` |
| Entitlement Value | `orn:{partition}:governance:{orgId}:entitlement-values:{valueId}` |

### Finding Your Org ID
Call `GET /api/v1/org` or check the Okta Admin Console URL.

### Finding App Type (for ORN)
The app type appears in the Admin Console URL:
- `https://domain-admin.okta.com/admin/app/{appType}/instance/{appId}`
- Examples: `oidc_client`, `salesforce`, `saml_2_0`

---

## Rate Limits Reference

| API Endpoint | Rate Limit | Notes |
|--------------|------------|-------|
| `/api/v1/users` | ~600/min | Standard management API |
| `/api/v1/apps/{appId}/users` | ~600/min | Standard management API |
| `/governance/api/v1/grants` | ~100/min | IGA API - lower limits |
| `/governance/api/v1/entitlements` | ~100/min | IGA API - lower limits |
| `/governance/api/v1/entitlement-bundles` | ~100/min | IGA API - lower limits |

**Best Practices**:
- Use `expand=user` to reduce API calls
- Paginate with maximum `limit` values
- Use parallel execution with backoff for rate limits
- Cache results when analyzing patterns
