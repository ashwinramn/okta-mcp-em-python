# Changelog

All notable changes to this project are documented in this file.

## [1.0.0] - 2024-12-11

### 🎉 Initial Public Release

First public release of the Okta MCP Server for Entitlement Management.

### Features

- **15 MCP Tools** for Okta Identity Governance operations
- **Three-stage workflow** for CSV-to-entitlements processing
- **Intelligent rate limiting** with per-endpoint tracking
- **Concurrent batch operations** with semaphore-based control
- **S3 integration** for cloud-based CSV storage
- **Comprehensive error handling** with detailed logging

### Tools Available

| Category | Tools |
|----------|-------|
| Basic | `okta_test`, `list_csv_files`, `read_csv_file`, `move_to_processed`, `sync_s3_files` |
| API | `execute_okta_api_call`, `okta_iga_list_entitlements`, `okta_iga_list_entitlement_values`, `okta_user_search`, `okta_assign_user_to_app`, `okta_iga_create_custom_grant`, `okta_iga_list_grants`, `okta_get_rate_status`, `okta_create_app_attributes` |
| Batch | `okta_batch_user_search`, `okta_batch_assign_users`, `okta_batch_create_grants` |
| Workflow | `analyze_csv_for_entitlements`, `prepare_entitlement_structure`, `execute_user_grants` |

---

## Development History

### Key Technical Discoveries

During development, several critical API requirements were discovered:

#### Entitlement Creation API Structure

The Okta Governance API requires specific field structures:

```python
{
    "parent": {
        "externalId": app_id,  # Must use externalId, not id
        "type": "APPLICATION"   # Must be uppercase
    },
    "values": [...]  # All values in single API call
}
```

#### Grant Creation Requirements

1. Users **must be assigned to the application** before grants can be created
2. Grant structure requires `targetPrincipal` with `type: "OKTA_USER"`
3. Entitlement values must be referenced by ID, not string value
4. Multiple entitlement values for same type must be in single `entitlements` array

#### Application Schema vs Entitlements

Two distinct concepts that were initially confused:

- **Application Attributes**: Simple profile fields (User_ID, Email, etc.)
  - API: `/api/v1/meta/schemas/apps/{appId}/default`
  
- **Entitlements**: Governance features with multiple values (Role, Permission_Set)
  - API: `/governance/api/v1/entitlements`

### Rate Limiting Architecture

Implemented dynamic rate limiting based on Okta's endpoint categories:

| Endpoint Pattern | Limit/min |
|-----------------|-----------|
| `/api/v1/apps` | 100 |
| `/api/v1/apps/{id}` | 500 |
| `/api/v1/users` | 600 |
| `/api/v1/users/{idOrLogin}` | 2,000 |
| `/governance/api/v1` | 1,200 |

Safety threshold: 70% of limit triggers throttling.

### Workflow Evolution

**Initial approach** (problematic):
- Single monolithic function
- No verification between steps
- Failed silently on missing prerequisites

**Final approach** (robust):
1. `analyze_csv_for_entitlements` - Parse and cache
2. `prepare_entitlement_structure` - Create with verification
3. `execute_user_grants` - Assign users, then grant

Each stage validates prerequisites before proceeding.

---

## Lessons Learned

1. **API documentation gaps**: Real-world API behavior sometimes differs from docs
2. **Schema-first**: Application schema attributes must exist before entitlements
3. **Idempotency matters**: Handle "already exists" gracefully (HTTP 409)
4. **Batch with limits**: Concurrent processing needs rate limit awareness
5. **Verification steps**: Always confirm API operations succeeded

---

## Acknowledgments

This project was developed with significant AI assistance using Claude, demonstrating the "vibecoding" approach to software development.
