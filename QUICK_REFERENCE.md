# Quick Reference: Entitlement vs Application Attributes

## The Key Difference

### Application Attributes (Schema Properties)
**What they are**: Simple profile fields stored in the app user profile
**When to use**: For user information, metadata, timestamps, identifiers
**How to create**: Use `okta_create_app_attributes()` tool

**Examples**:
```
✅ User_ID
✅ Email
✅ Employee_Number
✅ Last_Login
✅ Access_Date
✅ Department
✅ Manager
✅ Status
✅ Active
✅ Cost_Center
```

**API**: `/api/v1/meta/schemas/apps/{appId}/default`

---

### Entitlements (Governance Features)
**What they are**: Access control mechanisms with multiple values
**When to use**: For permissions, roles, access levels
**How to create**: Use `prepare_entitlement_structure()` workflow tool

**Examples**:
```
✅ Role (with values: Admin, User, Viewer, etc.)
✅ Permission_Set (with values: READ, WRITE, ADMIN, etc.)
✅ Security_Groups
✅ Access_Level
```

**API**: `/governance/api/v1/entitlements`

---

## The Correct Structure

### Entitlement Type (Column Name)
```
Column: "Role"
```

### Entitlement Values (Rows under that column)
```
Admin
Auditor
Employee
Finance
HR
IT_Ops
Payment Processor
Sales
Security
Viewer
Admin; HR
Auditor; IT_Ops
... (all unique values)
```

### API Call Structure
```json
{
  "app": {"id": "0oaXXX"},
  "attribute": "Role",
  "name": "Role",
  "displayName": "Role",
  "externalValue": "Role",
  "dataType": "string",
  "multiValue": false,
  "description": "Generated description",
  "parent": {
    "externalId": "0oaXXX",
    "type": "APPLICATION"
  },
  "values": [
    {
      "name": "Admin",
      "displayName": "Admin",
      "externalValue": "Admin",
      "description": "Generated description"
    },
    {
      "name": "Auditor",
      "displayName": "Auditor",
      "externalValue": "Auditor",
      "description": "Generated description"
    }
    // ... ALL other values
  ]
}
```

---

## Workflow Order

1. **Analyze CSV**: `analyze_csv_for_entitlements(filename)`
   - Identifies entitlements vs attributes
   - Extracts all unique values

2. **Prepare Structure**: `prepare_entitlement_structure(filename, appId)`
   - **NEW**: Automatically creates schema attributes if missing
   - Creates entitlements with ALL values at once
   - Uses correct API structure

3. **Execute Grants**: `execute_user_grants(filename, appId)`
   - Assigns entitlements to users
   - Handles rate limiting

---

## What Was Wrong Before

### ❌ Wrong Approach
1. Created schema attributes as if they were entitlements
2. Used incorrect API structure (missing fields)
3. Only created ONE entitlement value instead of ALL
4. Wrong parent structure (`id` instead of `externalId`)
5. Wrong type case ("application" instead of "APPLICATION")

### ✅ Correct Approach
1. Schema attributes created automatically when needed
2. Correct API structure with all required fields
3. ALL entitlement values created in single API call
4. Correct parent structure and field names
5. Proper field casing and naming

---

## Remember

**Schema Attribute** = Individual field in app profile
**Entitlement Type** = Column name (e.g., "Role")
**Entitlement Value** = Each unique value under that column (e.g., "Admin", "User")

**One entitlement type = Many entitlement values**
