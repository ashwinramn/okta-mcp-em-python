"""
Application Knowledge Base for Separation of Duties (SoD) Analysis.

This module contains authoritative SoD patterns, duty mappings, and compliance
references for supported Okta Entitlement Management applications.

Sources:
- NIST SP 800-53 Rev 5 - AC-5 (Separation of Duties)
- ISACA SoD Implementation Guide
- SOX IT Control Objectives (Section 404)
- SOC 2 Trust Services Criteria (CC6.1, CC6.3)
- Application-specific security documentation
"""

from typing import Dict, Any, List, Optional


# =============================================================================
# ISACA Duty Categories
# =============================================================================
# Four fundamental duties that should be segregated (ISACA best practices)

DUTY_CATEGORIES = {
    "authorization": {
        "description": "Approval of transactions affecting assets",
        "risk": "Can approve their own transactions or changes",
        "examples": ["Approve payments", "Authorize users", "Sign off on changes"]
    },
    "custody": {
        "description": "Direct access to or control of assets",
        "risk": "Can access or modify assets directly",
        "examples": ["Access data", "Modify records", "Transfer funds"]
    },
    "recording": {
        "description": "Recording or reporting of transactions",
        "risk": "Can manipulate records to conceal actions",
        "examples": ["Create entries", "Generate reports", "Log transactions"]
    },
    "verification": {
        "description": "Reconciliation and control activities",
        "risk": "Can review and clear their own activities",
        "examples": ["Audit logs", "Reconcile accounts", "Review changes"]
    }
}

# ISACA Toxic Pairing Rules
ISACA_TOXIC_PAIRINGS = [
    {
        "pair": ("authorization", "custody"),
        "risk": "Embezzlement risk - can approve and execute transactions",
        "severity": "CRITICAL"
    },
    {
        "pair": ("custody", "recording"),
        "risk": "Undetected theft - can take assets and hide in records",
        "severity": "CRITICAL"
    },
    {
        "pair": ("authorization", "recording"),
        "risk": "Fraud concealment - can approve and record own transactions",
        "severity": "HIGH"
    },
    {
        "pair": ("authorization", "verification"),
        "risk": "Detection failure - can approve and clear own activities",
        "severity": "CRITICAL"
    },
    {
        "pair": ("custody", "verification"),
        "risk": "Detection failure - can access assets and verify own actions",
        "severity": "HIGH"
    },
    {
        "pair": ("recording", "verification"),
        "risk": "Audit bypass - can record and verify own entries",
        "severity": "HIGH"
    }
]


# =============================================================================
# Compliance Framework References
# =============================================================================

COMPLIANCE_FRAMEWORKS = {
    "nist": {
        "name": "NIST SP 800-53 Rev 5",
        "primary_control": "AC-5",
        "control_name": "Separation of Duties",
        "related_controls": ["AC-2", "AC-3", "AC-6", "AU-9", "CM-5"],
        "url": "https://csf.tools/reference/nist-sp-800-53/r5/ac/ac-5/",
        "guidance": "Identify and document duties; Define access authorizations to support separation"
    },
    "sox": {
        "name": "Sarbanes-Oxley Act",
        "primary_control": "Section 404",
        "control_name": "Internal Controls over Financial Reporting",
        "guidance": "IT Control Objectives for Sarbanes-Oxley, 3rd Edition",
        "applies_to": ["Financial systems", "ERP", "Payroll", "Accounts Payable/Receivable"]
    },
    "soc2": {
        "name": "SOC 2 Trust Services Criteria",
        "primary_control": "CC6.1",
        "control_name": "Logical and Physical Access Controls",
        "related_controls": ["CC6.3", "CC7.2"],
        "guidance": "Role-based access, SoD enforcement for trust service commitments"
    },
    "isaca": {
        "name": "ISACA SoD Implementation Guide",
        "url": "https://www.isaca.org/resources/isaca-journal/issues/2016/volume-3/implementing-segregation-of-duties-a-practical-experience-based-on-best-practices",
        "guidance": "Four duties to segregate: Authorization, Custody, Recording, Verification"
    }
}


# =============================================================================
# Supported Entitlement Management Applications (11 Priority Apps)
# =============================================================================

SUPPORTED_EM_APPS: Dict[str, Dict[str, Any]] = {
    # =========================================================================
    # 1. SALESFORCE
    # =========================================================================
    "salesforce": {
        "label": "Salesforce.com",
        "aliases": ["salesforce", "sfdc", "salesforce.com"],
        "okta_entitlements": ["Profile", "Permission Set", "Role", "Feature License", "Public Groups"],
        "risk_category": "CRITICAL",
        "data_classification": ["PII", "Financial", "Sales", "CRM"],
        "duty_mapping": {
            "System Administrator": "authorization",
            "Modify All Data": "custody",
            "View All Data": "custody",
            "Export Reports": "recording",
            "Manage Users": "authorization",
            "API Enabled": "custody",
            "Author Apex": "custody",
            "Customize Application": "authorization"
        },
        "known_toxic_pairs": [
            {
                "name": "System Admin + Data Export",
                "list1": ["System Administrator"],
                "list2": ["Export Reports", "Data Export"],
                "severity": "CRITICAL",
                "rationale": "Admin can export all data including PII without oversight",
                "compliance": {"sox": "Section 404", "nist": "AC-5", "soc2": "CC6.1"}
            },
            {
                "name": "Modify All Data + View All Data",
                "list1": ["Modify All Data"],
                "list2": ["View All Data"],
                "severity": "HIGH",
                "rationale": "User can modify and view all records without separation",
                "compliance": {"nist": "AC-5", "soc2": "CC6.3"}
            },
            {
                "name": "Manage Users + API Access",
                "list1": ["Manage Users"],
                "list2": ["API Enabled"],
                "severity": "HIGH",
                "rationale": "Can create users and access via API for automation abuse",
                "compliance": {"nist": "AC-6", "soc2": "CC6.1"}
            },
            {
                "name": "Quote Create + Quote Approve",
                "list1": ["Create Quotes"],
                "list2": ["Approve Quotes"],
                "severity": "CRITICAL",
                "rationale": "Financial fraud risk - create and approve own quotes",
                "compliance": {"sox": "Section 404", "nist": "AC-5"}
            }
        ],
        "reference_urls": [
            "https://help.salesforce.com/s/articleView?id=sf.security_about.htm",
            "https://trailhead.salesforce.com/content/learn/modules/data_security"
        ]
    },

    # =========================================================================
    # 2. GOOGLE WORKSPACE
    # =========================================================================
    "google_workspace": {
        "label": "Google Workspace",
        "aliases": ["google", "gsuite", "g suite", "google workspace"],
        "okta_entitlements": ["Licenses", "Roles"],
        "risk_category": "CRITICAL",
        "data_classification": ["PII", "Email", "Documents", "Collaboration"],
        "duty_mapping": {
            "Super Admin": "authorization",
            "User Management Admin": "authorization",
            "Groups Admin": "authorization",
            "Services Admin": "custody",
            "Security Admin": "verification",
            "Help Desk Admin": "recording"
        },
        "known_toxic_pairs": [
            {
                "name": "Super Admin + User Management",
                "list1": ["Super Admin"],
                "list2": ["User Management Admin"],
                "severity": "CRITICAL",
                "rationale": "Redundant privilege - Super Admin already has all permissions",
                "compliance": {"nist": "AC-6", "soc2": "CC6.1"}
            },
            {
                "name": "User Admin + Groups Admin",
                "list1": ["User Management Admin"],
                "list2": ["Groups Admin"],
                "severity": "HIGH",
                "rationale": "Can create users and add to privileged groups",
                "compliance": {"nist": "AC-5", "soc2": "CC6.3"}
            },
            {
                "name": "Services Admin + Security Settings",
                "list1": ["Services Admin"],
                "list2": ["Security Admin"],
                "severity": "HIGH",
                "rationale": "Can enable services and modify security controls",
                "compliance": {"nist": "AC-3", "soc2": "CC6.1"}
            }
        ],
        "reference_urls": [
            "https://support.google.com/a/answer/2405986",
            "https://support.google.com/a/answer/9807615"
        ]
    },

    # =========================================================================
    # 3. MICROSOFT 365
    # =========================================================================
    "microsoft_365": {
        "label": "Microsoft Office 365",
        "aliases": ["microsoft 365", "office 365", "o365", "m365", "microsoft office 365"],
        "okta_entitlements": ["Licenses", "Roles"],
        "risk_category": "CRITICAL",
        "data_classification": ["PII", "Email", "Documents", "Financial"],
        "duty_mapping": {
            "Global Administrator": "authorization",
            "User Administrator": "authorization",
            "Exchange Administrator": "custody",
            "SharePoint Administrator": "custody",
            "Compliance Administrator": "verification",
            "Security Administrator": "verification",
            "Billing Administrator": "custody"
        },
        "known_toxic_pairs": [
            {
                "name": "Global Admin + Compliance Admin",
                "list1": ["Global Administrator"],
                "list2": ["Compliance Administrator"],
                "severity": "CRITICAL",
                "rationale": "Can modify data and compliance policies - audit trail risk",
                "compliance": {"sox": "Section 404", "nist": "AC-5", "soc2": "CC6.1"}
            },
            {
                "name": "User Admin + Exchange Admin",
                "list1": ["User Administrator"],
                "list2": ["Exchange Administrator"],
                "severity": "HIGH",
                "rationale": "Can create users and access mailboxes",
                "compliance": {"nist": "AC-5", "soc2": "CC6.3"}
            },
            {
                "name": "SharePoint Admin + Security Admin",
                "list1": ["SharePoint Administrator"],
                "list2": ["Security Administrator"],
                "severity": "HIGH",
                "rationale": "Can access documents and modify security policies",
                "compliance": {"nist": "AC-6", "soc2": "CC6.1"}
            },
            {
                "name": "Global Admin + Any Admin Role",
                "list1": ["Global Administrator"],
                "list2": ["User Administrator", "Exchange Administrator", "SharePoint Administrator"],
                "severity": "CRITICAL",
                "rationale": "Redundant privilege - Global Admin has all permissions",
                "compliance": {"nist": "AC-6"}
            }
        ],
        "reference_urls": [
            "https://learn.microsoft.com/en-us/microsoft-365/admin/add-users/about-admin-roles",
            "https://learn.microsoft.com/en-us/azure/active-directory/roles/best-practices"
        ]
    },

    # =========================================================================
    # 4. NETSUITE
    # =========================================================================
    "netsuite": {
        "label": "NetSuite",
        "aliases": ["netsuite", "oracle netsuite"],
        "okta_entitlements": ["Roles"],
        "risk_category": "CRITICAL",
        "data_classification": ["Financial", "ERP", "PII", "Inventory"],
        "duty_mapping": {
            "Administrator": "authorization",
            "A/P Clerk": "recording",
            "A/R Clerk": "recording",
            "Accountant": "recording",
            "CEO": "authorization",
            "CFO": "authorization",
            "Sales Manager": "custody",
            "Warehouse Manager": "custody",
            "Inventory Manager": "custody"
        },
        "known_toxic_pairs": [
            {
                "name": "Vendor Create + Payment Processing",
                "list1": ["A/P Clerk"],
                "list2": ["Accountant"],
                "severity": "CRITICAL",
                "rationale": "Classic vendor fraud - create vendor and process payment",
                "compliance": {"sox": "Section 404", "nist": "AC-5", "soc2": "CC6.1"}
            },
            {
                "name": "Invoice Create + Payment Approve",
                "list1": ["A/R Clerk"],
                "list2": ["CFO", "CEO"],
                "severity": "CRITICAL",
                "rationale": "Can create and approve own invoices",
                "compliance": {"sox": "Section 404", "nist": "AC-5"}
            },
            {
                "name": "Journal Entry + Bank Reconciliation",
                "list1": ["Accountant"],
                "list2": ["Administrator"],
                "severity": "HIGH",
                "rationale": "Can post entries and reconcile without oversight",
                "compliance": {"sox": "Section 404", "soc2": "CC6.3"}
            },
            {
                "name": "Inventory Adjust + Inventory Count",
                "list1": ["Warehouse Manager"],
                "list2": ["Inventory Manager"],
                "severity": "HIGH",
                "rationale": "Can adjust and verify inventory counts",
                "compliance": {"nist": "AC-5", "soc2": "CC6.1"}
            }
        ],
        "reference_urls": [
            "https://docs.oracle.com/en/cloud/saas/netsuite/ns-online-help/section_N3419816.html",
            "https://tipalti.com/netsuite-hub/netsuite-segregation-of-duties/"
        ]
    },

    # =========================================================================
    # 5. ORACLE IAM
    # =========================================================================
    "oracle_iam": {
        "label": "Oracle IAM",
        "aliases": ["oracle iam", "oracle identity", "oracle identity cloud"],
        "okta_entitlements": ["User Role"],
        "risk_category": "CRITICAL",
        "data_classification": ["Identity", "Access Control", "Security"],
        "duty_mapping": {
            "Identity Domain Administrator": "authorization",
            "Security Administrator": "authorization",
            "User Administrator": "authorization",
            "Application Administrator": "custody",
            "Audit Administrator": "verification"
        },
        "known_toxic_pairs": [
            {
                "name": "Identity Admin + Audit Admin",
                "list1": ["Identity Domain Administrator"],
                "list2": ["Audit Administrator"],
                "severity": "CRITICAL",
                "rationale": "Can modify access and audit logs",
                "compliance": {"sox": "Section 404", "nist": "AU-9", "soc2": "CC6.1"}
            },
            {
                "name": "User Admin + App Admin",
                "list1": ["User Administrator"],
                "list2": ["Application Administrator"],
                "severity": "HIGH",
                "rationale": "Can create users and assign to applications",
                "compliance": {"nist": "AC-5", "soc2": "CC6.3"}
            },
            {
                "name": "Security Admin + Identity Admin",
                "list1": ["Security Administrator"],
                "list2": ["Identity Domain Administrator"],
                "severity": "CRITICAL",
                "rationale": "Full control over identity and security",
                "compliance": {"nist": "AC-6", "soc2": "CC6.1"}
            }
        ],
        "reference_urls": [
            "https://docs.oracle.com/en/cloud/paas/identity-cloud/uaids/understand-administrator-roles.html"
        ]
    },

    # =========================================================================
    # 6. SAP CONCUR
    # =========================================================================
    "sap_concur": {
        "label": "SAP Concur",
        "aliases": ["concur", "sap concur"],
        "okta_entitlements": ["User Role"],
        "risk_category": "HIGH",
        "data_classification": ["Financial", "Travel", "Expense"],
        "duty_mapping": {
            "Company Admin": "authorization",
            "Expense User": "recording",
            "Expense Approver": "authorization",
            "Expense Processor": "custody",
            "Expense Auditor": "verification"
        },
        "known_toxic_pairs": [
            {
                "name": "Expense Submit + Expense Approve",
                "list1": ["Expense User"],
                "list2": ["Expense Approver"],
                "severity": "CRITICAL",
                "rationale": "Can submit and approve own expense reports",
                "compliance": {"sox": "Section 404", "nist": "AC-5", "soc2": "CC6.1"}
            },
            {
                "name": "Expense Approve + Expense Process",
                "list1": ["Expense Approver"],
                "list2": ["Expense Processor"],
                "severity": "HIGH",
                "rationale": "Can approve and process for payment",
                "compliance": {"sox": "Section 404", "nist": "AC-5"}
            },
            {
                "name": "Company Admin + Expense Auditor",
                "list1": ["Company Admin"],
                "list2": ["Expense Auditor"],
                "severity": "HIGH",
                "rationale": "Admin can modify config and audit own changes",
                "compliance": {"nist": "AU-9", "soc2": "CC7.2"}
            }
        ],
        "reference_urls": [
            "https://www.concurtraining.com/customers/tech_pubs/Docs/ConcurPremier/SG/SG_Shared.pdf"
        ]
    },

    # =========================================================================
    # 7. SERVICENOW
    # =========================================================================
    "servicenow": {
        "label": "ServiceNow",
        "aliases": ["servicenow", "snow"],
        "okta_entitlements": ["Role"],
        "risk_category": "HIGH",
        "data_classification": ["ITSM", "ITOM", "Security Operations"],
        "duty_mapping": {
            "admin": "authorization",
            "itil": "recording",
            "change_manager": "authorization",
            "problem_manager": "authorization",
            "security_admin": "verification",
            "catalog_admin": "custody"
        },
        "known_toxic_pairs": [
            {
                "name": "Change Requester + Change Approver",
                "list1": ["itil"],
                "list2": ["change_manager"],
                "severity": "CRITICAL",
                "rationale": "Can create and approve own change requests",
                "compliance": {"sox": "Section 404", "nist": "CM-5", "soc2": "CC8.1"}
            },
            {
                "name": "Admin + Security Admin",
                "list1": ["admin"],
                "list2": ["security_admin"],
                "severity": "CRITICAL",
                "rationale": "Full system control with security oversight",
                "compliance": {"nist": "AC-5", "soc2": "CC6.1"}
            },
            {
                "name": "Incident Create + Incident Close",
                "list1": ["itil"],
                "list2": ["problem_manager"],
                "severity": "MEDIUM",
                "rationale": "Can create and close incidents without review",
                "compliance": {"nist": "AC-5"}
            },
            {
                "name": "Catalog Admin + Workflow Admin",
                "list1": ["catalog_admin"],
                "list2": ["admin"],
                "severity": "HIGH",
                "rationale": "Can create catalog items and approval workflows",
                "compliance": {"nist": "AC-6", "soc2": "CC6.3"}
            }
        ],
        "reference_urls": [
            "https://docs.servicenow.com/bundle/washingtondc-platform-security/page/administer/contextual-security/concept/segregation-of-duties.html"
        ]
    },

    # =========================================================================
    # 8. SPLUNK ENTERPRISE
    # =========================================================================
    "splunk": {
        "label": "Splunk Enterprise",
        "aliases": ["splunk", "splunk enterprise", "splunk cloud"],
        "okta_entitlements": ["Roles"],
        "risk_category": "HIGH",
        "data_classification": ["Security", "Logs", "SIEM", "Audit"],
        "duty_mapping": {
            "admin": "authorization",
            "power": "custody",
            "user": "recording",
            "sc_admin": "authorization",
            "can_delete": "custody"
        },
        "known_toxic_pairs": [
            {
                "name": "Admin + Delete Capability",
                "list1": ["admin"],
                "list2": ["can_delete"],
                "severity": "CRITICAL",
                "rationale": "Can manage system and delete audit logs",
                "compliance": {"sox": "Section 404", "nist": "AU-9", "soc2": "CC7.2"}
            },
            {
                "name": "Power User + Admin",
                "list1": ["power"],
                "list2": ["admin"],
                "severity": "HIGH",
                "rationale": "Excessive privilege combination",
                "compliance": {"nist": "AC-6", "soc2": "CC6.1"}
            },
            {
                "name": "Index Write + Search All",
                "list1": ["indexes_edit"],
                "list2": ["search"],
                "severity": "HIGH",
                "rationale": "Can inject data and search to verify",
                "compliance": {"nist": "AC-5", "soc2": "CC6.3"}
            }
        ],
        "reference_urls": [
            "https://docs.splunk.com/Documentation/Splunk/latest/Security/Rolesandcapabilities",
            "https://docs.splunk.com/Documentation/Splunk/latest/Admin/Aboutusersandroles"
        ]
    },

    # =========================================================================
    # 9. WORKDAY
    # =========================================================================
    "workday": {
        "label": "Workday",
        "aliases": ["workday"],
        "okta_entitlements": ["User Based Security Groups"],
        "risk_category": "CRITICAL",
        "data_classification": ["HR", "Payroll", "Financial", "PII"],
        "duty_mapping": {
            "HR Administrator": "authorization",
            "Payroll Administrator": "custody",
            "Benefits Administrator": "recording",
            "Security Administrator": "authorization",
            "Auditor": "verification"
        },
        "known_toxic_pairs": [
            {
                "name": "Payroll Admin + HR Admin",
                "list1": ["Payroll Administrator"],
                "list2": ["HR Administrator"],
                "severity": "CRITICAL",
                "rationale": "Can create employees and process payroll - ghost employee risk",
                "compliance": {"sox": "Section 404", "nist": "AC-5", "soc2": "CC6.1"}
            },
            {
                "name": "Security Admin + HR Admin",
                "list1": ["Security Administrator"],
                "list2": ["HR Administrator"],
                "severity": "CRITICAL",
                "rationale": "Can modify security and HR data",
                "compliance": {"nist": "AC-5", "soc2": "CC6.1"}
            },
            {
                "name": "Benefits Admin + Payroll Admin",
                "list1": ["Benefits Administrator"],
                "list2": ["Payroll Administrator"],
                "severity": "HIGH",
                "rationale": "Can modify benefits and process related payroll",
                "compliance": {"sox": "Section 404", "nist": "AC-5"}
            },
            {
                "name": "Any Admin + Auditor",
                "list1": ["HR Administrator", "Payroll Administrator", "Security Administrator"],
                "list2": ["Auditor"],
                "severity": "CRITICAL",
                "rationale": "Can modify data and review audit reports",
                "compliance": {"nist": "AU-9", "soc2": "CC7.2"}
            }
        ],
        "reference_urls": [
            "https://doc.workday.com/admin-guide/en-us/security/security-groups/qxl1645629086449.html"
        ]
    },

    # =========================================================================
    # 10. ZENDESK
    # =========================================================================
    "zendesk": {
        "label": "Zendesk",
        "aliases": ["zendesk"],
        "okta_entitlements": ["Custom role", "Role"],
        "risk_category": "MEDIUM",
        "data_classification": ["Customer Data", "Support", "PII"],
        "duty_mapping": {
            "Admin": "authorization",
            "Agent": "recording",
            "Light Agent": "recording",
            "Team Lead": "authorization",
            "Billing Admin": "custody"
        },
        "known_toxic_pairs": [
            {
                "name": "Admin + Billing Admin",
                "list1": ["Admin"],
                "list2": ["Billing Admin"],
                "severity": "HIGH",
                "rationale": "Can modify system and billing without oversight",
                "compliance": {"sox": "Section 404", "soc2": "CC6.1"}
            },
            {
                "name": "Agent + Admin",
                "list1": ["Agent"],
                "list2": ["Admin"],
                "severity": "MEDIUM",
                "rationale": "Excessive privilege for frontline support",
                "compliance": {"nist": "AC-6"}
            },
            {
                "name": "Delete Tickets + View All Tickets",
                "list1": ["ticket:delete"],
                "list2": ["ticket:view_all"],
                "severity": "HIGH",
                "rationale": "Can view and delete any customer interaction",
                "compliance": {"nist": "AC-5", "soc2": "CC6.3"}
            }
        ],
        "reference_urls": [
            "https://support.zendesk.com/hc/en-us/articles/4408832171418-Zendesk-agent-roles-and-permissions"
        ]
    },

    # =========================================================================
    # 11. TABLEAU
    # =========================================================================
    "tableau": {
        "label": "Tableau Cloud",
        "aliases": ["tableau", "tableau cloud", "tableau server"],
        "okta_entitlements": ["Site Roles"],
        "risk_category": "MEDIUM",
        "data_classification": ["Analytics", "Business Intelligence", "Financial Reports"],
        "duty_mapping": {
            "Site Administrator": "authorization",
            "Creator": "recording",
            "Explorer": "custody",
            "Viewer": "verification",
            "Server Administrator": "authorization",
            "Data Steward": "verification"
        },
        "known_toxic_pairs": [
            {
                "name": "Site Admin + Creator",
                "list1": ["Site Administrator"],
                "list2": ["Creator"],
                "severity": "MEDIUM",
                "rationale": "Can manage site and publish sensitive reports",
                "compliance": {"nist": "AC-6", "soc2": "CC6.1"}
            },
            {
                "name": "Creator + Data Steward",
                "list1": ["Creator"],
                "list2": ["Data Steward"],
                "severity": "HIGH",
                "rationale": "Can create reports and certify own data sources",
                "compliance": {"nist": "AC-5", "soc2": "CC6.3"}
            },
            {
                "name": "Site Admin + Server Admin",
                "list1": ["Site Administrator"],
                "list2": ["Server Administrator"],
                "severity": "CRITICAL",
                "rationale": "Full control over all sites and server settings",
                "compliance": {"nist": "AC-6", "soc2": "CC6.1"}
            }
        ],
        "reference_urls": [
            "https://help.tableau.com/current/server/en-us/users_site_roles.htm",
            "https://help.tableau.com/current/online/en-us/to_site_startup.htm"
        ]
    }
}


# =============================================================================
# Helper Functions
# =============================================================================

def lookup_app_by_name(app_name: str) -> Optional[Dict[str, Any]]:
    """
    Look up an application in the knowledge base by name or alias.

    Args:
        app_name: Application name or alias (case-insensitive)

    Returns:
        Application knowledge dict if found, None otherwise
    """
    if not app_name:
        return None

    app_name_lower = app_name.lower().strip()

    # Direct key lookup
    if app_name_lower in SUPPORTED_EM_APPS:
        return SUPPORTED_EM_APPS[app_name_lower]

    # Search by alias
    for key, app_data in SUPPORTED_EM_APPS.items():
        aliases = [a.lower() for a in app_data.get("aliases", [])]
        if app_name_lower in aliases:
            return app_data
        # Partial match on label
        if app_name_lower in app_data.get("label", "").lower():
            return app_data

    return None


def get_toxic_pair_by_duty(duty1: str, duty2: str) -> Optional[Dict[str, Any]]:
    """
    Look up ISACA toxic pairing by duty categories.

    Args:
        duty1: First duty category
        duty2: Second duty category

    Returns:
        Toxic pairing info if the combination is toxic, None otherwise
    """
    pair_set = frozenset([duty1.lower(), duty2.lower()])

    for pairing in ISACA_TOXIC_PAIRINGS:
        if frozenset(pairing["pair"]) == pair_set:
            return pairing

    return None


def get_duty_for_entitlement(app_key: str, entitlement_value: str) -> Optional[str]:
    """
    Look up the duty category for an entitlement value in a specific app.

    Args:
        app_key: Application key in SUPPORTED_EM_APPS
        entitlement_value: The entitlement value (e.g., "System Administrator")

    Returns:
        Duty category ("authorization", "custody", "recording", "verification") or None
    """
    app_data = SUPPORTED_EM_APPS.get(app_key)
    if not app_data:
        return None

    duty_mapping = app_data.get("duty_mapping", {})

    # Direct lookup
    if entitlement_value in duty_mapping:
        return duty_mapping[entitlement_value]

    # Case-insensitive lookup
    value_lower = entitlement_value.lower()
    for mapped_value, duty in duty_mapping.items():
        if mapped_value.lower() == value_lower:
            return duty

    return None


def list_supported_apps() -> List[Dict[str, str]]:
    """
    List all supported applications.

    Returns:
        List of dicts with 'key', 'label', and 'risk_category' for each app
    """
    return [
        {
            "key": key,
            "label": data["label"],
            "risk_category": data["risk_category"]
        }
        for key, data in SUPPORTED_EM_APPS.items()
    ]


def get_authoritative_sod_sources() -> Dict[str, Any]:
    """
    Get authoritative SoD sources for LLM context.

    Returns:
        Dict with NIST, ISACA, SOX, and SOC2 references
    """
    return {
        "nist_sp_800_53": {
            "control": "AC-5 (Separation of Duties)",
            "url": COMPLIANCE_FRAMEWORKS["nist"]["url"],
            "key_guidance": COMPLIANCE_FRAMEWORKS["nist"]["guidance"],
            "related_controls": COMPLIANCE_FRAMEWORKS["nist"]["related_controls"]
        },
        "isaca": {
            "url": COMPLIANCE_FRAMEWORKS["isaca"]["url"],
            "four_duties": list(DUTY_CATEGORIES.keys()),
            "toxic_pairings": [
                f"{p['pair'][0]} + {p['pair'][1]} = {p['risk']}"
                for p in ISACA_TOXIC_PAIRINGS
            ]
        },
        "sox": {
            "control": COMPLIANCE_FRAMEWORKS["sox"]["primary_control"],
            "guidance": COMPLIANCE_FRAMEWORKS["sox"]["guidance"],
            "applies_to": COMPLIANCE_FRAMEWORKS["sox"]["applies_to"]
        },
        "soc2": {
            "primary_control": COMPLIANCE_FRAMEWORKS["soc2"]["primary_control"],
            "related": COMPLIANCE_FRAMEWORKS["soc2"]["related_controls"]
        },
        "okta_sod_docs": {
            "url": "https://help.okta.com/oie/en-us/content/topics/identity-governance/sd/create-rules.htm",
            "max_values_per_list": 50,
            "operators": ["ANY_ONE_OF", "ALL_OF"]
        }
    }
