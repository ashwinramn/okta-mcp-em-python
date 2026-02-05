# 🔐 Okta MCP Server for Entitlement Management

> **Talk to Okta IGA like you talk to a coworker.** Import access data, discover patterns, and create entitlement bundles—all through natural conversation.

---

## ⚠️ Disclaimer: Vibe Coded

**This project was "vibe coded"**—built rapidly through AI-assisted development with Claude/Copilot. While functional and tested against real Okta tenants, it:

- May contain unconventional patterns or edge cases not fully handled
- Has not undergone formal security review
- Is provided **as-is** for experimentation and learning
- Should be **tested thoroughly in a sandbox environment** before any production use

**Use at your own risk.** Always validate operations in a non-production Okta tenant first.

---

## 🤔 The Opportunity

**Okta Identity Governance (IGA)** gives you powerful tools to manage entitlements, grants, and access bundles. This MCP server helps you get value from those features faster by automating the setup work:

| Instead of... | You can say... |
|---------------|----------------|
| Manually creating entitlements from a CSV export | *"Import the HR system access from that CSV"* |
| Analyzing access patterns to define bundles | *"Find patterns and suggest bundles"* |
| Granting access to users one by one | *"Grant these permissions to all 500 users"* |

**The goal:** Spend less time on data entry, more time on governance strategy.

## 💡 How It Works

This MCP server lets you **describe what you want in plain English**, and the AI handles the Okta API calls:

```
You: "Import the HR system access from that CSV into Okta"
AI:  ✅ Analyzed CSV: 3 entitlement types, 847 users
     ✅ Created entitlements in app 0oa123abc
     ✅ Granted access to 847 users (23 already had access)
```

```
You: "Find patterns in who has what access and suggest bundles"
AI:  Found 12 patterns:
     🟢 Engineering dept → always gets Developer role (94% match)
     🟢 Managers → always get Approval permission (89% match)
     Want me to create these as bundles?
```

---

## 🎯 What This Does

| Capability | Description |
|------------|-------------|
| **CSV → Okta Import** | Parse access reports, create entitlement structures, grant to users in bulk |
| **Pattern Mining** | Analyze existing grants to discover who-gets-what patterns |
| **Bundle Creation** | Turn patterns into IGA bundles with auto-generated descriptions |
| **Bulk Operations** | Parallel API calls with automatic rate limiting |
| **Natural Language** | No API knowledge needed—just describe what you want |

---

## 📊 Two Main Workflows

### Workflow 1: CSV Import
**Use case:** You have a CSV export from a legacy system and need to get it into Okta IGA

```
list_csv_files  →  analyze_csv_for_entitlements  →  prepare_entitlement_structure  →  execute_user_grants
      │                      │                               │                              │
      ▼                      ▼                               ▼                              ▼
 See available         Parse & validate              Create entitlements            Assign users &
  CSV files               the data                    in Okta app                   grant access
```

### Workflow 2: Pattern Mining → Bundles
**Use case:** You have existing access in Okta and want to create bundles for access requests

```
analyze_entitlement_patterns  →  preview_bundle_creation  →  create_bundle_from_pattern
            │                             │                            │
            ▼                             ▼                            ▼
    Discover correlations          See what would be           Create the bundle
    between profiles &             created (dry run)            in Okta IGA
      entitlements
```

---

## 📁 Project Structure

```
okta-mcp-em-python/
├── server.py               # MCP server entry point
├── client.py               # Okta API client with rate limiting
├── batch.py                # Parallel execution engine
├── s3_client.py            # AWS S3 integration (optional)
├── tools/
│   ├── __init__.py
│   ├── api.py              # Okta API tools
│   ├── basic.py            # CSV & connection tools
│   ├── batch.py            # Batch operation tools
│   ├── workflow.py         # CSV import workflow tools
│   ├── bundle.py           # Pattern mining & bundle creation
│   └── menu.py             # Guided workflow navigation
├── csv/                    # CSV files for processing
│   ├── test_data/          # Sample CSV files
│   ├── processed/          # Completed files
│   ├── processed_and_assigned/
│   └── analysis_cache/     # Cached pattern analysis results
├── .env                    # Environment variables (create this)
├── requirements.txt
└── pyproject.toml
```

---

## 📋 Prerequisites

| Requirement | Details |
|-------------|---------|
| **Python** | 3.10 or higher |
| **Okta Tenant** | Workforce Identity Cloud with IGA enabled |
| **API Token** | Okta API token with appropriate permissions |
| **MCP Client** | Claude Desktop, VS Code with Copilot, or any MCP-compatible client |

---

## 🚀 Quick Start

### Step 1: Clone & Setup

```bash
# Clone the repository
git clone https://github.com/ashwinramn/okta-mcp-em-python.git
cd okta-mcp-em-python

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Step 2: Configure Environment

Create a `.env` file in the project root:

```bash
# Required: Okta Configuration
OKTA_DOMAIN=your-domain.okta.com
OKTA_API_TOKEN=your-api-token

# Optional: S3 for remote CSV storage
S3_ENABLED=false
S3_BUCKET_NAME=your-bucket-name
S3_PREFIX=csv-files/
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
```

### Step 3: Configure Your MCP Client

<details>
<summary><strong>Claude Desktop</strong></summary>

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "okta-entitlements": {
      "command": "python3",
      "args": ["/full/path/to/okta-mcp-em-python/server.py"]
    }
  }
}
```
</details>

<details>
<summary><strong>VS Code with GitHub Copilot</strong></summary>

Add to your VS Code MCP settings or `settings.json`:

```json
{
  "mcp.servers": {
    "okta-entitlements": {
      "command": "python3",
      "args": ["/full/path/to/okta-mcp-em-python/server.py"]
    }
  }
}
```
</details>

### Step 4: Test the Connection

Restart your MCP client, then ask:

> **"Check my Okta connection"**

You should see a success message with your Okta org details.

---

## 🛠️ Available Tools

### 🧭 Navigation
| Tool | Description |
|------|-------------|
| `okta_test` | Verify Okta API connectivity |
| `show_workflow_menu` | Display guided workflow menu |

### 📥 CSV Import Workflow
| Tool | Description |
|------|-------------|
| `list_csv_files` | List available CSV files (local + S3) |
| `analyze_csv_for_entitlements` | Analyze CSV structure and identify entitlements |
| `prepare_entitlement_structure` | Create/update entitlements in Okta app |
| `execute_user_grants` | Grant entitlements to users in bulk |

### 📦 Bundle Mining Workflow
| Tool | Description |
|------|-------------|
| `analyze_entitlement_patterns` | Discover patterns between user profiles and entitlements |
| `preview_bundle_creation` | Preview bundle before creation (dry run) |
| `create_bundle_from_pattern` | Create entitlement bundle in Okta |

### ⚙️ Utility Tools
| Tool | Description |
|------|-------------|
| `okta_user_search` | Search users by various criteria |
| `okta_batch_user_search` | Search multiple users in parallel |
| `okta_batch_create_grants` | Create multiple grants in parallel |
| `okta_get_rate_status` | Check Okta API rate limits |

---

## 💬 Example Conversations

### Example 1: CSV Import Workflow

```
You: "Check my Okta connection"
AI:  ✅ Connected to your-domain.okta.com
     Call show_workflow_menu to see available workflows.

You: "Show me the workflow menu"
AI:  ┌─────────────────────────────────────────┐
     │  1. Import CSV → Okta                   │
     │  2. Mine Patterns → Bundles             │
     └─────────────────────────────────────────┘

You: "1"
AI:  📁 Available CSV files:
     1. hr_platform_access_report.csv
     2. finance_core_access_report.csv
     3. dev_platform_access_report.csv

You: "Analyze hr_platform_access_report.csv"
AI:  📊 Analysis Complete
     ├── Rows: 847
     ├── User column: Email
     └── Entitlements detected:
         • Role (15 unique values)
         • Permission (8 unique values)
         • Support_Group (4 unique values)
     
     Ready to import? Provide the Okta App ID.

You: "Yes, app ID is 0oa123abc"
AI:  ✅ Created entitlement structure in app 0oa123abc
     ├── Role: 15 values created
     ├── Permission: 8 values created
     └── Support_Group: 4 values created

You: "Now grant the permissions to users"
AI:  🚀 Processing 847 users...
     ✅ Complete!
     ├── Users processed: 847
     ├── New assignments: 824
     ├── Already assigned: 23
     └── Grants created: 2,541
```

### Example 2: Bundle Mining Workflow

```
You: "2"
AI:  Enter the Okta App ID to analyze for patterns.

You: "0oa123abc"
AI:  🔍 Analyzing entitlement patterns...
     
     Found 24 patterns across 3 entitlement types:
     
     🟢 STRONG (>85% correlation)
     1. department=Engineering → Role: Developer (94%)
     2. department=Finance → Role: Analyst (91%)
     3. title contains "Manager" → Permission: Approve (89%)
     
     🟡 MODERATE (70-85% correlation)
     4. department=Support → Support_Group: Tier1 (78%)
     5. location=HQ → Permission: Building_Access (72%)

You: "Preview pattern 1"
AI:  📦 Bundle Preview (Dry Run)
     ├── Name: Engineering Access Bundle
     ├── Description: Standard access for Engineering department
     │   members including developer tools and deployment
     │   permissions.
     └── Entitlements:
         • Role = Developer
         • Permission = Deploy
         • Permission = Code_Review

You: "Create it"
AI:  ✅ Bundle created successfully!
     └── Bundle ID: enb789xyz
```

---

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| **Guided Workflows** | Step-by-step navigation—just follow the prompts |
| **Pattern Mining** | ML-free pattern discovery using correlation analysis |
| **Natural Language Bundles** | Auto-generated descriptions for business users |
| **Smart Rate Limiting** | Automatic throttling to respect Okta API limits |
| **Concurrent Processing** | Parallel batch operations (up to 10x faster) |
| **Flexible CSV Parsing** | Handles messy data, various formats, encoding issues |
| **S3 Integration** | Optionally pull CSV files from AWS S3 |
| **Analysis Caching** | Pattern results cached for quick bundle creation |

---

## 📝 CSV Format

The server handles various CSV formats flexibly. Minimum requirements:

| Required | Description |
|----------|-------------|
| **User identifier column** | Email, username, login, employee ID, etc. |
| **Entitlement columns** | Role, Permission, Group, Access Level, etc. |

### Example CSV

```csv
Email,Department,Title,Role,Permission,Support_Group
john.doe@company.com,Engineering,Developer,Admin,Deploy,Tier2
jane.smith@company.com,Finance,Analyst,Viewer,Read,Tier1
bob.wilson@company.com,Engineering,Manager,Admin,Approve,Tier2
```

The AI will automatically:
- Detect which column contains user identifiers
- Identify which columns represent entitlements vs. profile attributes
- Handle missing values, duplicates, and encoding issues

---

## 🐛 Troubleshooting

### Test the server manually

```bash
python3 server.py
```

### Common Issues

| Issue | Solution |
|-------|----------|
| **Connection failed** | Verify `OKTA_DOMAIN` and `OKTA_API_TOKEN` in `.env` |
| **Rate limited** | Wait a few minutes, or check `okta_get_rate_status` |
| **Users not found** | Ensure CSV user identifiers match Okta login format |
| **No patterns found** | App needs existing grants with entitlements to analyze |
| **Module not found** | Run `pip install -r requirements.txt` in virtual env |

### Debug Mode

For verbose logging, set in your environment:

```bash
export LOG_LEVEL=DEBUG
```

---

## 🔗 Related Resources

- [Okta IGA Documentation](https://developer.okta.com/docs/guides/identity-governance/)
- [Model Context Protocol](https://modelcontextprotocol.io/)
- [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk)

---

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.

---

## 🤝 Contributing

Contributions welcome! This is a vibe-coded project, so:

1. **Issues** - Report bugs or suggest features
2. **PRs** - Improvements to error handling, edge cases, and documentation are especially welcome
3. **Testing** - More real-world testing against different Okta configurations

---

<p align="center">
  <em>Built with 🤖 + ☕ by <a href="https://github.com/ashwinramn">@ashwinramn</a></em>
</p>