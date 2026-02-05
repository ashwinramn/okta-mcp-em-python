# Okta MCP Server for Entitlement Management

A **Model Context Protocol (MCP)** server that enables AI assistants to manage Okta entitlements, grants, and user permissions through natural language.

## 🎯 What This Does

This MCP server allows AI assistants (like Claude) to:
- **Import CSV files** containing user entitlement data into Okta
- **Mine entitlement patterns** from existing access to create bundles
- **Create entitlements** in Okta applications automatically
- **Grant permissions** to users in bulk
- **Search and manage users** via the Okta API

## 📊 Two Main Workflows

### Workflow 1: CSV Import
```
list_csv_files → analyze_csv_for_entitlements → prepare_entitlement_structure → execute_user_grants
```
**Use case:** Onboard a new application's access data from CSV into Okta IGA

### Workflow 2: Pattern Mining → Bundles
```
analyze_entitlement_patterns → preview_bundle_creation → create_bundle_from_pattern
```
**Use case:** Discover access patterns and create entitlement bundles for access requests

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
├── .env                    # Environment variables (not in repo)
├── requirements.txt
└── pyproject.toml
```

## 📋 Prerequisites

- **Python 3.10+**
- **Okta Workforce Identity Cloud** tenant with IGA enabled
- **Okta API Token** with appropriate permissions

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/ashwinramn/okta-mcp-em-python.git
cd okta-mcp-em-python
```

### 2. Create Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment

Create a `.env` file in the project root:

```bash
# Okta Configuration (Required)
OKTA_DOMAIN=your-domain.okta.com
OKTA_API_TOKEN=your-api-token

# S3 Configuration (Optional - for remote CSV storage)
S3_ENABLED=false
S3_BUCKET_NAME=your-bucket-name
S3_PREFIX=csv-files/
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
```

### 5. Configure MCP Client

**For Claude Desktop**, edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "okta-entitlements": {
      "command": "python3",
      "args": ["/path/to/okta-mcp-em-python/server.py"]
    }
  }
}
```

**For VS Code with Copilot**, add to your settings or MCP configuration.

### 6. Restart & Test

Restart your MCP client and ask: **"Check my Okta connection"**

## 🛠️ Available Tools

### Navigation
| Tool | Description |
|------|-------------|
| `okta_test` | Verify Okta API connectivity |
| `show_workflow_menu` | Display guided workflow menu |

### CSV Import Workflow
| Tool | Description |
|------|-------------|
| `list_csv_files` | List available CSV files (local + S3) |
| `analyze_csv_for_entitlements` | Analyze CSV structure and identify entitlements |
| `prepare_entitlement_structure` | Create/update entitlements in Okta app |
| `execute_user_grants` | Grant entitlements to users in bulk |

### Bundle Mining Workflow
| Tool | Description |
|------|-------------|
| `analyze_entitlement_patterns` | Discover patterns between user profiles and entitlements |
| `preview_bundle_creation` | Preview bundle before creation (dry run) |
| `create_bundle_from_pattern` | Create entitlement bundle in Okta |

### Utility Tools
| Tool | Description |
|------|-------------|
| `okta_user_search` | Search users by various criteria |
| `okta_batch_user_search` | Search multiple users in parallel |
| `okta_batch_create_grants` | Create multiple grants in parallel |
| `okta_get_rate_status` | Check Okta API rate limits |

## 📊 Example Conversations

### CSV Import Workflow

```
You: "Check my Okta connection"
AI: ✅ Connected! Call show_workflow_menu to see workflows.

You: "Show me the workflow menu"
AI: [Displays menu with 2 workflow options]

You: "1" (or "Import a CSV file")
AI: [Lists available CSV files]

You: "Analyze hr_platform_access_report.csv"
AI: Found 3 entitlements: Role, Permission, Support_Group
    Are these correct? If yes, enter App ID...

You: "Yes, app ID is 0oa123abc"
AI: [Creates entitlement structure in Okta]

You: "Now grant the permissions"
AI: [Assigns grants to users - 150 users processed]
```

### Bundle Mining Workflow

```
You: "2" (or "Create bundles from existing access")
AI: Enter the Okta App ID to analyze.

You: "0oa123abc"
AI: [Analyzes patterns]
    Found 24 patterns:
    1. 🟢 Strong - department=Engineering → Role: Developer (90% coverage)
    2. 🟡 Moderate - title=Manager → Permission: Approve (78% coverage)

You: "Preview pattern 1"
AI: Bundle: "Engineering Access"
    Description: "Standard access for the Engineering department..."
    Entitlements: Role=Developer, Permission=Deploy

You: "Create it"
AI: ✅ Bundle created! ID: enb123xyz
```

## 🔑 Key Features

- **Guided Workflows** - Step-by-step navigation through complex operations
- **Pattern Mining** - Automatically discover access patterns from existing data
- **Natural Language Bundles** - Auto-generated descriptions for business users
- **Rate Limiting** - Automatic throttling to respect Okta API limits
- **Concurrent Processing** - Parallel batch operations for speed
- **Flexible CSV Parsing** - Handles various formats and data quality issues
- **S3 Integration** - Optionally pull CSV files from AWS S3
- **Caching** - Analysis results cached for quick bundle creation

## 📝 CSV Format

The server can handle various CSV formats. At minimum, it needs:
- A column identifying users (username, email, login, etc.)
- Columns for entitlements/permissions/roles

Example:
```csv
Email,Department,Title,Role,Permission,Support_Group
john.doe@company.com,Engineering,Developer,Admin,Deploy,Tier2
jane.smith@company.com,Finance,Analyst,Viewer,Read,Tier1
```

## 🐛 Troubleshooting

**Test the server manually:**
```bash
python3 server.py
```

**Common issues:**
- **Connection failed**: Check `OKTA_DOMAIN` and `OKTA_API_TOKEN` in `.env`
- **Rate limited**: Wait a few minutes or check `okta_get_rate_status`
- **Users not found**: Verify user identifiers match Okta login format
- **No patterns found**: Ensure app has existing grants with entitlements

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.

## 🤝 Contributing

Contributions welcome! Please open an issue or submit a pull request.
