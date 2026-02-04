# Okta MCP Server for Entitlement Management

A **Model Context Protocol (MCP)** server that enables AI assistants to manage Okta entitlements, grants, and user permissions through natural language.

## 🎯 What This Does

This MCP server allows AI assistants (like Claude) to:
- **Analyze CSV files** containing user entitlement data
- **Create entitlements** in Okta applications automatically
- **Grant permissions** to users in bulk
- **Search and manage users** via the Okta API
- **Handle messy data** - typos, mixed formats, duplicates, etc.

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
│   └── workflow.py         # Entitlement workflow tools
├── csv/                    # CSV files for processing
│   ├── processed/          # Completed files
│   └── processed_and_assigned/
├── .env                    # Environment variables (not in repo)
├── requirements.txt
└── pyproject.toml
```

## 📋 Prerequisites

- **Python 3.10+**
- **Okta Workforce Identity Cloud** tenant
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

| Tool | Description |
|------|-------------|
| `check_okta_connection` | Verify Okta API connectivity |
| `list_csv_files` | List available CSV files |
| `analyze_csv_for_entitlements` | Analyze CSV structure and identify entitlements |
| `prepare_entitlement_structure` | Create/update entitlements in Okta app |
| `execute_user_grants` | Grant entitlements to users in bulk |
| `search_okta_users` | Search users by various criteria |
| `get_rate_limit_status` | Check Okta API rate limits |

## 📊 Entitlement Workflow

The typical workflow has 3 stages:

```
1. Analyze CSV → 2. Prepare Entitlements → 3. Execute Grants
```

### Example Conversation

```
You: "Analyze the audit_rbac.csv file"
AI: [Analyzes CSV, identifies columns, users, and entitlements]

You: "Create the entitlements in app 0oa123abc"
AI: [Creates entitlement definitions in Okta]

You: "Now grant the permissions to users"
AI: [Assigns grants to users in parallel]
```

## 🔑 Key Features

- **Rate Limiting** - Automatic throttling to respect Okta API limits
- **Concurrent Processing** - Parallel batch operations for speed
- **Flexible CSV Parsing** - Handles various formats, headers, and data quality issues
- **S3 Integration** - Optionally pull CSV files from AWS S3
- **Error Recovery** - Detailed error messages and graceful handling

## 📝 CSV Format

The server can handle various CSV formats. At minimum, it needs:
- A column identifying users (username, email, login, etc.)
- A column identifying entitlements/permissions/roles

Example:
```csv
Username,Email,Permission_Set,Resource
john.doe@company.com,john@example.com,Admin,SAP_Finance
jane.smith@company.com,jane@example.com,Viewer,Workday_HR
```

## 🐛 Troubleshooting

**Test the server manually:**
```bash
python3 server.py
```

**Common issues:**
- **Connection failed**: Check `OKTA_DOMAIN` and `OKTA_API_TOKEN` in `.env`
- **Rate limited**: Wait a few minutes or check `get_rate_limit_status`
- **Users not found**: Verify user identifiers match Okta login format

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.

## 🤝 Contributing

Contributions welcome! Please open an issue or submit a pull request.
