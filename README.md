# Okta MCP Server for Entitlement Management

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![MCP](https://img.shields.io/badge/MCP-Model%20Context%20Protocol-purple.svg)](https://modelcontextprotocol.io/)

> ⚠️ **Disclaimer**: This is an experimental project created with AI assistance ("vibecoded"). It is **NOT** an official Okta product. Use at your own risk. See [LICENSE](LICENSE) for details.

A **Model Context Protocol (MCP)** server that enables natural language management of Okta Identity Governance entitlements. Process CSV files to bulk-create entitlements and assign grants to users—all through conversational AI.

## 🎯 What Problem Does This Solve?

Managing entitlements in Okta Identity Governance often involves:
- Manual CSV parsing and data transformation
- Multiple API calls with complex payload structures
- Rate limit management for bulk operations
- User lookup and application assignment workflows

This MCP server automates the entire workflow through natural language commands like:
- *"Analyze the audit CSV and show me the entitlement structure"*
- *"Create the entitlements in my Okta app"*
- *"Grant users their permissions from the CSV"*

## 🏗️ Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Claude AI     │────▶│   MCP Server    │────▶│   Okta APIs     │
│   (Natural      │     │   (Python)      │     │   - Users       │
│    Language)    │◀────│                 │◀────│   - Apps        │
└─────────────────┘     └─────────────────┘     │   - Governance  │
                               │                └─────────────────┘
                               ▼
                        ┌─────────────────┐
                        │   CSV Files     │
                        │   (Local/S3)    │
                        └─────────────────┘
```

## 📁 Project Structure

```
okta-mcp-em-python/
├── server.py               # MCP server entry point
├── client.py               # Okta API client with rate limiting
├── batch.py                # Parallel execution engine
├── s3_client.py            # AWS S3 integration (optional)
├── tools/
│   ├── api.py              # Okta API tools
│   ├── basic.py            # CSV & connection tools
│   ├── batch.py            # Batch operation tools
│   └── workflow.py         # Entitlement workflow tools
├── csv/                    # CSV files for processing
│   ├── processed/          # Completed (structure created)
│   └── processed_and_assigned/  # Completed (with user grants)
├── .env.example            # Environment template
└── requirements.txt        # Python dependencies
```

## 🚀 Quick Start

### Prerequisites

- **Python 3.10+** - Verify: `python3 --version`
- **Okta Workforce Identity Cloud** tenant with Identity Governance
- **API Token** with appropriate permissions
- **Claude Desktop** or another MCP-compatible client

### 1. Clone & Install

```bash
git clone https://github.com/ashwinrama/okta-mcp-em-python.git
cd okta-mcp-em-python

# Create virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env with your Okta credentials
```

Required variables:
```bash
OKTA_DOMAIN=your-domain.okta.com
OKTA_API_TOKEN=your-api-token
```

### 3. S3 Integration (Optional)

If you want to retrieve CSV files from AWS S3 instead of local storage:

1.  **Enable S3 in `.env`**:
    ```bash
    S3_ENABLED=true
    S3_BUCKET_NAME=your-iam-governance-bucket
    S3_PREFIX=audit-reports/  # Optional: Default folder
    
    # Optional: Restrict search to specific paths (overrides S3_PREFIX)
    S3_ALLOWED_PATHS=finance/reports/,hr/audits/
    ```

2.  **Configure AWS Credentials**:
    The server uses standard AWS credential resolution (boto3). You can:
    - Set `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` in `.env`
    - Use your existing `~/.aws/credentials` (run `aws configure`)
    - Use IAM roles if running in AWS environments

3.  **Sync Files**:
    Once configured, you can ask: *"Link to S3 and sync my files"* or use the `sync_s3_files` tool.


### 4. Configure MCP Client

**For Claude Desktop** (macOS):

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "okta-mcp-em-python": {
      "command": "/path/to/okta-mcp-em-python/.venv/bin/python",
      "args": ["/path/to/okta-mcp-em-python/server.py"]
    }
  }
}
```

**For Claude Desktop** (Windows):

Edit `%APPDATA%\Claude\claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "okta-mcp-em-python": {
      "command": "C:\\path\\to\\okta-mcp-em-python\\.venv\\Scripts\\python.exe",
      "args": ["C:\\path\\to\\okta-mcp-em-python\\server.py"]
    }
  }
}
```

### 5. Restart & Test

1. Restart Claude Desktop
2. Ask: *"Check my Okta connection"*
3. You should see a success message with your user info

## 📊 Three-Stage Workflow

The entitlement workflow has three distinct stages:

### Stage 1: Analyze CSV

```
"Analyze the first CSV file"
```

- Parses CSV structure
- Identifies entitlement columns (Role, Permission_Set, etc.)
- Extracts unique values
- Caches data for subsequent steps

### Stage 2: Create Entitlement Structure

```
"Create the entitlement structure for app 0oaXXXXX"
```

- Checks existing entitlements in the app
- Creates missing entitlement definitions via Governance API
- Automatically handles schema attributes

### Stage 3: Grant Users

```
"Grant users their entitlements"
```

- Searches for users by email/login
- Assigns users to the application
- Creates entitlement grants (concurrent, rate-limited)
- Reports success/failure summary

## 🛠️ Available Tools

| Tool | Description |
|------|-------------|
| `okta_test` | Test Okta connection |
| `list_csv_files` | List available CSV files |
| `read_csv_file` | Read CSV contents |
| `validate_csv_preflight` | Pre-flight check for CSV errors |
| `analyze_csv_for_entitlements` | Stage 1: Analyze CSV |
| `prepare_entitlement_structure` | Stage 2: Create entitlements |
| `execute_user_grants` | Stage 3: Grant users |
| `okta_iga_list_entitlements` | List app entitlements |
| `okta_iga_list_entitlement_values` | List entitlement values |
| `okta_user_search` | Search for Okta user |
| `okta_batch_user_search` | Parallel user search |
| `okta_batch_assign_users` | Parallel app assignment |
| `okta_batch_create_grants` | Parallel grant creation |
| `okta_get_rate_status` | Check API rate limits |
| `sync_s3_files` | Sync CSVs from S3 |

## ⚡ Key Features

- **Intelligent Rate Limiting**: Tracks Okta's per-endpoint limits with 70% safety threshold
- **Concurrent Processing**: Semaphore-based parallelism for bulk operations
- **Auto-throttle**: Exponential backoff on rate limit hits
- **S3 Integration**: Optional CSV retrieval from AWS S3
- **Comprehensive Logging**: Detailed operation logs for debugging

## 📋 CSV Format

Expected CSV columns:

| Column | Required | Description |
|--------|----------|-------------|
| `Email` | Yes | User email (for Okta lookup) |
| `User_ID` | No | Internal user identifier |
| `Role` | No | Entitlement type (multi-value supported with `;`) |
| `Permission_Set` | No | Entitlement type |
| `Effective_Access` | No | Filter: `Permitted` or `Denied` |

### Sample CSV Files Included

| File | Rows | Description |
|------|------|-------------|
| `sample_small_baseline.csv` | 10 | Simple happy path for quick demos |
| `sample_medium_denormalized.csv` | 45 | Multiple entries per user, denied access scenarios |
| `sample_permission_creep.csv` | 20 | Shows role accumulation over time |

Sample row:
```csv
Email,User_ID,Access_Date,Action_Type,Role,Permission_Set,Effective_Access
alice.johnson@acme.example.com,U001,2025-01-15T09:30:00Z,LOGIN,Admin,SYSTEM_ADMIN,Permitted
```

## 🐛 Troubleshooting

**Server won't start:**
```bash
cd /path/to/okta-mcp-em-python
source .venv/bin/activate
python -c "import server; print('✅ Server imports successfully')"
```

**Connection test fails:**
- Verify `OKTA_DOMAIN` doesn't include `https://`
- Confirm API token hasn't expired
- Check token has required permissions

**Rate limit errors:**
- Use `okta_get_rate_status` to check current limits
- Reduce batch concurrency if needed
- Wait for reset window

## 🎬 Demo Video

[Coming soon - Link to demo video]

## 📚 Resources

- [Okta Identity Governance API](https://developer.okta.com/docs/api/iga/)
- [Model Context Protocol](https://modelcontextprotocol.io/)
- [Blog Post: Building This Project](https://iamse.blog/your-post-url)

## 🙏 Acknowledgments

This project was built with significant AI assistance (Claude). It represents an experiment in "vibecoding" - using AI to accelerate development while maintaining human oversight for architecture and security decisions.

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.

---

**Author**: Ashwin Ramnarayanan  
**Disclaimer**: This is not an official Okta product. Use at your own risk.
