# Okta MCP Server for Entitlement Management

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![MCP](https://img.shields.io/badge/MCP-Model%20Context%20Protocol-purple.svg)](https://modelcontextprotocol.io/)

> ⚠️ **Disclaimer**: This is an experimental project created with AI assistance ("vibecoded"). It is **NOT** an official Okta product. Use at your own risk. See [LICENSE](LICENSE) for details.

A **Model Context Protocol (MCP)** server that enables natural language management of Okta Identity Governance entitlements. Process CSV files to bulk-create entitlements and assign grants to users—all through conversational AI.

---

## 📑 Table of Contents

- [What Problem Does This Solve?](#-what-problem-does-this-solve)
- [Architecture](#-architecture)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
  - [Step 1: Clone & Install](#step-1-clone--install)
  - [Step 2: Get Okta Credentials](#step-2-get-okta-credentials)
  - [Step 3: Configure Environment](#step-3-configure-environment)
  - [Step 4: Optional S3 Setup](#step-4-optional-s3-setup)
  - [Step 5: Configure Claude Desktop](#step-5-configure-claude-desktop)
  - [Step 6: Test Your Setup](#step-6-test-your-setup)
- [Three-Stage Workflow](#-three-stage-workflow)
- [Available Tools](#-available-tools)
- [CSV Format](#-csv-format)
- [Troubleshooting](#-troubleshooting)
- [Resources](#-resources)

---

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

---

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

**Key Components:**
- **MCP Server (Python)**: Exposes tools for CSV processing and Okta API operations
- **Claude AI**: Orchestrates workflow through natural language
- **Okta APIs**: Identity Governance, Users, and Applications management
- **CSV Storage**: Local filesystem or AWS S3

---

## 📋 Prerequisites

Before you begin, ensure you have:

- **Python 3.10 or higher** installed
  ```bash
  python3 --version  # Should show 3.10 or higher
  ```

- **Claude Desktop** installed
  - Download from [claude.ai/download](https://claude.ai/download)
  
- **Okta Workforce Identity** tenant
  - With **Identity Governance** enabled
  - Admin access to create API tokens

- **Git** installed (for cloning)
  ```bash
  git --version
  ```

- **(Optional) AWS Account** 
  - Only if you want to use S3 for CSV storage

---

## 🚀 Installation

### Step 1: Clone & Install

**1.1 Clone the repository:**
```bash
git clone https://github.com/YOUR_USERNAME/okta-mcp-em-python.git
cd okta-mcp-em-python
```

**1.2 Create a Python virtual environment:**
```bash
# Create virtual environment
python3 -m venv .venv

# Activate it
source .venv/bin/activate  # macOS/Linux
# OR
.venv\Scripts\activate     # Windows
```

**1.3 Install dependencies:**
```bash
pip install -r requirements.txt
```

You should see packages installing: `mcp`, `httpx`, `python-dotenv`, `boto3`

---

### Step 2: Get Okta Credentials

You need an Okta API token with appropriate permissions.

**2.1 Log into your Okta Admin Console:**
- Navigate to your Okta tenant (e.g., `https://your-domain.okta.com/admin`)

**2.2 Create an API Token:**
1. In Admin Console, go to **Security** > **API** > **Tokens**
2. Click **Create Token**
3. Name it something descriptive: `MCP Server - Entitlement Management`
4. Click **Create Token**
5. **IMPORTANT**: Copy the token immediately - you won't see it again!
   ```
   Example: 00CaBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890
   ```

**2.3 Required API Scopes:**

Your token needs these permissions:
- `okta.users.read` - Search and retrieve user information
- `okta.apps.read` - List and read application details
- `okta.apps.manage` - Assign users to applications
- `okta.governance.entitlements.manage` - Create and manage entitlements

> 💡 **Note**: API tokens inherit permissions from the admin user who created them. Ensure your admin account has Identity Governance Administrator role.

**2.4 Note your Okta domain:**
- Your domain is the part before `/admin`
- Example: If your URL is `https://dev-12345.okta.com/admin`, your domain is `dev-12345.okta.com`
- Do NOT include `https://`

---

### Step 3: Configure Environment

**3.1 Create your environment file:**
```bash
cp .env.example .env
```

**3.2 Edit `.env` with your credentials:**
```bash
# Use your preferred text editor
nano .env
# OR
code .env
# OR
open .env
```

**3.3 Update the required values:**
```bash
# ===========================================
# OKTA CONFIGURATION (Required)
# ===========================================
OKTA_DOMAIN=your-domain.okta.com          # Replace with your domain
OKTA_API_TOKEN=00CaBcDe...                # Replace with your API token

# ===========================================
# S3 INTEGRATION (Optional - see Step 4)
# ===========================================
S3_ENABLED=false                          # Keep as false for now
```

**3.4 Save the file**

---

### Step 4: Optional S3 Setup

If you want to store CSV files in AWS S3 instead of locally, follow these steps. Otherwise, skip to Step 5.

#### 4.1 Create an S3 Bucket

**Using AWS Console:**
1. Log into AWS Console
2. Go to **S3** service
3. Click **Create bucket**
4. Name it (e.g., `my-okta-governance-csvs`)
5. Choose your region (e.g., `us-east-1`)
6. Keep default settings
7. Click **Create bucket**

**4.2 Upload CSV files:**
1. Click on your bucket
2. Create a folder (e.g., `csv-files/`)
3. Upload your CSV files to this folder

#### 4.3 Create IAM User with S3 Access

**Using AWS Console:**
1. Go to **IAM** > **Users**
2. Click **Create user**
3. Name: `okta-mcp-s3-access`
4. Click **Next**
5. Select **Attach policies directly**
6. Search and select **AmazonS3ReadOnlyAccess**
7. Click **Next** > **Create user**

**Create Access Keys:**
1. Click on the user you just created
2. Go to **Security credentials** tab
3. Scroll to **Access keys**
4. Click **Create access key**
5. Choose **Application running outside AWS**
6. Click **Next** > **Create access key**
7. **IMPORTANT**: Copy both:
   - Access key ID (starts with `AKIA`)
   - Secret access key (you won't see this again!)

#### 4.4 Configure S3 in `.env`

```bash
# ===========================================
# S3 INTEGRATION
# ===========================================
S3_ENABLED=true
S3_BUCKET_NAME=my-okta-governance-csvs     # Your bucket name
S3_PREFIX=csv-files/                       # Your folder path
AWS_REGION=us-east-1                       # Your region

# AWS Credentials
AWS_ACCESS_KEY_ID=AKIA...                  # Your access key
AWS_SECRET_ACCESS_KEY=...                  # Your secret key
```

> 💡 **Alternative**: If you have AWS CLI configured (`~/.aws/credentials`), you can omit `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` - the server will use your CLI credentials automatically.

---

### Step 5: Configure Claude Desktop

Now you need to tell Claude Desktop how to run your MCP server.

#### For macOS:

**5.1 Find the configuration file location:**
```bash
# The file is at:
~/Library/Application Support/Claude/claude_desktop_config.json
```

**5.2 Get the absolute path to your project:**
```bash
cd /path/to/okta-mcp-em-python
pwd
# Copy the output - you'll need it
```

**5.3 Edit the Claude Desktop config:**
```bash
# Open in your editor
code ~/Library/Application\ Support/Claude/claude_desktop_config.json
# OR
nano ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

**5.4 Add your MCP server configuration:**
```json
{
  "mcpServers": {
    "okta-mcp-em-python": {
      "command": "/ABSOLUTE/PATH/TO/okta-mcp-em-python/.venv/bin/python",
      "args": ["/ABSOLUTE/PATH/TO/okta-mcp-em-python/server.py"]
    }
  }
}
```

**Example with actual path:**
```json
{
  "mcpServers": {
    "okta-mcp-em-python": {
      "command": "/Users/john/Documents/okta-mcp-em-python/.venv/bin/python",
      "args": ["/Users/john/Documents/okta-mcp-em-python/server.py"]
    }
  }
}
```

> ⚠️ **CRITICAL**: Use **absolute paths** (starting with `/`), not relative paths like `./` or `~/`

#### For Windows:

**5.1 Find the configuration file:**
```
%APPDATA%\Claude\claude_desktop_config.json
```

**5.2 Get the absolute path to your project:**
```cmd
cd C:\path\to\okta-mcp-em-python
cd
REM Copy the output
```

**5.3 Edit the configuration file:**
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

> ⚠️ **Note**: Use double backslashes (`\\`) in Windows paths

**5.4 Save the file**

---

### Step 6: Test Your Setup

**6.1 Restart Claude Desktop**
- Completely quit Claude Desktop
- Reopen it
- Start a new conversation

**6.2 Run the connection test:**

In Claude, type:
```
Test my Okta connection
```

**Expected Success Output:**
```
✅ Connection successful!

Your Okta Instance: your-domain.okta.com
Authenticated as: admin@your-company.com (U0a1b2c3d4e5)
User Status: ACTIVE

MCP Server Ready!
```

**If you see an error**, see [Troubleshooting](#-troubleshooting) below.

---

## 📊 Three-Stage Workflow

The entitlement management workflow has three distinct stages:

### Stage 1: Analyze CSV Structure

**What it does:**
- Parses CSV file structure
- Identifies entitlement columns (Role, Permission_Set, etc.)
- Extracts all unique values
- Aggregates multi-row user data
- Caches results for next stages

**Command:**
```
Analyze the first CSV file
```

**Example Output:**
```
📊 CSV Analysis Results
=======================
File: sample_small_baseline.csv
Total Rows: 10
Unique Users: 8

Entitlement Columns Found:
├─ Role: Admin, User, Manager (3 values)
└─ Permission_Set: READ_ONLY, FULL_ACCESS (2 values)

Application Attributes:
├─ User_ID (identifier)
├─ Access_Date (timestamp)
└─ Action_Type (metadata)

Ready for Stage 2!
```

---

### Stage 2: Create Entitlement Structure

**What it does:**
- Checks if app already has entitlements
- Creates missing entitlement definitions in Okta
- Uses Governance API: `POST /governance/api/v1/entitlements`
- Sets up application schema attributes

**Requirements:**
- Okta Application ID (you'll be prompted for this)
- Stage 1 must be completed first

**Command:**
```
Create the entitlement structure for app 0oaXXXXXXXXX
```

**Example Output:**
```
🏗️  Creating Entitlement Structure
===================================
Application: Employee Portal (0oaXXXXXXXXX)

Existing Entitlements: None found

Creating new entitlements:
✅ Role entitlement created
   ├─ Admin
   ├─ User
   └─ Manager

✅ Permission_Set entitlement created
   ├─ READ_ONLY
   └─ FULL_ACCESS

Structure ready! Proceed to Stage 3.
```

---

### Stage 3: Grant Entitlements to Users

**What it does:**
- Searches for users by email/login (concurrent, rate-limited)
- Assigns users to the application
- Creates entitlement grants via Governance API
- Provides detailed success/failure summary

**Requirements:**
- Stages 1 and 2 must be completed
- Users must exist in Okta

**Command:**
```
Grant users their entitlements from the CSV
```

**Example Output:**
```
👥 Granting User Entitlements
==============================
Processing 8 users...

User Search: ████████████████ 8/8 (100%)
✅ Found: 7 users
⚠️  Not found: 1 user (jane.doe@company.com)

App Assignment: ████████████████ 7/7 (100%)
✅ Assigned all found users

Grant Creation: ████████████████ 14/14 (100%)
✅ 14 grants created successfully

Summary:
├─ Total users processed: 8
├─ Successfully granted: 7
├─ Failed: 1 (user not found in Okta)
└─ Duration: 12.4s

Rate Limits: All green ✅
```

---

## 🛠️ Available Tools

The MCP server provides 15 tools organized into 5 categories:

### CSV Operations
| Tool | Description |
|------|-------------|
| `list_csv_files` | List all CSV files in the `/csv` folder |
| `read_csv_file` | Read contents of a specific CSV |
| `validate_csv_preflight` | Pre-flight validation for common errors |
| `move_to_processed` | Move completed CSVs to processed folder |
| `sync_s3_files` | Sync CSV files from S3 bucket (if enabled) |

### Discovery & Testing  
| Tool | Description |
|------|-------------|
| `okta_test` | Test Okta API connection and credentials |
| `okta_user_search` | Search for a single user by attribute |
| `okta_iga_list_entitlements` | List entitlements for an application |
| `okta_iga_list_entitlement_values` | List values for a specific entitlement |

### Workflow (Staged)
| Tool | Description |
|------|-------------|
| `analyze_csv_for_entitlements` | **Stage 1**: Analyze CSV structure |
| `prepare_entitlement_structure` | **Stage 2**: Create entitlements in Okta |
| `execute_user_grants` | **Stage 3**: Grant users their entitlements |

### Batch Operations
| Tool | Description |
|------|-------------|
| `okta_batch_user_search` | Search multiple users in parallel |
| `okta_batch_assign_users` | Assign multiple users to app in parallel |
| `okta_batch_create_grants` | Create multiple grants in parallel |

### Monitoring
| Tool | Description |
|------|-------------|
| `okta_get_rate_status` | Check current API rate limit status |

---

## 📋 CSV Format

### Required Columns

| Column | Required | Description | Example |
|--------|----------|-------------|---------|
| `Email` | ✅ Yes | User email for Okta lookup | `alice@company.com` |

### Optional Columns

| Column | Type | Description |
|--------|------|-------------|
| `User_ID` | Attribute | Internal user identifier |
| `Access_Date` | Attribute | When access was granted |
| `Action_Type` | Attribute | Type of action (LOGIN, EXPORT, etc.) |
| `Role` | Entitlement | User role (supports multiple with `;`) |
| `Permission_Set` | Entitlement | Permission sets |
| `Effective_Access` | Filter | `Permitted` or `Denied` |

### Sample CSV

```csv
Email,User_ID,Access_Date,Action_Type,Role,Permission_Set,Effective_Access
alice.johnson@acme.example.com,U001,2025-01-15T09:30:00Z,LOGIN,Admin,SYSTEM_ADMIN,Permitted
bob.smith@acme.example.com,U002,2025-01-15T09:35:00Z,LOGIN,User,READ_ONLY,Permitted
bob.smith@acme.example.com,U002,2025-01-15T14:20:00Z,EXPORT,User,DATA_EXPORT,Permitted
```

### Multi-Value Support

Users can have multiple rows that will be aggregated:
```csv
Email,Role
alice@company.com,Admin
alice@company.com,Manager
alice@company.com,Auditor
```

Results in: Alice gets all three roles (Admin, Manager, Auditor)

### Sample Files Included

| File | Rows | Use Case |
|------|------|----------|
| `sample_small_baseline.csv` | 10 | Quick testing and demos |
| `sample_medium_denormalized.csv` | 45 | Multi-row users, denied access |
| `sample_permission_creep.csv` | 20 | Shows role accumulation over time |

---

## 🐛 Troubleshooting

### Server won't start in Claude

**Symptom:** No MCP tools available in Claude

**Solutions:**
1. **Check Python path is absolute:**
   ```bash
   # Verify your path
   cd /path/to/okta-mcp-em-python
   pwd  # Copy this exact path
   ```

2. **Test server manually:**
   ```bash
   cd /path/to/okta-mcp-em-python
   source .venv/bin/activate
   python server.py
   # Should show: "Okta MCP Server running"
   ```

3. **Check Claude Desktop logs:**
   - macOS: `~/Library/Logs/Claude/mcp*.log`
   - Windows: `%APPDATA%\Claude\logs\mcp*.log`

---

### Connection test fails

**Symptom:** `okta_test` returns authentication error

**Solutions:**

1. **Verify OKTA_DOMAIN format:**
   ```bash
   # ✅ Correct
   OKTA_DOMAIN=dev-12345.okta.com
   
   # ❌ Wrong (no https://)
   OKTA_DOMAIN=https://dev-12345.okta.com
   ```

2. **Check API token hasn't expired:**
   - Log into Okta Admin Console
   - Go to **Security** > **API** > **Tokens**
   - Verify token status is "Active"

3. **Test token with curl:**
   ```bash
   curl -H "Authorization: SSWS YOUR_TOKEN_HERE" \
        https://your-domain.okta.com/api/v1/users/me
   ```

4. **Verify token permissions:**
   - Token needs governance management permissions
   - Admin user who created token needs IGA Admin role

---

### Rate limit errors

**Symptom:** `429 Too Many Requests` errors

**Solutions:**

1. **Check current limits:**
   ```
   Show me my rate limit status
   ```

2. **Wait for limit reset:**
   - Limits reset every 60 seconds
   - Server automatically throttles at 70% capacity

3. **Reduce concurrency:**
   - Default: 20 concurrent operations
   - Server uses adaptive delays between batches

---

### Users not found in Okta

**Symptom:** Stage 3 reports "User not found"

**Solutions:**

1. **Verify email format in CSV:**
   ```csv
   # ✅ Correct
   alice@company.com
   
   # ❌ Wrong
   alice@company.com  <-- (trailing space)
   Alice@company.com  <-- (case sensitive in some cases)
   ```

2. **Check user exists in Okta:**
   ```
   Search for user alice@company.com
   ```

3. **User might be deactivated:**
   - Only ACTIVE users can receive grants
   - Reactivate users in Okta Admin Console

---

### S3 sync fails

**Symptom:** Cannot sync files from S3

**Solutions:**

1. **Verify S3 is enabled in `.env`:**
   ```bash
   S3_ENABLED=true
   ```

2. **Test AWS credentials:**
   ```bash
   aws s3 ls s3://your-bucket-name/
   ```

3. **Check bucket permissions:**
   - IAM user needs `s3:ListBucket` and `s3:GetObject`
   - Verify bucket name is correct (no `s3://` prefix in config)

4. **Region mismatch:**
   ```bash
   AWS_REGION=us-east-1  # Must match bucket region
   ```

---

## 📚 Resources

### Official Documentation
- [Okta Identity Governance API](https://developer.okta.com/docs/api/openapi/okta-governance/guides/overview/)
- [Okta Entitlements API Reference](https://developer.okta.com/docs/api/openapi/okta-governance/management/tag/Entitlement/)
- [Model Context Protocol Specification](https://modelcontextprotocol.io/)
- [Claude Desktop Documentation](https://claude.ai/docs)

### Related Projects
- [MCP Servers Repository](https://github.com/modelcontextprotocol/servers)
- [Okta Python SDK](https://github.com/okta/okta-sdk-python)

### Author's Resources
- **Blog**: [iamse.blog](https://iamse.blog) - Identity & AI tutorials
- **LinkedIn**: [Connect for questions](https://linkedin.com/in/ashwinrama)

---

## 🎬 Demo Video

[Coming soon - Full workflow demonstration]

---

## 🙏 Acknowledgments

This project was built with significant AI assistance using Claude (Anthropic). It represents an experiment in "vibecoding" - using AI to accelerate development while maintaining human oversight for architecture, security, and design decisions.

Special thanks to:
- Okta Developer Relations team for API documentation
- MCP community for protocol development
- Everyone providing feedback and testing

---

## 📄 License

MIT License - See [LICENSE](LICENSE) for full details.

**Disclaimer**: This is an independent, experimental implementation created for educational and demonstration purposes. It is NOT an official Okta product and is not supported by Okta, Inc.

---

## 📞 Support & Contributing

**Found a bug?** Open an issue on GitHub

**Have a feature request?** Start a discussion

**Want to contribute?** PRs welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

---

**Author**: Ashwin Ramnarayanan  
**Role**: Senior Solutions Engineer @ Okta  
**Specialization**: Identity Governance & AI Integration  

**⚠️ Important**: This is an experimental project and not an official Okta product. Use at your own risk in non-production environments.
