# Checkmarx to Elasticsearch RBAC Sync

Automatically synchronize Checkmarx SAST team memberships to Elasticsearch role mappings, enabling seamless role-based access control (RBAC) across your security tooling.

## Overview

This tool bridges Checkmarx SAST and Elasticsearch by:
- Extracting team memberships from Checkmarx
- Creating corresponding roles in Elasticsearch (optional)
- Mapping users to Elasticsearch roles based on their Checkmarx team membership
- Maintaining synchronization through scheduled runs

**Key Features:**
- 🔒 Secure credential management with multiple input methods
- 🔄 Automatic retry with exponential backoff
- ⚡ Idempotent updates (skips unchanged mappings)
- 🔍 Comprehensive audit logging
- ✅ Input validation and sanitization
- 📊 Detailed sync statistics and reporting
- 🛡️ Token refresh for long-running operations

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Role Configuration](#role-configuration)
- [Scheduling](#scheduling)
- [Troubleshooting](#troubleshooting)
- [Security Considerations](#security-considerations)
- [Examples](#examples)

## Prerequisites

- Python 3.7 or higher
- Network access to both Checkmarx and Elasticsearch APIs
- Credentials with appropriate permissions:
  - **Checkmarx**: User with `access_control_api` scope (typically admin)
  - **Elasticsearch**: User with `manage_security` cluster privilege

### Python Dependencies

```bash
pip install requests
```

No other external dependencies required.

## Installation

1. **Clone or download the script:**
   ```bash
   curl -O https://your-repo/cx-es-rbac-sync.py
   chmod +x cx-es-rbac-sync.py
   ```

2. **Create a `.env` file** (recommended):
   ```bash
   cp .env.example .env
   # Edit .env with your credentials
   ```

3. **Verify connectivity:**
   ```bash
   ./cx-es-rbac-sync.py --dry-run
   ```

## Configuration

### Configuration Priority

The script uses the following priority order (highest to lowest):

1. **Command-line arguments** (e.g., `--cx-password`)
2. **.env file** (specified by `--env-file` or default `.env`)
3. **Environment variables** (e.g., `export CHECKMARX_PASSWORD=...`)
4. **Default values** (where applicable)

### .env File Format

Create a `.env` file in the same directory as the script:

```bash
# Checkmarx Configuration
CHECKMARX_URL=https://checkmarx.example.com
CHECKMARX_USERNAME=admin
CHECKMARX_PASSWORD=your_secure_password_here
CHECKMARX_CLIENT_SECRET=014DF517-39D1-4453-B7B3-9930C563627C

# Elasticsearch Configuration
ELASTICSEARCH_URL=https://elasticsearch.example.com:9200
ELASTICSEARCH_USERNAME=elastic
ELASTICSEARCH_PASSWORD=your_elastic_password_here

# SSL Configuration (optional)
ELASTICSEARCH_VERIFY_SSL=true
# ELASTICSEARCH_CA_CERT=/path/to/ca-cert.pem
```

**Important:** Add `.env` to your `.gitignore` to prevent accidentally committing credentials!

```bash
echo ".env" >> .gitignore
```

### Environment Variables

Alternatively, use environment variables:

```bash
export CHECKMARX_URL=https://checkmarx.example.com
export CHECKMARX_USERNAME=admin
export CHECKMARX_PASSWORD=your_password
export ELASTICSEARCH_URL=https://elasticsearch.example.com:9200
export ELASTICSEARCH_USERNAME=elastic
export ELASTICSEARCH_PASSWORD=your_password

./cx-es-rbac-sync.py
```

### Configuration Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `CHECKMARX_URL` | Yes | - | Checkmarx base URL (e.g., `https://checkmarx.company.com`) |
| `CHECKMARX_USERNAME` | Yes | - | Checkmarx username with API access |
| `CHECKMARX_PASSWORD` | Yes | - | Checkmarx password |
| `CHECKMARX_CLIENT_SECRET` | No | Default client secret | OAuth client secret (use default unless customized) |
| `ELASTICSEARCH_URL` | Yes | - | Elasticsearch base URL including port |
| `ELASTICSEARCH_USERNAME` | Yes | - | Elasticsearch username with security permissions |
| `ELASTICSEARCH_PASSWORD` | Yes | - | Elasticsearch password |
| `ELASTICSEARCH_VERIFY_SSL` | No | `true` | Verify SSL certificates (`true`/`false`) |
| `ELASTICSEARCH_CA_CERT` | No | - | Path to CA certificate file |

## Usage

### Basic Usage

```bash
# Sync all teams using .env file
./cx-es-rbac-sync.py

# Use custom env file
./cx-es-rbac-sync.py --env-file /etc/cx-sync/production.env

# Sync specific teams only
./cx-es-rbac-sync.py --teams Engineering QA Security

# Create roles that don't exist in Elasticsearch
./cx-es-rbac-sync.py --create-roles

# Force update even if no changes detected
./cx-es-rbac-sync.py --force
```

### Command-Line Options

```
Usage: cx-es-rbac-sync.py [OPTIONS]

Options:
  --env-file PATH           Path to .env file (default: .env)
  
  Checkmarx Options:
  --cx-url URL             Checkmarx base URL
  --cx-user USERNAME       Checkmarx username
  --cx-password PASSWORD   Checkmarx password
  --cx-client-secret SEC   OAuth client secret
  
  Elasticsearch Options:
  --es-url URL             Elasticsearch base URL
  --es-user USERNAME       Elasticsearch username
  --es-password PASSWORD   Elasticsearch password
  --es-verify-ssl BOOL     Verify SSL certificates (true/false)
  --es-ca-cert PATH        Path to CA certificate file
  
  Sync Options:
  --teams TEAM [TEAM ...]  Specific teams to sync (default: all)
  --create-roles           Create ES roles if they don't exist
  --force                  Force update even if no changes detected
  --dry-run                Show what would be synced without making changes
  
  General Options:
  --verbose, -v            Enable verbose logging
  --help, -h               Show this help message
```

### Dry Run Mode

Test your configuration without making any changes:

```bash
./cx-es-rbac-sync.py --dry-run
```

Output:
```
================================================================================
DRY RUN MODE - No changes will be made
================================================================================

TEAM MEMBERSHIPS THAT WOULD BE SYNCED
================================================================================

Team: Engineering
Users (5): alice@example.com, bob@example.com, charlie@example.com, ...

Team: Security
Users (3): david@example.com, eve@example.com, frank@example.com

================================================================================
```

### Verbose Mode

Enable detailed logging for troubleshooting:

```bash
./cx-es-rbac-sync.py --verbose
```

## Role Configuration

### Default Role Permissions

By default, roles are created with the following permissions (configured in `ROLE_CONFIG`):

```python
ROLE_CONFIG = {
    "cluster": [],  # No cluster-level permissions
    "indices": [
        {
            "names": ["issues*", "scans*", "assets*"],
            "privileges": ["read", "read_cross_cluster"],
            "query": {
                "term": {
                    "saltminer.asset.attribute.team": "$TEAM"
                }
            }
        }
    ],
    "applications": [
        {
            "application": "kibana-.kibana",
            "privileges": ["read"],
            "resources": ["*"]
        }
    ]
}
```

### Document-Level Security

The `$TEAM` placeholder in the query is automatically replaced with the team name, enabling document-level security:

```json
{
  "query": {
    "term": {
      "saltminer.asset.attribute.team": "Engineering"
    }
  }
}
```

This ensures users only see documents where the `team` field matches their team.

### Customizing Role Permissions

To customize role permissions, edit the `ROLE_CONFIG` dictionary in the script:

```python
ROLE_CONFIG = {
    "cluster": ["monitor"],  # Add cluster monitoring
    "indices": [
        {
            "names": ["custom-index-*"],
            "privileges": ["read", "write"],  # Add write access
            "query": {
                "term": {
                    "custom.field": "$TEAM"
                }
            }
        }
    ],
    "applications": [
        {
            "application": "kibana-.kibana",
            "privileges": ["all"],  # Full Kibana access
            "resources": ["space:$TEAM"]  # Restrict to team space
        }
    ]
}
```

### Team Name Mapping

Checkmarx uses hierarchical team names (e.g., `/CxServer/Company/Engineering`). The script:
1. Extracts the last segment as the role name (`Engineering`)
2. Detects conflicts if multiple teams map to the same name
3. Logs conflicts to `sync_errors.log` and skips conflicting teams

**Example:**
```
Checkmarx Team                    → Elasticsearch Role
/CxServer/Company/Engineering     → Engineering
/CxServer/Company/QA              → QA
/CxServer/Department/Engineering  → ⚠️  CONFLICT - skipped
```

**Resolution:** Rename teams in Checkmarx or use `--teams` to specify which team to sync.

## Scheduling

### Cron (Linux/macOS)

Run sync every 6 hours:

```bash
# Edit crontab
crontab -e

# Add entry (runs at 00:00, 06:00, 12:00, 18:00)
0 */6 * * * /usr/local/bin/cx-es-rbac-sync.py >> /var/log/cx-sync.log 2>&1
```

### Systemd Timer (Linux)

Create `/etc/systemd/system/cx-sync.service`:

```ini
[Unit]
Description=Checkmarx to Elasticsearch RBAC Sync
After=network-online.target

[Service]
Type=oneshot
User=cx-sync
EnvironmentFile=/etc/cx-sync/.env
ExecStart=/usr/local/bin/cx-es-rbac-sync.py
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Create `/etc/systemd/system/cx-sync.timer`:

```ini
[Unit]
Description=Run CX-ES Sync every 6 hours

[Timer]
OnBootSec=10min
OnUnitActiveSec=6h
Persistent=true

[Install]
WantedBy=timers.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable cx-sync.timer
sudo systemctl start cx-sync.timer

# Check status
sudo systemctl status cx-sync.timer
```

### Windows Task Scheduler

1. Open Task Scheduler
2. Create Basic Task
3. Set trigger (e.g., Daily, repeat every 6 hours)
4. Action: Start a program
   - Program: `python.exe`
   - Arguments: `C:\path\to\cx-es-rbac-sync.py`
   - Start in: `C:\path\to\`

### Docker/Kubernetes

**Dockerfile:**

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY cx-es-rbac-sync.py .
RUN pip install requests

CMD ["python", "cx-es-rbac-sync.py"]
```

**Kubernetes CronJob:**

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: cx-es-sync
spec:
  schedule: "0 */6 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: cx-sync
            image: your-registry/cx-es-sync:latest
            env:
            - name: CHECKMARX_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: cx-sync-secrets
                  key: checkmarx-password
            - name: ELASTICSEARCH_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: cx-sync-secrets
                  key: elasticsearch-password
            envFrom:
            - configMapRef:
                name: cx-sync-config
          restartPolicy: OnFailure
```

## Troubleshooting

### Common Issues

#### 1. Authentication Failed

**Error:** `Authentication failed: 401 Unauthorized`

**Solutions:**
- Verify credentials in `.env` file
- Ensure user has `access_control_api` scope in Checkmarx
- Check if account is locked or password expired
- Try authenticating manually via Checkmarx UI

#### 2. SSL Certificate Verification Failed

**Error:** `SSL: CERTIFICATE_VERIFY_FAILED`

**Solutions:**
```bash
# Option 1: Provide CA certificate
./cx-es-rbac-sync.py --es-ca-cert /path/to/ca-cert.pem

# Option 2: Disable SSL verification (NOT RECOMMENDED for production)
./cx-es-rbac-sync.py --es-verify-ssl false
```

#### 3. Team Name Conflicts

**Error:** `CONFLICT DETECTED: Multiple Checkmarx teams map to the same role name`

**Solutions:**
- Check `sync_errors.log` for conflicting team paths
- Rename teams in Checkmarx to have unique last segments
- Use `--teams` flag to specify which team to sync:
  ```bash
  ./cx-es-rbac-sync.py --teams Engineering
  ```

#### 4. Permission Denied

**Error:** `Failed to create role: 403 Forbidden`

**Solutions:**
- Ensure Elasticsearch user has `manage_security` cluster privilege
- Grant required role privileges:
  ```bash
  # Example: Grant manage_security to user
  curl -X POST "https://elasticsearch:9200/_security/user/elastic/_password" \
    -H 'Content-Type: application/json' \
    -d '{"password" : "newpassword"}'
  ```

#### 5. Connection Timeouts

**Error:** `Request failed: Connection timeout`

**Solutions:**
- Check network connectivity to Checkmarx/Elasticsearch
- Verify firewall rules allow outbound connections
- Increase timeout in script (edit `REQUEST_TIMEOUT` constant)
- Check if services are behind a proxy (configure `HTTP_PROXY` env var)

### Log Files

The script generates several log files:

1. **sync_errors.log** - Team name conflicts and critical errors
2. **sync_audit.log** - JSON audit trail of all operations
3. **stdout/stderr** - Real-time operation logs

**View recent errors:**
```bash
tail -f sync_errors.log
```

**View audit trail:**
```bash
cat sync_audit.log | jq '.'
```

### Verbose Debugging

Enable verbose mode to see detailed API interactions:

```bash
./cx-es-rbac-sync.py --verbose
```

## Security Considerations

### Credential Management

**Best Practices:**

1. **Never commit credentials to version control**
   ```bash
   echo ".env" >> .gitignore
   ```

2. **Use restrictive file permissions**
   ```bash
   chmod 600 .env
   chown cx-sync:cx-sync .env
   ```

3. **Use a dedicated service account** with minimum required permissions

4. **Rotate credentials regularly** (every 90 days recommended)

5. **Use secret management systems** in production:
   - AWS Secrets Manager
   - HashiCorp Vault
   - Azure Key Vault
   - Kubernetes Secrets

### Network Security

1. **Use HTTPS/TLS** for all API communications (enforce `ELASTICSEARCH_VERIFY_SSL=true`)
2. **Implement network segmentation** - restrict access to Checkmarx/Elasticsearch
3. **Use VPN/bastion hosts** for cross-network communication
4. **Configure firewall rules** to allow only required outbound connections

### Audit & Compliance

1. **Review audit logs regularly:**
   ```bash
   grep "failed" sync_audit.log | jq '.'
   ```

2. **Monitor for anomalies:**
   - Unexpected role creations
   - Failed authentication attempts
   - Large changes in team membership

3. **Implement alerting** on sync failures:
   ```bash
   # Example: Alert on non-zero exit code
   ./cx-es-rbac-sync.py || send-alert "CX sync failed"
   ```

### Least Privilege

**Checkmarx Permissions:**
- Read access to teams and users
- No write access required

**Elasticsearch Permissions:**
- `manage_security` cluster privilege
- Read/write access to `_security` API
- No data access required

## Examples

### Example 1: Initial Setup and Dry Run

```bash
# Create .env file
cat > .env << 'EOF'
CHECKMARX_URL=https://checkmarx.company.com
CHECKMARX_USERNAME=sync-service
CHECKMARX_PASSWORD=secure-password-123
ELASTICSEARCH_URL=https://elasticsearch.company.com:9200
ELASTICSEARCH_USERNAME=sync-service
ELASTICSEARCH_PASSWORD=elastic-password-456
ELASTICSEARCH_VERIFY_SSL=true
EOF

# Secure the file
chmod 600 .env

# Test with dry run
./cx-es-rbac-sync.py --dry-run

# Run actual sync with role creation
./cx-es-rbac-sync.py --create-roles
```

### Example 2: Sync Specific Teams

```bash
# Only sync Engineering and Security teams
./cx-es-rbac-sync.py --teams Engineering Security --create-roles
```

### Example 3: Production Deployment with Custom Config

```bash
# Production environment with custom env file
./cx-es-rbac-sync.py \
  --env-file /etc/cx-sync/production.env \
  --create-roles \
  --verbose
```

### Example 4: Override Single Value

```bash
# Use .env for most config, but override Elasticsearch password
./cx-es-rbac-sync.py --es-password new-password-123
```

### Example 5: Automated Monitoring Script

```bash
#!/bin/bash
# sync-with-monitoring.sh

LOG_FILE="/var/log/cx-sync.log"
ERROR_FILE="/var/log/cx-sync-error.log"

# Run sync
if /usr/local/bin/cx-es-rbac-sync.py >> "$LOG_FILE" 2>> "$ERROR_FILE"; then
    echo "[$(date)] Sync completed successfully" >> "$LOG_FILE"
else
    echo "[$(date)] Sync failed with exit code $?" >> "$ERROR_FILE"
    # Send alert
    mail -s "CX Sync Failed" admin@company.com < "$ERROR_FILE"
fi

# Rotate logs
find /var/log -name "cx-sync*.log" -mtime +30 -delete
```

## Return Codes

The script uses the following exit codes:

| Code | Meaning |
|------|---------|
| 0 | Success (all teams synced successfully) |
| 1 | Error (configuration error, API failure, or some teams failed) |
| 130 | Interrupted by user (Ctrl+C) |

Use these codes in automation:

```bash
if ./cx-es-rbac-sync.py; then
    echo "Sync successful"
else
    echo "Sync failed with code $?"
    exit 1
fi
```

## Performance Tuning

For environments with many teams/users:

1. **Adjust retry settings** in script:
   ```python
   MAX_RETRIES = 5
   REQUEST_TIMEOUT = 60
   ```

2. **Use team filtering** to split sync across multiple runs:
   ```bash
   # Split by team prefix
   ./cx-es-rbac-sync.py --teams Engineering-*
   ./cx-es-rbac-sync.py --teams Security-*
   ```

3. **Enable idempotency** (default) to skip unchanged mappings

4. **Monitor execution time** and adjust schedule accordingly

## Support

For issues, questions, or contributions:

- **Issue Tracker:** [GitHub Issues](https://github.com/your-org/cx-es-sync/issues)
- **Documentation:** [Wiki](https://github.com/your-org/cx-es-sync/wiki)
- **Security Issues:** security@company.com (do not file public issues)

## License

[Your License Here]

## Changelog

### Version 2.0.0 (Current)
- ✨ Added automatic token refresh
- ✨ Implemented retry logic with exponential backoff
- ✨ Added idempotency checks
- ✨ Comprehensive audit logging
- ✨ Input validation and sanitization
- 🔒 Enhanced security features
- 📊 Detailed sync statistics
- 🐛 Fixed bare except clauses
- 🔧 Improved error handling

### Version 1.0.0
- Initial release
- Basic sync functionality
- Role creation support

---

**Last Updated:** December 2024