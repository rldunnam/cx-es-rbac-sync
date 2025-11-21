# Checkmarx to Elasticsearch Role Sync Script

## NAME
    sync_script.py - Sync Checkmarx SAST team memberships to Elasticsearch role mappings

## SYNOPSIS
    python3 sync_script.py [OPTIONS]

## DESCRIPTION
    This script synchronizes team memberships from Checkmarx SAST to Elasticsearch role 
    mappings. It extracts the last segment of Checkmarx hierarchical team names and creates 
    or updates corresponding role mappings in Elasticsearch.
    
    For example: Checkmarx team "/CxServer/DIT" creates an Elasticsearch role mapping 
    named "DIT" with all team members.

## OPTIONS

### Checkmarx Configuration
    --cx-url URL
        Checkmarx base URL
        Default: Value from CHECKMARX_URL configuration variable
        Example: https://checkmarx.example.com

    --cx-user USERNAME
        Checkmarx username for API authentication
        Default: Value from CHECKMARX_USERNAME configuration variable

    --cx-password PASSWORD
        Checkmarx password for API authentication
        Default: Value from CHECKMARX_PASSWORD configuration variable

### Elasticsearch Configuration
    --es-url URL
        Elasticsearch base URL
        Default: Value from ELASTICSEARCH_URL configuration variable
        Example: https://elasticsearch.example.com:9200

    --es-user USERNAME
        Elasticsearch username for API authentication
        Default: Value from ELASTICSEARCH_USERNAME configuration variable

    --es-password PASSWORD
        Elasticsearch password for API authentication
        Default: Value from ELASTICSEARCH_PASSWORD configuration variable

    --es-verify-ssl {true|false}
        Verify SSL certificate when connecting to Elasticsearch
        Default: Value from ELASTICSEARCH_VERIFY_SSL configuration variable (true)
        Set to 'false' to disable SSL verification (not recommended for production)

    --es-ca-cert PATH
        Path to CA certificate file for SSL verification
        Default: Value from ELASTICSEARCH_CA_CERT configuration variable (None)
        Example: /path/to/ca-certificate.pem

### Sync Options
    --teams TEAM [TEAM ...]
        Sync only specific teams (space-separated list)
        Default: Sync all teams
        Example: --teams DIT Engineering QA

    --create-roles
        Automatically create Elasticsearch roles if they don't exist
        Uses the ROLE_CONFIG template defined in the script
        Default: Do not create roles (sync will fail if role doesn't exist)

    --dry-run
        Preview what would be synced without making any changes
        Shows team memberships that would be updated
        Does not modify Elasticsearch

    -h, --help
        Display help message and exit

## CONFIGURATION FILE
    The script uses configuration variables at the top of the file for default values:
    
    - CHECKMARX_URL
    - CHECKMARX_USERNAME
    - CHECKMARX_PASSWORD
    - ELASTICSEARCH_URL
    - ELASTICSEARCH_USERNAME
    - ELASTICSEARCH_PASSWORD
    - ELASTICSEARCH_VERIFY_SSL
    - ELASTICSEARCH_CA_CERT
    - ROLE_CONFIG (role creation template)
    - ERROR_LOG_FILE (default: sync_errors.log)

## ROLE CREATION
    When --create-roles is used, roles are created with permissions defined in ROLE_CONFIG:
    
    Default Configuration:
    - Indices: issues*, scans*, assets*
    - Privileges: read, read_cross_cluster
    - Document-level security: Only documents where saltminer.asset.attribute.team matches role name
    - Kibana: Read access to all spaces

## CONFLICT HANDLING
    If multiple Checkmarx teams have the same last segment (e.g., /CxServer/DIT and 
    /CxServer/Backup/DIT), the script will:
    
    1. Log conflicts to sync_errors.log
    2. Skip all conflicting teams
    3. Continue processing non-conflicting teams
    4. Display warnings in console output

## EXIT STATUS
    0   Success
    1   Error occurred during execution

## FILES
    sync_errors.log
        Error log file containing team name conflicts and other errors

## EXAMPLES

    Basic sync using configured defaults:
        python3 sync_script.py

    Dry run to preview changes:
        python3 sync_script.py --dry-run

    Sync specific teams only:
        python3 sync_script.py --teams DIT Engineering QA

    Create roles automatically if they don't exist:
        python3 sync_script.py --create-roles

    Disable SSL verification (development only):
        python3 sync_script.py --es-verify-ssl false

    Use custom CA certificate:
        python3 sync_script.py --es-ca-cert /etc/ssl/certs/es-ca.pem

    Override configured Checkmarx URL:
        python3 sync_script.py --cx-url https://checkmarx-prod.example.com

    Full example with multiple options:
        python3 sync_script.py \
            --cx-url https://checkmarx.example.com \
            --es-url https://elasticsearch.example.com:9200 \
            --es-verify-ssl false \
            --teams DIT Engineering \
            --create-roles \
            --dry-run

## AUTHENTICATION
    Checkmarx:
    - Uses OAuth2 password grant flow
    - Requires access_control_api scope
    - User must have "manage-users" permission

    Elasticsearch:
    - Uses HTTP Basic Authentication
    - User must have manage_security privilege to create/update role mappings

## LOGGING
    Console Output:
    - INFO: Normal operations and progress
    - WARNING: Non-critical issues (conflicts, skipped teams)
    - ERROR: Failed operations
    
    File Output:
    - sync_errors.log: Detailed conflict information and errors

## NOTES
    - Team names are extracted from the last segment of Checkmarx hierarchical paths
    - Role mappings completely replace existing mappings (not merged)
    - Usernames must match between Checkmarx and Elasticsearch
    - The script requires Python 3.6+ and the 'requests' library

## DEPENDENCIES
    pip install requests

## AUTHOR
    Created for syncing Checkmarx SAST teams to Elasticsearch role-based access control

## SEE ALSO
    Checkmarx API Documentation: https://checkmarx.com/resource/documents/en/34965-8158-authentication.html
    Elasticsearch Security API: https://www.elastic.co/guide/en/elasticsearch/reference/current/security-api.html
