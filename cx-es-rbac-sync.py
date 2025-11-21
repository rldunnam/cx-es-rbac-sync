#!/usr/bin/env python3
"""
Sync Checkmarx SAST team memberships to Elasticsearch role mappings.
"""

import requests
import json
from typing import Dict, List, Set
from collections import defaultdict
import argparse
import logging
from datetime import datetime

# ============================================================================
# CONFIGURATION - Update these values for your environment
# ============================================================================

# Checkmarx Configuration
CHECKMARX_URL = "https://checkmarx.example.com"
CHECKMARX_USERNAME = "admin"
CHECKMARX_PASSWORD = "your_password_here"

# Elasticsearch Configuration
ELASTICSEARCH_URL = "https://elasticsearch.example.com:9200"
ELASTICSEARCH_USERNAME = "elastic"
ELASTICSEARCH_PASSWORD = "your_password_here"

# SSL Certificate Configuration
# Set to False to disable SSL verification (not recommended for production)
ELASTICSEARCH_VERIFY_SSL = True
# Or specify path to CA certificate file
ELASTICSEARCH_CA_CERT = None  # Example: "/path/to/ca-cert.pem"

# Role Creation Configuration
# These settings control what permissions are granted to auto-created roles
ROLE_CONFIG = {
    "cluster": [],  # Cluster-level permissions
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
            "resources": ["*"]  # All Kibana spaces
        }
    ]
}

# Error log file
ERROR_LOG_FILE = "sync_errors.log"

# ============================================================================

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def log_error_to_file(message: str):
    """Log error messages to a separate error log file."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(ERROR_LOG_FILE, 'a') as f:
        f.write(f"[{timestamp}] {message}\n")


class CheckmarxClient:
    """Client for interacting with Checkmarx SAST API."""
    
    def __init__(self, base_url: str, username: str, password: str):
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self.token = None
        self.session = requests.Session()
    
    def authenticate(self):
        """Authenticate and obtain access token."""
        auth_url = f"{self.base_url}/cxrestapi/auth/identity/connect/token"
        
        # Try with access_control_api scope first (for user management APIs)
        data = {
            'username': self.username,
            'password': self.password,
            'grant_type': 'password',
            'scope': 'access_control_api',
            'client_id': 'resource_owner_client',
            'client_secret': '014DF517-39D1-4453-B7B3-9930C563627C'
        }
        
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        
        try:
            response = self.session.post(auth_url, data=data, headers=headers)
            response.raise_for_status()
            self.token = response.json()['access_token']
            self.session.headers.update({'Authorization': f'Bearer {self.token}'})
            logger.info("Successfully authenticated to Checkmarx")
        except requests.exceptions.RequestException as e:
            logger.error(f"Authentication failed: {e}")
            raise
    
    def get_teams(self) -> List[Dict]:
        """Get all teams from Checkmarx."""
        url = f"{self.base_url}/cxrestapi/auth/teams"
        
        try:
            response = self.session.get(url)
            response.raise_for_status()
            teams = response.json()
            logger.info(f"Retrieved {len(teams)} teams from Checkmarx")
            return teams
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get teams: {e}")
            raise
    
    def get_users_by_team(self, team_id: int, team_name: str = "") -> List[Dict]:
        """Get all users for a specific team."""
        url = f"{self.base_url}/cxrestapi/auth/teams/{team_id}/users"
        
        try:
            response = self.session.get(url)
            response.raise_for_status()
            users = response.json()
            return users
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get users for team {team_id} ({team_name}): {e}")
            return []
    
    def get_team_memberships(self) -> Dict[str, Set[str]]:
        """
        Get team memberships mapping.
        Returns: Dict mapping team names (last segment only) to sets of usernames.
        Logs conflicts to error file and skips conflicting teams.
        """
        memberships = defaultdict(set)
        team_name_mapping = defaultdict(list)  # Track which full names map to each short name
        teams = self.get_teams()
        
        # First pass: collect all mappings and detect conflicts
        for team in teams:
            full_team_name = team['fullName']
            team_id = team['id']
            
            # Extract last part of hierarchical name (e.g., /CxServer/DIT -> DIT)
            short_name = full_team_name.split('/')[-1]
            team_name_mapping[short_name].append((full_team_name, team_id))
        
        # Check for conflicts
        conflicts = {name: paths for name, paths in team_name_mapping.items() if len(paths) > 1}
        conflicting_full_names = set()
        
        if conflicts:
            logger.warning("=" * 80)
            logger.warning("CONFLICT DETECTED: Multiple Checkmarx teams map to the same role name")
            logger.warning("Conflicting teams will be skipped and logged to error file")
            logger.warning("=" * 80)
            
            log_error_to_file("=" * 80)
            log_error_to_file("TEAM NAME CONFLICTS DETECTED")
            log_error_to_file("=" * 80)
            
            for role_name, full_paths in conflicts.items():
                conflict_msg = f"\nRole name '{role_name}' conflicts with:"
                logger.warning(conflict_msg)
                log_error_to_file(conflict_msg)
                
                for full_path, _ in full_paths:
                    logger.warning(f"  - {full_path}")
                    log_error_to_file(f"  - {full_path}")
                    conflicting_full_names.add(full_path)
            
            log_error_to_file("\nThese teams were SKIPPED. To resolve:")
            log_error_to_file("1. Rename teams in Checkmarx to have unique last segments")
            log_error_to_file("2. Use --teams flag to manually specify which team to sync")
            log_error_to_file("=" * 80 + "\n")
            
            logger.warning(f"\nSkipping {len(conflicting_full_names)} conflicting teams")
            logger.warning(f"Details logged to: {ERROR_LOG_FILE}")
            logger.warning("=" * 80 + "\n")
        
        # Second pass: collect user memberships (skip conflicting teams)
        for team in teams:
            full_team_name = team['fullName']
            team_id = team['id']
            short_name = full_team_name.split('/')[-1]
            
            # Skip conflicting teams
            if full_team_name in conflicting_full_names:
                logger.info(f"SKIPPED (conflict): '{full_team_name}'")
                continue
            
            users = self.get_users_by_team(team_id, full_team_name)
            
            if users:
                for user in users:
                    username = user.get('userName', user.get('username', ''))
                    if username:
                        memberships[short_name].add(username)
                
                logger.info(f"Team '{full_team_name}' -> Role '{short_name}': {len(users)} users")
            else:
                logger.warning(f"Team '{full_team_name}': No users found")
        
        return dict(memberships)


class ElasticsearchClient:
    """Client for interacting with Elasticsearch Security API."""
    
    def __init__(self, base_url: str, username: str, password: str, verify_ssl=True, ca_cert=None, role_config=None):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.auth = (username, password)
        self.session.headers.update({'Content-Type': 'application/json'})
        self.role_config = role_config or ROLE_CONFIG
        
        # Configure SSL verification
        if ca_cert:
            self.session.verify = ca_cert
        else:
            self.session.verify = verify_ssl
        
        # Suppress InsecureRequestWarning if SSL verification is disabled
        if not verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    def get_role_mapping(self, role_name: str) -> Dict:
        """Get current role mapping for a role."""
        url = f"{self.base_url}/_security/role_mapping/{role_name}"
        
        try:
            response = self.session.get(url)
            if response.status_code == 404:
                return None
            response.raise_for_status()
            return response.json().get(role_name, {})
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get role mapping for {role_name}: {e}")
            return None
    
    def update_role_mapping(self, role_name: str, usernames: List[str], 
                          enabled: bool = True) -> bool:
        """
        Update role mapping with list of usernames.
        """
        url = f"{self.base_url}/_security/role_mapping/{role_name}"
        
        # Build the role mapping structure
        mapping = {
            "enabled": enabled,
            "roles": [role_name],
            "rules": {
                "any": [
                    {"field": {"username": username}} 
                    for username in usernames
                ]
            }
        }
        
        try:
            response = self.session.put(url, json=mapping)
            response.raise_for_status()
            logger.info(f"Updated role mapping '{role_name}' with {len(usernames)} users")
            return True
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to update role mapping {role_name}: {e}")
            return False
    
    def create_role_if_not_exists(self, role_name: str) -> bool:
        """Create a role if it doesn't exist, using the configured role template."""
        url = f"{self.base_url}/_security/role/{role_name}"
        
        # Check if role exists
        try:
            response = self.session.get(url)
            if response.status_code == 200:
                logger.info(f"Role '{role_name}' already exists")
                return True
        except:
            pass
        
        # Build role definition from config template
        role_def = {
            "cluster": self.role_config.get("cluster", []),
            "indices": [],
            "applications": []
        }
        
        # Process index permissions, replacing placeholders with actual role name
        for idx_config in self.role_config.get("indices", []):
            idx_def = {
                "names": idx_config["names"],
                "privileges": idx_config["privileges"]
            }
            
            # Add document-level security query if present
            if "query" in idx_config:
                # Replace $TEAM placeholder in the query structure
                query_with_team = self._replace_team_placeholder(idx_config["query"], role_name)
                idx_def["query"] = query_with_team
            
            role_def["indices"].append(idx_def)
        
        # Add application privileges (e.g., Kibana)
        for app_config in self.role_config.get("applications", []):
            role_def["applications"].append(app_config)
        
        # Create the role
        try:
            response = self.session.put(url, json=role_def)
            response.raise_for_status()
            logger.info(f"Created role '{role_name}' with document-level security")
            logger.debug(f"Role definition: {json.dumps(role_def, indent=2)}")
            return True
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to create role {role_name}: {e}")
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f"Response: {e.response.text}")
            return False
    
    def _replace_team_placeholder(self, obj, team_name: str):
        """Recursively replace $TEAM placeholder in query structure."""
        if isinstance(obj, dict):
            return {k: self._replace_team_placeholder(v, team_name) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._replace_team_placeholder(item, team_name) for item in obj]
        elif isinstance(obj, str) and "$TEAM" in obj:
            return obj.replace("$TEAM", team_name)
        else:
            return obj


def sync_team_memberships(cx_client: CheckmarxClient, 
                         es_client: ElasticsearchClient,
                         team_filter: List[str] = None,
                         create_roles: bool = False):
    """
    Sync Checkmarx team memberships to Elasticsearch role mappings.
    
    Args:
        cx_client: Checkmarx client instance
        es_client: Elasticsearch client instance
        team_filter: Optional list of team names to sync (sync all if None)
        create_roles: If True, create ES roles that don't exist
    """
    logger.info("Starting team membership sync")
    
    # Get team memberships from Checkmarx
    memberships = cx_client.get_team_memberships()
    
    # Filter teams if specified
    if team_filter:
        memberships = {k: v for k, v in memberships.items() if k in team_filter}
    
    # Sync each team to Elasticsearch
    success_count = 0
    fail_count = 0
    
    for team_name, usernames in memberships.items():
        logger.info(f"\nProcessing team: {team_name}")
        
        # Optionally create role if it doesn't exist
        if create_roles:
            es_client.create_role_if_not_exists(team_name)
        
        # Update role mapping
        if usernames:
            if es_client.update_role_mapping(team_name, list(usernames)):
                success_count += 1
            else:
                fail_count += 1
        else:
            logger.warning(f"Team '{team_name}' has no users, skipping")
    
    logger.info(f"\nSync complete: {success_count} successful, {fail_count} failed")


def main():
    parser = argparse.ArgumentParser(
        description='Sync Checkmarx SAST team memberships to Elasticsearch role mappings'
    )
    
    # Checkmarx arguments (optional - use config variables if not provided)
    parser.add_argument('--cx-url', default=CHECKMARX_URL, help='Checkmarx base URL')
    parser.add_argument('--cx-user', default=CHECKMARX_USERNAME, help='Checkmarx username')
    parser.add_argument('--cx-password', default=CHECKMARX_PASSWORD, help='Checkmarx password')
    
    # Elasticsearch arguments (optional - use config variables if not provided)
    parser.add_argument('--es-url', default=ELASTICSEARCH_URL, help='Elasticsearch base URL')
    parser.add_argument('--es-user', default=ELASTICSEARCH_USERNAME, help='Elasticsearch username')
    parser.add_argument('--es-password', default=ELASTICSEARCH_PASSWORD, help='Elasticsearch password')
    parser.add_argument('--es-verify-ssl', type=lambda x: x.lower() == 'true', 
                       default=ELASTICSEARCH_VERIFY_SSL, 
                       help='Verify SSL certificate (true/false)')
    parser.add_argument('--es-ca-cert', default=ELASTICSEARCH_CA_CERT, 
                       help='Path to CA certificate file')
    
    # Optional arguments
    parser.add_argument('--teams', nargs='+', help='Specific teams to sync (default: all)')
    parser.add_argument('--create-roles', action='store_true', 
                       help='Create ES roles if they don\'t exist')
    parser.add_argument('--dry-run', action='store_true', 
                       help='Show what would be synced without making changes')
    
    args = parser.parse_args()
    
    try:
        # Initialize clients
        cx_client = CheckmarxClient(args.cx_url, args.cx_user, args.cx_password)
        cx_client.authenticate()
        
        es_client = ElasticsearchClient(args.es_url, args.es_user, args.es_password, 
                                       args.es_verify_ssl, args.es_ca_cert)
        
        # Perform sync
        if args.dry_run:
            logger.info("DRY RUN MODE - No changes will be made")
            memberships = cx_client.get_team_memberships()
            if args.teams:
                memberships = {k: v for k, v in memberships.items() if k in args.teams}
            
            for team, users in memberships.items():
                print(f"\nTeam: {team}")
                print(f"Users ({len(users)}): {', '.join(sorted(users))}")
        else:
            sync_team_memberships(cx_client, es_client, args.teams, args.create_roles)
        
    except Exception as e:
        logger.error(f"Script failed: {e}")
        return 1
    
    return 0


if __name__ == '__main__':
    exit(main())
