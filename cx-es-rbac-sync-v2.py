#!/usr/bin/env python3
"""
Sync Checkmarx SAST team memberships to Elasticsearch role mappings.
"""

import requests
import json
import os
import re
import time
from typing import Dict, List, Set, Optional
from collections import defaultdict
import argparse
import logging
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

# ============================================================================
# CONFIGURATION
# ============================================================================

# Default .env file location
DEFAULT_ENV_FILE = '.env'

# Checkmarx client configuration
CHECKMARX_CLIENT_ID = 'resource_owner_client'
# Note: This is a well-known default. For production, consider making it configurable.

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

# Retry configuration
MAX_RETRIES = 3
RETRY_DELAY = 2  # seconds
RETRY_BACKOFF = 2  # multiplier for exponential backoff

# Request timeout
REQUEST_TIMEOUT = 30  # seconds

# Token expiration buffer (refresh if token expires within this time)
TOKEN_EXPIRY_BUFFER = 300  # 5 minutes

# Error log file
ERROR_LOG_FILE = "sync_errors.log"

# Audit log file
AUDIT_LOG_FILE = "sync_audit.log"

# ============================================================================

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def load_env_file(env_file: str) -> Dict[str, str]:
    """
    Load environment variables from a .env file.
    
    Args:
        env_file: Path to .env file
        
    Returns:
        Dictionary of environment variables
    """
    env_vars = {}
    
    if not os.path.exists(env_file):
        return env_vars
    
    try:
        with open(env_file, 'r') as f:
            for line in f:
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                
                # Parse KEY=VALUE
                if '=' in line:
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    # Remove quotes if present
                    if value.startswith('"') and value.endswith('"'):
                        value = value[1:-1]
                    elif value.startswith("'") and value.endswith("'"):
                        value = value[1:-1]
                    
                    env_vars[key] = value
        
        logger.info(f"Loaded configuration from {env_file}")
        return env_vars
        
    except Exception as e:
        logger.warning(f"Failed to load {env_file}: {e}")
        return env_vars


def get_config_value(key: str, cli_value: Optional[str], env_vars: Dict[str, str], 
                     default: Optional[str] = None, required: bool = False) -> Optional[str]:
    """
    Get configuration value with priority: CLI args > .env file > environment > default
    
    Args:
        key: Configuration key name (environment variable name)
        cli_value: Value from CLI argument
        env_vars: Dictionary from .env file
        default: Default value if not found
        required: Whether this value is required
        
    Returns:
        Configuration value or None
        
    Raises:
        ValueError: If required value is not found
    """
    # Priority 1: CLI argument
    if cli_value is not None:
        return cli_value
    
    # Priority 2: .env file
    if key in env_vars:
        return env_vars[key]
    
    # Priority 3: Environment variable
    if key in os.environ:
        return os.environ[key]
    
    # Priority 4: Default value
    if default is not None:
        return default
    
    # If required and not found, raise error
    if required:
        raise ValueError(
            f"Required configuration '{key}' not found. "
            f"Provide via --{key.lower().replace('_', '-')} argument, "
            f".env file, or {key} environment variable."
        )
    
    return None


def validate_url(url: str, name: str = "URL") -> bool:
    """
    Validate URL format.
    
    Args:
        url: URL to validate
        name: Name for error messages
        
    Returns:
        True if valid
        
    Raises:
        ValueError: If URL is invalid
    """
    if not url:
        raise ValueError(f"{name} cannot be empty")
    
    try:
        result = urlparse(url)
        if not all([result.scheme, result.netloc]):
            raise ValueError(f"Invalid {name}: {url}")
        if result.scheme not in ['http', 'https']:
            raise ValueError(f"{name} must use http or https scheme: {url}")
        return True
    except Exception as e:
        raise ValueError(f"Invalid {name}: {url} - {e}")


def validate_team_name(name: str) -> bool:
    """
    Validate team/role name to prevent injection attacks.
    
    Args:
        name: Team/role name to validate
        
    Returns:
        True if valid
        
    Raises:
        ValueError: If name is invalid
    """
    if not name:
        raise ValueError("Team name cannot be empty")
    
    if len(name) > 255:
        raise ValueError(f"Team name too long (max 255 chars): {name}")
    
    # Allow alphanumeric, spaces, hyphens, underscores, forward slashes (for hierarchical names)
    if not re.match(r'^[\w\s\-/]+$', name):
        raise ValueError(f"Team name contains invalid characters: {name}")
    
    return True


def validate_username(username: str) -> bool:
    """
    Validate username format.
    
    Args:
        username: Username to validate
        
    Returns:
        True if valid
        
    Raises:
        ValueError: If username is invalid
    """
    if not username:
        raise ValueError("Username cannot be empty")
    
    if len(username) > 255:
        raise ValueError(f"Username too long (max 255 chars): {username}")
    
    # Basic validation - adjust pattern as needed for your environment
    if not re.match(r'^[\w\-@.]+$', username):
        raise ValueError(f"Username contains invalid characters: {username}")
    
    return True


def log_error_to_file(message: str):
    """Log error messages to a separate error log file."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    try:
        with open(ERROR_LOG_FILE, 'a') as f:
            f.write(f"[{timestamp}] {message}\n")
    except Exception as e:
        logger.error(f"Failed to write to error log: {e}")


def audit_log(action: str, details: Dict):
    """
    Write audit trail to secure audit log.
    
    Args:
        action: Action being performed
        details: Dictionary of details (will be sanitized)
    """
    timestamp = datetime.utcnow().isoformat()
    
    # Sanitize details - remove sensitive information
    sanitized_details = {}
    for key, value in details.items():
        if any(sensitive in key.lower() for sensitive in ['password', 'token', 'secret', 'credential']):
            sanitized_details[key] = "***REDACTED***"
        else:
            sanitized_details[key] = value
    
    audit_entry = {
        "timestamp": timestamp,
        "action": action,
        "details": sanitized_details
    }
    
    try:
        with open(AUDIT_LOG_FILE, 'a') as f:
            f.write(json.dumps(audit_entry) + "\n")
    except Exception as e:
        logger.error(f"Failed to write to audit log: {e}")


def retry_with_backoff(func):
    """
    Decorator to retry function with exponential backoff.
    
    Args:
        func: Function to wrap
        
    Returns:
        Wrapped function
    """
    def wrapper(*args, **kwargs):
        delay = RETRY_DELAY
        last_exception = None
        
        for attempt in range(MAX_RETRIES):
            try:
                return func(*args, **kwargs)
            except requests.exceptions.RequestException as e:
                last_exception = e
                if attempt < MAX_RETRIES - 1:
                    logger.warning(f"Request failed (attempt {attempt + 1}/{MAX_RETRIES}), "
                                 f"retrying in {delay}s: {e}")
                    time.sleep(delay)
                    delay *= RETRY_BACKOFF
                else:
                    logger.error(f"Request failed after {MAX_RETRIES} attempts: {e}")
        
        raise last_exception
    
    return wrapper


class CheckmarxClient:
    """Client for interacting with Checkmarx SAST API."""
    
    def __init__(self, base_url: str, username: str, password: str, client_secret: Optional[str] = None):
        validate_url(base_url, "Checkmarx URL")
        validate_username(username)
        
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self.client_secret = client_secret or '014DF517-39D1-4453-B7B3-9930C563627C'
        self.token = None
        self.token_expiry = None
        self.session = requests.Session()
    
    def __enter__(self):
        """Context manager entry."""
        self.authenticate()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup session."""
        self.close()
    
    def close(self):
        """Close the session."""
        if self.session:
            self.session.close()
    
    def _is_token_valid(self) -> bool:
        """Check if current token is still valid."""
        if not self.token or not self.token_expiry:
            return False
        
        # Check if token will expire soon
        time_until_expiry = self.token_expiry - time.time()
        return time_until_expiry > TOKEN_EXPIRY_BUFFER
    
    def _ensure_authenticated(self):
        """Ensure we have a valid token, refreshing if necessary."""
        if not self._is_token_valid():
            logger.info("Token expired or missing, re-authenticating...")
            self.authenticate()
    
    @retry_with_backoff
    def authenticate(self) -> bool:
        """Authenticate and obtain access token."""
        auth_url = f"{self.base_url}/cxrestapi/auth/identity/connect/token"
        
        data = {
            'username': self.username,
            'password': self.password,
            'grant_type': 'password',
            'scope': 'access_control_api',
            'client_id': CHECKMARX_CLIENT_ID,
            'client_secret': self.client_secret
        }
        
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        
        try:
            response = self.session.post(auth_url, data=data, headers=headers, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            
            token_data = response.json()
            self.token = token_data['access_token']
            expires_in = token_data.get('expires_in', 3600)  # Default to 1 hour
            self.token_expiry = time.time() + expires_in
            
            self.session.headers.update({'Authorization': f'Bearer {self.token}'})
            logger.info("Successfully authenticated to Checkmarx")
            
            audit_log("checkmarx_auth", {
                "status": "success",
                "username": self.username,
                "url": self.base_url
            })
            
            return True
        except requests.exceptions.RequestException as e:
            logger.error(f"Authentication failed: {e}")
            audit_log("checkmarx_auth", {
                "status": "failed",
                "username": self.username,
                "url": self.base_url,
                "error": str(e)
            })
            raise
    
    @retry_with_backoff
    def get_teams(self) -> List[Dict]:
        """Get all teams from Checkmarx."""
        self._ensure_authenticated()
        url = f"{self.base_url}/cxrestapi/auth/teams"
        
        try:
            response = self.session.get(url, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            teams = response.json()
            logger.info(f"Retrieved {len(teams)} teams from Checkmarx")
            return teams
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get teams: {e}")
            raise
    
    @retry_with_backoff
    def get_users_by_team(self, team_id: int, team_name: str = "") -> List[Dict]:
        """Get all users for a specific team."""
        self._ensure_authenticated()
        url = f"{self.base_url}/cxrestapi/auth/teams/{team_id}/users"
        
        try:
            response = self.session.get(url, timeout=REQUEST_TIMEOUT)
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
        team_name_mapping = defaultdict(list)
        teams = self.get_teams()
        
        # First pass: collect all mappings and detect conflicts
        for team in teams:
            full_team_name = team['fullName']
            team_id = team['id']
            
            try:
                validate_team_name(full_team_name)
            except ValueError as e:
                logger.warning(f"Invalid team name '{full_team_name}': {e}")
                continue
            
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
                        try:
                            validate_username(username)
                            memberships[short_name].add(username)
                        except ValueError as e:
                            logger.warning(f"Invalid username '{username}' in team '{full_team_name}': {e}")
                            continue
                
                logger.info(f"Team '{full_team_name}' -> Role '{short_name}': {len(memberships[short_name])} users")
            else:
                logger.warning(f"Team '{full_team_name}': No users found")
        
        return dict(memberships)


class ElasticsearchClient:
    """Client for interacting with Elasticsearch Security API."""
    
    def __init__(self, base_url: str, username: str, password: str, 
                 verify_ssl: bool = True, ca_cert: Optional[str] = None, 
                 role_config: Optional[Dict] = None):
        validate_url(base_url, "Elasticsearch URL")
        validate_username(username)
        
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.auth = (username, password)
        self.session.headers.update({'Content-Type': 'application/json'})
        self.role_config = role_config or ROLE_CONFIG
        
        # Configure SSL verification
        if ca_cert:
            if not os.path.exists(ca_cert):
                raise ValueError(f"CA certificate file not found: {ca_cert}")
            self.session.verify = ca_cert
        else:
            self.session.verify = verify_ssl
        
        # Suppress InsecureRequestWarning if SSL verification is disabled
        if not verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            logger.warning("SSL verification disabled - not recommended for production")
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup session."""
        self.close()
    
    def close(self):
        """Close the session."""
        if self.session:
            self.session.close()
    
    @retry_with_backoff
    def get_role_mapping(self, role_name: str) -> Optional[Dict]:
        """Get current role mapping for a role."""
        validate_team_name(role_name)
        url = f"{self.base_url}/_security/role_mapping/{role_name}"
        
        try:
            response = self.session.get(url, timeout=REQUEST_TIMEOUT)
            if response.status_code == 404:
                return None
            response.raise_for_status()
            return response.json().get(role_name, {})
        except requests.exceptions.HTTPError as e:
            if e.response.status_code != 404:
                logger.error(f"Failed to get role mapping for {role_name}: {e}")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get role mapping for {role_name}: {e}")
            return None
    
    def _needs_update(self, role_name: str, usernames: Set[str]) -> bool:
        """
        Check if role mapping needs update (idempotency check).
        
        Args:
            role_name: Name of the role
            usernames: Set of usernames to map
            
        Returns:
            True if update is needed
        """
        current = self.get_role_mapping(role_name)
        if not current:
            return True
        
        # Extract current usernames from role mapping
        current_users = set()
        rules = current.get('rules', {})
        
        if 'any' in rules:
            for rule in rules['any']:
                if 'field' in rule and 'username' in rule['field']:
                    current_users.add(rule['field']['username'])
        
        # Compare sets
        needs_update = current_users != usernames
        
        if not needs_update:
            logger.debug(f"Role mapping '{role_name}' is already up to date")
        
        return needs_update
    
    @retry_with_backoff
    def update_role_mapping(self, role_name: str, usernames: List[str], 
                          enabled: bool = True, force: bool = False) -> bool:
        """
        Update role mapping with list of usernames.
        
        Args:
            role_name: Name of the role
            usernames: List of usernames to map
            enabled: Whether the mapping is enabled
            force: Force update even if no changes detected
            
        Returns:
            True if successful
        """
        validate_team_name(role_name)
        
        # Validate all usernames
        for username in usernames:
            validate_username(username)
        
        # Check if update is needed (idempotency)
        if not force and not self._needs_update(role_name, set(usernames)):
            logger.info(f"Role mapping '{role_name}' unchanged, skipping update")
            return True
        
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
            response = self.session.put(url, json=mapping, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            logger.info(f"Updated role mapping '{role_name}' with {len(usernames)} users")
            
            audit_log("es_role_mapping_update", {
                "role": role_name,
                "user_count": len(usernames),
                "status": "success"
            })
            
            return True
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to update role mapping {role_name}: {e}")
            
            audit_log("es_role_mapping_update", {
                "role": role_name,
                "user_count": len(usernames),
                "status": "failed",
                "error": str(e)
            })
            
            return False
    
    @retry_with_backoff
    def create_role_if_not_exists(self, role_name: str) -> bool:
        """Create a role if it doesn't exist, using the configured role template."""
        validate_team_name(role_name)
        url = f"{self.base_url}/_security/role/{role_name}"
        
        # Check if role exists
        try:
            response = self.session.get(url, timeout=REQUEST_TIMEOUT)
            if response.status_code == 200:
                logger.info(f"Role '{role_name}' already exists")
                return True
        except requests.exceptions.HTTPError as e:
            if e.response.status_code != 404:
                logger.error(f"Error checking role existence: {e}")
                return False
        except requests.exceptions.RequestException as e:
            logger.error(f"Error checking role existence: {e}")
            return False
        
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
                query_with_team = self._replace_team_placeholder(idx_config["query"], role_name)
                idx_def["query"] = query_with_team
            
            role_def["indices"].append(idx_def)
        
        # Add application privileges (e.g., Kibana)
        for app_config in self.role_config.get("applications", []):
            role_def["applications"].append(app_config)
        
        # Create the role
        try:
            response = self.session.put(url, json=role_def, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            logger.info(f"Created role '{role_name}' with document-level security")
            
            audit_log("es_role_create", {
                "role": role_name,
                "status": "success"
            })
            
            return True
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to create role {role_name}: {e}")
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_detail = e.response.text
                    # Sanitize error detail - don't log full responses that might contain sensitive data
                    if len(error_detail) > 500:
                        error_detail = error_detail[:500] + "... (truncated)"
                    logger.error(f"Response: {error_detail}")
                except Exception:
                    pass
            
            audit_log("es_role_create", {
                "role": role_name,
                "status": "failed",
                "error": str(e)
            })
            
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
                         team_filter: Optional[List[str]] = None,
                         create_roles: bool = False,
                         force_update: bool = False) -> Dict[str, int]:
    """
    Sync Checkmarx team memberships to Elasticsearch role mappings.
    
    Args:
        cx_client: Checkmarx client instance
        es_client: Elasticsearch client instance
        team_filter: Optional list of team names to sync (sync all if None)
        create_roles: If True, create ES roles that don't exist
        force_update: Force update even if no changes detected
        
    Returns:
        Dictionary with sync statistics
    """
    logger.info("Starting team membership sync")
    start_time = time.time()
    
    # Get team memberships from Checkmarx
    memberships = cx_client.get_team_memberships()
    
    # Filter teams if specified
    if team_filter:
        memberships = {k: v for k, v in memberships.items() if k in team_filter}
        logger.info(f"Filtered to {len(memberships)} teams based on --teams argument")
    
    # Sync each team to Elasticsearch
    stats = {
        'total': len(memberships),
        'success': 0,
        'failed': 0,
        'skipped': 0
    }
    
    for team_name, usernames in memberships.items():
        logger.info(f"\nProcessing team: {team_name}")
        
        # Optionally create role if it doesn't exist
        if create_roles:
            if not es_client.create_role_if_not_exists(team_name):
                stats['failed'] += 1
                continue
        
        # Update role mapping
        if usernames:
            if es_client.update_role_mapping(team_name, list(usernames), force=force_update):
                stats['success'] += 1
            else:
                stats['failed'] += 1
        else:
            logger.warning(f"Team '{team_name}' has no users, skipping")
            stats['skipped'] += 1
    
    duration = time.time() - start_time
    
    logger.info(f"\n{'=' * 80}")
    logger.info(f"Sync complete in {duration:.2f} seconds")
    logger.info(f"Total teams: {stats['total']}")
    logger.info(f"Successful: {stats['success']}")
    logger.info(f"Failed: {stats['failed']}")
    logger.info(f"Skipped: {stats['skipped']}")
    logger.info(f"{'=' * 80}")
    
    audit_log("sync_complete", {
        "duration_seconds": round(duration, 2),
        "stats": stats
    })
    
    return stats


def main():
    parser = argparse.ArgumentParser(
        description='Sync Checkmarx SAST team memberships to Elasticsearch role mappings',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Configuration Priority (highest to lowest):
  1. Command-line arguments
  2. .env file (specified by --env-file or default .env)
  3. Environment variables
  4. Default values

Example .env file format:
  CHECKMARX_URL=https://checkmarx.example.com
  CHECKMARX_USERNAME=admin
  CHECKMARX_PASSWORD=secretpass
  CHECKMARX_CLIENT_SECRET=your-client-secret
  ELASTICSEARCH_URL=https://elasticsearch.example.com:9200
  ELASTICSEARCH_USERNAME=elastic
  ELASTICSEARCH_PASSWORD=secretpass
  ELASTICSEARCH_VERIFY_SSL=true

Examples:
  # Use default .env file
  %(prog)s
  
  # Use custom env file
  %(prog)s --env-file /path/to/production.env
  
  # Override specific values
  %(prog)s --cx-password newpass --create-roles
  
  # Dry run to see what would be synced
  %(prog)s --dry-run
  
  # Force update even if no changes detected
  %(prog)s --force
        """
    )
    
    # Environment file argument
    parser.add_argument('--env-file', default=DEFAULT_ENV_FILE,
                       help=f'Path to .env file (default: {DEFAULT_ENV_FILE})')
    
    # Checkmarx arguments
    parser.add_argument('--cx-url', help='Checkmarx base URL')
    parser.add_argument('--cx-user', '--cx-username', dest='cx_user', help='Checkmarx username')
    parser.add_argument('--cx-password', help='Checkmarx password')
    parser.add_argument('--cx-client-secret', help='Checkmarx OAuth client secret')
    
    # Elasticsearch arguments
    parser.add_argument('--es-url', help='Elasticsearch base URL')
    parser.add_argument('--es-user', '--es-username', dest='es_user', help='Elasticsearch username')
    parser.add_argument('--es-password', help='Elasticsearch password')
    parser.add_argument('--es-verify-ssl', type=lambda x: x.lower() in ('true', '1', 'yes'), 
                       help='Verify SSL certificate (true/false)')
    parser.add_argument('--es-ca-cert', help='Path to CA certificate file')
    
    # Optional arguments
    parser.add_argument('--teams', nargs='+', help='Specific teams to sync (default: all)')
    parser.add_argument('--create-roles', action='store_true', 
                       help='Create ES roles if they don\'t exist')
    parser.add_argument('--force', action='store_true',
                       help='Force update even if no changes detected')
    parser.add_argument('--dry-run', action='store_true', 
                       help='Show what would be synced without making changes')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    try:
        # Load environment file
        env_vars = load_env_file(args.env_file)
        
        # Get configuration values with priority: CLI > .env > environment > default
        cx_url = get_config_value('CHECKMARX_URL', args.cx_url, env_vars, required=True)
        cx_user = get_config_value('CHECKMARX_USERNAME', args.cx_user, env_vars, required=True)
        cx_password = get_config_value('CHECKMARX_PASSWORD', args.cx_password, env_vars, required=True)
        cx_client_secret = get_config_value('CHECKMARX_CLIENT_SECRET', args.cx_client_secret, env_vars)
        
        es_url = get_config_value('ELASTICSEARCH_URL', args.es_url, env_vars, required=True)
        es_user = get_config_value('ELASTICSEARCH_USERNAME', args.es_user, env_vars, required=True)
        es_password = get_config_value('ELASTICSEARCH_PASSWORD', args.es_password, env_vars, required=True)
        
        # Optional configuration
        es_verify_ssl_str = get_config_value('ELASTICSEARCH_VERIFY_SSL', 
                                            'true' if args.es_verify_ssl is None else str(args.es_verify_ssl),
                                            env_vars, default='true')
        es_verify_ssl = es_verify_ssl_str.lower() in ('true', '1', 'yes')
        
        es_ca_cert = get_config_value('ELASTICSEARCH_CA_CERT', args.es_ca_cert, env_vars)
        
        # Log configuration source (without sensitive values)
        logger.info(f"Using Checkmarx URL: {cx_url}")
        logger.info(f"Using Elasticsearch URL: {es_url}")
        logger.info(f"SSL verification: {es_verify_ssl}")
        if es_ca_cert:
            logger.info(f"CA certificate: {es_ca_cert}")
        
        # Initialize clients with context managers
        with CheckmarxClient(cx_url, cx_user, cx_password, cx_client_secret) as cx_client, \
             ElasticsearchClient(es_url, es_user, es_password, es_verify_ssl, es_ca_cert) as es_client:
            
            # Perform sync
            if args.dry_run:
                logger.info("=" * 80)
                logger.info("DRY RUN MODE - No changes will be made")
                logger.info("=" * 80)
                memberships = cx_client.get_team_memberships()
                if args.teams:
                    memberships = {k: v for k, v in memberships.items() if k in args.teams}
                
                print("\n" + "=" * 80)
                print("TEAM MEMBERSHIPS THAT WOULD BE SYNCED")
                print("=" * 80)
                for team, users in sorted(memberships.items()):
                    print(f"\nTeam: {team}")
                    print(f"Users ({len(users)}): {', '.join(sorted(users))}")
                print("\n" + "=" * 80)
            else:
                stats = sync_team_memberships(cx_client, es_client, args.teams, 
                                             args.create_roles, args.force)
                
                # Return non-zero exit code if there were failures
                if stats['failed'] > 0:
                    return 1
        
    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        return 1
    except KeyboardInterrupt:
        logger.warning("Interrupted by user")
        return 130
    except Exception as e:
        logger.error(f"Script failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1
    
    return 0


if __name__ == '__main__':
    exit(main())