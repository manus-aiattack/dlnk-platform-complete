import requests
import base64
import json
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from core.logger import log


@dataclass
class OAuthConfig:
    client_id: str
    client_secret: str
    redirect_uri: str
    scope: str
    auth_url: str
    token_url: str
    grant_type: str = "authorization_code"


@dataclass
class OAuthToken:
    access_token: str
    token_type: str
    expires_in: int = None
    refresh_token: str = None
    scope: str = None


class OAuthHandler:
    def __init__(self):
        self.tokens = {}
        self.configs = {}

    def add_oauth_config(self, name: str, config: OAuthConfig):
        """Add OAuth configuration for a service"""
        self.configs[name] = config
        log.info(f"Added OAuth config for {name}")

    def get_authorization_url(self, service_name: str, state: str = None) -> Optional[str]:
        """Get authorization URL for OAuth flow"""
        if service_name not in self.configs:
            log.error(f"No OAuth config found for {service_name}")
            return None

        config = self.configs[service_name]
        params = {
            'client_id': config.client_id,
            'redirect_uri': config.redirect_uri,
            'scope': config.scope,
            'response_type': 'code'
        }

        if state:
            params['state'] = state

        # Build URL with parameters
        param_string = '&'.join([f"{k}={v}" for k, v in params.items()])
        return f"{config.auth_url}?{param_string}"

    def exchange_code_for_token(self, service_name: str, code: str) -> Optional[OAuthToken]:
        """Exchange authorization code for access token"""
        if service_name not in self.configs:
            log.error(f"No OAuth config found for {service_name}")
            return None

        config = self.configs[service_name]

        # Prepare token request
        data = {
            'grant_type': config.grant_type,
            'client_id': config.client_id,
            'client_secret': config.client_secret,
            'redirect_uri': config.redirect_uri,
            'code': code
        }

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json'
        }

        try:
            response = requests.post(
                config.token_url,
                data=data,
                headers=headers,
                timeout=30
            )
            response.raise_for_status()

            token_data = response.json()
            token = OAuthToken(
                access_token=token_data['access_token'],
                token_type=token_data.get('token_type', 'Bearer'),
                expires_in=token_data.get('expires_in'),
                refresh_token=token_data.get('refresh_token'),
                scope=token_data.get('scope')
            )

            self.tokens[service_name] = token
            log.info(f"Successfully obtained token for {service_name}")
            return token

        except Exception as e:
            log.error(f"Failed to exchange code for token: {e}")
            return None

    def get_client_credentials_token(self, service_name: str) -> Optional[OAuthToken]:
        """Get token using client credentials flow"""
        if service_name not in self.configs:
            log.error(f"No OAuth config found for {service_name}")
            return None

        config = self.configs[service_name]

        # Prepare token request
        data = {
            'grant_type': 'client_credentials',
            'client_id': config.client_id,
            'client_secret': config.client_secret,
            'scope': config.scope
        }

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json'
        }

        try:
            response = requests.post(
                config.token_url,
                data=data,
                headers=headers,
                timeout=30
            )
            response.raise_for_status()

            token_data = response.json()
            token = OAuthToken(
                access_token=token_data['access_token'],
                token_type=token_data.get('token_type', 'Bearer'),
                expires_in=token_data.get('expires_in'),
                scope=token_data.get('scope')
            )

            self.tokens[service_name] = token
            log.info(
                f"Successfully obtained client credentials token for {service_name}")
            return token

        except Exception as e:
            log.error(f"Failed to get client credentials token: {e}")
            return None

    def refresh_token(self, service_name: str) -> Optional[OAuthToken]:
        """Refresh access token using refresh token"""
        if service_name not in self.tokens:
            log.error(f"No token found for {service_name}")
            return None

        token = self.tokens[service_name]
        if not token.refresh_token:
            log.error(f"No refresh token available for {service_name}")
            return None

        if service_name not in self.configs:
            log.error(f"No OAuth config found for {service_name}")
            return None

        config = self.configs[service_name]

        # Prepare refresh request
        data = {
            'grant_type': 'refresh_token',
            'refresh_token': token.refresh_token,
            'client_id': config.client_id,
            'client_secret': config.client_secret
        }

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json'
        }

        try:
            response = requests.post(
                config.token_url,
                data=data,
                headers=headers,
                timeout=30
            )
            response.raise_for_status()

            token_data = response.json()
            new_token = OAuthToken(
                access_token=token_data['access_token'],
                token_type=token_data.get('token_type', 'Bearer'),
                expires_in=token_data.get('expires_in'),
                refresh_token=token_data.get(
                    'refresh_token', token.refresh_token),
                scope=token_data.get('scope')
            )

            self.tokens[service_name] = new_token
            log.info(f"Successfully refreshed token for {service_name}")
            return new_token

        except Exception as e:
            log.error(f"Failed to refresh token: {e}")
            return None

    def get_auth_headers(self, service_name: str) -> Optional[Dict[str, str]]:
        """Get authorization headers for API requests"""
        if service_name not in self.tokens:
            log.error(f"No token found for {service_name}")
            return None

        token = self.tokens[service_name]
        return {
            'Authorization': f"{token.token_type} {token.access_token}"
        }

    def is_token_valid(self, service_name: str) -> bool:
        """Check if token is still valid"""
        if service_name not in self.tokens:
            return False

        token = self.tokens[service_name]
        # For now, assume token is valid if we have it
        # In production, you'd check expiration time
        return True

    def revoke_token(self, service_name: str) -> bool:
        """Revoke access token"""
        if service_name not in self.tokens:
            log.warning(f"No token found for {service_name}")
            return True

        # Remove token from storage
        del self.tokens[service_name]
        log.info(f"Revoked token for {service_name}")
        return True

    def get_common_oauth_configs(self) -> Dict[str, OAuthConfig]:
        """Get common OAuth configurations for popular services"""
        configs = {}

        # GitHub OAuth
        configs['github'] = OAuthConfig(
            client_id="",
            client_secret="",
            redirect_uri="http://localhost:8080/callback",
            scope="repo,user,admin:org",
            auth_url="https://github.com/login/oauth/authorize",
            token_url="https://github.com/login/oauth/access_token"
        )

        # Google OAuth
        configs['google'] = OAuthConfig(
            client_id="",
            client_secret="",
            redirect_uri="http://localhost:8080/callback",
            scope="https://www.googleapis.com/auth/cloud-platform",
            auth_url="https://accounts.google.com/o/oauth2/v2/auth",
            token_url="https://oauth2.googleapis.com/token"
        )

        # Microsoft OAuth
        configs['microsoft'] = OAuthConfig(
            client_id="",
            client_secret="",
            redirect_uri="http://localhost:8080/callback",
            scope="https://graph.microsoft.com/.default",
            auth_url="https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            token_url="https://login.microsoftonline.com/common/oauth2/v2.0/token"
        )

        # AWS OAuth
        configs['aws'] = OAuthConfig(
            client_id="",
            client_secret="",
            redirect_uri="http://localhost:8080/callback",
            scope="aws.cognito.signin.user.admin",
            auth_url="https://your-domain.auth.us-east-1.amazoncognito.com/oauth2/authorize",
            token_url="https://your-domain.auth.us-east-1.amazoncognito.com/oauth2/token"
        )

        return configs
