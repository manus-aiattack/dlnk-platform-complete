"""
API Client for dLNk CLI
"""

import httpx
import asyncio
from typing import Dict, Any, Optional, List
from cli.config import get_config


class APIClient:
    """
    API Client for dLNk Attack Platform
    
    Handles all API communication from CLI
    """
    
    def __init__(self):
        self.config = get_config()
        self.base_url = self.config.api.url
        self.timeout = self.config.api.timeout
    
    def _get_headers(self) -> Dict[str, str]:
        """Get request headers"""
        return self.config.get_api_headers()
    
    async def _request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Make HTTP request"""
        url = f"{self.base_url}{endpoint}"
        headers = self._get_headers()
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            if method == "GET":
                response = await client.get(url, headers=headers, params=params)
            elif method == "POST":
                response = await client.post(url, headers=headers, json=data)
            elif method == "PUT":
                response = await client.put(url, headers=headers, json=data)
            elif method == "DELETE":
                response = await client.delete(url, headers=headers)
            else:
                raise ValueError(f"Unsupported method: {method}")
            
            response.raise_for_status()
            return response.json()
    
    # Authentication
    async def login(self, api_key: str) -> Dict[str, Any]:
        """Login with API key"""
        return await self._request("POST", "/auth/login", {"api_key": api_key})
    
    async def logout(self) -> Dict[str, Any]:
        """Logout"""
        return await self._request("POST", "/auth/logout")
    
    # Attacks
    async def start_attack(
        self,
        target_url: str,
        attack_type: str,
        options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Start a new attack"""
        data = {
            "target_url": target_url,
            "attack_type": attack_type,
            "options": options or {}
        }
        return await self._request("POST", "/attacks", data)
    
    async def list_attacks(
        self,
        status: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """List attacks"""
        params = {"limit": limit}
        if status:
            params["status"] = status
        result = await self._request("GET", "/attacks", params=params)
        return result.get("attacks", [])
    
    async def get_attack(self, attack_id: str) -> Dict[str, Any]:
        """Get attack details"""
        return await self._request("GET", f"/attacks/{attack_id}")
    
    async def stop_attack(self, attack_id: str) -> Dict[str, Any]:
        """Stop an attack"""
        return await self._request("POST", f"/attacks/{attack_id}/stop")
    
    async def delete_attack(self, attack_id: str) -> Dict[str, Any]:
        """Delete an attack"""
        return await self._request("DELETE", f"/attacks/{attack_id}")
    
    async def get_attack_results(self, attack_id: str) -> Dict[str, Any]:
        """Get attack results"""
        return await self._request("GET", f"/attacks/{attack_id}/results")
    
    # Reports
    async def generate_report(
        self,
        attack_id: str,
        format: str = "html"
    ) -> Dict[str, Any]:
        """Generate attack report"""
        data = {"format": format}
        return await self._request("POST", f"/reports/{attack_id}", data)
    
    async def list_reports(
        self,
        attack_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List reports"""
        params = {}
        if attack_id:
            params["attack_id"] = attack_id
        result = await self._request("GET", "/reports", params=params)
        return result.get("reports", [])
    
    async def get_report(self, report_id: str) -> Dict[str, Any]:
        """Get report details"""
        return await self._request("GET", f"/reports/{report_id}")
    
    async def delete_report(self, report_id: str) -> Dict[str, Any]:
        """Delete a report"""
        return await self._request("DELETE", f"/reports/{report_id}")
    
    # Files
    async def list_files(self, attack_id: str) -> List[Dict[str, Any]]:
        """List exfiltrated files"""
        result = await self._request("GET", f"/files/{attack_id}")
        return result.get("files", [])
    
    async def download_file(self, file_id: str) -> bytes:
        """Download file"""
        url = f"{self.base_url}/files/download/{file_id}"
        headers = self._get_headers()
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            return response.content
    
    async def delete_file(self, file_id: str) -> Dict[str, Any]:
        """Delete a file"""
        return await self._request("DELETE", f"/files/{file_id}")
    
    # Admin - Users
    async def list_users(self) -> List[Dict[str, Any]]:
        """List users"""
        result = await self._request("GET", "/admin/users")
        return result.get("users", [])
    
    async def create_user(
        self,
        username: str,
        role: str,
        quota_limit: int = 100
    ) -> Dict[str, Any]:
        """Create user"""
        data = {
            "username": username,
            "role": role,
            "quota_limit": quota_limit
        }
        return await self._request("POST", "/admin/users", data)
    
    async def delete_user(self, user_id: str) -> Dict[str, Any]:
        """Delete user"""
        return await self._request("DELETE", f"/admin/users/{user_id}")
    
    # Admin - Licenses
    async def generate_license(
        self,
        organization: str,
        license_type: str,
        duration_days: int
    ) -> Dict[str, Any]:
        """Generate license"""
        data = {
            "organization": organization,
            "type": license_type,
            "duration_days": duration_days
        }
        return await self._request("POST", "/admin/licenses", data)
    
    async def list_licenses(self) -> List[Dict[str, Any]]:
        """List licenses"""
        result = await self._request("GET", "/admin/licenses")
        return result.get("licenses", [])
    
    async def revoke_license(self, license_key: str) -> Dict[str, Any]:
        """Revoke license"""
        return await self._request("DELETE", f"/admin/licenses/{license_key}")
    
    # System
    async def get_system_status(self) -> Dict[str, Any]:
        """Get system status"""
        return await self._request("GET", "/system/status")
    
    async def get_system_stats(self) -> Dict[str, Any]:
        """Get system statistics"""
        return await self._request("GET", "/system/stats")
    
    async def get_resource_usage(self) -> Dict[str, Any]:
        """Get resource usage"""
        return await self._request("GET", "/system/resources")
    
    async def list_agents(self) -> List[Dict[str, Any]]:
        """List all agents"""
        result = await self._request("GET", "/agents")
        return result.get("agents", [])
    
    async def get_agent(self, agent_name: str) -> Dict[str, Any]:
        """Get agent details"""
        return await self._request("GET", f"/agents/{agent_name}")
    
    async def get_logs(
        self,
        level: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get system logs"""
        params = {"limit": limit}
        if level:
            params["level"] = level
        result = await self._request("GET", "/system/logs", params=params)
        return result.get("logs", [])


# Synchronous wrapper functions for CLI
def run_async(coro):
    """Run async function synchronously"""
    return asyncio.run(coro)


class SyncAPIClient:
    """Synchronous wrapper for APIClient"""
    
    def __init__(self):
        self.client = APIClient()
    
    def __getattr__(self, name):
        """Wrap all async methods to sync"""
        attr = getattr(self.client, name)
        if asyncio.iscoroutinefunction(attr):
            def wrapper(*args, **kwargs):
                return run_async(attr(*args, **kwargs))
            return wrapper
        return attr


# Global client instance
_client = None


def get_client() -> SyncAPIClient:
    """Get global client instance"""
    global _client
    if _client is None:
        _client = SyncAPIClient()
    return _client

