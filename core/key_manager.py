"""
API Key Management System
Handles creation, validation, and management of API keys
"""

import secrets
import hashlib
import json
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path


class KeyManager:
    """Manages API keys for the platform"""
    
    def __init__(self, storage_path: str = "/home/ubuntu/aiprojectattack/data/keys.json"):
        self.storage_path = Path(storage_path)
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        self.keys = self._load_keys()
        
    def _load_keys(self) -> Dict[str, Dict]:
        """Load keys from storage"""
        if self.storage_path.exists():
            with open(self.storage_path, 'r') as f:
                return json.load(f)
        else:
            # Initialize with default admin key
            default_keys = {
                "admin_key_001": {
                    "key": "admin_key_001",
                    "user_name": "Administrator",
                    "key_type": "admin",
                    "created_at": datetime.now().isoformat(),
                    "is_active": True,
                    "quota_limit": -1,  # Unlimited
                    "quota_used": 0,
                    "permissions": ["all"]
                }
            }
            self._save_keys(default_keys)
            return default_keys
    
    def _save_keys(self, keys: Dict[str, Dict] = None):
        """Save keys to storage"""
        if keys is None:
            keys = self.keys
        with open(self.storage_path, 'w') as f:
            json.dump(keys, f, indent=2)
    
    def generate_key(self) -> str:
        """Generate a new random API key"""
        return secrets.token_urlsafe(32)
    
    def create_key(
        self,
        user_name: str,
        key_type: str = "user",
        quota_limit: int = 100,
        permissions: List[str] = None
    ) -> Dict[str, str]:
        """Create a new API key"""
        if permissions is None:
            permissions = ["attack", "scan", "report"]
        
        key = self.generate_key()
        
        self.keys[key] = {
            "key": key,
            "user_name": user_name,
            "key_type": key_type,
            "created_at": datetime.now().isoformat(),
            "is_active": True,
            "quota_limit": quota_limit,
            "quota_used": 0,
            "permissions": permissions,
            "last_used": None
        }
        
        self._save_keys()
        
        return {
            "key": key,
            "user_name": user_name,
            "key_type": key_type,
            "quota_limit": quota_limit
        }
    
    def validate_key(self, key: str) -> Optional[Dict]:
        """Validate API key and return key info"""
        if key not in self.keys:
            return None
        
        key_info = self.keys[key]
        
        if not key_info["is_active"]:
            return None
        
        # Check quota
        if key_info["quota_limit"] > 0 and key_info["quota_used"] >= key_info["quota_limit"]:
            return None
        
        # Update last used
        key_info["last_used"] = datetime.now().isoformat()
        self._save_keys()
        
        return key_info
    
    def increment_quota(self, key: str, amount: int = 1):
        """Increment quota usage for a key"""
        if key in self.keys:
            self.keys[key]["quota_used"] += amount
            self._save_keys()
    
    def list_keys(self) -> List[Dict]:
        """List all API keys"""
        return [
            {
                "key": k[:16] + "..." if len(k) > 16 else k,
                "user_name": v["user_name"],
                "key_type": v["key_type"],
                "created_at": v["created_at"],
                "is_active": v["is_active"],
                "quota_used": v["quota_used"],
                "quota_limit": v["quota_limit"]
            }
            for k, v in self.keys.items()
        ]
    
    def deactivate_key(self, key: str) -> bool:
        """Deactivate an API key"""
        if key in self.keys:
            self.keys[key]["is_active"] = False
            self._save_keys()
            return True
        return False
    
    def activate_key(self, key: str) -> bool:
        """Activate an API key"""
        if key in self.keys:
            self.keys[key]["is_active"] = True
            self._save_keys()
            return True
        return False
    
    def delete_key(self, key: str) -> bool:
        """Delete an API key"""
        if key in self.keys and key != "admin_key_001":  # Protect admin key
            del self.keys[key]
            self._save_keys()
            return True
        return False
    
    def update_quota(self, key: str, new_limit: int) -> bool:
        """Update quota limit for a key"""
        if key in self.keys:
            self.keys[key]["quota_limit"] = new_limit
            self._save_keys()
            return True
        return False
    
    def get_key_stats(self, key: str) -> Optional[Dict]:
        """Get statistics for a specific key"""
        if key in self.keys:
            key_info = self.keys[key]
            return {
                "user_name": key_info["user_name"],
                "key_type": key_info["key_type"],
                "quota_used": key_info["quota_used"],
                "quota_limit": key_info["quota_limit"],
                "quota_remaining": key_info["quota_limit"] - key_info["quota_used"] if key_info["quota_limit"] > 0 else -1,
                "is_active": key_info["is_active"],
                "created_at": key_info["created_at"],
                "last_used": key_info.get("last_used")
            }
        return None


# Global key manager instance
key_manager = KeyManager()

