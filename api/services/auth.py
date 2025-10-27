"""
Authentication Service
"""

import secrets
import hashlib
from typing import Optional, Dict
from datetime import datetime
from core.logger import log


class AuthService:
    """Authentication service"""
    
    def __init__(self, db):
        self.db = db
    
    def generate_api_key(self) -> str:
        """Generate new API key"""
        return secrets.token_urlsafe(32)
    
    def hash_key(self, api_key: str) -> str:
        """Hash API key (optional, for extra security)"""
        return hashlib.sha256(api_key.encode()).hexdigest()
    
    async def verify_key(self, api_key: str) -> Optional[Dict]:
        """Verify API key and return user"""
        user = await self.db.get_user_by_key(api_key)
        
        if user:
            # Update last login
            await self.db.update_last_login(user["id"])
            log.info(f"[Auth] User {user['username']} authenticated")
        
        return user
    
    async def create_user_key(self, username: str, role: str = "user", quota_limit: int = 100) -> Dict:
        """Create new user with API key"""
        api_key = self.generate_api_key()
        
        user_id = await self.db.create_user(username, role, api_key, quota_limit)
        
        log.success(f"[Auth] Created user {username} with role {role}")
        
        return {
            "user_id": user_id,
            "username": username,
            "role": role,
            "api_key": api_key,
            "quota_limit": quota_limit,
            "created_at": datetime.now().isoformat()
        }
    
    async def check_quota(self, user_id: int) -> bool:
        """Check if user has quota remaining"""
        user = await self.db.get_user_by_id(user_id)
        
        if not user:
            return False
        
        return user["quota_used"] < user["quota_limit"]
    
    async def consume_quota(self, user_id: int, amount: int = 1):
        """Consume user quota"""
        await self.db.update_quota(user_id, amount)

