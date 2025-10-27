"""
Authentication Service for dLNk dLNk Framework
Handles user authentication, JWT tokens, and session management
"""

import asyncio
import hashlib
import secrets
import jwt
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, List
from dataclasses import dataclass, asdict
from enum import Enum
import json
import redis.asyncio as aioredis
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr


class UserRole(str, Enum):
    """User roles for RBAC"""
    ADMIN = "admin"
    USER = "user"
    VIEWER = "viewer"


@dataclass
class User:
    """User data model"""
    user_id: str
    username: str
    email: str
    password_hash: str
    role: UserRole
    api_key: str
    license_key: Optional[str]
    created_at: str
    last_login: Optional[str]
    is_active: bool
    metadata: Dict


class AuthService:
    """
    Authentication Service
    
    Features:
    - User registration and login
    - JWT token generation and validation
    - API key management
    - Session management
    - Password hashing
    - Role-based access control
    """
    
    def __init__(self, redis_url: str = "redis://localhost:6379", 
                 secret_key: str = None):
        self.redis_url = redis_url
        self.redis: Optional[aioredis.Redis] = None
        self.secret_key = secret_key or secrets.token_urlsafe(32)
        self.jwt_algorithm = "HS256"
        self.token_expiry = timedelta(hours=24)
        self.refresh_token_expiry = timedelta(days=30)
        
    async def initialize(self):
        """Initialize Redis connection"""
        self.redis = await aioredis.from_url(
            self.redis_url,
            encoding="utf-8",
            decode_responses=True
        )
        
        # Create default admin user if not exists
        await self._create_default_admin()
        
    async def _create_default_admin(self):
        """Create default admin user"""
        admin_username = "admin"
        
        # Check if admin exists
        if await self.redis.exists(f"user:{admin_username}"):
            return
            
        # Create admin user
        admin_user = User(
            user_id=self._generate_user_id(),
            username=admin_username,
            email="admin@dlnkhack.local",
            password_hash=self._hash_password("admin123"),
            role=UserRole.ADMIN,
            api_key=self._generate_api_key(),
            license_key=f"DLNK-ENT-{secrets.token_hex(8).upper()}",
            created_at=datetime.utcnow().isoformat(),
            last_login=None,
            is_active=True,
            metadata={"created_by": "system"}
        )
        
        await self._save_user(admin_user)
        print(f"✅ Production admin user created: {admin_username}")
        print(f"🔑 Admin API Key: {admin_user.api_key}")
        print(f"📋 License Key: {admin_user.license_key}")
        print("⚠️  SAVE THESE CREDENTIALS - They will not be shown again!")
        
    def _generate_user_id(self) -> str:
        """Generate unique user ID"""
        return f"usr_{secrets.token_hex(8)}"
        
    def _generate_api_key(self) -> str:
        """Generate API key with production format"""
        # Production format: dlnk_live_<64_hex_chars>
        return f"dlnk_live_{secrets.token_hex(32)}"
        
    def _hash_password(self, password: str) -> str:
        """Hash password with salt"""
        salt = secrets.token_hex(16)
        pwd_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000
        )
        return f"{salt}${pwd_hash.hex()}"
        
    def _verify_password(self, password: str, password_hash: str) -> bool:
        """Verify password against hash"""
        try:
            salt, pwd_hash = password_hash.split('$')
            new_hash = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),
                salt.encode('utf-8'),
                100000
            )
            return new_hash.hex() == pwd_hash
        except Exception:
            return False
            
    async def _save_user(self, user: User):
        """Save user to Redis"""
        user_data = asdict(user)
        user_data['role'] = user.role.value
        
        # Save user data
        await self.redis.set(
            f"user:{user.username}",
            json.dumps(user_data)
        )
        
        # Index by user_id
        await self.redis.set(
            f"user_id:{user.user_id}",
            user.username
        )
        
        # Index by email
        await self.redis.set(
            f"user_email:{user.email}",
            user.username
        )
        
        # Index by API key
        await self.redis.set(
            f"api_key:{user.api_key}",
            user.username
        )
        
    async def _get_user(self, username: str) -> Optional[User]:
        """Get user by username"""
        user_data = await self.redis.get(f"user:{username}")
        if not user_data:
            return None
            
        data = json.loads(user_data)
        data['role'] = UserRole(data['role'])
        return User(**data)
        
    async def register_user(self, username: str, email: str, password: str,
                           role: UserRole = UserRole.USER) -> Dict:
        """
        Register new user
        
        Args:
            username: Username
            email: Email address
            password: Plain password
            role: User role
            
        Returns:
            User data with API key
        """
        # Check if username exists
        if await self.redis.exists(f"user:{username}"):
            raise ValueError(f"Username '{username}' already exists")
            
        # Check if email exists
        if await self.redis.exists(f"user_email:{email}"):
            raise ValueError(f"Email '{email}' already registered")
            
        # Create user
        user = User(
            user_id=self._generate_user_id(),
            username=username,
            email=email,
            password_hash=self._hash_password(password),
            role=role,
            api_key=self._generate_api_key(),
            license_key=None,
            created_at=datetime.utcnow().isoformat(),
            last_login=None,
            is_active=True,
            metadata={}
        )
        
        await self._save_user(user)
        
        return {
            "user_id": user.user_id,
            "username": user.username,
            "email": user.email,
            "role": user.role.value,
            "api_key": user.api_key,
            "created_at": user.created_at
        }
        
    async def authenticate(self, username: str, password: str) -> Dict:
        """
        Authenticate user with username and password
        
        Args:
            username: Username
            password: Plain password
            
        Returns:
            Access token and user data
        """
        # Get user
        user = await self._get_user(username)
        if not user:
            raise ValueError("Invalid username or password")
            
        # Check if active
        if not user.is_active:
            raise ValueError("User account is disabled")
            
        # Verify password
        if not self._verify_password(password, user.password_hash):
            raise ValueError("Invalid username or password")
            
        # Update last login
        user.last_login = datetime.utcnow().isoformat()
        await self._save_user(user)
        
        # Generate tokens
        access_token = self._generate_token(user, self.token_expiry)
        refresh_token = self._generate_token(user, self.refresh_token_expiry)
        
        # Store refresh token
        await self.redis.setex(
            f"refresh_token:{user.user_id}",
            int(self.refresh_token_expiry.total_seconds()),
            refresh_token
        )
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": int(self.token_expiry.total_seconds()),
            "user": {
                "user_id": user.user_id,
                "username": user.username,
                "email": user.email,
                "role": user.role.value,
                "api_key": user.api_key
            }
        }
        
    def _generate_token(self, user: User, expiry: timedelta) -> str:
        """Generate JWT token"""
        payload = {
            "user_id": user.user_id,
            "username": user.username,
            "email": user.email,
            "role": user.role.value,
            "exp": datetime.utcnow() + expiry,
            "iat": datetime.utcnow()
        }
        return jwt.encode(payload, self.secret_key, algorithm=self.jwt_algorithm)
        
    async def verify_token(self, token: str) -> Dict:
        """
        Verify JWT token
        
        Args:
            token: JWT token
            
        Returns:
            Decoded token payload
        """
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.jwt_algorithm]
            )
            
            # Check if user still exists and is active
            user = await self._get_user(payload['username'])
            if not user or not user.is_active:
                raise ValueError("Invalid token")
                
            return payload
            
        except jwt.ExpiredSignatureError:
            raise ValueError("Token has expired")
        except jwt.InvalidTokenError:
            raise ValueError("Invalid token")
            
    async def verify_api_key(self, api_key: str) -> Optional[User]:
        """
        Verify API key
        
        Args:
            api_key: API key
            
        Returns:
            User object if valid
        """
        username = await self.redis.get(f"api_key:{api_key}")
        if not username:
            return None
            
        user = await self._get_user(username)
        if not user or not user.is_active:
            return None
            
        return user
        
    async def refresh_access_token(self, refresh_token: str) -> Dict:
        """
        Refresh access token using refresh token
        
        Args:
            refresh_token: Refresh token
            
        Returns:
            New access token
        """
        try:
            payload = jwt.decode(
                refresh_token,
                self.secret_key,
                algorithms=[self.jwt_algorithm]
            )
            
            user_id = payload['user_id']
            
            # Verify refresh token in Redis
            stored_token = await self.redis.get(f"refresh_token:{user_id}")
            if stored_token != refresh_token:
                raise ValueError("Invalid refresh token")
                
            # Get user
            username = await self.redis.get(f"user_id:{user_id}")
            user = await self._get_user(username)
            
            if not user or not user.is_active:
                raise ValueError("Invalid refresh token")
                
            # Generate new access token
            access_token = self._generate_token(user, self.token_expiry)
            
            return {
                "access_token": access_token,
                "token_type": "bearer",
                "expires_in": int(self.token_expiry.total_seconds())
            }
            
        except jwt.InvalidTokenError:
            raise ValueError("Invalid refresh token")
            
    async def logout(self, user_id: str):
        """
        Logout user (invalidate refresh token)
        
        Args:
            user_id: User ID
        """
        await self.redis.delete(f"refresh_token:{user_id}")
        
    async def update_user(self, username: str, updates: Dict) -> Dict:
        """
        Update user data
        
        Args:
            username: Username
            updates: Fields to update
            
        Returns:
            Updated user data
        """
        user = await self._get_user(username)
        if not user:
            raise ValueError(f"User '{username}' not found")
            
        # Update allowed fields
        if 'email' in updates:
            user.email = updates['email']
        if 'role' in updates:
            user.role = UserRole(updates['role'])
        if 'is_active' in updates:
            user.is_active = updates['is_active']
        if 'license_key' in updates:
            user.license_key = updates['license_key']
        if 'metadata' in updates:
            user.metadata.update(updates['metadata'])
            
        await self._save_user(user)
        
        return {
            "user_id": user.user_id,
            "username": user.username,
            "email": user.email,
            "role": user.role.value,
            "is_active": user.is_active,
            "license_key": user.license_key
        }
        
    async def change_password(self, username: str, old_password: str,
                             new_password: str):
        """
        Change user password
        
        Args:
            username: Username
            old_password: Current password
            new_password: New password
        """
        user = await self._get_user(username)
        if not user:
            raise ValueError(f"User '{username}' not found")
            
        # Verify old password
        if not self._verify_password(old_password, user.password_hash):
            raise ValueError("Invalid current password")
            
        # Update password
        user.password_hash = self._hash_password(new_password)
        await self._save_user(user)
        
        # Invalidate refresh token
        await self.logout(user.user_id)
        
    async def reset_api_key(self, username: str) -> str:
        """
        Reset user API key
        
        Args:
            username: Username
            
        Returns:
            New API key
        """
        user = await self._get_user(username)
        if not user:
            raise ValueError(f"User '{username}' not found")
            
        # Delete old API key index
        await self.redis.delete(f"api_key:{user.api_key}")
        
        # Generate new API key
        new_api_key = self._generate_api_key()
        user.api_key = new_api_key
        
        await self._save_user(user)
        
        return new_api_key
        
    async def list_users(self, role: Optional[UserRole] = None) -> List[Dict]:
        """
        List all users
        
        Args:
            role: Filter by role (optional)
            
        Returns:
            List of users
        """
        users = []
        
        # Get all user keys
        cursor = 0
        while True:
            cursor, keys = await self.redis.scan(
                cursor,
                match="user:*",
                count=100
            )
            
            for key in keys:
                if key.startswith("user:") and ":" in key[5:]:
                    username = key.split(":", 1)[1]
                    user = await self._get_user(username)
                    
                    if user and (role is None or user.role == role):
                        users.append({
                            "user_id": user.user_id,
                            "username": user.username,
                            "email": user.email,
                            "role": user.role.value,
                            "is_active": user.is_active,
                            "created_at": user.created_at,
                            "last_login": user.last_login
                        })
                        
            if cursor == 0:
                break
                
        return users
        
    async def delete_user(self, username: str):
        """
        Delete user
        
        Args:
            username: Username
        """
        user = await self._get_user(username)
        if not user:
            raise ValueError(f"User '{username}' not found")
            
        # Don't allow deleting the last admin
        if user.role == UserRole.ADMIN:
            admins = await self.list_users(role=UserRole.ADMIN)
            if len(admins) <= 1:
                raise ValueError("Cannot delete the last admin user")
                
        # Delete all user data
        await self.redis.delete(f"user:{username}")
        await self.redis.delete(f"user_id:{user.user_id}")
        await self.redis.delete(f"user_email:{user.email}")
        await self.redis.delete(f"api_key:{user.api_key}")
        await self.redis.delete(f"refresh_token:{user.user_id}")


# FastAPI integration
security = HTTPBearer()

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    auth_service: AuthService = None
) -> Dict:
    """Dependency to get current user from JWT token"""
    if not auth_service:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Auth service not initialized"
        )
        
    try:
        token = credentials.credentials
        payload = await auth_service.verify_token(token)
        return payload
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )


async def require_role(required_role: UserRole):
    """Dependency to require specific role"""
    async def role_checker(current_user: Dict = Depends(get_current_user)):
        user_role = UserRole(current_user['role'])
        
        # Admin has access to everything
        if user_role == UserRole.ADMIN:
            return current_user
            
        # Check role
        if user_role != required_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires {required_role.value} role"
            )
            
        return current_user
        
    return role_checker


# Pydantic models for API
class RegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: UserRole = UserRole.USER


class LoginRequest(BaseModel):
    username: str
    password: str


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str


class UpdateUserRequest(BaseModel):
    email: Optional[EmailStr] = None
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None
    license_key: Optional[str] = None


if __name__ == "__main__":
    # Test the auth service
    async def test():
        auth = AuthService()
        await auth.initialize()
        
        print("✅ Auth service initialized")
        
        # Test registration
        try:
            user = await auth.register_user(
                "testuser",
                "testuser@localhost",
                "password123"
            )
            print(f"✅ User registered: {user}")
        except ValueError as e:
            print(f"⚠️ Registration: {e}")
            
        # Test authentication
        try:
            result = await auth.authenticate("admin", "admin123")
            print(f"✅ Authentication successful")
            print(f"   Access token: {result['access_token'][:50]}...")
        except ValueError as e:
            print(f"❌ Authentication failed: {e}")
            
    asyncio.run(test())

