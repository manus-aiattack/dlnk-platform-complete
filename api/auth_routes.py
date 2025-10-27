"""
Authentication API Routes
FastAPI routes for authentication and user management
"""

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from typing import Optional, List
from services.auth_service import (
    AuthService,
    UserRole,
    RegisterRequest,
    LoginRequest,
    ChangePasswordRequest,
    UpdateUserRequest,
    get_current_user,
    require_role
)

# Create router
router = APIRouter(prefix="/auth", tags=["authentication"])
security = HTTPBearer()

# Global auth service instance (will be injected)
auth_service: Optional[AuthService] = None


def set_auth_service(service: AuthService):
    """Set the global auth service instance"""
    global auth_service
    auth_service = service


def get_auth_service() -> AuthService:
    """Dependency to get auth service"""
    if not auth_service:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Auth service not initialized"
        )
    return auth_service


# API Models
class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
    expires_in: int
    user: dict


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class ApiKeyResponse(BaseModel):
    api_key: str


# Routes

@router.post("/register", response_model=dict, status_code=status.HTTP_201_CREATED)
async def register(
    request: RegisterRequest,
    auth: AuthService = Depends(get_auth_service)
):
    """
    Register a new user
    
    - **username**: Unique username
    - **email**: Email address
    - **password**: Password (min 8 characters)
    - **role**: User role (admin, user, viewer)
    """
    try:
        user = await auth.register_user(
            username=request.username,
            email=request.email,
            password=request.password,
            role=request.role
        )
        return {
            "success": True,
            "message": "User registered successfully",
            "data": user
        }
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.post("/login", response_model=TokenResponse)
async def login(
    request: LoginRequest,
    auth: AuthService = Depends(get_auth_service)
):
    """
    Login with username and password
    
    Returns JWT access token and refresh token
    """
    try:
        result = await auth.authenticate(
            username=request.username,
            password=request.password
        )
        return result
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )


@router.post("/refresh", response_model=dict)
async def refresh_token(
    request: RefreshTokenRequest,
    auth: AuthService = Depends(get_auth_service)
):
    """
    Refresh access token using refresh token
    """
    try:
        result = await auth.refresh_access_token(request.refresh_token)
        return {
            "success": True,
            "data": result
        }
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )


@router.post("/logout")
async def logout(
    current_user: dict = Depends(get_current_user),
    auth: AuthService = Depends(get_auth_service)
):
    """
    Logout (invalidate refresh token)
    """
    await auth.logout(current_user['user_id'])
    return {
        "success": True,
        "message": "Logged out successfully"
    }


@router.get("/me")
async def get_current_user_info(
    current_user: dict = Depends(get_current_user),
    auth: AuthService = Depends(get_auth_service)
):
    """
    Get current user information
    """
    user = await auth._get_user(current_user['username'])
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
        
    return {
        "success": True,
        "data": {
            "user_id": user.user_id,
            "username": user.username,
            "email": user.email,
            "role": user.role.value,
            "api_key": user.api_key,
            "license_key": user.license_key,
            "created_at": user.created_at,
            "last_login": user.last_login,
            "is_active": user.is_active
        }
    }


@router.post("/change-password")
async def change_password(
    request: ChangePasswordRequest,
    current_user: dict = Depends(get_current_user),
    auth: AuthService = Depends(get_auth_service)
):
    """
    Change current user's password
    """
    try:
        await auth.change_password(
            username=current_user['username'],
            old_password=request.old_password,
            new_password=request.new_password
        )
        return {
            "success": True,
            "message": "Password changed successfully"
        }
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.post("/reset-api-key", response_model=ApiKeyResponse)
async def reset_api_key(
    current_user: dict = Depends(get_current_user),
    auth: AuthService = Depends(get_auth_service)
):
    """
    Reset current user's API key
    """
    try:
        new_api_key = await auth.reset_api_key(current_user['username'])
        return {
            "api_key": new_api_key
        }
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


# Admin routes

@router.get("/users", dependencies=[Depends(require_role(UserRole.ADMIN))])
async def list_users(
    role: Optional[str] = None,
    auth: AuthService = Depends(get_auth_service)
):
    """
    List all users (Admin only)
    
    - **role**: Filter by role (optional)
    """
    user_role = UserRole(role) if role else None
    users = await auth.list_users(role=user_role)
    
    return {
        "success": True,
        "data": users,
        "count": len(users)
    }


@router.get("/users/{username}", dependencies=[Depends(require_role(UserRole.ADMIN))])
async def get_user(
    username: str,
    auth: AuthService = Depends(get_auth_service)
):
    """
    Get user by username (Admin only)
    """
    user = await auth._get_user(username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User '{username}' not found"
        )
        
    return {
        "success": True,
        "data": {
            "user_id": user.user_id,
            "username": user.username,
            "email": user.email,
            "role": user.role.value,
            "api_key": user.api_key,
            "license_key": user.license_key,
            "created_at": user.created_at,
            "last_login": user.last_login,
            "is_active": user.is_active,
            "metadata": user.metadata
        }
    }


@router.put("/users/{username}", dependencies=[Depends(require_role(UserRole.ADMIN))])
async def update_user(
    username: str,
    request: UpdateUserRequest,
    auth: AuthService = Depends(get_auth_service)
):
    """
    Update user (Admin only)
    """
    try:
        updates = request.dict(exclude_none=True)
        if 'role' in updates:
            updates['role'] = updates['role'].value
            
        user = await auth.update_user(username, updates)
        return {
            "success": True,
            "message": "User updated successfully",
            "data": user
        }
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.delete("/users/{username}", dependencies=[Depends(require_role(UserRole.ADMIN))])
async def delete_user(
    username: str,
    auth: AuthService = Depends(get_auth_service)
):
    """
    Delete user (Admin only)
    """
    try:
        await auth.delete_user(username)
        return {
            "success": True,
            "message": f"User '{username}' deleted successfully"
        }
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.post("/users/{username}/reset-api-key", 
            dependencies=[Depends(require_role(UserRole.ADMIN))])
async def admin_reset_api_key(
    username: str,
    auth: AuthService = Depends(get_auth_service)
):
    """
    Reset user's API key (Admin only)
    """
    try:
        new_api_key = await auth.reset_api_key(username)
        return {
            "success": True,
            "message": "API key reset successfully",
            "data": {
                "api_key": new_api_key
            }
        }
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


# API Key authentication endpoint
@router.post("/verify-api-key")
async def verify_api_key(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    auth: AuthService = Depends(get_auth_service)
):
    """
    Verify API key
    
    Use this endpoint to verify if an API key is valid
    """
    api_key = credentials.credentials
    user = await auth.verify_api_key(api_key)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key"
        )
        
    return {
        "success": True,
        "data": {
            "user_id": user.user_id,
            "username": user.username,
            "email": user.email,
            "role": user.role.value,
            "license_key": user.license_key
        }
    }

