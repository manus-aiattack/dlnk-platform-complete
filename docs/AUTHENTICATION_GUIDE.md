# Authentication & Admin System Guide

Complete guide for the authentication and admin panel system in dLNk dLNk Framework.

## Overview

The authentication system provides:
- **User Management** - Registration, login, roles, permissions
- **JWT Authentication** - Secure token-based authentication
- **API Key Management** - API keys for programmatic access
- **Admin Panel** - Web-based administration interface
- **Role-Based Access Control (RBAC)** - Admin, User, Viewer roles
- **License Integration** - Seamless integration with license system

---

## Architecture

### Components

1. **AuthService** (`services/auth_service.py`)
   - User registration and authentication
   - Password hashing and verification
   - JWT token generation and validation
   - API key management
   - Session management

2. **Auth API Routes** (`api/auth_routes.py`)
   - FastAPI endpoints for authentication
   - User CRUD operations
   - Admin-only endpoints

3. **Main API Server** (`api/main_api.py`)
   - Integrated API server
   - Authentication middleware
   - Static file serving for web UI

4. **Web Interfaces**
   - **Dashboard** (`web/dashboard_dlnk.html`) - Main attack dashboard
   - **Admin Panel** (`web/admin_panel.html`) - Administration interface

---

## Quick Start

### 1. Install Dependencies

```bash
pip install fastapi uvicorn pyjwt aioredis python-multipart
```

### 2. Start Redis

```bash
# Using Docker
docker run -d -p 6379:6379 redis:latest

# Or using system Redis
redis-server
```

### 3. Start API Server

```bash
cd dlnk_dlnk_framework_v3/dlnk_dlnk
python api/main_api.py
```

The server will start on `localhost:8000`

### 4. Access Interfaces

- **API Documentation**: localhost:8000/api/docs
- **Main Dashboard**: localhost:8000/dashboard/dashboard_dlnk.html
- **Admin Panel**: localhost:8000/admin/admin_panel.html

---

## Default Credentials

### Admin Account

```
Username: admin
Password: admin123
```

**⚠️ IMPORTANT: Change the default password immediately in production!**

---

## User Roles

### Admin
- Full system access
- User management
- License management
- System configuration
- View all logs and activity

### User
- Access to attack functions
- View own activity
- Limited agent access based on license

### Viewer
- Read-only access
- View dashboards and reports
- No attack capabilities

---

## API Endpoints

### Authentication

#### Register User
```bash
POST /api/auth/register
Content-Type: application/json

{
  "username": "newuser",
  "email": "user@localhost:8000",
  "password": "securepassword",
  "role": "user"
}
```

#### Login
```bash
POST /api/auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "admin123"
}

# Response:
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "token_type": "bearer",
  "expires_in": 86400,
  "user": {
    "user_id": "usr_abc123",
    "username": "admin",
    "email": "admin@dlnkhack.local",
    "role": "admin",
    "api_key": "DLNK-..."
  }
}
```

#### Get Current User
```bash
GET /api/auth/me
Authorization: Bearer <access_token>
```

#### Change Password
```bash
POST /api/auth/change-password
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "old_password": "currentpassword",
  "new_password": "newpassword"
}
```

#### Reset API Key
```bash
POST /api/auth/reset-api-key
Authorization: Bearer <access_token>
```

#### Refresh Token
```bash
POST /api/auth/refresh
Content-Type: application/json

{
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGc..."
}
```

#### Logout
```bash
POST /api/auth/logout
Authorization: Bearer <access_token>
```

### Admin Endpoints

#### List Users (Admin Only)
```bash
GET /api/auth/users?role=user
Authorization: Bearer <admin_access_token>
```

#### Get User (Admin Only)
```bash
GET /api/auth/users/{username}
Authorization: Bearer <admin_access_token>
```

#### Update User (Admin Only)
```bash
PUT /api/auth/users/{username}
Authorization: Bearer <admin_access_token>
Content-Type: application/json

{
  "email": "newemail@localhost:8000",
  "role": "admin",
  "is_active": true,
  "license_key": "DLNK-ENT-..."
}
```

#### Delete User (Admin Only)
```bash
DELETE /api/auth/users/{username}
Authorization: Bearer <admin_access_token>
```

### API Key Authentication

#### Verify API Key
```bash
POST /api/auth/verify-api-key
Authorization: Bearer <api_key>
```

---

## Using JWT Tokens

### In HTTP Requests

```python
import requests

# Login
response = requests.post('localhost:8000/api/auth/login', json={
    'username': 'admin',
    'password': 'admin123'
})
data = response.json()
access_token = data['access_token']

# Use token in subsequent requests
headers = {'Authorization': f'Bearer {access_token}'}
response = requests.get('localhost:8000/api/auth/me', headers=headers)
print(response.json())
```

### In JavaScript

```javascript
// Login
const response = await fetch('localhost:8000/api/auth/login', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
        username: 'admin',
        password: 'admin123'
    })
});

const data = await response.json();
const accessToken = data.access_token;

// Store token
localStorage.setItem('access_token', accessToken);

// Use token
const userResponse = await fetch('localhost:8000/api/auth/me', {
    headers: {'Authorization': `Bearer ${accessToken}`}
});
```

---

## Using API Keys

API keys are permanent credentials that don't expire (unlike JWT tokens).

### Get Your API Key

1. Login to the dashboard
2. Go to your profile
3. Copy your API key

Or via API:
```bash
GET /api/auth/me
Authorization: Bearer <access_token>

# Response includes api_key field
```

### Use API Key

```bash
# Same as JWT token
curl -H "Authorization: Bearer DLNK-your-api-key" \
     localhost:8000/api/auth/verify-api-key
```

### Reset API Key

If your API key is compromised:

```bash
POST /api/auth/reset-api-key
Authorization: Bearer <access_token>
```

---

## Admin Panel Features

### Dashboard
- System statistics
- Active users count
- Running agents
- Active workflows
- Recent activity log

### User Management
- Create new users
- Edit user details
- Change user roles
- Activate/deactivate users
- Delete users
- Reset user API keys

### License Management
- Generate new licenses
- View all licenses
- Check license status
- Revoke licenses

### Agent Status
- View all 62 agents
- Check agent health
- Monitor agent activity

### Workflow Management
- View running workflows
- Check workflow history
- Monitor workflow status

### System Logs
- View system logs
- Filter by level
- Search logs

### Settings
- System configuration
- Update settings
- Manage integrations

---

## Security Best Practices

### 1. Change Default Credentials

```python
# After first login, change admin password
POST /api/auth/change-password
{
    "old_password": "admin123",
    "new_password": "your-strong-password-here"
}
```

### 2. Use Strong Passwords

- Minimum 12 characters
- Mix of uppercase, lowercase, numbers, symbols
- No dictionary words
- Unique per user

### 3. Secure the Secret Key

In `api/main_api.py`, change the secret key:

```python
auth_service = AuthService(
    redis_url="redis://localhost:6379",
    secret_key="your-very-long-random-secret-key-here"  # Change this!
)
```

Generate a secure key:
```python
import secrets
print(secrets.token_urlsafe(32))
```

### 4. Enable HTTPS

In production, always use HTTPS:

```python
# Use nginx as reverse proxy
server {
    listen 443 ssl;
    server_name yourdomain.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### 5. Rotate API Keys Regularly

```bash
# Reset API key every 90 days
POST /api/auth/reset-api-key
```

### 6. Monitor Failed Login Attempts

Implement rate limiting and monitoring for failed logins.

### 7. Use Environment Variables

```bash
# .env file
REDIS_URL=redis://localhost:6379
JWT_SECRET_KEY=your-secret-key
API_HOST=0.0.0.0
API_PORT=8000
```

```python
import os
from dotenv import load_dotenv

load_dotenv()

auth_service = AuthService(
    redis_url=os.getenv('REDIS_URL'),
    secret_key=os.getenv('JWT_SECRET_KEY')
)
```

---

## Integration with Framework

### Protect Your Endpoints

```python
from api.auth_routes import get_current_user, require_role
from services.auth_service import UserRole

@app.post("/api/attack/start")
async def start_attack(
    target: str,
    current_user: dict = Depends(get_current_user)
):
    # User is authenticated
    # current_user contains: user_id, username, email, role
    ...

@app.post("/api/admin/config")
async def update_config(
    config: dict,
    current_user: dict = Depends(require_role(UserRole.ADMIN))
):
    # Only admins can access this
    ...
```

### Check License in Endpoints

```python
from services.license_service import LicenseService

@app.post("/api/attack/zeroday")
async def zeroday_hunt(
    target: str,
    current_user: dict = Depends(get_current_user),
    license_svc: LicenseService = Depends(get_license_service)
):
    # Get user's license
    user = await auth_service._get_user(current_user['username'])
    
    if not user.license_key:
        raise HTTPException(400, "No license assigned")
    
    # Verify license
    license_data = await license_svc.verify_license(user.license_key)
    
    # Check if feature is allowed
    if 'zeroday_hunting' not in license_data['features']:
        raise HTTPException(403, "Feature not available in your license")
    
    # Proceed with attack
    ...
```

---

## Troubleshooting

### Cannot Login

1. Check if Redis is running:
   ```bash
   redis-cli ping
   # Should return: PONG
   ```

2. Check if API server is running:
   ```bash
   curl localhost:8000/health
   ```

3. Verify credentials:
   ```bash
   # Default admin: admin / admin123
   ```

### Token Expired

Tokens expire after 24 hours. Use refresh token:

```bash
POST /api/auth/refresh
{
    "refresh_token": "your-refresh-token"
}
```

### API Key Not Working

1. Verify the key is correct
2. Check if user is active
3. Try resetting the API key

### Admin Panel Not Loading

1. Check if static files are mounted correctly
2. Verify web directory exists
3. Check browser console for errors

### CORS Errors

Add your frontend origin to CORS middleware:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://yourdomain.com"],  # Specify your domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

---

## Production Deployment

### 1. Use Production ASGI Server

```bash
# Install gunicorn
pip install gunicorn

# Run with gunicorn
gunicorn api.main_api:app \
    --workers 4 \
    --worker-class uvicorn.workers.UvicornWorker \
    --bind 0.0.0.0:8000
```

### 2. Use Redis with Authentication

```bash
# redis.conf
requirepass your-redis-password
```

```python
auth_service = AuthService(
    redis_url="redis://:your-redis-password@localhost:6379"
)
```

### 3. Enable Rate Limiting

```bash
pip install slowapi
```

```python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

@app.post("/api/auth/login")
@limiter.limit("5/minute")
async def login(...):
    ...
```

### 4. Set Up Monitoring

```bash
pip install prometheus-fastapi-instrumentator
```

```python
from prometheus_fastapi_instrumentator import Instrumentator

Instrumentator().instrument(app).expose(app)
```

### 5. Configure Logging

```python
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('api.log'),
        logging.StreamHandler()
    ]
)
```

---

## API Reference

Complete API documentation is available at:
- **Swagger UI**: localhost:8000/api/docs
- **ReDoc**: localhost:8000/api/redoc

---

## Support

For issues or questions:
1. Check the logs: `tail -f api.log`
2. Review the API documentation
3. Check Redis connection
4. Verify environment variables

---

**Created by:** dLNk HACK Team  
**Version:** 3.0.0  
**Last Updated:** 2024-10-22

