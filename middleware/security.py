"""
Security Middleware
Rate limiting, security headers, and request validation
"""

from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from typing import Dict, Optional
import time
from collections import defaultdict
import hashlib


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware to prevent abuse"""
    
    def __init__(self, app, requests_per_minute: int = 60):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.requests: Dict[str, list] = defaultdict(list)
        self.cleanup_interval = 60  # Clean up old entries every 60 seconds
        self.last_cleanup = time.time()
    
    def _get_client_id(self, request: Request) -> str:
        """Get unique client identifier"""
        # Use API key if available, otherwise use IP
        api_key = request.headers.get("X-API-Key")
        if api_key:
            return hashlib.sha256(api_key.encode()).hexdigest()[:16]
        
        # Get client IP
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        
        return request.client.host if request.client else "unknown"
    
    def _cleanup_old_requests(self):
        """Remove old request timestamps"""
        current_time = time.time()
        if current_time - self.last_cleanup > self.cleanup_interval:
            cutoff_time = current_time - 60
            for client_id in list(self.requests.keys()):
                self.requests[client_id] = [
                    ts for ts in self.requests[client_id]
                    if ts > cutoff_time
                ]
                if not self.requests[client_id]:
                    del self.requests[client_id]
            self.last_cleanup = current_time
    
    async def dispatch(self, request: Request, call_next):
        """Process request with rate limiting"""
        
        # Skip rate limiting for health check
        if request.url.path == "/health":
            return await call_next(request)
        
        client_id = self._get_client_id(request)
        current_time = time.time()
        
        # Cleanup old requests periodically
        self._cleanup_old_requests()
        
        # Get recent requests from this client
        recent_requests = [
            ts for ts in self.requests[client_id]
            if ts > current_time - 60
        ]
        
        # Check rate limit
        if len(recent_requests) >= self.requests_per_minute:
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Rate limit exceeded",
                    "message": f"Maximum {self.requests_per_minute} requests per minute",
                    "retry_after": 60
                },
                headers={"Retry-After": "60"}
            )
        
        # Record this request
        self.requests[client_id].append(current_time)
        
        # Add rate limit headers to response
        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(self.requests_per_minute)
        response.headers["X-RateLimit-Remaining"] = str(
            self.requests_per_minute - len(recent_requests) - 1
        )
        response.headers["X-RateLimit-Reset"] = str(int(current_time + 60))
        
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses"""
    
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        
        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self' data:; "
            "connect-src 'self' https:; "
            "frame-ancestors 'none'"
        )
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "geolocation=(), "
            "microphone=(), "
            "camera=()"
        )
        
        # Custom security headers
        response.headers["X-Powered-By"] = "dLNk Attack Platform"
        response.headers["X-Security-Version"] = "2.0.0"
        
        return response


class RequestValidationMiddleware(BaseHTTPMiddleware):
    """Validate and sanitize requests"""
    
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10MB
    
    async def dispatch(self, request: Request, call_next):
        """Validate request before processing"""
        
        # Check content length
        content_length = request.headers.get("Content-Length")
        if content_length and int(content_length) > self.MAX_CONTENT_LENGTH:
            return JSONResponse(
                status_code=413,
                content={
                    "error": "Payload too large",
                    "message": f"Maximum content length is {self.MAX_CONTENT_LENGTH} bytes"
                }
            )
        
        # Validate content type for POST/PUT requests
        if request.method in ["POST", "PUT", "PATCH"]:
            content_type = request.headers.get("Content-Type", "")
            if not content_type:
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "Missing Content-Type header",
                        "message": "Content-Type header is required for POST/PUT/PATCH requests"
                    }
                )
        
        # Check for suspicious patterns in URL
        suspicious_patterns = [
            "../",  # Path traversal
            "..\\",  # Path traversal (Windows)
            "<script",  # XSS attempt
            "javascript:",  # XSS attempt
            "eval(",  # Code injection
            "exec(",  # Code injection
        ]
        
        url_path = str(request.url.path).lower()
        for pattern in suspicious_patterns:
            if pattern in url_path:
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "Invalid request",
                        "message": "Suspicious pattern detected in URL"
                    }
                )
        
        return await call_next(request)


class IPWhitelistMiddleware(BaseHTTPMiddleware):
    """IP whitelist middleware (optional)"""
    
    def __init__(self, app, whitelist: Optional[list] = None, enabled: bool = False):
        super().__init__(app)
        self.whitelist = whitelist or []
        self.enabled = enabled
    
    async def dispatch(self, request: Request, call_next):
        """Check IP whitelist"""
        
        if not self.enabled or not self.whitelist:
            return await call_next(request)
        
        # Get client IP
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            client_ip = forwarded.split(",")[0].strip()
        else:
            client_ip = request.client.host if request.client else "unknown"
        
        # Check whitelist
        if client_ip not in self.whitelist and client_ip != "unknown":
            return JSONResponse(
                status_code=403,
                content={
                    "error": "Access denied",
                    "message": "Your IP address is not whitelisted"
                }
            )
        
        return await call_next(request)





class RateLimiter:
    """Simple rate limiter"""
    
    def __init__(self, max_requests: int = 60, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, list] = defaultdict(list)
    
    def check_rate_limit(self, client_id: str) -> bool:
        """Check if client is within rate limit"""
        current_time = time.time()
        cutoff_time = current_time - self.window_seconds
        
        # Remove old requests
        self.requests[client_id] = [
            ts for ts in self.requests[client_id]
            if ts > cutoff_time
        ]
        
        # Check limit
        if len(self.requests[client_id]) >= self.max_requests:
            return False
        
        # Add new request
        self.requests[client_id].append(current_time)
        return True


class SecurityMiddleware:
    """Security middleware placeholder"""
    pass

