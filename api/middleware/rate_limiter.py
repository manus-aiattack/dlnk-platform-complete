"""
Rate Limiting Middleware
Protect API from abuse and DoS attacks
"""

import time
from typing import Dict, Optional
from fastapi import Request, HTTPException
from collections import defaultdict
import asyncio


class RateLimiter:
    """Rate limiting middleware using sliding window algorithm"""
    
    def __init__(
        self, 
        requests_per_minute: int = 60,
        requests_per_hour: int = 1000,
        requests_per_day: int = 10000
    ):
        self.requests_per_minute = requests_per_minute
        self.requests_per_hour = requests_per_hour
        self.requests_per_day = requests_per_day
        
        # Storage for request timestamps
        # Format: {api_key: [timestamp1, timestamp2, ...]}
        self.request_history: Dict[str, list] = defaultdict(list)
        
        # Lock for thread safety
        self.lock = asyncio.Lock()
    
    async def check_rate_limit(self, api_key: str) -> bool:
        """ตรวจสอบว่าเกิน rate limit หรือไม่"""
        async with self.lock:
            current_time = time.time()
            
            # Clean old timestamps
            await self._clean_old_timestamps(api_key, current_time)
            
            # Get request history
            history = self.request_history[api_key]
            
            # Check minute limit
            minute_ago = current_time - 60
            minute_requests = sum(1 for ts in history if ts > minute_ago)
            if minute_requests >= self.requests_per_minute:
                return False
            
            # Check hour limit
            hour_ago = current_time - 3600
            hour_requests = sum(1 for ts in history if ts > hour_ago)
            if hour_requests >= self.requests_per_hour:
                return False
            
            # Check day limit
            day_ago = current_time - 86400
            day_requests = sum(1 for ts in history if ts > day_ago)
            if day_requests >= self.requests_per_day:
                return False
            
            # Add current request
            history.append(current_time)
            
            return True
    
    async def _clean_old_timestamps(self, api_key: str, current_time: float):
        """ลบ timestamps ที่เก่าเกิน 1 วัน"""
        day_ago = current_time - 86400
        self.request_history[api_key] = [
            ts for ts in self.request_history[api_key] 
            if ts > day_ago
        ]
    
    async def get_rate_limit_info(self, api_key: str) -> Dict[str, int]:
        """ดูข้อมูล rate limit ปัจจุบัน"""
        async with self.lock:
            current_time = time.time()
            await self._clean_old_timestamps(api_key, current_time)
            
            history = self.request_history[api_key]
            
            # Count requests in different time windows
            minute_ago = current_time - 60
            hour_ago = current_time - 3600
            day_ago = current_time - 86400
            
            minute_requests = sum(1 for ts in history if ts > minute_ago)
            hour_requests = sum(1 for ts in history if ts > hour_ago)
            day_requests = sum(1 for ts in history if ts > day_ago)
            
            return {
                "minute": {
                    "used": minute_requests,
                    "limit": self.requests_per_minute,
                    "remaining": max(0, self.requests_per_minute - minute_requests)
                },
                "hour": {
                    "used": hour_requests,
                    "limit": self.requests_per_hour,
                    "remaining": max(0, self.requests_per_hour - hour_requests)
                },
                "day": {
                    "used": day_requests,
                    "limit": self.requests_per_day,
                    "remaining": max(0, self.requests_per_day - day_requests)
                }
            }
    
    async def reset_rate_limit(self, api_key: str):
        """รีเซ็ต rate limit สำหรับ API key"""
        async with self.lock:
            if api_key in self.request_history:
                del self.request_history[api_key]


# Global rate limiter instance
rate_limiter = RateLimiter(
    requests_per_minute=60,
    requests_per_hour=1000,
    requests_per_day=10000
)


async def rate_limit_middleware(request: Request, call_next):
    """Middleware สำหรับตรวจสอบ rate limit"""
    
    # Skip rate limiting for health check
    if request.url.path == "/health":
        return await call_next(request)
    
    # Get API key
    api_key = request.headers.get("X-API-Key")
    
    if api_key:
        # Check rate limit
        allowed = await rate_limiter.check_rate_limit(api_key)
        
        if not allowed:
            # Get rate limit info
            info = await rate_limiter.get_rate_limit_info(api_key)
            
            raise HTTPException(
                status_code=429,
                detail={
                    "error": "Rate limit exceeded",
                    "message": "Too many requests. Please try again later.",
                    "rate_limit": info
                }
            )
    
    # Continue with request
    response = await call_next(request)
    
    # Add rate limit headers
    if api_key:
        info = await rate_limiter.get_rate_limit_info(api_key)
        response.headers["X-RateLimit-Limit-Minute"] = str(info["minute"]["limit"])
        response.headers["X-RateLimit-Remaining-Minute"] = str(info["minute"]["remaining"])
        response.headers["X-RateLimit-Limit-Hour"] = str(info["hour"]["limit"])
        response.headers["X-RateLimit-Remaining-Hour"] = str(info["hour"]["remaining"])
    
    return response


class IPRateLimiter:
    """Rate limiting based on IP address"""
    
    def __init__(self, requests_per_minute: int = 100):
        self.requests_per_minute = requests_per_minute
        self.request_history: Dict[str, list] = defaultdict(list)
        self.lock = asyncio.Lock()
    
    async def check_rate_limit(self, ip: str) -> bool:
        """ตรวจสอบ rate limit สำหรับ IP"""
        async with self.lock:
            current_time = time.time()
            minute_ago = current_time - 60
            
            # Clean old timestamps
            self.request_history[ip] = [
                ts for ts in self.request_history[ip]
                if ts > minute_ago
            ]
            
            # Check limit
            if len(self.request_history[ip]) >= self.requests_per_minute:
                return False
            
            # Add current request
            self.request_history[ip].append(current_time)
            
            return True


# Global IP rate limiter
ip_rate_limiter = IPRateLimiter(requests_per_minute=100)


async def ip_rate_limit_middleware(request: Request, call_next):
    """Middleware สำหรับตรวจสอบ IP rate limit"""
    
    # Skip for health check
    if request.url.path == "/health":
        return await call_next(request)
    
    # Get client IP
    client_ip = request.client.host if request.client else "unknown"
    
    # Check rate limit
    allowed = await ip_rate_limiter.check_rate_limit(client_ip)
    
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail={
                "error": "Too many requests from your IP",
                "message": "Please try again later."
            }
        )
    
    return await call_next(request)

