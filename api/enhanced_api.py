"""
Enhanced API with Performance Optimization and Caching
Phase 4: API & Backend Optimization
"""

import asyncio
import json
import time
import logging
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timedelta
from functools import wraps
from dataclasses import dataclass, asdict
import hashlib
import pickle

import redis.asyncio as aioredis
import asyncpg
from fastapi import FastAPI, Depends, HTTPException, status, Request, Response
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel
from starlette.middleware.base import BaseHTTPMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from core.enhanced_orchestrator import EnhancedOrchestrator
from core.ai_models.enhanced_ai_decision_engine import EnhancedAIDecisionEngine
from core.self_healing.enhanced_error_detector import EnhancedErrorDetector
from core.self_learning.enhanced_adaptive_learner import EnhancedAdaptiveLearner
from core.data_models import AttackPhase, Strategy, AgentData
from core.logger import log


# Performance monitoring dataclass
@dataclass
class PerformanceMetrics:
    """API performance metrics"""
    endpoint: str
    method: str
    status_code: int
    response_time_ms: float
    request_size: int
    response_size: int
    timestamp: str
    cache_hit: bool = False


# Cache configuration
@dataclass
class CacheConfig:
    """Cache configuration"""
    default_ttl: int = 300  # 5 minutes
    short_ttl: int = 60      # 1 minute
    medium_ttl: int = 600    # 10 minutes
    long_ttl: int = 3600     # 1 hour
    agents_ttl: int = 1800   # 30 minutes
    results_ttl: int = 900   # 15 minutes


class PerformanceMonitor:
    """Performance monitoring and metrics collection"""

    def __init__(self):
        self.metrics: List[PerformanceMetrics] = []
        self.start_time = time.time()

    def record_request(
        self,
        endpoint: str,
        method: str,
        status_code: int,
        response_time: float,
        request_size: int = 0,
        response_size: int = 0,
        cache_hit: bool = False
    ):
        """Record performance metrics"""
        metric = PerformanceMetrics(
            endpoint=endpoint,
            method=method,
            status_code=status_code,
            response_time_ms=response_time,
            request_size=request_size,
            response_size=response_size,
            timestamp=datetime.now().isoformat(),
            cache_hit=cache_hit
        )
        self.metrics.append(metric)

        # Keep only last 1000 metrics
        if len(self.metrics) > 1000:
            self.metrics.pop(0)

        # Log slow requests
        if response_time > 1000:  # > 1 second
            log.warning(f"Slow request detected: {endpoint} took {response_time:.2f}ms")

    def get_stats(self) -> Dict[str, Any]:
        """Get performance statistics"""
        if not self.metrics:
            return {"message": "No metrics available"}

        response_times = [m.response_time_ms for m in self.metrics]
        cache_hits = [m.cache_hit for m in self.metrics]

        return {
            "total_requests": len(self.metrics),
            "avg_response_time_ms": sum(response_times) / len(response_times),
            "p95_response_time_ms": sorted(response_times)[int(len(response_times) * 0.95)] if len(response_times) > 0 else 0,
            "p99_response_time_ms": sorted(response_times)[int(len(response_times) * 0.99)] if len(response_times) > 0 else 0,
            "error_rate": len([m for m in self.metrics if m.status_code >= 400]) / len(self.metrics),
            "cache_hit_rate": sum(cache_hits) / len(cache_hits) if cache_hits else 0,
            "uptime_seconds": time.time() - self.start_time
        }


class CacheManager:
    """Advanced caching manager with Redis integration"""

    def __init__(self, redis_url: str, config: CacheConfig = None):
        self.redis_url = redis_url
        self.config = config or CacheConfig()
        self.redis_pool: Optional[aioredis.ConnectionPool] = None

    async def connect(self):
        """Connect to Redis"""
        try:
            self.redis_pool = aioredis.ConnectionPool.from_url(
                self.redis_url,
                encoding="utf-8",
                decode_responses=True,
                max_connections=50
            )
            log.success("CacheManager connected to Redis")
        except Exception as e:
            log.error(f"Failed to connect to Redis: {e}")

    async def get_redis(self) -> aioredis.Redis:
        """Get Redis connection"""
        if not self.redis_pool:
            await self.connect()
        return aioredis.Redis(connection_pool=self.redis_pool)

    def _generate_key(self, key: str) -> str:
        """Generate cache key with prefix"""
        return f"manus_api:{key}"

    def _serialize(self, data: Any) -> str:
        """Serialize data for caching"""
        try:
            return json.dumps(data, default=str)
        except (TypeError, ValueError):
            # Fallback to pickle for complex objects
            return pickle.dumps(data).hex()

    def _deserialize(self, data: str) -> Any:
        """Deserialize cached data"""
        try:
            return json.loads(data)
        except (json.JSONDecodeError, TypeError):
            # Fallback to pickle
            try:
                return pickle.loads(bytes.fromhex(data))
            except:
                return data

    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        try:
            redis = await self.get_redis()
            cache_key = self._generate_key(key)
            result = await redis.get(cache_key)

            if result:
                return self._deserialize(result)
            return None
        except Exception as e:
            log.warning(f"Cache get failed: {e}")
            return None

    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in cache"""
        try:
            redis = await self.get_redis()
            cache_key = self._generate_key(key)
            serialized = self._serialize(value)
            ttl = ttl or self.config.default_ttl

            await redis.setex(cache_key, ttl, serialized)
            return True
        except Exception as e:
            log.warning(f"Cache set failed: {e}")
            return False

    async def delete(self, key: str) -> bool:
        """Delete from cache"""
        try:
            redis = await self.get_redis()
            cache_key = self._generate_key(key)
            result = await redis.delete(cache_key)
            return result > 0
        except Exception as e:
            log.warning(f"Cache delete failed: {e}")
            return False

    async def clear_pattern(self, pattern: str) -> bool:
        """Clear cache by pattern"""
        try:
            redis = await self.get_redis()
            cache_pattern = self._generate_key(pattern)
            keys = await redis.keys(cache_pattern)

            if keys:
                await redis.delete(*keys)
                return True
            return False
        except Exception as e:
            log.warning(f"Cache clear pattern failed: {e}")
            return False


class DatabaseConnectionPool:
    """Advanced database connection pooling"""

    def __init__(self, database_url: str):
        self.database_url = database_url
        self.pool: Optional[asyncpg.Pool] = None

    async def connect(self):
        """Create connection pool"""
        try:
            self.pool = await asyncpg.create_pool(
                self.database_url,
                min_size=10,
                max_size=100,
                max_queries=50000,
                max_inactive_connection_lifetime=300,
                command_timeout=60,
                server_settings={
                    'application_name': 'manus_api'
                }
            )
            log.success("DatabaseConnectionPool created")
        except Exception as e:
            log.error(f"Failed to create database pool: {e}")
            raise

    async def get_connection(self):
        """Get database connection from pool"""
        if not self.pool:
            await self.connect()
        return self.pool.acquire()

    async def execute(self, query: str, *args, timeout: int = 30) -> Any:
        """Execute query with timeout"""
        if not self.pool:
            await self.connect()

        try:
            async with self.pool.acquire() as connection:
                return await connection.fetch(query, *args, timeout=timeout)
        except Exception as e:
            log.error(f"Database query failed: {e}")
            raise

    async def close(self):
        """Close connection pool"""
        if self.pool:
            await self.pool.close()
            log.info("DatabaseConnectionPool closed")


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Custom rate limiting middleware"""

    def __init__(self, app, redis_url: str):
        super().__init__(app)
        self.redis = aioredis.from_url(redis_url, encoding="utf-8", decode_responses=True)
        self.rate_limits = {
            "requests_per_minute": 60,
            "requests_per_hour": 1000,
            "burst_limit": 10
        }

    async def dispatch(self, request: Request, call_next):
        """Apply rate limiting"""
        client_ip = get_remote_address(request)
        endpoint = request.url.path

        # Check rate limits
        current_time = int(time.time())
        minute_key = f"rate_limit:{client_ip}:{endpoint}:minute"
        hour_key = f"rate_limit:{client_ip}:{endpoint}:hour"

        # Check minute limit
        minute_count = await self.redis.incr(minute_key)
        if minute_count == 1:
            await self.redis.expire(minute_key, 60)

        if minute_count > self.rate_limits["requests_per_minute"]:
            return JSONResponse(
                status_code=429,
                content={"error": "Rate limit exceeded", "limit": "60 requests per minute"},
                headers={"X-RateLimit-Limit": str(self.rate_limits["requests_per_minute"])}
            )

        # Check hour limit
        hour_count = await self.redis.incr(hour_key)
        if hour_count == 1:
            await self.redis.expire(hour_key, 3600)

        if hour_count > self.rate_limits["requests_per_hour"]:
            return JSONResponse(
                status_code=429,
                content={"error": "Rate limit exceeded", "limit": "1000 requests per hour"},
                headers={"X-RateLimit-Limit": str(self.rate_limits["requests_per_hour"])}
            )

        # Add rate limit headers
        response = await call_next(request)
        response.headers["X-RateLimit-Remaining-Minute"] = str(
            max(0, self.rate_limits["requests_per_minute"] - minute_count)
        )
        response.headers["X-RateLimit-Remaining-Hour"] = str(
            max(0, self.rate_limits["requests_per_hour"] - hour_count)
        )

        return response


# Cache decorator
def cached(ttl: Optional[int] = None, key_func=None):
    """Decorator for caching function results"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Generate cache key
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                # Default key generation
                key_data = {
                    "func": func.__name__,
                    "args": str(args),
                    "kwargs": str(sorted(kwargs.items())) if kwargs else ""
                }
                cache_key = hashlib.md5(str(key_data).encode()).hexdigest()

            # Try to get from cache
            cached_result = await cache_manager.get(cache_key)
            if cached_result is not None:
                wrapper.cache_hit = True
                return cached_result

            # Execute function
            result = await func(*args, **kwargs)

            # Cache result
            await cache_manager.set(cache_key, result, ttl)

            wrapper.cache_hit = False
            return result
        return wrapper
    return decorator


# Performance monitoring decorator
def track_performance(func):
    """Decorator for tracking performance"""
    @wraps(func)
    async def wrapper(*args, **kwargs):
        start_time = time.time()
        request_size = len(str(args)) + len(str(kwargs))
        cache_hit = False

        try:
            result = await func(*args, **kwargs)

            # Check if result came from cache
            if hasattr(wrapper, 'cache_hit'):
                cache_hit = wrapper.cache_hit
                delattr(wrapper, 'cache_hit')

            # Record metrics
            performance_monitor.record_request(
                endpoint=func.__name__,
                method="GET",
                status_code=200,
                response_time_ms=(time.time() - start_time) * 1000,
                request_size=request_size,
                response_size=len(str(result)),
                cache_hit=cache_hit
            )

            return result

        except Exception as e:
            # Record error metrics
            performance_monitor.record_request(
                endpoint=func.__name__,
                method="GET",
                status_code=500,
                response_time_ms=(time.time() - start_time) * 1000,
                request_size=request_size,
                response_size=0
            )
            raise

    return wrapper


# Global instances
cache_manager = None
performance_monitor = PerformanceMonitor()
db_pool = None


# Enhanced API Application
def create_enhanced_app():
    """Create enhanced FastAPI application with optimizations"""
    global cache_manager, db_pool

    # Initialize cache manager
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    cache_manager = CacheManager(redis_url)

    # Initialize database pool
    database_url = os.getenv("DATABASE_URL", "postgresql://user:pass@localhost/db")
    db_pool = DatabaseConnectionPool(database_url)

    app = FastAPI(
        title="Manus AI Attack Platform - Enhanced API",
        version="2.0.0",
        description="High-performance API with advanced caching and optimization"
    )

    # Add middleware
    app.add_middleware(GZipMiddleware, minimum_size=1000)
    app.add_middleware(CORSMiddleware,
                      allow_origins=["*"],
                      allow_credentials=True,
                      allow_methods=["*"],
                      allow_headers=["*"])

    # Add rate limiting
    app.add_middleware(RateLimitMiddleware, redis_url=redis_url)

    # Add performance monitoring middleware
    @app.middleware("http")
    async def performance_middleware(request: Request, call_next):
        start_time = time.time()
        response = await call_next(request)
        response_time = (time.time() - start_time) * 1000

        # Add performance header
        response.headers["X-Response-Time"] = f"{response_time:.2f}ms"
        return response

    # Health check endpoint
    @app.get("/health")
    async def health_check():
        """Enhanced health check with detailed status"""
        try:
            # Check database connection
            db_status = "healthy"
            try:
                if db_pool and db_pool.pool:
                    async with db_pool.pool.acquire() as conn:
                        await conn.fetchval("SELECT 1")
                else:
                    await db_pool.connect()
            except Exception as e:
                db_status = f"unhealthy: {e}"

            # Check cache connection
            cache_status = "healthy"
            try:
                redis = await cache_manager.get_redis()
                await redis.ping()
            except Exception as e:
                cache_status = f"unhealthy: {e}"

            return {
                "status": "healthy",
                "timestamp": datetime.now().isoformat(),
                "database": db_status,
                "cache": cache_status,
                "uptime_seconds": time.time() - performance_monitor.start_time,
                "version": "2.0.0"
            }
        except Exception as e:
            raise HTTPException(status_code=503, detail=f"Health check failed: {e}")

    # Performance metrics endpoint
    @app.get("/metrics/performance")
    async def get_performance_stats():
        """Get API performance statistics"""
        return performance_monitor.get_stats()

    # Cache management endpoints
    @app.post("/cache/clear/{pattern}")
    async def clear_cache_pattern(pattern: str):
        """Clear cache by pattern"""
        success = await cache_manager.clear_pattern(pattern)
        return {"success": success, "pattern": pattern}

    @app.get("/cache/stats")
    async def get_cache_stats():
        """Get cache statistics"""
        try:
            redis = await cache_manager.get_redis()
            info = await redis.info()
            return {
                "connected": True,
                "memory_used_mb": info.get("used_memory", 0) / 1024 / 1024,
                "total_keys": info.get("db0", {}).get("keys", 0),
                "hit_rate": info.get("keyspace_hits", 0) / max(info.get("keyspace_hits", 0) + info.get("keyspace_misses", 1), 1)
            }
        except Exception as e:
            return {"connected": False, "error": str(e)}

    # Enhanced agent endpoints
    @app.get("/api/v2/agents")
    @track_performance
    @cached(ttl=cache_manager.config.agents_ttl if cache_manager else 1800)
    async def get_agents_enhanced():
        """Get agents with caching and performance optimization"""
        try:
            # This would normally query the database
            # For now, return mock data
            agents = [
                {"name": "NmapAgent", "type": "reconnaissance", "version": "1.0.0"},
                {"name": "SQLMapAgent", "type": "vulnerability_discovery", "version": "1.0.0"},
                {"name": "SQLInjectionExploiter", "type": "exploitation", "version": "1.0.0"}
            ]
            return {"agents": agents, "count": len(agents)}
        except Exception as e:
            log.error(f"Failed to get agents: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to get agents: {e}")

    # Enhanced attack execution endpoint
    @app.post("/api/v2/attacks/execute")
    async def execute_attack_enhanced(attack_config: Dict[str, Any]):
        """Execute attack with background processing"""
        try:
            # Validate configuration
            if not attack_config.get("target") or not attack_config.get("phase"):
                raise HTTPException(status_code=400, detail="Target and phase are required")

            # This would normally create a background task
            # For now, return mock response
            return {
                "attack_id": f"attack_{int(time.time())}",
                "status": "queued",
                "estimated_completion": "2024-01-01T12:00:00Z",
                "target": attack_config["target"]
            }
        except Exception as e:
            log.error(f"Attack execution failed: {e}")
            raise HTTPException(status_code=500, detail=f"Attack execution failed: {e}")

    # Database query optimization endpoint
    @app.get("/api/v2/queries/optimize")
    async def optimize_queries():
        """Optimize database queries"""
        try:
            # This would analyze and optimize slow queries
            # For now, return mock optimization report
            return {
                "optimizations_applied": ["index_creation", "query_rewrite"],
                "performance_improvement_percent": 45,
                "recommendations": [
                    "Add index on attack_results.target_id",
                    "Optimize connection pool settings"
                ]
            }
        except Exception as e:
            log.error(f"Query optimization failed: {e}")
            raise HTTPException(status_code=500, detail=f"Query optimization failed: {e}")

    return app


# Startup event
@app.on_event("startup")
async def startup_event():
    """Initialize enhanced services"""
    try:
        await cache_manager.connect()
        await db_pool.connect()
        log.success("Enhanced API services initialized")
    except Exception as e:
        log.error(f"Failed to initialize enhanced services: {e}")
        raise


# Shutdown event
@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup enhanced services"""
    try:
        if db_pool:
            await db_pool.close()
        log.info("Enhanced API services shutdown complete")
    except Exception as e:
        log.error(f"Error during shutdown: {e}")


if __name__ == "__main__":
    app = create_enhanced_app()
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        workers=4,
        log_level="info",
        access_log=True
    )