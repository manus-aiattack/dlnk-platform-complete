"""
Intelligent Caching System
"""

import asyncio
import time
import hashlib
import json
from typing import Dict, Any, Optional, Callable
from datetime import datetime, timedelta
from collections import OrderedDict
import logging

log = logging.getLogger(__name__)


class CacheManager:
    """
    Intelligent Caching System
    
    Features:
    - LRU cache
    - TTL support
    - Cache warming
    - Cache invalidation
    - Hit rate tracking
    """
    
    def __init__(self, max_size: int = 1000, default_ttl: int = 3600):
        self.max_size = max_size
        self.default_ttl = default_ttl
        
        self.cache = OrderedDict()
        self.metadata = {}
        
        # Statistics
        self.hits = 0
        self.misses = 0
        self.evictions = 0
    
    def _generate_key(self, key: str) -> str:
        """Generate cache key"""
        return hashlib.md5(key.encode()).hexdigest()
    
    async def get(self, key: str) -> Optional[Any]:
        """
        Get value from cache
        
        Args:
            key: Cache key
        
        Returns:
            Cached value or None
        """
        cache_key = self._generate_key(key)
        
        if cache_key in self.cache:
            # Check if expired
            if self._is_expired(cache_key):
                await self.delete(key)
                self.misses += 1
                return None
            
            # Move to end (LRU)
            self.cache.move_to_end(cache_key)
            
            # Update access time
            self.metadata[cache_key]['last_access'] = datetime.now()
            self.metadata[cache_key]['access_count'] += 1
            
            self.hits += 1
            
            log.debug(f"[CacheManager] Cache hit: {key}")
            
            return self.cache[cache_key]
        
        self.misses += 1
        log.debug(f"[CacheManager] Cache miss: {key}")
        
        return None
    
    async def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[int] = None
    ):
        """
        Set value in cache
        
        Args:
            key: Cache key
            value: Value to cache
            ttl: Time to live in seconds
        """
        cache_key = self._generate_key(key)
        
        # Check if cache is full
        if len(self.cache) >= self.max_size and cache_key not in self.cache:
            # Evict least recently used
            evicted_key = next(iter(self.cache))
            del self.cache[evicted_key]
            del self.metadata[evicted_key]
            self.evictions += 1
            
            log.debug(f"[CacheManager] Evicted LRU entry")
        
        # Store value
        self.cache[cache_key] = value
        self.cache.move_to_end(cache_key)
        
        # Store metadata
        self.metadata[cache_key] = {
            'key': key,
            'created': datetime.now(),
            'last_access': datetime.now(),
            'access_count': 0,
            'ttl': ttl or self.default_ttl,
            'size': len(json.dumps(value, default=str))
        }
        
        log.debug(f"[CacheManager] Cached: {key}")
    
    async def delete(self, key: str):
        """Delete value from cache"""
        
        cache_key = self._generate_key(key)
        
        if cache_key in self.cache:
            del self.cache[cache_key]
            del self.metadata[cache_key]
            log.debug(f"[CacheManager] Deleted: {key}")
    
    def _is_expired(self, cache_key: str) -> bool:
        """Check if cache entry is expired"""
        
        if cache_key not in self.metadata:
            return True
        
        meta = self.metadata[cache_key]
        age = (datetime.now() - meta['created']).total_seconds()
        
        return age > meta['ttl']
    
    async def clear(self):
        """Clear all cache"""
        
        self.cache.clear()
        self.metadata.clear()
        
        log.info("[CacheManager] Cache cleared")
    
    async def clear_expired(self):
        """Clear expired entries"""
        
        expired_keys = []
        
        for cache_key in list(self.cache.keys()):
            if self._is_expired(cache_key):
                expired_keys.append(cache_key)
        
        for cache_key in expired_keys:
            original_key = self.metadata[cache_key]['key']
            await self.delete(original_key)
        
        log.info(f"[CacheManager] Cleared {len(expired_keys)} expired entries")
    
    async def get_or_compute(
        self,
        key: str,
        compute_func: Callable,
        *args,
        ttl: Optional[int] = None,
        **kwargs
    ) -> Any:
        """
        Get from cache or compute and cache
        
        Args:
            key: Cache key
            compute_func: Function to compute value if not cached
            *args: Function arguments
            ttl: Time to live
            **kwargs: Function keyword arguments
        
        Returns:
            Cached or computed value
        """
        # Try to get from cache
        cached_value = await self.get(key)
        
        if cached_value is not None:
            return cached_value
        
        # Compute value
        log.debug(f"[CacheManager] Computing value for: {key}")
        
        if asyncio.iscoroutinefunction(compute_func):
            value = await compute_func(*args, **kwargs)
        else:
            value = compute_func(*args, **kwargs)
        
        # Cache value
        await self.set(key, value, ttl)
        
        return value
    
    async def warm_cache(
        self,
        keys: list,
        compute_func: Callable
    ):
        """
        Warm cache with pre-computed values
        
        Args:
            keys: List of keys to warm
            compute_func: Function to compute values
        """
        log.info(f"[CacheManager] Warming cache with {len(keys)} entries...")
        
        for key in keys:
            try:
                if asyncio.iscoroutinefunction(compute_func):
                    value = await compute_func(key)
                else:
                    value = compute_func(key)
                
                await self.set(key, value)
                
            except Exception as e:
                log.error(f"[CacheManager] Failed to warm cache for {key}: {e}")
        
        log.info("[CacheManager] Cache warming complete")
    
    async def invalidate_pattern(self, pattern: str):
        """
        Invalidate cache entries matching pattern
        
        Args:
            pattern: Pattern to match (simple substring match)
        """
        invalidated = []
        
        for cache_key, meta in list(self.metadata.items()):
            if pattern in meta['key']:
                await self.delete(meta['key'])
                invalidated.append(meta['key'])
        
        log.info(f"[CacheManager] Invalidated {len(invalidated)} entries matching '{pattern}'")
    
    def get_statistics(self) -> Dict:
        """Get cache statistics"""
        
        total_requests = self.hits + self.misses
        hit_rate = self.hits / total_requests if total_requests > 0 else 0.0
        
        total_size = sum(meta['size'] for meta in self.metadata.values())
        
        stats = {
            'size': len(self.cache),
            'max_size': self.max_size,
            'hits': self.hits,
            'misses': self.misses,
            'hit_rate': hit_rate,
            'evictions': self.evictions,
            'total_size_bytes': total_size
        }
        
        return stats
    
    async def get_top_entries(self, limit: int = 10) -> list:
        """Get most accessed cache entries"""
        
        entries = []
        
        for cache_key, meta in self.metadata.items():
            entries.append({
                'key': meta['key'],
                'access_count': meta['access_count'],
                'age': (datetime.now() - meta['created']).total_seconds(),
                'size': meta['size']
            })
        
        # Sort by access count
        entries.sort(key=lambda x: x['access_count'], reverse=True)
        
        return entries[:limit]


# Global cache instance
_cache_manager = None


def get_cache_manager() -> CacheManager:
    """Get global cache manager instance"""
    global _cache_manager
    
    if _cache_manager is None:
        _cache_manager = CacheManager()
    
    return _cache_manager


if __name__ == '__main__':
    async def test():
        cache = CacheManager(max_size=5)
        
        # Test set and get
        await cache.set('key1', 'value1')
        value = await cache.get('key1')
        print(f"Cached value: {value}")
        
        # Test get_or_compute
        async def expensive_computation(x):
            await asyncio.sleep(0.1)
            return x * 2
        
        result1 = await cache.get_or_compute('compute_10', expensive_computation, 10)
        print(f"Computed: {result1}")
        
        result2 = await cache.get_or_compute('compute_10', expensive_computation, 10)
        print(f"From cache: {result2}")
        
        # Get statistics
        stats = cache.get_statistics()
        print(f"\nCache Statistics:")
        print(f"  Size: {stats['size']}/{stats['max_size']}")
        print(f"  Hit Rate: {stats['hit_rate']:.1%}")
        print(f"  Hits: {stats['hits']}, Misses: {stats['misses']}")
    
    asyncio.run(test())

