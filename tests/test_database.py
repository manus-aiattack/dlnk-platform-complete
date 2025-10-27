#!/usr/bin/env python3
"""
Test Database Connections
Tests PostgreSQL, Redis, and SQLite connections
"""
import asyncio
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

async def test_database():
    """Test database connections"""
    print("=" * 80)
    print("Testing Database Connections")
    print("=" * 80)
    print()
    
    results = {
        'postgresql': False,
        'redis': False,
        'sqlite': False
    }
    
    # Test PostgreSQL
    print("Testing PostgreSQL...")
    try:
        from core.database_manager import DatabaseManager
        db = DatabaseManager()
        await db.connect()
        print("  ✓ PostgreSQL connection successful")
        await db.close()
        results['postgresql'] = True
    except Exception as e:
        print(f"  ✗ PostgreSQL error: {e}")
        print("  ℹ This is expected if PostgreSQL is not running")
    
    print()
    
    # Test Redis
    print("Testing Redis...")
    try:
        from core.redis_client import get_redis_client
        redis = await get_redis_client()
        await redis.ping()
        print("  ✓ Redis connection successful")
        results['redis'] = True
    except Exception as e:
        print(f"  ✗ Redis error: {e}")
        print("  ℹ This is expected if Redis is not running")
    
    print()
    
    # Test SQLite (fallback)
    print("Testing SQLite...")
    try:
        import aiosqlite
        import os
        
        # Create workspace directory if not exists
        os.makedirs('workspace', exist_ok=True)
        
        db_path = 'workspace/test_manus.db'
        async with aiosqlite.connect(db_path) as db:
            await db.execute('CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY)')
            await db.commit()
        print(f"  ✓ SQLite connection successful (path: {db_path})")
        results['sqlite'] = True
    except Exception as e:
        print(f"  ✗ SQLite error: {e}")
    
    print()
    
    # Summary
    print("=" * 80)
    print("Summary")
    print("=" * 80)
    total = len(results)
    success = sum(results.values())
    print(f"Databases tested: {total}")
    print(f"Successful: {success}")
    print(f"Failed: {total - success}")
    print()
    
    for db_name, status in results.items():
        status_str = "✓" if status else "✗"
        print(f"  {status_str} {db_name.upper()}: {'Connected' if status else 'Not available'}")
    
    print()
    
    if results['sqlite']:
        print("✓ At least SQLite is working (fallback database)")
        print("  System can run in development mode")
    
    if results['postgresql'] and results['redis']:
        print("✓ PostgreSQL and Redis are working")
        print("  System is production-ready!")
    elif not results['postgresql'] or not results['redis']:
        print("⚠ PostgreSQL or Redis not available")
        print("  For production, please start these services:")
        print("    sudo systemctl start postgresql redis")
    
    print()
    
    return results

if __name__ == "__main__":
    results = asyncio.run(test_database())
    
    # Exit with 0 if at least SQLite works
    sys.exit(0 if results['sqlite'] else 1)

