#!/usr/bin/env python3
"""
Database Setup Script for dLNk Attack Platform
Creates database schema and generates default admin key
"""

import asyncio
import os
import sys
import secrets
import hashlib
from datetime import datetime

# Add project root to path
sys.path.insert(0, '/mnt/c/projecattack/Manus')

from api.services.database import Database
from api.services.auth import AuthService


async def setup_database():
    """Setup database and create default admin key"""
    print("🚀 Setting up dLNk Attack Platform Database...")

    # Initialize database
    db = Database()

    try:
        # Connect to database
        print("🔗 Connecting to database...")
        await db.connect()
        print("✅ Database connected successfully!")

        # Initialize schema
        print("🏗️ Initializing database schema...")
        await db._init_schema()  # This should run the schema.sql
        print("✅ Schema initialized!")

        # Create AuthService
        auth_service = AuthService(db)

        # Generate default admin key
        print("🔑 Generating default admin key...")
        admin_key = auth_service.generate_api_key()

        # Create admin user
        admin_data = await auth_service.create_user_key(
            username="admin",
            role="admin",
            quota_limit=None  # Unlimited for admin
        )

        print(f"✅ Admin user created!")
        print(f"🆔 Username: admin")
        print(f"🔑 Generated API Key: {admin_data['api_key']}")
        print(f"👤 Role: {admin_data['role']}")
        print(f"📊 Quota: Unlimited")

        # Save admin key to file
        with open('/mnt/c/projecattack/Manus/ADMIN_KEY.txt', 'w') as f:
            f.write(f"Admin API Key: {admin_data['api_key']}\n")
            f.write(f"Generated: {datetime.now().isoformat()}\n")
            f.write(f"Role: admin\n")
            f.write(f"Username: admin\n")

        print("📁 Admin key saved to ADMIN_KEY.txt")

        # Test the key
        print("🧪 Testing admin key...")
        user = await auth_service.verify_key(admin_data['api_key'])
        if user:
            print("✅ Admin key verification successful!")
        else:
            print("❌ Admin key verification failed!")
            return False

        print("\n🎉 Database setup completed successfully!")
        print(f"Use this admin key for testing: {admin_data['api_key']}")
        return True

    except Exception as e:
        print(f"❌ Database setup failed: {e}")
        return False
    finally:
        # Disconnect
        if hasattr(db, 'pool') and db.pool:
            await db.disconnect()
            print("🔌 Database disconnected")


async def test_api_endpoints():
    """Test basic API endpoints"""
    print("\n🧪 Testing API endpoints...")

    try:
        # Test health endpoint
        import aiohttp
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get('http://localhost:8000/health') as response:
                    if response.status == 200:
                        data = await response.json()
                        print("✅ Health endpoint working:", data['status'])
                    else:
                        print(f"❌ Health endpoint failed: {response.status}")
            except Exception as e:
                print(f"❌ Health endpoint error: {e}")

            # Test status endpoint
            try:
                async with session.get('http://localhost:8000/api/status') as response:
                    if response.status == 200:
                        data = await response.json()
                        print("✅ Status endpoint working")
                    else:
                        print(f"❌ Status endpoint failed: {response.status}")
            except Exception as e:
                print(f"❌ Status endpoint error: {e}")

    except ImportError:
        print("⚠️  aiohttp not available, skipping endpoint tests")
    except Exception as e:
        print(f"❌ Endpoint tests failed: {e}")


if __name__ == "__main__":
    # Set environment variables for database connection
    os.environ.setdefault('DB_HOST', 'localhost')
    os.environ.setdefault('DB_PORT', '5432')
    os.environ.setdefault('DB_USER', 'dlnk')
    os.environ.setdefault('DB_PASSWORD', 'dlnk')
    os.environ.setdefault('DB_NAME', 'dlnk_attack_platform')

    print("Database configuration:")
    print(f"  Host: {os.getenv('DB_HOST')}")
    print(f"  Port: {os.getenv('DB_PORT')}")
    print(f"  User: {os.getenv('DB_USER')}")
    print(f"  Database: {os.getenv('DB_NAME')}")

    # Run setup
    success = asyncio.run(setup_database())

    if success:
        # Test endpoints
        asyncio.run(test_api_endpoints())
    else:
        print("❌ Setup failed, please check database connection")
        sys.exit(1)