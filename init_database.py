#!/usr/bin/env python3
"""
Database Initialization Script
Initializes the database schema for dLNk Attack Platform
"""
import asyncio
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from core.database_manager import DatabaseManager
from core.logger import log


async def init_database():
    """Initialize database schema"""
    print("=" * 80)
    print("dLNk Attack Platform - Database Initialization")
    print("=" * 80)
    print()
    
    db_manager = DatabaseManager()
    
    try:
        print("📡 Connecting to PostgreSQL database...")
        await db_manager.connect()
        print("✅ Database connected successfully!")
        print()
        
        print("📊 Database tables created:")
        print("  - cycles")
        print("  - agent_actions")
        print("  - attack_logs")
        print("  - exfiltrated_data")
        print("  - vulnerabilities")
        print("  - credentials")
        print("  - persistence_mechanisms")
        print()
        
        print("✅ Database initialization completed successfully!")
        print()
        
        # Close connection
        await db_manager.close()
        
        return 0
        
    except Exception as e:
        print(f"❌ Error initializing database: {e}")
        print()
        print("Troubleshooting:")
        print("1. Check that PostgreSQL is running: sudo systemctl status postgresql")
        print("2. Verify database credentials in .env file")
        print("3. Ensure database exists: psql -U dlnk_user -d dlnk -h localhost")
        print()
        return 1


def main():
    """Main entry point"""
    try:
        exit_code = asyncio.run(init_database())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n⚠️  Interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

