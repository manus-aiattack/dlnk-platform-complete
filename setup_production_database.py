#!/usr/bin/env python3
"""
Production Database Setup Script
Initialize PostgreSQL database with production schema and data
"""

import sys
import os

# Add project root to path
sys.path.insert(0, '/home/ubuntu/aiprojectattack')

from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError
import secrets

# Import models and config
try:
    from config.database import Base, engine, check_database_connection, init_database
    from models.database_models import User, APIKey, Target, Campaign, SystemSettings, UserRole
    from services.auth_service import AuthService
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("⚠️  Make sure all dependencies are installed: pip install -r requirements.txt")
    sys.exit(1)


def create_database_if_not_exists():
    """Create database if it doesn't exist"""
    # Connect to PostgreSQL server (not specific database)
    postgres_url = "postgresql://dlnk_user:dlnk_secure_password_2024@localhost:5432/postgres"
    
    try:
        temp_engine = create_engine(postgres_url)
        with temp_engine.connect() as conn:
            # Set isolation level to autocommit for CREATE DATABASE
            conn.execute(text("COMMIT"))
            
            # Check if database exists
            result = conn.execute(text(
                "SELECT 1 FROM pg_database WHERE datname='dlnk_attack_db'"
            ))
            
            if not result.fetchone():
                print("📦 Creating database 'dlnk_attack_db'...")
                conn.execute(text("CREATE DATABASE dlnk_attack_db"))
                print("✅ Database created successfully")
            else:
                print("ℹ️  Database 'dlnk_attack_db' already exists")
                
    except OperationalError as e:
        print(f"❌ Failed to connect to PostgreSQL: {e}")
        print("\n💡 Make sure PostgreSQL is installed and running:")
        print("   sudo apt-get install postgresql postgresql-contrib")
        print("   sudo systemctl start postgresql")
        print("\n💡 Create the database user:")
        print("   sudo -u postgres psql")
        print("   CREATE USER dlnk_user WITH PASSWORD 'dlnk_secure_password_2024';")
        print("   ALTER USER dlnk_user CREATEDB;")
        sys.exit(1)


def setup_production_database():
    """Setup production database with tables and initial data"""
    print("\n" + "="*60)
    print("🚀 dLNk Attack Platform - Production Database Setup")
    print("="*60 + "\n")
    
    # Step 1: Create database if needed
    create_database_if_not_exists()
    
    # Step 2: Check connection
    print("\n🔍 Checking database connection...")
    if not check_database_connection():
        print("❌ Database connection failed. Exiting.")
        sys.exit(1)
    print("✅ Database connection successful\n")
    
    # Step 3: Create tables
    print("📋 Creating database tables...")
    try:
        init_database()
    except Exception as e:
        print(f"❌ Failed to create tables: {e}")
        sys.exit(1)
    
    # Step 4: Create admin user with production API key
    print("\n👤 Creating admin user...")
    from sqlalchemy.orm import Session
    
    db = Session(bind=engine)
    
    try:
        # Check if admin already exists
        existing_admin = db.query(User).filter(User.username == "admin").first()
        
        if existing_admin:
            print("⚠️  Admin user already exists")
            print(f"   User ID: {existing_admin.id}")
            print(f"   Username: {existing_admin.username}")
            print(f"   Role: {existing_admin.role.value}")
        else:
            # Create admin user
            admin_user = User(
                username="admin",
                email="admin@dlnk.local",
                full_name="System Administrator",
                role=UserRole.ADMIN,
                is_active=True
            )
            db.add(admin_user)
            db.commit()
            db.refresh(admin_user)
            
            # Generate admin API key
            admin_key = f"dlnk_live_{secrets.token_hex(32)}"
            
            # Hash the key
            import hashlib
            key_hash = hashlib.sha256(admin_key.encode()).hexdigest()
            
            # Create API key record
            api_key_record = APIKey(
                key_hash=key_hash,
                user_id=admin_user.id,
                name="Default Admin Key",
                role=UserRole.ADMIN,
                is_active=True
            )
            db.add(api_key_record)
            db.commit()
            
            print("✅ Admin user created successfully")
            print(f"\n{'='*60}")
            print("🔑 PRODUCTION CREDENTIALS - SAVE THESE!")
            print(f"{'='*60}")
            print(f"Username: {admin_user.username}")
            print(f"Email: {admin_user.email}")
            print(f"User ID: {admin_user.id}")
            print(f"API Key: {admin_key}")
            print(f"{'='*60}")
            print("⚠️  The API key will NOT be shown again!")
            print(f"{'='*60}\n")
            
            # Save to file
            with open("/home/ubuntu/aiprojectattack/ADMIN_CREDENTIALS.txt", "w") as f:
                f.write("dLNk Attack Platform - Admin Credentials\n")
                f.write("="*60 + "\n")
                f.write(f"Username: {admin_user.username}\n")
                f.write(f"Email: {admin_user.email}\n")
                f.write(f"User ID: {admin_user.id}\n")
                f.write(f"API Key: {admin_key}\n")
                f.write("="*60 + "\n")
                f.write("⚠️  Keep this file secure and delete after saving credentials!\n")
            
            print("💾 Credentials saved to: /home/ubuntu/aiprojectattack/ADMIN_CREDENTIALS.txt\n")
        
        # Step 5: Initialize system settings
        print("⚙️  Initializing system settings...")
        
        settings_to_create = [
            {
                "key": "line_contact_url",
                "value": {"url": "https://line.me/ti/p/~dlnk_admin"},
                "description": "LINE contact URL for purchasing API keys"
            },
            {
                "key": "max_concurrent_campaigns",
                "value": {"limit": 10},
                "description": "Maximum number of concurrent attack campaigns"
            },
            {
                "key": "default_timeout_seconds",
                "value": {"timeout": 300},
                "description": "Default timeout for attack operations"
            }
        ]
        
        for setting_data in settings_to_create:
            existing = db.query(SystemSettings).filter(
                SystemSettings.key == setting_data["key"]
            ).first()
            
            if not existing:
                setting = SystemSettings(**setting_data)
                db.add(setting)
        
        db.commit()
        print("✅ System settings initialized\n")
        
    except Exception as e:
        print(f"❌ Error during setup: {e}")
        db.rollback()
        sys.exit(1)
    finally:
        db.close()
    
    print("\n" + "="*60)
    print("✅ Production database setup completed successfully!")
    print("="*60)
    print("\n📝 Next steps:")
    print("   1. Save the admin credentials from ADMIN_CREDENTIALS.txt")
    print("   2. Delete ADMIN_CREDENTIALS.txt after saving")
    print("   3. Start the production server: python3 integrated_server.py")
    print("   4. Test the API with the admin API key\n")


if __name__ == "__main__":
    setup_production_database()

