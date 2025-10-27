#!/usr/bin/env python3
"""
Production Environment Setup Script
Sets up database, environment variables, and production configuration
"""

import os
import sys
import json
import asyncio
from pathlib import Path
from datetime import datetime

def create_production_env():
    """Create production .env file with secure defaults"""

    env_content = """# Manus AI Platform Configuration - PRODUCTION
# Generated on: {}
# IMPORTANT: Change all default values before production deployment!

# Environment
NODE_ENV=production
DOMAIN_NAME=yourdomain.com
PROTOCOL=https

# Logging
LOG_LEVEL=INFO
LOG_FILE=logs/manus.log
JSON_LOG_FILE=logs/manus.json

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
API_DEBUG=False

# Web Dashboard Configuration
WEB_HOST=0.0.0.0
WEB_PORT=3000
WEB_DEBUG=False

# Database Configuration (PostgreSQL) - PRODUCTION
DB_HOST=localhost
DB_PORT=5432
DB_NAME=manus_production
DB_USER=manus_user
DB_PASSWORD=YOUR_SECURE_PASSWORD_HERE_CHANGE_ME
DB_SSL_MODE=prefer

# Alternative: Full DATABASE_URL
DATABASE_URL=postgresql://manus_user:YOUR_SECURE_PASSWORD_HERE_CHANGE_ME@localhost:5432/manus_production

# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=YOUR_REDIS_PASSWORD_HERE_CHANGE_ME
REDIS_DB=0
REDIS_URL=redis://:YOUR_REDIS_PASSWORD_HERE_CHANGE_ME@localhost:6379/0

# JWT Security Configuration - CRITICAL: Change these!
JWT_SECRET_KEY=YOUR_JWT_SECRET_KEY_HERE_MUST_BE_AT_LEAST_32_CHARS_CHANGE_ME
JWT_REFRESH_SECRET_KEY=YOUR_REFRESH_SECRET_KEY_HERE_MUST_BE_AT_LEAST_32_CHARS_CHANGE_ME
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=15
JWT_REFRESH_TOKEN_EXPIRE_DAYS=7
JWT_ALGORITHM=HS256

# Shell Password Configuration
SHELL_PASSWORD=YOUR_SHELL_PASSWORD_HERE_CHANGE_ME

# Security Configuration
BCRYPT_ROUNDS=12
SESSION_TIMEOUT_MINUTES=30
MAX_LOGIN_ATTEMPTS=5
ACCOUNT_LOCKOUT_MINUTES=15

# Rate Limiting
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW_MINUTES=15
RATE_LIMIT_ENABLED=True

# CORS Configuration
ALLOWED_ORIGINS=https://yourdomain.com,https://app.yourdomain.com

# External API Keys (optional - use empty values for security)
OPENAI_API_KEY=
ANTHROPIC_API_KEY=

# AWS Configuration (if using AWS services)
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_REGION=us-east-1

# Monitoring and Observability
SENTRY_DSN=
PROMETHEUS_ENABLED=True

# Backup Configuration
BACKUP_S3_BUCKET=
BACKUP_ENCRYPTION_KEY=

# Secret Key (for Flask/Django style apps)
SECRET_KEY=YOUR_SECRET_KEY_HERE_CHANGE_ME

# Agent Configuration
MAX_CONCURRENT_AGENTS=5
AGENT_TIMEOUT=300
AGENT_RETRY_ATTEMPTS=3

# Workflow Configuration
WORKFLOW_TIMEOUT=3600
TARGET_TIMEOUT=600
MAX_TARGETS=100

# External Tools
NMAP_PATH=nmap
METASPLOIT_PATH=/usr/share/metasploit-framework
NUCLEI_PATH=nuclei
SQLMAP_PATH=sqlmap
WPSCAN_PATH=wpscan

# LLM Configuration
LLM_PROVIDER=openai
LLM_API_KEY=YOUR_API_KEY_HERE
LLM_MODEL=gpt-4
LLM_TEMPERATURE=0.7

# Feature Flags
SIMULATION_MODE=False
ENABLE_PERSISTENCE=True
ENABLE_LATERAL_MOVEMENT=True
ENABLE_DATA_EXFILTRATION=True
ENABLE_PRIVILEGE_ESCALATION=True

# Performance
CACHE_ENABLED=True
CACHE_TTL=3600

# Reporting
REPORT_FORMAT=html
REPORT_INCLUDE_PAYLOADS=False
REPORT_INCLUDE_LOGS=True

# Proxy Configuration
PROXY_ENABLED=False
PROXY_URL=
PROXY_USERNAME=
PROXY_PASSWORD=

# Notifications
NOTIFICATION_ENABLED=False
NOTIFICATION_WEBHOOK=
NOTIFICATION_EMAIL=

# Workspace
WORKSPACE_DIR=workspace
""".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    env_file = Path(".env")
    if env_file.exists():
        backup_file = Path(f".env.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        env_file.rename(backup_file)
        print(f"⚠️  Existing .env file backed up to: {backup_file}")

    with open(env_file, "w") as f:
        f.write(env_content)

    print(f"✅ Production .env file created: {env_file}")
    print("🚨 IMPORTANT: Update all placeholder values (YOUR_*) before deployment!")

def create_database_migration():
    """Create database migration script for production"""

    migration_content = '''#!/usr/bin/env python3
"""
Production Database Migration Script
Creates and migrates database schema for production deployment
"""

import asyncio
import asyncpg
import os
from config import settings
from core.logger import log

async def create_production_database():
    """Create production database with proper security"""

    # Connect to PostgreSQL server (not specific database)
    server_config = {
        "host": settings.DATABASE_HOST,
        "port": settings.DATABASE_PORT,
        "user": settings.DATABASE_USER,
        "password": settings.DATABASE_PASSWORD,
    }

    try:
        # Connect to PostgreSQL server
        conn = await asyncpg.connect(**server_config)

        # Create database if it doesn't exist
        db_exists = await conn.fetchval(
            "SELECT 1 FROM pg_database WHERE datname = $1",
            settings.DATABASE_NAME
        )

        if not db_exists:
            await conn.execute(f'CREATE DATABASE {settings.DATABASE_NAME}')
            log.info(f"✅ Created database: {settings.DATABASE_NAME}")
        else:
            log.info(f"ℹ️  Database already exists: {settings.DATABASE_NAME}")

        await conn.close()

        # Connect to the specific database
        db_config = {
            "host": settings.DATABASE_HOST,
            "port": settings.DATABASE_PORT,
            "user": settings.DATABASE_USER,
            "password": settings.DATABASE_PASSWORD,
            "database": settings.DATABASE_NAME
        }

        conn = await asyncpg.connect(**db_config)

        # Create tables
        schema_sql = """
        -- Security: Enable row-level security where appropriate
        ALTER DATABASE {db_name} SET row_security = on;

        -- Create cycles table
        CREATE TABLE IF NOT EXISTS cycles (
            id SERIAL PRIMARY KEY,
            target_host TEXT NOT NULL,
            start_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            end_time TIMESTAMP WITH TIME ZONE,
            status TEXT NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );

        -- Create agent_actions table
        CREATE TABLE IF NOT EXISTS agent_actions (
            id SERIAL PRIMARY KEY,
            cycle_id INTEGER REFERENCES cycles(id) ON DELETE CASCADE,
            agent_name TEXT NOT NULL,
            action_type TEXT NOT NULL,
            parameters JSONB,
            result JSONB,
            status TEXT NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );

        -- Create security_events table
        CREATE TABLE IF NOT EXISTS security_events (
            id SERIAL PRIMARY KEY,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            message TEXT NOT NULL,
            details JSONB,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );

        -- Create users table (if authentication is needed)
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP WITH TIME ZONE
        );

        -- Create sessions table
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
            ip_address INET,
            user_agent TEXT
        );

        -- Create indexes for performance
        CREATE INDEX IF NOT EXISTS idx_cycles_target_host ON cycles(target_host);
        CREATE INDEX IF NOT EXISTS idx_cycles_status ON cycles(status);
        CREATE INDEX IF NOT EXISTS idx_cycles_start_time ON cycles(start_time);
        CREATE INDEX IF NOT EXISTS idx_agent_actions_cycle_id ON agent_actions(cycle_id);
        CREATE INDEX IF NOT EXISTS idx_agent_actions_agent_name ON agent_actions(agent_name);
        CREATE INDEX IF NOT EXISTS idx_security_events_type ON security_events(event_type);
        CREATE INDEX IF NOT EXISTS idx_security_events_severity ON security_events(severity);
        CREATE INDEX IF NOT EXISTS idx_security_events_created_at ON security_events(created_at);

        -- Create views for monitoring
        CREATE OR REPLACE VIEW cycle_summary AS
        SELECT
            c.id,
            c.target_host,
            c.start_time,
            c.end_time,
            c.status,
            COUNT(aa.id) as action_count,
            MAX(aa.created_at) as last_action
        FROM cycles c
        LEFT JOIN agent_actions aa ON c.id = aa.cycle_id
        GROUP BY c.id, c.target_host, c.start_time, c.end_time, c.status;

        -- Set ownership and permissions
        -- TODO: Set appropriate permissions for production user

        log.info("✅ Database schema created successfully")
        await conn.close()

    except Exception as e:
        log.critical(f"❌ Failed to create database schema: {e}")
        raise

if __name__ == "__main__":
    print("🚀 Starting production database setup...")

    # Check environment variables
    required_vars = [
        'DB_HOST', 'DB_PORT', 'DB_USER', 'DB_PASSWORD', 'DB_NAME'
    ]

    missing_vars = []
    for var in required_vars:
        if not os.getenv(var):
            missing_vars.append(var)

    if missing_vars:
        print(f"❌ Missing required environment variables: {missing_vars}")
        print("⚠️  Please set up .env file first!")
        sys.exit(1)

    try:
        asyncio.run(create_production_database())
        print("🎉 Database setup completed successfully!")
    except Exception as e:
        print(f"❌ Database setup failed: {e}")
        sys.exit(1)
'''

    migration_file = Path("setup/migrate_database.py")
    migration_file.parent.mkdir(exist_ok=True)

    with open(migration_file, "w") as f:
        f.write(migration_content)

    # Make executable
    os.chmod(migration_file, 0o755)

    print(f"✅ Database migration script created: {migration_file}")

def create_production_checklist():
    """Create production deployment checklist"""

    checklist_content = """# Production Deployment Checklist

## 🔒 Security Preparations
- [ ] Change all default passwords in .env file
- [ ] Generate strong, unique JWT secrets (32+ characters)
- [ ] Set up proper database user permissions
- [ ] Configure firewall rules
- [ ] Enable SSL/TLS for all services
- [ ] Set up intrusion detection

## 🗄️ Database Setup
- [ ] Install PostgreSQL (13+ recommended)
- [ ] Create database user with limited permissions
- [ ] Run database migration script
- [ ] Verify database connectivity
- [ ] Set up database backups
- [ ] Configure connection pooling

## 🌐 Network Configuration
- [ ] Set up reverse proxy (nginx/Apache)
- [ ] Configure SSL certificates
- [ ] Set up load balancing (if needed)
- [ ] Configure DNS records
- [ ] Test network connectivity

## 📊 Monitoring & Logging
- [ ] Set up log rotation
- [ ] Configure centralized logging
- [ ] Set up monitoring (Prometheus/Grafana)
- [ ] Configure alerting
- [ ] Set up health checks

## 🚀 Deployment
- [ ] Test in staging environment
- [ ] Set up CI/CD pipeline
- [ ] Configure deployment scripts
- [ ] Set up rollback procedures
- [ ] Test backup and restore

## 📋 Security Validation
- [ ] Run security scans
- [ ] Test authentication and authorization
- [ ] Verify input validation
- [ ] Test rate limiting
- [ ] Validate security headers

## 🎯 Final Checks
- [ ] Performance testing
- [ ] Load testing
- [ ] Security penetration testing
- [ ] Documentation review
- [ ] Team training
"""

    checklist_file = Path("PRODUCTION_CHECKLIST.md")
    with open(checklist_file, "w") as f:
        f.write(checklist_content)

    print(f"✅ Production checklist created: {checklist_file}")

def main():
    """Main setup function"""

    print("🚀 Manus AI Platform - Production Setup")
    print("=" * 50)

    # Create directories
    setup_dir = Path("setup")
    setup_dir.mkdir(exist_ok=True)

    logs_dir = Path("logs")
    logs_dir.mkdir(exist_ok=True)

    workspace_dir = Path("workspace")
    workspace_dir.mkdir(exist_ok=True)

    print("📁 Directories created")

    # Create production environment file
    create_production_env()

    # Create database migration script
    create_database_migration()

    # Create production checklist
    create_production_checklist()

    print("\n" + "=" * 50)
    print("🎉 Production setup completed!")
    print("\n📋 Next steps:")
    print("1. Review and update .env file with secure values")
    print("2. Install PostgreSQL and Redis")
    print("3. Run: python setup/migrate_database.py")
    print("4. Follow PRODUCTION_CHECKLIST.md")
    print("5. Test deployment in staging environment")

if __name__ == "__main__":
    main()