#!/usr/bin/env python3
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
