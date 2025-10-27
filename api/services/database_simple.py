"""
Database Service - SQLite for development
"""

import asyncpg
import os
import aiosqlite
from typing import Dict, List, Any, Optional
from datetime import datetime
from core.logger import log


class Database:
    """Database service for SQLite"""
    
    def __init__(self):
        self.db_path = os.getenv("DATABASE_URL", "postgresql://dlnk_user:dlnk_password@localhost/dlnk_attack_db").replace("sqlite:///", "")
        self.connection = None
    
    async def connect(self):
        """Connect to database"""
        try:
            self.connection = await aiosqlite.connect(self.db_path)
            log.success("[Database] Connected to SQLite")
            
            # Initialize schema
            await self._init_schema()
            
        except Exception as e:
            log.error(f"[Database] Connection failed: {e}")
            raise
    
    async def disconnect(self):
        """Disconnect from database"""
        if self.connection:
            await self.connection.close()
            log.info("[Database] Disconnected")
    
    async def health_check(self) -> bool:
        """Check database health"""
        try:
            await self.connection.execute("SELECT 1")
            return True
        except Exception as e:
            log.error(f"[Database] Health check failed: {e}")
            return False
    
    async def _init_schema(self):
        """Initialize database schema"""
        try:
            # Create users table
            await self.connection.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT DEFAULT 'user',
                    is_active BOOLEAN DEFAULT 1,
                    api_key TEXT UNIQUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create attacks table
            await self.connection.execute("""
                CREATE TABLE IF NOT EXISTS attacks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    target TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    attack_type TEXT NOT NULL,
                    config TEXT,
                    results TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            """)
            
            # Create attack_logs table
            await self.connection.execute("""
                CREATE TABLE IF NOT EXISTS attack_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    attack_id INTEGER NOT NULL,
                    level TEXT NOT NULL,
                    message TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (attack_id) REFERENCES attacks (id)
                )
            """)
            
            await self.connection.commit()
            log.success("[Database] Schema initialized")
            
        except Exception as e:
            log.error(f"[Database] Schema initialization failed: {e}")
            raise
    
    async def create_user(self, username: str, email: str, password_hash: str, role: str = "user") -> int:
        """Create a new user"""
        try:
            cursor = await self.connection.execute("""
                INSERT INTO users (username, email, password_hash, role)
                VALUES (?, ?, ?, ?)
            """, (username, email, password_hash, role))
            
            await self.connection.commit()
            return cursor.lastrowid
            
        except Exception as e:
            log.error(f"[Database] Create user failed: {e}")
            raise
    
    async def get_user_by_username(self, username: str) -> Optional[Dict]:
        """Get user by username"""
        try:
            cursor = await self.connection.execute("""
                SELECT id, username, email, password_hash, role, is_active, api_key, created_at
                FROM users WHERE username = ?
            """, (username,))
            
            row = await cursor.fetchone()
            if row:
                return {
                    "id": row[0],
                    "username": row[1],
                    "email": row[2],
                    "password_hash": row[3],
                    "role": row[4],
                    "is_active": bool(row[5]),
                    "api_key": row[6],
                    "created_at": row[7]
                }
            return None
            
        except Exception as e:
            log.error(f"[Database] Get user failed: {e}")
            raise
    
    async def get_user_by_api_key(self, api_key: str) -> Optional[Dict]:
        """Get user by API key"""
        try:
            cursor = await self.connection.execute("""
                SELECT id, username, email, password_hash, role, is_active, api_key, created_at
                FROM users WHERE api_key = ?
            """, (api_key,))
            
            row = await cursor.fetchone()
            if row:
                return {
                    "id": row[0],
                    "username": row[1],
                    "email": row[2],
                    "password_hash": row[3],
                    "role": row[4],
                    "is_active": bool(row[5]),
                    "api_key": row[6],
                    "created_at": row[7]
                }
            return None
            
        except Exception as e:
            log.error(f"[Database] Get user by API key failed: {e}")
            raise
    
    async def create_attack(self, user_id: int, name: str, target: str, attack_type: str, config: str = None) -> int:
        """Create a new attack"""
        try:
            cursor = await self.connection.execute("""
                INSERT INTO attacks (user_id, name, target, attack_type, config)
                VALUES (?, ?, ?, ?, ?)
            """, (user_id, name, target, attack_type, config))
            
            await self.connection.commit()
            return cursor.lastrowid
            
        except Exception as e:
            log.error(f"[Database] Create attack failed: {e}")
            raise
    
    async def get_attack(self, attack_id: int) -> Optional[Dict]:
        """Get attack by ID"""
        try:
            cursor = await self.connection.execute("""
                SELECT id, user_id, name, target, status, attack_type, config, results, created_at, updated_at
                FROM attacks WHERE id = ?
            """, (attack_id,))
            
            row = await cursor.fetchone()
            if row:
                return {
                    "id": row[0],
                    "user_id": row[1],
                    "name": row[2],
                    "target": row[3],
                    "status": row[4],
                    "attack_type": row[5],
                    "config": row[6],
                    "results": row[7],
                    "created_at": row[8],
                    "updated_at": row[9]
                }
            return None
            
        except Exception as e:
            log.error(f"[Database] Get attack failed: {e}")
            raise
    
    async def get_active_attacks_count(self) -> int:
        """Get count of active attacks"""
        try:
            cursor = await self.connection.execute("""
                SELECT COUNT(*) FROM attacks WHERE status IN ('pending', 'running')
            """)
            
            row = await cursor.fetchone()
            return row[0] if row else 0
            
        except Exception as e:
            log.error(f"[Database] Get active attacks count failed: {e}")
            return 0
    
    async def log_attack_event(self, attack_id: int, level: str, message: str):
        """Log an attack event"""
        try:
            await self.connection.execute("""
                INSERT INTO attack_logs (attack_id, level, message)
                VALUES (?, ?, ?)
            """, (attack_id, level, message))
            
            await self.connection.commit()
            
        except Exception as e:
            log.error(f"[Database] Log attack event failed: {e}")
            raise
