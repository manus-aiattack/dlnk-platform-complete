"""
Database Service - SQLite Fallback
For development and testing without PostgreSQL
"""

import aiosqlite
import os
import secrets
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path
from core.logger import log


class DatabaseSQLite:
    """Database service for SQLite (fallback)"""
    
    def __init__(self):
        self.conn: Optional[aiosqlite.Connection] = None
        # Use workspace directory for database
        workspace_dir = os.getenv("WORKSPACE_DIR", "workspace")
        os.makedirs(workspace_dir, exist_ok=True)
        self.db_path = os.path.join(workspace_dir, "dlnk.db")
        log.info(f"[DatabaseSQLite] Using database: {self.db_path}")
    
    async def connect(self):
        """Connect to database"""
        try:
            self.conn = await aiosqlite.connect(self.db_path)
            self.conn.row_factory = aiosqlite.Row
            log.success("[DatabaseSQLite] Connected to SQLite")
            
            # Initialize schema
            await self._init_schema()
            
        except Exception as e:
            log.error(f"[DatabaseSQLite] Connection failed: {e}")
            raise
    
    async def init_db(self):
        """Initialize database (alias for connect)"""
        await self.connect()
    
    async def disconnect(self):
        """Disconnect from database"""
        if self.conn:
            await self.conn.close()
            log.info("[DatabaseSQLite] Disconnected")
    
    async def health_check(self) -> bool:
        """Check database health"""
        try:
            async with self.conn.execute("SELECT 1") as cursor:
                await cursor.fetchone()
            return True
        except Exception as e:
            return False
    
    async def _init_schema(self):
        """Initialize database schema"""
        schema = """
        -- Users table
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('admin', 'user')),
            api_key TEXT UNIQUE NOT NULL,
            quota_limit INTEGER DEFAULT 100,
            quota_used INTEGER DEFAULT 0,
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            metadata TEXT DEFAULT '{}'
        );
        
        -- Attacks table
        CREATE TABLE IF NOT EXISTS attacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            attack_id TEXT UNIQUE NOT NULL,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            target_url TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'success', 'failed', 'stopped')),
            started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            results TEXT DEFAULT '{}',
            error_message TEXT,
            metadata TEXT DEFAULT '{}'
        );
        
        -- Agent logs table
        CREATE TABLE IF NOT EXISTS agent_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            attack_id TEXT REFERENCES attacks(attack_id) ON DELETE CASCADE,
            agent_name TEXT NOT NULL,
            log_level TEXT NOT NULL,
            message TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            metadata TEXT DEFAULT '{}'
        );
        
        -- Vulnerabilities table
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            attack_id TEXT REFERENCES attacks(attack_id) ON DELETE CASCADE,
            vuln_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            url TEXT NOT NULL,
            description TEXT,
            evidence TEXT,
            discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            metadata TEXT DEFAULT '{}'
        );
        
        -- Loot table
        CREATE TABLE IF NOT EXISTS loot (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            attack_id TEXT REFERENCES attacks(attack_id) ON DELETE CASCADE,
            loot_type TEXT NOT NULL,
            data TEXT NOT NULL,
            file_path TEXT,
            collected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            metadata TEXT DEFAULT '{}'
        );
        
        -- Create indexes
        CREATE INDEX IF NOT EXISTS idx_attacks_user_id ON attacks(user_id);
        CREATE INDEX IF NOT EXISTS idx_attacks_status ON attacks(status);
        CREATE INDEX IF NOT EXISTS idx_agent_logs_attack_id ON agent_logs(attack_id);
        CREATE INDEX IF NOT EXISTS idx_vulnerabilities_attack_id ON vulnerabilities(attack_id);
        CREATE INDEX IF NOT EXISTS idx_loot_attack_id ON loot(attack_id);
        """
        
        await self.conn.executescript(schema)
        await self.conn.commit()
        log.success("[DatabaseSQLite] Schema initialized")
    
    # User operations
    async def get_user_by_api_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        """Get user by API key"""
        async with self.conn.execute(
            "SELECT * FROM users WHERE api_key = ?", (api_key,)
        ) as cursor:
            row = await cursor.fetchone()
            if row:
                return dict(row)
            return None
    
    async def get_user_by_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        """Alias for get_user_by_api_key"""
        return await self.get_user_by_api_key(api_key)
    
    async def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Get user by ID"""
        async with self.conn.execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        ) as cursor:
            row = await cursor.fetchone()
            if row:
                return dict(row)
            return None
    
    async def create_user(self, username: str, role: str = "user", quota_limit: int = 100) -> str:
        """Create a new user and return API key"""
        api_key = secrets.token_urlsafe(32)
        
        await self.conn.execute(
            """INSERT INTO users (username, role, api_key, quota_limit)
               VALUES (?, ?, ?, ?)""",
            (username, role, api_key, quota_limit)
        )
        await self.conn.commit()
        
        log.info(f"[DatabaseSQLite] Created user: {username}")
        return api_key
    
    async def create_default_admin(self) -> str:
        """Create default admin user if not exists"""
        async with self.conn.execute(
            "SELECT api_key FROM users WHERE username = 'admin'"
        ) as cursor:
            row = await cursor.fetchone()
            if row:
                return row[0]
        
        api_key = await self.create_user("admin", "admin", quota_limit=999999)
        
        # Save to file
        workspace_dir = os.getenv("WORKSPACE_DIR", "workspace")
        key_file = os.path.join(workspace_dir, "ADMIN_KEY.txt")
        with open(key_file, "w") as f:
            f.write(api_key)
        
        log.success(f"[DatabaseSQLite] Admin API key saved to: {key_file}")
        return api_key
    
    async def update_user_quota(self, user_id: int, quota_used: int):
        """Update user quota"""
        await self.conn.execute(
            "UPDATE users SET quota_used = ? WHERE id = ?",
            (quota_used, user_id)
        )
        await self.conn.commit()
    
    async def update_last_login(self, user_id: int):
        """Update last login timestamp"""
        await self.conn.execute(
            "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
            (user_id,)
        )
        await self.conn.commit()
    
    # Attack operations
    async def create_attack(self, attack_data: Dict[str, Any]) -> int:
        """Create a new attack record"""
        cursor = await self.conn.execute(
            """INSERT INTO attacks (attack_id, user_id, target_url, attack_type, status, metadata)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                attack_data["attack_id"],
                attack_data["user_id"],
                attack_data["target_url"],
                attack_data["attack_type"],
                attack_data.get("status", "pending"),
                attack_data.get("metadata", "{}")
            )
        )
        await self.conn.commit()
        return cursor.lastrowid
    
    async def get_attack(self, attack_id: str) -> Optional[Dict[str, Any]]:
        """Get attack by ID"""
        async with self.conn.execute(
            "SELECT * FROM attacks WHERE attack_id = ?", (attack_id,)
        ) as cursor:
            row = await cursor.fetchone()
            if row:
                return dict(row)
            return None
    
    async def update_attack_status(self, attack_id: str, status: str, results: Optional[Dict] = None):
        """Update attack status"""
        if results:
            await self.conn.execute(
                "UPDATE attacks SET status = ?, results = ?, completed_at = CURRENT_TIMESTAMP WHERE attack_id = ?",
                (status, str(results), attack_id)
            )
        else:
            await self.conn.execute(
                "UPDATE attacks SET status = ? WHERE attack_id = ?",
                (status, attack_id)
            )
        await self.conn.commit()
    
    async def list_attacks(self, user_id: Optional[int] = None, status: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        """List attacks with optional filters"""
        query = "SELECT * FROM attacks WHERE 1=1"
        params = []
        
        if user_id:
            query += " AND user_id = ?"
            params.append(user_id)
        
        if status:
            query += " AND status = ?"
            params.append(status)
        
        query += " ORDER BY started_at DESC LIMIT ?"
        params.append(limit)
        
        async with self.conn.execute(query, params) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]
    
    # Agent log operations
    async def add_agent_log(self, attack_id: str, agent_name: str, log_level: str, message: str, metadata: Optional[Dict] = None):
        """Add agent log entry"""
        await self.conn.execute(
            """INSERT INTO agent_logs (attack_id, agent_name, log_level, message, metadata)
               VALUES (?, ?, ?, ?, ?)""",
            (attack_id, agent_name, log_level, message, str(metadata or {}))
        )
        await self.conn.commit()
    
    async def get_agent_logs(self, attack_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Get agent logs for an attack"""
        async with self.conn.execute(
            "SELECT * FROM agent_logs WHERE attack_id = ? ORDER BY timestamp DESC LIMIT ?",
            (attack_id, limit)
        ) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]
    
    # Vulnerability operations
    async def add_vulnerability(self, vuln_data: Dict[str, Any]):
        """Add vulnerability"""
        await self.conn.execute(
            """INSERT INTO vulnerabilities (attack_id, vuln_type, severity, url, description, evidence, metadata)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                vuln_data["attack_id"],
                vuln_data["vuln_type"],
                vuln_data["severity"],
                vuln_data["url"],
                vuln_data.get("description", ""),
                vuln_data.get("evidence", ""),
                vuln_data.get("metadata", "{}")
            )
        )
        await self.conn.commit()
    
    async def get_vulnerabilities(self, attack_id: str) -> List[Dict[str, Any]]:
        """Get vulnerabilities for an attack"""
        async with self.conn.execute(
            "SELECT * FROM vulnerabilities WHERE attack_id = ? ORDER BY discovered_at DESC",
            (attack_id,)
        ) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]
    
    # Loot operations
    async def add_loot(self, loot_data: Dict[str, Any]):
        """Add loot"""
        await self.conn.execute(
            """INSERT INTO loot (attack_id, loot_type, data, file_path, metadata)
               VALUES (?, ?, ?, ?, ?)""",
            (
                loot_data["attack_id"],
                loot_data["loot_type"],
                loot_data["data"],
                loot_data.get("file_path", ""),
                loot_data.get("metadata", "{}")
            )
        )
        await self.conn.commit()
    
    async def get_loot(self, attack_id: str) -> List[Dict[str, Any]]:
        """Get loot for an attack"""
        async with self.conn.execute(
            "SELECT * FROM loot WHERE attack_id = ? ORDER BY collected_at DESC",
            (attack_id,)
        ) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]
    
    # Alias methods for compatibility
    async def get_attack_logs(self, attack_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Get attack logs (alias for get_agent_logs)"""
        return await self.get_agent_logs(attack_id, limit)
    
    async def get_attack_files(self, attack_id: str) -> List[Dict[str, Any]]:
        """Get attack files (returns loot files)"""
        return await self.get_loot(attack_id)

    async def update_quota(self, user_id: int, amount: int = 1):
        """Update user quota (increment quota_used)"""
        await self.conn.execute(
            "UPDATE users SET quota_used = quota_used + ? WHERE id = ?",
            (amount, user_id)
        )
        await self.conn.commit()
    
    async def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Get user by ID"""
        async with self.conn.execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        ) as cursor:
            row = await cursor.fetchone()
            if row:
                return dict(row)
            return None



    async def get_attack_logs(self, attack_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Get attack logs (alias for get_agent_logs)"""
        return await self.get_agent_logs(attack_id, limit)
    
    async def get_attack_files(self, attack_id: str) -> List[Dict[str, Any]]:
        """Get attack files (loot files)"""
        async with self.conn.execute(
            "SELECT * FROM loot WHERE attack_id = ? AND file_path IS NOT NULL AND file_path != '' ORDER BY collected_at DESC",
            (attack_id,)
        ) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

