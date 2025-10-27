"""
dLNk Attack Platform - Database Service
Handles all database operations
"""

import asyncpg
import os
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from loguru import logger
import json
from .decorators import require_pool


class DatabaseService:
    """Database service for dLNk Attack Platform"""
    
    def __init__(self):
        self.pool: Optional[asyncpg.Pool] = None
        # Build DATABASE_URL from individual components if not set
        db_url = os.getenv("DATABASE_URL", "")
        if not db_url:
            db_host = os.getenv("DB_HOST", "localhost")
            db_port = os.getenv("DB_PORT", "5432")
            db_user = os.getenv("DB_USER", "dlnk_user")
            db_password = os.getenv("DB_PASSWORD", "")
            db_name = os.getenv("DB_NAME", "dlnk")
            db_url = f"postgresql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"
        self.db_url = db_url
    
    async def connect(self):
        """Connect to database"""
        try:
            self.pool = await asyncpg.create_pool(
                self.db_url,
                min_size=5,
                max_size=20,
                command_timeout=60
            )
            logger.info("✅ Database connected")
            
            # Initialize schema
            await self.initialize_schema()
            
        except Exception as e:
            logger.error(f"❌ Database connection failed: {e}")
            raise
    
    async def disconnect(self):
        """Disconnect from database"""
        if self.pool:
            await self.pool.close()
            logger.info("Database disconnected")
    
    @require_pool
    async def initialize_schema(self):
        """Initialize database schema"""
        try:
            schema_path = os.path.join(
                os.path.dirname(__file__),
                "schema.sql"
            )
            
            if os.path.exists(schema_path):
                with open(schema_path, 'r') as f:
                    schema_sql = f.read()
                
                async with self.pool.acquire() as conn:
                    await conn.execute(schema_sql)
                
                logger.info("✅ Database schema initialized")
            else:
                logger.warning("⚠️  Schema file not found")
                
        except Exception as e:
            logger.error(f"❌ Schema initialization failed: {e}")
            raise
    
    # ===== API Key Management =====
    
    @require_pool
    async def create_api_key(
        self,
        key_type: str,
        user_name: Optional[str] = None,
        expires_in_days: Optional[int] = None,
        usage_limit: Optional[int] = None,
        notes: Optional[str] = None
    ) -> Dict[str, Any]:
        """Create new API key"""
        async with self.pool.acquire() as conn:
            # Generate key
            key_value = await conn.fetchval("SELECT generate_api_key()")
            
            # Calculate expiration
            expires_at = None
            if expires_in_days:
                expires_at = datetime.now() + timedelta(days=expires_in_days)
            
            # Insert key
            row = await conn.fetchrow("""
                INSERT INTO api_keys (
                    key_value, key_type, user_name, expires_at, usage_limit, notes
                )
                VALUES ($1, $2, $3, $4, $5, $6)
                RETURNING *
            """, key_value, key_type, user_name, expires_at, usage_limit, notes)
            
            logger.info(f"✅ API key created: {key_value} ({key_type})")
            
            return dict(row)
    
    @require_pool
    async def get_api_key(self, key_value: str) -> Optional[Dict[str, Any]]:
        """Get API key by value"""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT * FROM api_keys WHERE key_value = $1
            """, key_value)
            
            return dict(row) if row else None
    
    @require_pool
    async def validate_api_key(self, key_value: str) -> tuple[bool, Optional[str]]:
        """
        Validate API key
        Returns: (is_valid, error_message)
        """
        key = await self.get_api_key(key_value)
        
        if not key:
            return False, "Invalid API key"
        
        if not key['is_active']:
            return False, "API key is inactive"
        
        # Check expiration
        if key['expires_at'] and key['expires_at'] < datetime.now():
            return False, "API key expired"
        
        # Check usage limit
        if key['usage_limit'] and key['usage_count'] >= key['usage_limit']:
            return False, "API key usage limit exceeded"
        
        return True, None
    
    @require_pool
    async def list_api_keys(
        self,
        key_type: Optional[str] = None,
        is_active: Optional[bool] = None
    ) -> List[Dict[str, Any]]:
        """List API keys"""
        async with self.pool.acquire() as conn:
            query = "SELECT * FROM api_keys WHERE 1=1"
            params = []
            
            if key_type:
                params.append(key_type)
                query += f" AND key_type = ${len(params)}"
            
            if is_active is not None:
                params.append(is_active)
                query += f" AND is_active = ${len(params)}"
            
            query += " ORDER BY created_at DESC"
            
            rows = await conn.fetch(query, *params)
            return [dict(row) for row in rows]
    
    @require_pool
    async def update_api_key(
        self,
        key_id: str,
        **kwargs
    ) -> Dict[str, Any]:
        """Update API key"""
        async with self.pool.acquire() as conn:
            # Build update query
            set_clauses = []
            params = []
            
            for i, (key, value) in enumerate(kwargs.items(), start=1):
                set_clauses.append(f"{key} = ${i}")
                params.append(value)
            
            params.append(key_id)
            
            query = f"""
                UPDATE api_keys
                SET {', '.join(set_clauses)}
                WHERE id = ${len(params)}
                RETURNING *
            """
            
            row = await conn.fetchrow(query, *params)
            
            logger.info(f"✅ API key updated: {key_id}")
            
            return dict(row) if row else None
    
    async def revoke_api_key(self, key_id: str) -> bool:
        """Revoke API key"""
        result = await self.update_api_key(key_id, is_active=False)
        return result is not None
    
    @require_pool
    async def delete_api_key(self, key_id: str) -> bool:
        """Delete API key"""
        async with self.pool.acquire() as conn:
            result = await conn.execute("""
                DELETE FROM api_keys WHERE id = $1
            """, key_id)
            
            return result == "DELETE 1"
    
    # ===== Key Usage Logging =====
    
    @require_pool
    async def log_key_usage(
        self,
        key_id: str,
        endpoint: str,
        method: str,
        ip_address: str,
        user_agent: str,
        request_body: Optional[Dict] = None,
        response_status: Optional[int] = None,
        response_time_ms: Optional[int] = None
    ):
        """Log API key usage"""
        async with self.pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO key_usage_logs (
                    key_id, endpoint, method, ip_address, user_agent,
                    request_body, response_status, response_time_ms
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            """, key_id, endpoint, method, ip_address, user_agent,
                json.dumps(request_body) if request_body else None,
                response_status, response_time_ms)
    
    # ===== Attack Management =====
    
    @require_pool
    async def create_attack(
        self,
        key_id: str,
        target_url: str,
        attack_mode: str = 'auto'
    ) -> Dict[str, Any]:
        """Create new attack session"""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("""
                INSERT INTO attacks (key_id, target_url, attack_mode, status)
                VALUES ($1, $2, $3, 'pending')
                RETURNING *
            """, key_id, target_url, attack_mode)
            
            logger.info(f"✅ Attack created: {row['id']}")
            
            return dict(row)
    
    @require_pool
    async def get_attack(self, attack_id: str) -> Optional[Dict[str, Any]]:
        """Get attack by ID"""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT * FROM attacks WHERE id = $1
            """, attack_id)
            
            return dict(row) if row else None
    
    @require_pool
    async def update_attack(
        self,
        attack_id: str,
        **kwargs
    ) -> Dict[str, Any]:
        """Update attack"""
        async with self.pool.acquire() as conn:
            set_clauses = []
            params = []
            
            for i, (key, value) in enumerate(kwargs.items(), start=1):
                if key == 'target_info' or key == 'metadata':
                    value = json.dumps(value)
                set_clauses.append(f"{key} = ${i}")
                params.append(value)
            
            params.append(attack_id)
            
            query = f"""
                UPDATE attacks
                SET {', '.join(set_clauses)}
                WHERE id = ${len(params)}
                RETURNING *
            """
            
            row = await conn.fetchrow(query, *params)
            
            return dict(row) if row else None
    
    @require_pool
    async def list_attacks(
        self,
        key_id: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """List attacks"""
        async with self.pool.acquire() as conn:
            query = "SELECT * FROM attacks WHERE 1=1"
            params = []
            
            if key_id:
                params.append(key_id)
                query += f" AND key_id = ${len(params)}"
            
            if status:
                params.append(status)
                query += f" AND status = ${len(params)}"
            
            params.append(limit)
            query += f" ORDER BY started_at DESC LIMIT ${len(params)}"
            
            rows = await conn.fetch(query, *params)
            return [dict(row) for row in rows]
    
    # ===== Vulnerability Management =====
    
    @require_pool
    async def create_vulnerability(
        self,
        attack_id: str,
        vuln_type: str,
        severity: str,
        title: str,
        **kwargs
    ) -> Dict[str, Any]:
        """Create vulnerability"""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("""
                INSERT INTO vulnerabilities (
                    attack_id, vuln_type, severity, title,
                    description, url, parameter, payload, evidence,
                    cvss_score, cve_id, metadata
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                RETURNING *
            """, attack_id, vuln_type, severity, title,
                kwargs.get('description'),
                kwargs.get('url'),
                kwargs.get('parameter'),
                kwargs.get('payload'),
                kwargs.get('evidence'),
                kwargs.get('cvss_score'),
                kwargs.get('cve_id'),
                json.dumps(kwargs.get('metadata', {})))
            
            # Update attack vulnerabilities count
            await conn.execute("""
                UPDATE attacks
                SET vulnerabilities_found = vulnerabilities_found + 1
                WHERE id = $1
            """, attack_id)
            
            return dict(row)
    
    @require_pool
    async def list_vulnerabilities(
        self,
        attack_id: str
    ) -> List[Dict[str, Any]]:
        """List vulnerabilities for attack"""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT * FROM vulnerabilities
                WHERE attack_id = $1
                ORDER BY discovered_at DESC
            """, attack_id)
            
            return [dict(row) for row in rows]
    
    # ===== System Settings =====
    
    @require_pool
    async def get_setting(self, key: str) -> Optional[str]:
        """Get system setting"""
        async with self.pool.acquire() as conn:
            value = await conn.fetchval("""
                SELECT value FROM system_settings WHERE key = $1
            """, key)
            
            return value
    
    @require_pool
    async def set_setting(self, key: str, value: str):
        """Set system setting"""
        async with self.pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO system_settings (key, value, updated_at)
                VALUES ($1, $2, CURRENT_TIMESTAMP)
                ON CONFLICT (key) DO UPDATE
                SET value = $2, updated_at = CURRENT_TIMESTAMP
            """, key, value)
            
            logger.info(f"✅ Setting updated: {key} = {value}")
    
    # ===== Statistics =====
    
    @require_pool
    async def get_attack_statistics(self) -> Dict[str, Any]:
        """Get attack statistics"""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("""
                SELECT
                    COUNT(*) as total_attacks,
                    COUNT(*) FILTER (WHERE status = 'completed') as completed_attacks,
                    COUNT(*) FILTER (WHERE status = 'failed') as failed_attacks,
                    COUNT(*) FILTER (WHERE status IN ('pending', 'running')) as active_attacks,
                    AVG(vulnerabilities_found) as avg_vulnerabilities,
                    SUM(data_exfiltrated_bytes) as total_data_exfiltrated
                FROM attacks
            """)
            
            return dict(row)
    
    @require_pool
    async def get_key_statistics(self) -> List[Dict[str, Any]]:
        """Get key statistics"""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT * FROM key_statistics
                ORDER BY total_attacks DESC
            """)
            
            return [dict(row) for row in rows]


# Global database instance
db = DatabaseService()

