import asyncpg
import json
import asyncio
from datetime import datetime
from typing import List, Dict, Any, Optional
from core.logger import log
from config import settings

class DatabaseManager:
    def __init__(self):
        self.conn_pool = None
        self.db_config = {
            "host": settings.DATABASE_HOST,
            "port": settings.DATABASE_PORT,
            "user": settings.DATABASE_USER,
            "password": settings.DATABASE_PASSWORD,
            "database": settings.DATABASE_NAME
        }

    async def connect(self):
        """Establishes a connection pool to the PostgreSQL database."""
        # Initialize config here to ensure mocked settings in tests are used
        self.db_config = {
            "host": settings.DATABASE_HOST,
            "port": settings.DATABASE_PORT,
            "user": settings.DATABASE_USER,
            "password": settings.DATABASE_PASSWORD,
            "database": settings.DATABASE_NAME
        }
        try:
            self.conn_pool = await asyncpg.create_pool(**self.db_config)
            log.info(f"Connected to PostgreSQL database: {settings.DATABASE_NAME} at {settings.DATABASE_HOST}:{settings.DATABASE_PORT}")
            await self._create_tables()
        except Exception as e:
            log.critical(f"Failed to connect to PostgreSQL: {e}", exc_info=True)
            raise ConnectionError(f"Failed to connect to PostgreSQL: {e}")

    async def _create_tables(self):
        """Creates necessary tables if they don't exist."""
        schema = """
        CREATE TABLE IF NOT EXISTS cycles (
            id SERIAL PRIMARY KEY,
            target_host TEXT NOT NULL,
            start_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            end_time TIMESTAMP WITH TIME ZONE,
            status TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS agent_actions (
            id SERIAL PRIMARY KEY,
            cycle_id INTEGER REFERENCES cycles(id) ON DELETE CASCADE,
            agent_name TEXT NOT NULL,
            action_summary TEXT NOT NULL,
            report_data JSONB,
            timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS findings (
            id SERIAL PRIMARY KEY,
            host TEXT NOT NULL,
            finding_key TEXT UNIQUE NOT NULL,
            data JSONB,
            timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_cycles_target_host ON cycles(target_host);
        CREATE INDEX IF NOT EXISTS idx_agent_actions_cycle_id ON agent_actions(cycle_id);
        CREATE INDEX IF NOT EXISTS idx_findings_host ON findings(host);
        CREATE INDEX IF NOT EXISTS idx_findings_finding_key ON findings(finding_key);
        """
        async with self.conn_pool.acquire() as conn:
            await conn.execute(schema)
        log.info("PostgreSQL tables checked/created successfully.")

    async def create_cycle(self, target_host: str) -> int:
        """Logs the start of a new attack cycle and returns the cycle ID."""
        try:
            async with self.conn_pool.acquire() as conn:
                cycle_id = await conn.fetchval(
                    """
                    INSERT INTO cycles (target_host, status)
                    VALUES ($1, $2)
                    RETURNING id;
                    """,
                    target_host, "running"
                )
            log.info(f"Started new attack cycle {cycle_id} for target {target_host}")
            return cycle_id
        except Exception as e:
            log.error(f"Failed to create new attack cycle in PostgreSQL: {e}", exc_info=True)
            return -1

    async def end_cycle(self, cycle_id: int):
        """Logs the end of an attack cycle."""
        try:
            async with self.conn_pool.acquire() as conn:
                await conn.execute(
                    """
                    UPDATE cycles
                    SET status = $1, end_time = CURRENT_TIMESTAMP
                    WHERE id = $2;
                    """,
                    "completed", cycle_id
                )
            log.info(f"Attack cycle {cycle_id} marked as completed.")
        except Exception as e:
            log.error(f"Failed to end attack cycle {cycle_id} in PostgreSQL: {e}", exc_info=True)

    async def log_agent_action(
        self,
        cycle_id: int,
        agent_name: str,
        action_summary: str,
        report_data: dict = None,
        finding_key: str = None,
        host: str = None # Added host parameter for findings
    ):
        """Logs a generic agent action and its report to PostgreSQL."""
        try:
            async with self.conn_pool.acquire() as conn:
                action_id = await conn.fetchval(
                    """
                    INSERT INTO agent_actions (cycle_id, agent_name, action_summary, report_data)
                    VALUES ($1, $2, $3, $4)
                    RETURNING id;
                    """,
                    cycle_id, agent_name, action_summary, json.dumps(report_data, default=str) if report_data else {}
                )

                if finding_key and host:
                    # Store findings separately, upsert if already exists
                    await conn.execute(
                        """
                        INSERT INTO findings (host, finding_key, data)
                        VALUES ($1, $2, $3)
                        ON CONFLICT (finding_key) DO UPDATE
                        SET data = EXCLUDED.data, timestamp = CURRENT_TIMESTAMP;
                        """,
                        host, finding_key, json.dumps(report_data, default=str) if report_data else {}
                    )

            log.debug(f"Logged action {action_id} for agent {agent_name} in cycle {cycle_id}")
            return action_id
        except Exception as e:
            log.error(f"Failed to log agent action for cycle {cycle_id}: {e}", exc_info=True)
            return -1

    async def get_all_findings_for_host(self, host: str) -> List[Dict[str, Any]]:
        """Retrieves all findings for a given host."""
        try:
            async with self.conn_pool.acquire() as conn:
                records = await conn.fetch(
                    """
                    SELECT data FROM findings
                    WHERE host = $1;
                    """,
                    host
                )
            return [json.loads(r["data"]) for r in records]
        except Exception as e:
            log.error(f"Failed to retrieve findings for host {host}: {e}", exc_info=True)
            return []

    async def get_cycle_history(self, cycle_id: int) -> List[Dict[str, Any]]:
        """Retrieves the history of actions for a given cycle."""
        try:
            async with self.conn_pool.acquire() as conn:
                records = await conn.fetch(
                    """
                    SELECT id, agent_name, action_summary, report_data, timestamp
                    FROM agent_actions
                    WHERE cycle_id = $1
                    ORDER BY timestamp;
                    """,
                    cycle_id
                )
            
            history = []
            for r in records:
                action = {
                    "id": r["id"],
                    "agent_name": r["agent_name"],
                    "action_summary": r["action_summary"],
                    "timestamp": r["timestamp"].isoformat(),
                    "report_data": json.loads(r["report_data"]) if r["report_data"] else {}
                }
                history.append(action)
            return history
        except Exception as e:
            log.error(f"Failed to retrieve history for cycle {cycle_id}: {e}", exc_info=True)
            return []

    async def close(self):
        """Closes the connection pool to the PostgreSQL database."""
        if self.conn_pool:
            await self.conn_pool.close()
            log.info("PostgreSQL connection pool closed.")