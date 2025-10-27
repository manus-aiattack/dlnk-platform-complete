import asyncio
import asyncpg
import json
import uuid
from datetime import datetime, timezone
import os
from dotenv import load_dotenv

# Assuming redis_config is in a reachable path, e.g., parent directory
from database.redis_config import set_cache, get_cache

# Load environment variables
load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL", "")

async def get_db_connection():
    """Establishes and returns a database connection."""
    return await asyncpg.connect(DATABASE_URL)

async def log_attack_start(attack_id: uuid.UUID, target_id: str, user_id: int | None = None):
    """Logs the start of a new attack."""
    await log_attack_phase(attack_id, target_id, "start", "STARTED", {"message": "Attack initiated"}, user_id)

async def log_phase_complete(attack_id: uuid.UUID, target_id: str, phase: str, details: dict, user_id: int | None = None):
    """Logs the completion of a specific attack phase."""
    await log_attack_phase(attack_id, target_id, phase, "COMPLETED", details, user_id)

async def log_attack_failure(attack_id: uuid.UUID, target_id: str, phase: str, error_details: dict, user_id: int | None = None):
    """Logs the failure of a specific attack phase."""
    await log_attack_phase(attack_id, target_id, phase, "FAILED", error_details, user_id)

async def log_attack_complete(attack_id: uuid.UUID, target_id: str, user_id: int | None = None):
    """Logs the successful completion of the entire attack."""
    await log_attack_phase(attack_id, target_id, "end", "COMPLETED", {"message": "Attack finished successfully"}, user_id)

async def log_attack_phase(attack_id: uuid.UUID, target_id: str, phase: str, status: str, details: dict, user_id: int | None = None):
    """Generic function to log any attack phase or event."""
    conn = await get_db_connection()
    try:
        await conn.execute(
            "INSERT INTO attack_logs (attack_id, user_id, target_id, phase, status, details) VALUES ($1, $2, $3, $4, $5, $6)",
            attack_id, user_id, target_id, phase, status, json.dumps(details)
        )
        # Cache the latest status
        await cache_attack_status(attack_id, {"phase": phase, "status": status, "timestamp": datetime.now(timezone.utc).isoformat()})
    finally:
        await conn.close()

async def get_attack_history(attack_id: uuid.UUID) -> list:
    """Retrieves the full event history for a given attack ID."""
    conn = await get_db_connection()
    try:
        records = await conn.fetch(
            "SELECT timestamp, phase, status, details FROM attack_logs WHERE attack_id = $1 ORDER BY timestamp ASC",
            attack_id
        )
        return [dict(record) for record in records]
    finally:
        await conn.close()

async def save_workflow_state(attack_id: uuid.UUID, state_data: dict):
    """Saves or updates the state of a workflow."""
    conn = await get_db_connection()
    try:
        # Upsert functionality: Insert or update if the attack_id already exists
        await conn.execute(
            """
            INSERT INTO workflow_states (attack_id, state_data)
            VALUES ($1, $2)
            ON CONFLICT (attack_id) DO UPDATE
            SET state_data = EXCLUDED.state_data, updated_at = CURRENT_TIMESTAMP;
            """,
            attack_id, json.dumps(state_data)
        )
    finally:
        await conn.close()

async def load_workflow_state(attack_id: uuid.UUID) -> dict | None:
    """Loads the most recent state for a workflow."""
    conn = await get_db_connection()
    try:
        record = await conn.fetchrow("SELECT state_data FROM workflow_states WHERE attack_id = $1", attack_id)
        return json.loads(record['state_data']) if record else None
    finally:
        await conn.close()

async def cache_attack_status(attack_id: uuid.UUID, status: dict):
    """Caches the current status of an attack in Redis for quick access."""
    cache_key = f"attack_status:{attack_id}"
    await set_cache(cache_key, status, ttl=3600 * 24) # Cache for 24 hours

async def get_cached_attack_status(attack_id: uuid.UUID) -> dict | None:
    """Retrieves the cached status of an attack from Redis."""
    cache_key = f"attack_status:{attack_id}"
    return await get_cache(cache_key)

# Example Usage
async def main():
    test_attack_id = uuid.uuid4()
    test_target_id = "example.com"
    print(f"Starting test for Attack ID: {test_attack_id}")

    await log_attack_start(test_attack_id, test_target_id)
    print("Logged attack start.")

    await save_workflow_state(test_attack_id, {"step": 1, "context": "Initial reconnaissance"})
    print("Saved initial workflow state.")

    await log_phase_complete(test_attack_id, test_target_id, "reconnaissance", {"ports_found": [80, 443]})
    print("Logged phase completion.")

    loaded_state = await load_workflow_state(test_attack_id)
    print(f"Loaded workflow state: {loaded_state}")

    await save_workflow_state(test_attack_id, {"step": 2, "context": "Vulnerability scanning"})
    print("Updated workflow state.")

    cached_status = await get_cached_attack_status(test_attack_id)
    print(f"Cached status: {cached_status}")

    await log_attack_complete(test_attack_id, test_target_id)
    print("Logged attack completion.")

    history = await get_attack_history(test_attack_id)
    print("\n--- Attack History ---")
    for event in history:
        print(f"  - {event['timestamp']} | {event['phase']:<20} | {event['status']:<10} | {event['details']}")
    print("----------------------")

if __name__ == "__main__":
    # Ensure DB and Redis are running and accessible
    # asyncio.run(main())
    print("Run this module within an async context to test.")
