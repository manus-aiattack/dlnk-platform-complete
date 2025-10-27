import asyncio
import asyncpg
import hashlib
import secrets
import os
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL", "")

async def get_db_connection():
    """Establishes and returns a database connection."""
    return await asyncpg.connect(DATABASE_URL)

async def generate_api_key(user_id: int, expires_in_days: int = 30) -> str:
    """Generates a new API key for a user, stores its hash, and returns the key."""
    api_key = secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    expires_at = datetime.now(timezone.utc) + timedelta(days=expires_in_days)

    conn = await get_db_connection()
    try:
        await conn.execute(
            "INSERT INTO api_keys (user_id, key_hash, expires_at) VALUES ($1, $2, $3)",
            user_id, key_hash, expires_at
        )
        print(f"API key generated for user {user_id}")
        return api_key
    finally:
        await conn.close()

async def validate_api_key(api_key: str) -> bool:
    """Validates an API key against the database."""
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    conn = await get_db_connection()
    try:
        result = await conn.fetchrow(
            "SELECT is_active, expires_at FROM api_keys WHERE key_hash = $1", key_hash
        )
        if result and result['is_active'] and result['expires_at'] > datetime.now(timezone.utc):
            # Update last_used_at timestamp
            await conn.execute("UPDATE api_keys SET last_used_at = $1 WHERE key_hash = $2", datetime.now(timezone.utc), key_hash)
            return True
        return False
    finally:
        await conn.close()

async def revoke_api_key(api_key: str):
    """Revokes an active API key."""
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    conn = await get_db_connection()
    try:
        await conn.execute("UPDATE api_keys SET is_active = FALSE WHERE key_hash = $1", key_hash)
        print(f"API key with hash {key_hash} has been revoked.")
    finally:
        await conn.close()

async def check_expiration(api_key: str) -> str:
    """Checks the expiration status of an API key."""
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    conn = await get_db_connection()
    try:
        result = await conn.fetchrow("SELECT expires_at FROM api_keys WHERE key_hash = $1", key_hash)
        if not result:
            return "Invalid Key"
        if result['expires_at'] <= datetime.now(timezone.utc):
            # Deactivate expired key
            await conn.execute("UPDATE api_keys SET is_active = FALSE WHERE key_hash = $1", key_hash)
            return "Expired"
        return f"Expires at: {result['expires_at']}"
    finally:
        await conn.close()

def lock_terminal():
    """Placeholder function to simulate locking the terminal."""
    # In a real scenario, this would interact with the host OS to lock the session.
    print("Terminal has been locked due to security policy violation.")

def unlock_terminal(admin_key: str) -> bool:
    """Placeholder function to simulate unlocking the terminal with an admin key."""
    # This is a placeholder. A real implementation would be much more secure.
    correct_key = os.getenv("ADMIN_KEY", "default_admin_key")
    if admin_key == correct_key:
        print("Terminal unlocked.")
        return True
    print("Incorrect admin key.")
    return False

# Example Usage
async def main():
    # This assumes a user with a specific UUID exists. 
    # In a real app, you would get this from your user management system.
    # For testing, let's assume a user_id. You may need to create one first.
    # Example: INSERT INTO users (id, username, password_hash, email) VALUES (uuid_generate_v4(), 'testuser', 'hash', 'test@test.com');
    test_user_id = 1 # Replace with a valid user ID from your DB
    
    print("Generating API key...")
    new_key = await generate_api_key(test_user_id)
    print(f"Generated Key: {new_key}")

    print("\nValidating API key...")
    is_valid = await validate_api_key(new_key)
    print(f"Is key valid? {is_valid}")

    print("\nChecking expiration...")
    status = await check_expiration(new_key)
    print(f"Key status: {status}")

    print("\nRevoking API key...")
    await revoke_api_key(new_key)

    print("\nValidating revoked key...")
    is_valid_after_revoke = await validate_api_key(new_key)
    print(f"Is key still valid? {is_valid_after_revoke}")

if __name__ == "__main__":
    # You need a running event loop to test these async functions.
    # Also, ensure your database is running and the schema is loaded.
    # You might need to manually insert a user to get a user_id.
    # asyncio.run(main())
    print("Run this module within an async context to test.")
