import asyncio
import os
import asyncpg
import hashlib
import secrets
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Get database connection details from environment variables
DATABASE_URL = os.getenv("DATABASE_URL", "")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@example.com")

async def init_db():
    """Initializes the database by creating tables and an admin user."""
    conn = None
    try:
        conn = await asyncpg.connect(DATABASE_URL)
        print("Successfully connected to the database.")

        # Read schema.sql file
        schema_path = os.path.join(os.path.dirname(__file__), 'schema.sql')
        with open(schema_path, 'r') as f:
            schema = f.read()

        # Execute schema.sql
        await conn.execute(schema)
        print("Database schema created successfully.")

        # Create admin user
        admin_password = secrets.token_hex(16)
        password_hash = hashlib.sha256(admin_password.encode()).hexdigest()

        # Check if admin user already exists
        admin_exists = await conn.fetchval("SELECT 1 FROM users WHERE username = $1", ADMIN_USERNAME)
        if not admin_exists:
            await conn.execute(
                "INSERT INTO users (username, password_hash, email, is_admin) VALUES ($1, $2, $3, $4)",
                ADMIN_USERNAME, password_hash, ADMIN_EMAIL, True
            )
            print(f"Admin user '{ADMIN_USERNAME}' created with password: {admin_password}")
            print("IMPORTANT: Store this password securely and delete this message.")
        else:
            print(f"Admin user '{ADMIN_USERNAME}' already exists.")

    except Exception as e:
        print(f"An error occurred during database initialization: {e}")
    finally:
        if conn:
            await conn.close()
            print("Database connection closed.")

if __name__ == "__main__":
    # To run this script, you need to have the database server running
    # and the .env file correctly configured.
    print("Starting database initialization...")
    asyncio.run(init_db())
    print("Database initialization finished.")
