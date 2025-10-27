import asyncio
import asyncpg
import os

async def test():
    print(f"DATABASE_URL from env: {os.getenv('DATABASE_URL', '')}")
    print("\nTrying to connect...")
    try:
        conn = await asyncpg.connect(
            dsn="postgresql://dlnk@localhost:5432/dlnk_db"
        )
        print("✅ Connected!")
        result = await conn.fetchval("SELECT 1")
        print(f"✅ Query result: {result}")
        await conn.close()
    except Exception as e:
        print(f"❌ Failed: {e}")
        print(f"Error type: {type(e)}")

asyncio.run(test())
