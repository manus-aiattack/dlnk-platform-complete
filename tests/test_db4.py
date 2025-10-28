import asyncio
import asyncpg
import logging

logging.basicConfig(level=logging.DEBUG)

async def test():
    print("Connecting to postgresql://connext:***@localhost:5432/connext_db")
    try:
        conn = await asyncpg.connect(
            host='localhost',
            port=5432,
            user='connext',
            password='connext_password',
            database='connext_db',
            timeout=10
        )
        print("✅ Connected!")
        result = await conn.fetchval("SELECT 1")
        print(f"✅ Result: {result}")
        await conn.close()
    except Exception as e:
        print(f"❌ Failed: {e}")
        import traceback
        traceback.print_exc()

asyncio.run(test())
