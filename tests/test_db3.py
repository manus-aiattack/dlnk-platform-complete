import asyncio
import asyncpg

async def test( ):
    try:
        conn = await asyncpg.connect(
            host='localhost',
            port=5432,
            user='dlnk',
            password='dlnk_password',
            database='dlnk_db'
        )
        print("✅ Connected with password!")
        result = await conn.fetchval("SELECT 1")
        print(f"✅ Query result: {result}")
        await conn.close()
    except Exception as e:
        print(f"❌ Failed: {e}")

asyncio.run(test())
