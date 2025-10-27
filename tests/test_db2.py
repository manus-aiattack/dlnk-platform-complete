import asyncio
import asyncpg

async def test():
    # Method 1: TCP with explicit host
    print("Method 1: TCP localhost")
    try:
        conn = await asyncpg.connect(
            host='localhost',
            port=5432,
            user='dlnk',
            database='dlnk_db'
        )
        print("✅ TCP localhost: SUCCESS")
        await conn.close()
    except Exception as e:
        print(f"❌ TCP localhost: {e}")
    
    # Method 2: TCP with 127.0.0.1
    print("\nMethod 2: TCP 127.0.0.1")
    try:
        conn = await asyncpg.connect(
            host='127.0.0.1',
            port=5432,
            user='dlnk',
            database='dlnk_db'
        )
        print("✅ TCP 127.0.0.1: SUCCESS")
        await conn.close()
    except Exception as e:
        print(f"❌ TCP 127.0.0.1: {e}")
    
    # Method 3: Unix socket
    print("\nMethod 3: Unix socket")
    try:
        conn = await asyncpg.connect(
            host='/var/run/postgresql',
            user='dlnk',
            database='dlnk_db'
        )
        print("✅ Unix socket: SUCCESS")
        await conn.close()
    except Exception as e:
        print(f"❌ Unix socket: {e}")

asyncio.run(test())
