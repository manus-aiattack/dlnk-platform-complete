# PostgreSQL Setup Guide

## ภาพรวม

ระบบ dLNk Attack Platform รองรับทั้ง **SQLite** (สำหรับ development) และ **PostgreSQL** (สำหรับ production)

ปัจจุบันระบบใช้ **SQLite fallback** อัตโนมัติ ซึ่งทำงานได้ดี แต่ PostgreSQL จะให้ประสิทธิภาพและความเสถียรที่ดีกว่าสำหรับการใช้งานจริง

## การติดตั้ง PostgreSQL

### Ubuntu/Debian

```bash
# อัปเดต package list
sudo apt update

# ติดตั้ง PostgreSQL
sudo apt install -y postgresql postgresql-contrib libpq-dev

# เริ่มบริการ
sudo systemctl start postgresql
sudo systemctl enable postgresql

# ตรวจสอบสถานะ
sudo systemctl status postgresql
```

### macOS

```bash
# ใช้ Homebrew
brew install postgresql@14

# เริ่มบริการ
brew services start postgresql@14
```

### Docker

```bash
# รัน PostgreSQL container
docker run -d \
  --name dlnk-postgres \
  -e POSTGRES_USER=dlnk_user \
  -e POSTGRES_PASSWORD=dlnk_password \
  -e POSTGRES_DB=dlnk_attack_platform \
  -p 5432:5432 \
  postgres:14-alpine

# ตรวจสอบ logs
docker logs dlnk-postgres
```

## การตั้งค่า Database

### สร้าง Database และ User

```bash
# เข้าสู่ PostgreSQL shell
sudo -u postgres psql

# สร้าง user
CREATE USER dlnk_user WITH PASSWORD 'your_secure_password_here';

# สร้าง database
CREATE DATABASE dlnk_attack_platform;

# ให้สิทธิ์
GRANT ALL PRIVILEGES ON DATABASE dlnk_attack_platform TO dlnk_user;

# ออกจาก shell
\q
```

### Import Schema (ถ้ามี)

```bash
# ถ้ามีไฟล์ schema.sql
psql -U dlnk_user -d dlnk_attack_platform -h localhost < api/database/schema.sql

# หรือถ้าไม่มี schema.sql ระบบจะสร้างอัตโนมัติเมื่อเริ่มครั้งแรก
```

## การตั้งค่า Environment Variables

แก้ไขไฟล์ `.env` ในโฟลเดอร์ root ของโปรเจกต์:

```bash
# สร้างไฟล์ .env จาก template (ถ้ายังไม่มี)
cp env.template .env

# แก้ไข .env
nano .env
```

เพิ่มหรือแก้ไข configuration ดังนี้:

```bash
# Database Configuration
DATABASE_URL=postgresql://dlnk_user:your_secure_password_here@localhost:5432/dlnk_attack_platform

# หรือแยกเป็น components
DB_HOST=localhost
DB_PORT=5432
DB_USER=dlnk_user
DB_PASSWORD=your_secure_password_here
DB_NAME=dlnk_attack_platform

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000

# Ollama Configuration
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=mixtral:latest

# Security
SIMULATION_MODE=False  # False = LIVE ATTACK MODE
```

## การทดสอบการเชื่อมต่อ

### ทดสอบด้วย psql

```bash
psql -U dlnk_user -d dlnk_attack_platform -h localhost -c "SELECT version();"
```

### ทดสอบด้วย Python

สร้างไฟล์ `test_postgres.py`:

```python
#!/usr/bin/env python3
import asyncio
import asyncpg
import os
from dotenv import load_dotenv

load_dotenv()

async def test_connection():
    try:
        # อ่าน DATABASE_URL จาก environment
        dsn = os.getenv("DATABASE_URL")
        
        if not dsn:
            print("❌ DATABASE_URL not set in .env")
            return False
        
        print(f"🔗 Connecting to: {dsn.split('@')[1]}")  # แสดงเฉพาะ host/db
        
        # เชื่อมต่อ
        conn = await asyncpg.connect(dsn)
        
        # ทดสอบ query
        version = await conn.fetchval("SELECT version()")
        print(f"✅ Connected successfully!")
        print(f"📊 PostgreSQL version: {version.split(',')[0]}")
        
        # ปิดการเชื่อมต่อ
        await conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        return False

if __name__ == "__main__":
    result = asyncio.run(test_connection())
    exit(0 if result else 1)
```

รันทดสอบ:

```bash
python3 test_postgres.py
```

## การเริ่มใช้งาน

หลังจากตั้งค่าเรียบร้อยแล้ว:

```bash
# เริ่ม API server (จะใช้ PostgreSQL อัตโนมัติ)
python3 main.py server

# หรือ
uvicorn api.main:app --host 0.0.0.0 --port 8000
```

ระบบจะ:
1. ตรวจสอบว่ามี `DATABASE_URL` หรือไม่
2. ถ้ามี จะพยายามเชื่อมต่อ PostgreSQL
3. ถ้าเชื่อมต่อไม่ได้ จะ fallback ไปใช้ SQLite อัตโนมัติ

## การ Migrate จาก SQLite ไป PostgreSQL

ถ้าคุณมีข้อมูลใน SQLite อยู่แล้ว:

### วิธีที่ 1: Export/Import ด้วย Script

```python
#!/usr/bin/env python3
import asyncio
import aiosqlite
import asyncpg

async def migrate():
    # เชื่อมต่อ SQLite
    sqlite_conn = await aiosqlite.connect("workspace/dlnk.db")
    sqlite_conn.row_factory = aiosqlite.Row
    
    # เชื่อมต่อ PostgreSQL
    pg_conn = await asyncpg.connect("postgresql://dlnk_user:password@localhost/dlnk_attack_platform")
    
    # Migrate users
    async with sqlite_conn.execute("SELECT * FROM users") as cursor:
        async for row in cursor:
            await pg_conn.execute("""
                INSERT INTO users (username, role, api_key, quota_limit, quota_used, is_active, created_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                ON CONFLICT (api_key) DO NOTHING
            """, row['username'], row['role'], row['api_key'], 
                row['quota_limit'], row['quota_used'], row['is_active'], row['created_at'])
    
    # Migrate attacks, logs, vulnerabilities, loot...
    # (ทำซ้ำสำหรับแต่ละตาราง)
    
    await sqlite_conn.close()
    await pg_conn.close()
    print("✅ Migration complete!")

asyncio.run(migrate())
```

### วิธีที่ 2: เริ่มใหม่

ถ้าข้อมูลไม่สำคัญ สามารถเริ่มใหม่ได้เลย PostgreSQL จะสร้าง schema อัตโนมัติ

## Troubleshooting

### ปัญหา: Connection refused

```bash
# ตรวจสอบว่า PostgreSQL รันอยู่หรือไม่
sudo systemctl status postgresql

# เริ่มบริการ
sudo systemctl start postgresql
```

### ปัญหา: Authentication failed

```bash
# แก้ไข pg_hba.conf
sudo nano /etc/postgresql/14/main/pg_hba.conf

# เปลี่ยนจาก 'peer' เป็น 'md5' สำหรับ local connections
# local   all             all                                     md5

# Restart PostgreSQL
sudo systemctl restart postgresql
```

### ปัญหา: Database does not exist

```bash
# สร้าง database ใหม่
sudo -u postgres createdb dlnk_attack_platform
```

### ปัญหา: Permission denied

```bash
# ให้สิทธิ์ใหม่
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE dlnk_attack_platform TO dlnk_user;"
```

## สรุป

**SQLite (ปัจจุบัน):**
- ✅ ติดตั้งง่าย ไม่ต้องตั้งค่าอะไร
- ✅ เหมาะสำหรับ development และ testing
- ⚠️ ประสิทธิภาพจำกัดเมื่อมี concurrent requests มาก

**PostgreSQL (แนะนำสำหรับ production):**
- ✅ ประสิทธิภาพสูง รองรับ concurrent connections
- ✅ มี features มากกว่า (JSONB, full-text search, etc.)
- ✅ เหมาะสำหรับการใช้งานจริง
- ⚠️ ต้องติดตั้งและตั้งค่าเพิ่มเติม

ระบบจะทำงานได้ดีกับทั้งสองแบบ แต่ PostgreSQL จะให้ประสิทธิภาพที่ดีกว่าเมื่อมีผู้ใช้หลายคนพร้อมกัน

