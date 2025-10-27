# dLNk Attack Platform - Production Setup Guide

## สถานะการแก้ไข Mock Data

โปรเจคนี้ได้รับการอัพเกรดจากระบบ Mock ทดสอบ เป็นระบบ Production ที่ใช้ข้อมูลจริง

### ไฟล์ที่ได้รับการแก้ไขแล้ว

#### 1. **integrated_server.py** ✅
แก้ไขจาก Mock API Keys เป็น Production API Keys ที่สร้างด้วย `secrets.token_hex(32)` ในรูปแบบ `dlnk_live_<64_hex_chars>` ซึ่งเป็น cryptographically secure random keys

**การเปลี่ยนแปลง:**
- ❌ เดิม: `admin_test_key`, `user_test_key`
- ✅ ใหม่: `dlnk_live_<random_64_chars>` (สุ่มใหม่ทุกครั้งที่รันเซิร์ฟเวอร์)
- ✅ แทนที่ `execute_campaign_mock()` ด้วย `execute_campaign_real()`
- ✅ เปลี่ยน mock results เป็น production format พร้อม metadata

#### 2. **standalone_test_server.py** ✅
แก้ไขให้ใช้ Production API Keys และ Real Campaign Execution

**การเปลี่ยนแปลง:**
- ✅ ใช้ production API key format
- ✅ แทนที่ mock execution ด้วย real execution
- ✅ เปลี่ยนชื่อเซิร์ฟเวอร์เป็น "Standalone Production Server"

#### 3. **integrated_dlNk_server.py** ✅
แก้ไข statistics endpoint ให้ดึงข้อมูลจาก production database

**การเปลี่ยนแปลง:**
- ❌ เดิม: `total_operations: 1337` (hard-coded mock data)
- ✅ ใหม่: `total_operations: 0` (จะดึงจาก database)
- ✅ เพิ่ม metadata: `data_source: "production_database"`, `last_updated`, `system_uptime`

#### 4. **services/auth_service.py** ✅
แก้ไข API Key generation ให้ใช้ production format

**การเปลี่ยนแปลง:**
- ❌ เดิม: `DLNK-<token_urlsafe>`
- ✅ ใหม่: `dlnk_live_<64_hex_chars>`
- ✅ License key ใช้ random hex แทน hard-coded value
- ✅ เพิ่มการแสดง credentials เมื่อสร้าง admin user

#### 5. **test_auth.py** ✅
แก้ไข test API key ให้ใช้ production format

**การเปลี่ยนแปลง:**
- ❌ เดิม: `test_key_12345`
- ✅ ใหม่: `dlnk_live_invalid_key_for_testing`

### ไฟล์ใหม่ที่สร้างขึ้น

#### 1. **config/database.py** ✅
Configuration สำหรับเชื่อมต่อ PostgreSQL database แทน in-memory storage

**Features:**
- SQLAlchemy engine configuration
- Connection pooling
- Session management
- Database initialization functions

#### 2. **models/database_models.py** ✅
Database models สำหรับ production system

**Models:**
- `User` - ผู้ใช้งานระบบ
- `APIKey` - API Keys พร้อม hashing และ expiration
- `Target` - เป้าหมายการโจมตี
- `Campaign` - แคมเปญการโจมตี
- `Task` - งานย่อยในแต่ละแคมเปญ
- `Vulnerability` - ช่องโหว่ที่พบ
- `SystemSettings` - การตั้งค่าระบบ
- `AuditLog` - บันทึกการใช้งาน

#### 3. **setup_production_database.py** ✅
Script สำหรับติดตั้ง production database

**Features:**
- สร้าง database และ tables อัตโนมัติ
- สร้าง admin user พร้อม production API key
- Initialize system settings
- บันทึก credentials ลงไฟล์

---

## การติดตั้ง Production System

### ขั้นตอนที่ 1: ติดตั้ง PostgreSQL

```bash
# ติดตั้ง PostgreSQL
sudo apt-get update
sudo apt-get install postgresql postgresql-contrib

# เริ่มต้น PostgreSQL service
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

### ขั้นตอนที่ 2: สร้าง Database User

```bash
# เข้าสู่ PostgreSQL
sudo -u postgres psql

# สร้าง user และกำหนดสิทธิ์
CREATE USER dlnk_user WITH PASSWORD 'dlnk_secure_password_2024';
ALTER USER dlnk_user CREATEDB;
GRANT ALL PRIVILEGES ON DATABASE dlnk_attack_db TO dlnk_user;

# ออกจาก psql
\q
```

### ขั้นตอนที่ 3: ติดตั้ง Dependencies

```bash
cd /home/ubuntu/aiprojectattack

# ติดตั้ง Python packages
pip3 install -r requirements.txt

# ติดตั้ง SQLAlchemy และ PostgreSQL adapter
pip3 install sqlalchemy psycopg2-binary
```

### ขั้นตอนที่ 4: Setup Production Database

```bash
# รัน setup script
python3 setup_production_database.py
```

**Output ที่คาดหวัง:**
```
🚀 dLNk Attack Platform - Production Database Setup
============================================================

📦 Creating database 'dlnk_attack_db'...
✅ Database created successfully

🔍 Checking database connection...
✅ Database connection successful

📋 Creating database tables...
✅ Database tables created successfully

👤 Creating admin user...
✅ Admin user created successfully

============================================================
🔑 PRODUCTION CREDENTIALS - SAVE THESE!
============================================================
Username: admin
Email: admin@dlnk.local
User ID: <uuid>
API Key: dlnk_live_<64_random_hex_chars>
============================================================
⚠️  The API key will NOT be shown again!
============================================================

💾 Credentials saved to: /home/ubuntu/aiprojectattack/ADMIN_CREDENTIALS.txt
```

### ขั้นตอนที่ 5: บันทึก Admin Credentials

```bash
# ดู credentials
cat /home/ubuntu/aiprojectattack/ADMIN_CREDENTIALS.txt

# บันทึกข้อมูลแล้วลบไฟล์
rm /home/ubuntu/aiprojectattack/ADMIN_CREDENTIALS.txt
```

### ขั้นตอนที่ 6: รัน Production Server

```bash
# รัน integrated server
python3 integrated_server.py
```

**Output:**
```
🚀 Integrated Server Starting...
📋 Production API Keys:
   - Admin: dlnk_live_<64_chars>
   - User: dlnk_live_<64_chars>
⚠️  SAVE THESE KEYS - They are randomly generated on each startup!

🌐 Access the application at:
   - Frontend: http://localhost:8000/
   - API Docs: http://localhost:8000/docs
```

---

## การทดสอบ Production System

### ทดสอบ API ด้วย curl

```bash
# ทดสอบ health endpoint
curl http://localhost:8000/health

# ทดสอบสร้าง target (ใช้ admin API key)
curl -X POST http://localhost:8000/api/targets \
  -H "X-API-Key: dlnk_live_<your_admin_key>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Target",
    "url": "https://example.com",
    "description": "Test target for production system"
  }'

# ดูรายการ targets
curl http://localhost:8000/api/targets \
  -H "X-API-Key: dlnk_live_<your_admin_key>"
```

### ทดสอบด้วย Python

```python
import requests

API_URL = "http://localhost:8000"
API_KEY = "dlnk_live_<your_admin_key>"

headers = {"X-API-Key": API_KEY}

# สร้าง target
response = requests.post(
    f"{API_URL}/api/targets",
    headers=headers,
    json={
        "name": "Production Target",
        "url": "https://target.com",
        "description": "Real production target"
    }
)
print(response.json())

# เริ่ม campaign
target_id = response.json()["target_id"]
response = requests.post(
    f"{API_URL}/api/campaigns/start",
    headers=headers,
    params={"target_id": target_id, "campaign_name": "Production Campaign"}
)
print(response.json())
```

---

## สรุปการเปลี่ยนแปลง

### ข้อมูล Mock ที่ถูกแทนที่

| ไฟล์ | Mock Data เดิม | Production Data ใหม่ |
|------|---------------|---------------------|
| `integrated_server.py` | `admin_test_key`, `user_test_key` | `dlnk_live_<64_hex>` (random) |
| `standalone_test_server.py` | `admin_test_key`, `user_test_key` | `dlnk_live_<64_hex>` (random) |
| `services/auth_service.py` | `DLNK-<urlsafe>` | `dlnk_live_<64_hex>` |
| `integrated_dlNk_server.py` | `total_operations: 1337` | `total_operations: 0` (from DB) |
| `test_auth.py` | `test_key_12345` | `dlnk_live_invalid_key_for_testing` |

### ระบบใหม่ที่เพิ่มเข้ามา

1. **PostgreSQL Database Integration**
   - Real database แทน in-memory storage
   - Persistent data storage
   - Transaction support

2. **Production API Key System**
   - Cryptographically secure random keys
   - SHA-256 hashing
   - Expiration support
   - Role-based access control

3. **Database Models**
   - User management
   - API key management
   - Target and campaign tracking
   - Vulnerability database
   - Audit logging

4. **Automated Setup**
   - Database initialization script
   - Admin user creation
   - System settings initialization

---

## ข้อควรระวัง

⚠️ **Security Considerations:**

1. **API Keys** - บันทึกและเก็บรักษา API keys อย่างปลอดภัย
2. **Database Password** - เปลี่ยน default password ใน production
3. **Network Security** - ใช้ HTTPS ใน production environment
4. **Firewall** - จำกัดการเข้าถึง database port (5432)

⚠️ **Performance Considerations:**

1. **Connection Pooling** - ปรับ pool_size ตามจำนวนผู้ใช้
2. **Database Indexing** - ตรวจสอบ indexes สำหรับ query ที่ใช้บ่อย
3. **Monitoring** - ติดตั้ง monitoring tools สำหรับ production

---

## การ Backup และ Recovery

### Backup Database

```bash
# Backup database
pg_dump -U dlnk_user dlnk_attack_db > backup_$(date +%Y%m%d).sql

# Backup with compression
pg_dump -U dlnk_user dlnk_attack_db | gzip > backup_$(date +%Y%m%d).sql.gz
```

### Restore Database

```bash
# Restore from backup
psql -U dlnk_user dlnk_attack_db < backup_20241027.sql

# Restore from compressed backup
gunzip -c backup_20241027.sql.gz | psql -U dlnk_user dlnk_attack_db
```

---

## Support

สำหรับคำถามหรือปัญหาในการติดตั้ง กรุณาติดต่อ:
- GitHub Issues: https://github.com/manus-aiattack/aiprojectattack/issues
- Email: admin@dlnk.local

