# PostgreSQL Setup Guide

คู่มือการติดตั้งและตั้งค่า PostgreSQL สำหรับ dLNk Attack Platform

---

## ภาพรวม

dLNk Attack Platform ใช้ **PostgreSQL** เป็น primary database สำหรับ production และ **SQLite** เป็น fallback สำหรับ development

คู่มือนี้จะครอบคลุม:

- การติดตั้ง PostgreSQL
- การตั้งค่า Database และ User
- การ Import Schema
- การแก้ไขปัญหาที่พบบ่อย
- การ Backup และ Restore

---

## ความต้องการของระบบ

- **OS:** Ubuntu 22.04+ / Debian 11+ / WSL2
- **PostgreSQL:** 14.0 หรือสูงกว่า
- **Disk:** 10GB+ (แนะนำ SSD)
- **RAM:** 2GB+ (แนะนำ 4GB+)

---

## การติดตั้ง PostgreSQL

### Ubuntu / Debian

```bash
# Update package list
sudo apt update

# Install PostgreSQL
sudo apt install -y postgresql postgresql-contrib libpq-dev

# Start PostgreSQL service
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Check status
sudo systemctl status postgresql
```

### macOS

```bash
# ใช้ Homebrew
brew install postgresql@14

# Start service
brew services start postgresql@14
```

### Windows (WSL2)

```bash
# Install PostgreSQL
sudo apt update
sudo apt install -y postgresql postgresql-contrib

# Start service
sudo service postgresql start

# Enable auto-start
sudo update-rc.d postgresql enable
```

---

## การตั้งค่า Database

### 1. เข้าสู่ PostgreSQL Shell

```bash
sudo -u postgres psql
```

### 2. สร้าง Database และ User

```sql
-- สร้าง database
CREATE DATABASE dlnk_attack_platform;

-- สร้าง user
CREATE USER dlnk WITH PASSWORD 'your_secure_password_here';

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE dlnk_attack_platform TO dlnk;

-- เปลี่ยน owner
ALTER DATABASE dlnk_attack_platform OWNER TO dlnk;

-- ออกจาก psql
\q
```

### 3. ตั้งค่า Authentication

แก้ไขไฟล์ `pg_hba.conf`:

```bash
# หาตำแหน่งไฟล์
sudo -u postgres psql -c "SHOW hba_file;"

# แก้ไขไฟล์ (ตัวอย่าง)
sudo nano /etc/postgresql/14/main/pg_hba.conf
```

เพิ่มบรรทัดนี้:

```
# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   dlnk_attack_platform   dlnk                                    md5
host    dlnk_attack_platform   dlnk            127.0.0.1/32            md5
host    dlnk_attack_platform   dlnk            ::1/128                 md5
```

Restart PostgreSQL:

```bash
sudo systemctl restart postgresql
# หรือ (WSL2)
sudo service postgresql restart
```

### 4. ทดสอบการเชื่อมต่อ

```bash
psql -U dlnk -d dlnk_attack_platform -h localhost -W
```

---

## การ Import Schema

### Option 1: ใช้ SQL File

```bash
# ถ้ามีไฟล์ schema.sql
psql -U dlnk -d dlnk_attack_platform -h localhost -f database/schema.sql
```

### Option 2: ใช้ Python Script

```bash
# รัน init script
python3 init_database.py
```

### Option 3: Manual Import

```sql
-- เข้า psql
psql -U dlnk -d dlnk_attack_platform -h localhost

-- สร้าง tables
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    role VARCHAR(50) NOT NULL CHECK (role IN ('admin', 'user')),
    api_key VARCHAR(255) UNIQUE NOT NULL,
    quota_limit INTEGER DEFAULT 100,
    quota_used INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE TABLE attacks (
    id SERIAL PRIMARY KEY,
    attack_id VARCHAR(255) UNIQUE NOT NULL,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    target_url TEXT NOT NULL,
    attack_type VARCHAR(100) NOT NULL,
    status VARCHAR(50) NOT NULL CHECK (status IN ('pending', 'running', 'success', 'failed', 'stopped')),
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    results JSONB DEFAULT '{}'::jsonb,
    error_message TEXT,
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE TABLE agent_logs (
    id SERIAL PRIMARY KEY,
    attack_id VARCHAR(255) REFERENCES attacks(attack_id) ON DELETE CASCADE,
    agent_name VARCHAR(255) NOT NULL,
    log_level VARCHAR(50) NOT NULL,
    message TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE TABLE vulnerabilities (
    id SERIAL PRIMARY KEY,
    attack_id VARCHAR(255) REFERENCES attacks(attack_id) ON DELETE CASCADE,
    vuln_type VARCHAR(100) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    url TEXT NOT NULL,
    description TEXT,
    evidence TEXT,
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE TABLE loot (
    id SERIAL PRIMARY KEY,
    attack_id VARCHAR(255) REFERENCES attacks(attack_id) ON DELETE CASCADE,
    loot_type VARCHAR(100) NOT NULL,
    data TEXT NOT NULL,
    file_path TEXT,
    collected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    metadata JSONB DEFAULT '{}'::jsonb
);

-- สร้าง indexes
CREATE INDEX idx_attacks_user_id ON attacks(user_id);
CREATE INDEX idx_attacks_status ON attacks(status);
CREATE INDEX idx_agent_logs_attack_id ON agent_logs(attack_id);
CREATE INDEX idx_vulnerabilities_attack_id ON vulnerabilities(attack_id);
CREATE INDEX idx_loot_attack_id ON loot(attack_id);
```

---

## การตั้งค่า Environment Variables

สร้างไฟล์ `.env`:

```bash
# Database
DATABASE_URL=postgresql://dlnk:your_secure_password_here@localhost:5432/dlnk_attack_platform

# หรือแยกเป็นตัวแปรแต่ละตัว
DB_HOST=localhost
DB_PORT=5432
DB_NAME=dlnk_attack_platform
DB_USER=dlnk
DB_PASSWORD=your_secure_password_here
```

---

## Troubleshooting

### 1. **Connection Refused**

**ปัญหา:**
```
psql: error: connection to server on socket "/var/run/postgresql/.s.PGSQL.5432" failed: No such file or directory
```

**วิธีแก้:**

```bash
# ตรวจสอบว่า PostgreSQL กำลังรันอยู่
sudo systemctl status postgresql

# ถ้าไม่ได้รัน ให้ start
sudo systemctl start postgresql
```

---

### 2. **Authentication Failed**

**ปัญหา:**
```
psql: error: FATAL: password authentication failed for user "dlnk"
```

**วิธีแก้:**

```bash
# Reset password
sudo -u postgres psql
ALTER USER dlnk WITH PASSWORD 'new_password';
\q

# ตรวจสอบ pg_hba.conf
sudo nano /etc/postgresql/14/main/pg_hba.conf

# Restart
sudo systemctl restart postgresql
```

---

### 3. **Database Does Not Exist**

**ปัญหา:**
```
psql: error: FATAL: database "dlnk_attack_platform" does not exist
```

**วิธีแก้:**

```bash
# สร้าง database
sudo -u postgres createdb -O dlnk dlnk_attack_platform
```

---

### 4. **Permission Denied**

**ปัญหา:**
```
ERROR: permission denied for schema public
```

**วิธีแก้:**

```sql
-- เข้า psql as postgres
sudo -u postgres psql -d dlnk_attack_platform

-- Grant permissions
GRANT ALL ON SCHEMA public TO dlnk;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO dlnk;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO dlnk;
```

---

### 5. **Port Already in Use**

**ปัญหา:**
```
could not bind IPv4 address "127.0.0.1": Address already in use
```

**วิธีแก้:**

```bash
# หา process ที่ใช้ port 5432
sudo lsof -i :5432

# Kill process
sudo kill -9 <PID>

# หรือเปลี่ยน port ใน postgresql.conf
sudo nano /etc/postgresql/14/main/postgresql.conf
# แก้ไข: port = 5433
```

---

## Performance Tuning

### 1. แก้ไข `postgresql.conf`

```bash
sudo nano /etc/postgresql/14/main/postgresql.conf
```

แนะนำการตั้งค่า:

```conf
# Memory
shared_buffers = 256MB          # 25% ของ RAM
effective_cache_size = 1GB      # 50-75% ของ RAM
work_mem = 16MB
maintenance_work_mem = 128MB

# Connections
max_connections = 100

# Logging
logging_collector = on
log_directory = 'log'
log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'
log_statement = 'all'
log_duration = on
```

Restart:

```bash
sudo systemctl restart postgresql
```

---

## Backup และ Restore

### Backup

```bash
# Backup ทั้ง database
pg_dump -U dlnk -h localhost dlnk_attack_platform > backup_$(date +%Y%m%d).sql

# Backup แบบ compressed
pg_dump -U dlnk -h localhost dlnk_attack_platform | gzip > backup_$(date +%Y%m%d).sql.gz
```

### Restore

```bash
# Restore จาก SQL file
psql -U dlnk -h localhost -d dlnk_attack_platform < backup_20250126.sql

# Restore จาก compressed file
gunzip -c backup_20250126.sql.gz | psql -U dlnk -h localhost -d dlnk_attack_platform
```

---

## Monitoring

### ดูการเชื่อมต่อปัจจุบัน

```sql
SELECT * FROM pg_stat_activity WHERE datname = 'dlnk_attack_platform';
```

### ดูขนาด Database

```sql
SELECT pg_size_pretty(pg_database_size('dlnk_attack_platform'));
```

### ดูขนาด Tables

```sql
SELECT
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;
```

---

## Maintenance

### Vacuum

```bash
# Manual vacuum
psql -U dlnk -d dlnk_attack_platform -c "VACUUM ANALYZE;"

# Auto-vacuum (ตั้งค่าใน postgresql.conf)
autovacuum = on
```

### Reindex

```bash
psql -U dlnk -d dlnk_attack_platform -c "REINDEX DATABASE dlnk_attack_platform;"
```

---

## Security Best Practices

1. **ใช้ Strong Password**
   ```sql
   ALTER USER dlnk WITH PASSWORD 'Very$trong&Complex!Pass123';
   ```

2. **จำกัด Network Access**
   - แก้ไข `pg_hba.conf` ให้อนุญาตเฉพาะ IP ที่ต้องการ

3. **Enable SSL**
   ```conf
   # postgresql.conf
   ssl = on
   ssl_cert_file = '/path/to/server.crt'
   ssl_key_file = '/path/to/server.key'
   ```

4. **Regular Backups**
   - ตั้ง cron job สำหรับ backup อัตโนมัติ

5. **Update Regularly**
   ```bash
   sudo apt update
   sudo apt upgrade postgresql
   ```

---

## การติดต่อ

หากพบปัญหา:

- **Documentation:** [PostgreSQL Official Docs](https://www.postgresql.org/docs/)
- **GitHub Issues:** [Repository Issues](https://github.com/yourusername/dlnk-platform/issues)

---

**อัพเดทล่าสุด:** 2025-10-26  
**Version:** 2.0.0

