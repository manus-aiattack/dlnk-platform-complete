# คู่มือการเข้าถึงระบบ dLNk Attack Platform

## การเข้าถึงจากทุกที่ (ต่างจังหวัด, มือถือ, คอมพิวเตอร์)

### 1. Frontend Dashboard (ใช้งานระบบ)

**URL:** https://8000-ioez7uufj9x8f2mxaeiwn-b6134a46.manus-asia.computer/

**API Key:** `admin_key_001`

**วิธีใช้:**
1. เปิด URL ด้านบน
2. กรอก API Key: `admin_key_001`
3. คลิก "Initialize Connection"
4. เริ่มใช้งานได้เลย

**ฟีเจอร์:**
- Launch Attack
- Quick Scan / Full Scan / Vulnerability Scan
- AI Analysis
- ดูสถิติและผลลัพธ์
- Monitor Operations แบบ Real-time

### 2. Admin Panel (จัดการ API Keys)

**URL:** https://8000-ioez7uufj9x8f2mxaeiwn-b6134a46.manus-asia.computer/admin

**Admin Key:** `admin_key_001`

**วิธีใช้:**
1. เปิด URL ด้านบน
2. กรอก Admin Key: `admin_key_001`
3. คลิก "Access Panel"

**ฟีเจอร์:**
- สร้าง API Key ใหม่
- ดูรายการ Key ทั้งหมด
- Revoke Key
- ดูสถิติการใช้งาน

### 3. Web Terminal (จัดการระบบ)

**URL:** https://7681-ioez7uufj9x8f2mxaeiwn-b6134a46.manus-asia.computer/

**Credential:** `admin_key_001` (Password)

**วิธีใช้:**
1. เปิด URL ด้านบน
2. Username: เว้นว่าง (ไม่ต้องใส่)
3. Password: `admin_key_001`
4. จะได้ Terminal แบบเต็มรูปแบบ

**หมายเหตุ:** Web Terminal ทำงานผ่าน systemd service และจะ auto-start เมื่อ reboot

**คำสั่งที่ใช้บ่อย:**
```bash
# ดูสถานะระบบ
sudo systemctl status dlnk-platform

# Restart ระบบ
sudo systemctl restart dlnk-platform

# ดู logs
tail -f /var/log/dlnk/platform.log

# ดู database
sudo -u postgres psql -d dlnk

# ดู Redis
redis-cli

# ดู API keys
cat /home/ubuntu/aiprojectattack/data/keys.json

# อัพเดทโค้ดจาก GitHub
cd /home/ubuntu/aiprojectattack
git pull origin main
sudo systemctl restart dlnk-platform

# ดูการใช้งานระบบ
htop

# ดู disk usage
df -h

# ดู network connections
netstat -tulpn
```

### 4. API Documentation

**URL:** https://8000-ioez7uufj9x8f2mxaeiwn-b6134a46.manus-asia.computer/api/docs

**วิธีใช้:**
1. เปิด URL ด้านบน
2. คลิก "Authorize" ด้านบนขวา
3. กรอก API Key: `admin_key_001`
4. ทดสอบ API ได้เลย

## ข้อมูลระบบ

- **Database:** PostgreSQL (localhost:5432)
- **Cache:** Redis (localhost:6379)
- **Web Server:** Uvicorn (port 8000)
- **Web Terminal:** ttyd (port 7681)
- **Agents:** 163+ AI-powered attack agents
- **API Endpoints:** 121+ endpoints
- **Version:** v3.0.0-complete

## Auto-Start Services

ระบบถูกตั้งค่าให้เริ่มทำงานอัตโนมัติเมื่อ reboot:

- ✅ `dlnk-platform.service` - Main Platform
- ✅ `dlnk-terminal.service` - Web Terminal
- ✅ `postgresql@14-main.service` - Database
- ✅ `redis-server.service` - Cache

**ตรวจสอบ Auto-Start:**
```bash
sudo systemctl list-unit-files --type=service --state=enabled | grep -E "(dlnk|postgresql|redis)"
```

## การจัดการระบบ

### Start/Stop/Restart

```bash
# Platform Service
sudo systemctl start dlnk-platform
sudo systemctl stop dlnk-platform
sudo systemctl restart dlnk-platform
sudo systemctl status dlnk-platform

# Web Terminal Service
sudo systemctl start dlnk-terminal
sudo systemctl stop dlnk-terminal
sudo systemctl restart dlnk-terminal
sudo systemctl status dlnk-terminal

# ดูสถานะทั้งหมด
sudo systemctl list-units --type=service --state=running | grep -E "(dlnk|postgresql|redis)"
```

### ดู Logs

```bash
# Platform logs
tail -f /var/log/dlnk/platform.log
tail -f /var/log/dlnk/platform-error.log

# Systemd logs
journalctl -u dlnk-platform -f

# Temporary logs
tail -f /tmp/dlnk.log
```

### Database Management

```bash
# เข้า PostgreSQL
sudo -u postgres psql -d dlnk

# Backup database
sudo -u postgres pg_dump dlnk > backup.sql

# Restore database
sudo -u postgres psql -d dlnk < backup.sql

# ดูตาราง
sudo -u postgres psql -d dlnk -c "\dt"

# ดู users
sudo -u postgres psql -d dlnk -c "SELECT * FROM users;"
```

### Redis Management

```bash
# เข้า Redis CLI
redis-cli

# ดู keys ทั้งหมด
redis-cli KEYS '*'

# ล้าง cache
redis-cli FLUSHALL

# ดูข้อมูล
redis-cli GET key_name
```

## หมายเหตุสำคัญ

1. **API Key เป็นความลับ** - ห้ามแชร์ให้ใคร
2. **Web Terminal มี Full Access** - ใช้ด้วยความระมัดระวัง
3. **ระบบรันถาวร** - จะ restart อัตโนมัติหากเกิด error
4. **Backup ข้อมูลเป็นประจำ** - ใช้คำสั่ง pg_dump
5. **เข้าได้จากทุกที่** - แต่ต้องมี Internet

## GitHub Repository

**Repository:** https://github.com/manus-aiattack/aiprojectattack

**Clone:**
```bash
git clone https://github.com/manus-aiattack/aiprojectattack.git
```

## ติดต่อ

หากมีปัญหาหรือต้องการความช่วยเหลือ:
- ดู logs ที่ `/var/log/dlnk/`
- ตรวจสอบ GitHub Issues
- ใช้ Web Terminal เพื่อ debug

