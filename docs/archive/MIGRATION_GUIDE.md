# คู่มือการอัพเกรดระบบ Configuration (Migration Guide)

## ภาพรวม

เอกสารนี้อธิบายขั้นตอนการอัพเกรดระบบ dLNk Attack Platform จากการใช้ Hardcoded Values มาเป็นการใช้ Environment Variables แบบ Centralized

## ไฟล์ที่ถูกปรับปรุง

### 1. ไฟล์ใหม่ที่ถูกสร้างขึ้น

| ไฟล์ | คำอธิบาย |
|------|----------|
| `config/env_loader.py` | ระบบโหลดและตรวจสอบ Environment Variables |
| `llm_config_new.py` | LLM Configuration ที่ใช้ Environment Variables |
| `config/settings_new.py` | System Settings ที่ใช้ Environment Variables |
| `scripts/validate_config.py` | Script ตรวจสอบความถูกต้องของ Configuration |
| `test_db_fixed.py` | Database Connection Test ที่ใช้ Environment Variables |
| `.env.example.new` | Template ไฟล์ .env ที่ปรับปรุงแล้ว |

### 2. ไฟล์เดิมที่ควรแทนที่

| ไฟล์เดิม | แทนที่ด้วย | สถานะ |
|---------|-----------|--------|
| `llm_config.py` | `llm_config_new.py` | ✅ พร้อมใช้งาน |
| `config/settings.py` | `config/settings_new.py` | ✅ พร้อมใช้งาน |
| `.env.example` | `.env.example.new` | ✅ พร้อมใช้งาน |
| `test_db.py`, `test_db2.py`, `test_db3.py`, `test_db4.py` | `test_db_fixed.py` | ✅ พร้อมใช้งาน |

## ขั้นตอนการอัพเกรด

### Step 1: Backup ไฟล์เดิม

```bash
cd /path/to/manus

# สร้างไดเรกทอรี backup
mkdir -p backup/$(date +%Y%m%d)

# Backup ไฟล์สำคัญ
cp llm_config.py backup/$(date +%Y%m%d)/
cp config/settings.py backup/$(date +%Y%m%d)/
cp .env.example backup/$(date +%Y%m%d)/
cp .env backup/$(date +%Y%m%d)/ 2>/dev/null || true
```

### Step 2: แทนที่ไฟล์เดิมด้วยไฟล์ใหม่

```bash
# แทนที่ไฟล์ configuration
mv llm_config_new.py llm_config.py
mv config/settings_new.py config/settings.py
mv .env.example.new .env.example

# ลบไฟล์ test เดิมที่มี hardcoded values
rm -f test_db.py test_db2.py test_db3.py test_db4.py

# เปลี่ยนชื่อไฟล์ test ใหม่
mv test_db_fixed.py test_db.py
```

### Step 3: อัพเดทไฟล์ .env

```bash
# หากยังไม่มีไฟล์ .env ให้สร้างจาก .env.example
cp .env.example .env

# แก้ไขไฟล์ .env ด้วย text editor
nano .env  # หรือ vim, code, etc.
```

**สิ่งที่ต้องแก้ไขใน .env:**

1. **SECRET_KEY** - สร้าง Random Key ใหม่:
   ```bash
   openssl rand -hex 32
   ```

2. **DB_PASSWORD** - ตั้งรหัสผ่านฐานข้อมูล

3. **WEBSHELL_PASSWORD** - เปลี่ยนจากค่า Default

4. **SIMULATION_MODE** - ตั้งเป็น `True` สำหรับการทดสอบ

5. **C2_HOST** และ **C2_PORT** - ปรับตามสภาพแวดล้อมจริง (ถ้าไม่ใช่ localhost)

### Step 4: ติดตั้ง Dependencies ที่จำเป็น

```bash
# ติดตั้ง python-dotenv และ rich
pip3 install python-dotenv rich
```

### Step 5: ตรวจสอบ Configuration

```bash
# รัน validation script
python3 scripts/validate_config.py
```

หาก Script แสดงข้อผิดพลาด ให้แก้ไขตามคำแนะนำที่แสดง

### Step 6: ทดสอบการเชื่อมต่อฐานข้อมูล

```bash
# ทดสอบการเชื่อมต่อ Database
python3 test_db.py
```

### Step 7: ทดสอบ LLM Configuration

```bash
# ทดสอบ LLM Configuration
python3 llm_config.py
```

### Step 8: อัพเดท Agent Files (Optional แต่แนะนำ)

ไฟล์ Agent ที่มี Hardcoded Values ควรได้รับการอัพเดทเพื่อใช้ Configuration จาก `config/settings.py`:

**ตัวอย่าง: agents/advanced_backdoor_agent.py**

```python
# เพิ่ม import
from config.settings import WEBSHELL_DEFAULT_PASSWORD

# แทนที่ hardcoded password
return {
    "type": "web_shell",
    "path": shell_path,
    "access_url": access_url,
    "password": WEBSHELL_DEFAULT_PASSWORD,  # แทนที่ "dlnk"
    "deployed_at": datetime.now().isoformat()
}
```

**ตัวอย่าง: agents/xss_agent.py, agents/command_injection_exploiter.py**

```python
# เพิ่ม import
from config.settings import C2_DOMAIN, C2_PROTOCOL

# แทนที่ hardcoded C2 domain
self.listener_url = f"{C2_PROTOCOL}://{C2_DOMAIN}/collect"
```

### Step 9: ทดสอบระบบทั้งหมด

```bash
# รันระบบในโหมด Simulation
SIMULATION_MODE=True python3 startup.py

# หรือใช้ test script
python3 test_system.py
```

## การแก้ไขปัญหาที่อาจพบ

### ปัญหา: ImportError: No module named 'dotenv'

**วิธีแก้:**
```bash
pip3 install python-dotenv
```

### ปัญหา: ImportError: No module named 'rich'

**วิธีแก้:**
```bash
pip3 install rich
```

### ปัญหา: ConfigError: SECRET_KEY must be changed from default value

**วิธีแก้:**
```bash
# สร้าง random secret key
openssl rand -hex 32

# แล้วนำไปใส่ในไฟล์ .env
SECRET_KEY=<generated-key-here>
```

### ปัญหา: Database connection failed

**วิธีแก้:**
1. ตรวจสอบว่า PostgreSQL กำลังทำงาน:
   ```bash
   sudo systemctl status postgresql
   ```

2. ตรวจสอบ credentials ในไฟล์ .env

3. สร้าง database หากยังไม่มี:
   ```bash
   createdb dlnk_db
   ```

### ปัญหา: Ollama connection failed

**วิธีแก้:**
1. ตรวจสอบว่า Ollama กำลังทำงาน:
   ```bash
   ollama list
   ```

2. ตรวจสอบ OLLAMA_HOST และ OLLAMA_PORT ในไฟล์ .env

3. ดาวน์โหลด model หากยังไม่มี:
   ```bash
   ollama pull mixtral:latest
   ```

## Rollback (กรณีเกิดปัญหา)

หากเกิดปัญหาและต้องการย้อนกลับไปใช้ไฟล์เดิม:

```bash
cd /path/to/manus

# คืนค่าไฟล์จาก backup
cp backup/$(date +%Y%m%d)/llm_config.py .
cp backup/$(date +%Y%m%d)/settings.py config/
cp backup/$(date +%Y%m%d)/.env.example .
cp backup/$(date +%Y%m%d)/.env . 2>/dev/null || true
```

## Checklist หลังการอัพเกรด

- [ ] ไฟล์ .env ถูกสร้างและแก้ไขแล้ว
- [ ] SECRET_KEY ถูกเปลี่ยนจากค่า Default
- [ ] DB_PASSWORD ถูกตั้งค่าแล้ว
- [ ] WEBSHELL_PASSWORD ถูกเปลี่ยนจากค่า Default
- [ ] `python3 scripts/validate_config.py` ทำงานสำเร็จ
- [ ] `python3 test_db.py` เชื่อมต่อฐานข้อมูลได้
- [ ] `python3 llm_config.py` แสดง Configuration ถูกต้อง
- [ ] ระบบสามารถเริ่มต้นทำงานได้ปกติ
- [ ] Agent ทั้งหมดทำงานได้ตามปกติ

## สรุป

การอัพเกรดนี้จะช่วยให้ระบบมีความปลอดภัยและยืดหยุ่นมากขึ้น โดยแยก Configuration ออกจาก Source Code ทำให้สามารถปรับเปลี่ยนการตั้งค่าได้ง่ายและปลอดภัยกว่าเดิม

หากพบปัญหาหรือมีคำถาม กรุณาดูเอกสาร `CONFIGURATION_GUIDE.md` เพิ่มเติม

