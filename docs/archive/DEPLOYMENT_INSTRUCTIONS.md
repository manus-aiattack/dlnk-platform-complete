# คำสั่งรันระบบ dLNk Attack Platform

## ✅ ระบบพร้อมใช้งาน Production

---

## 📋 ข้อกำหนดระบบ

- **OS:** Ubuntu 22.04+ (หรือ Debian-based)
- **Python:** 3.11
- **Database:** PostgreSQL 13+ (optional)
- **Redis:** 5.0+ (optional)
- **RAM:** 4GB ขึ้นไป
- **Disk:** 10GB ขึ้นไป

---

## 🚀 วิธีติดตั้งและรัน (Ubuntu 24.04)

### ⚡ วิธีที่ 1: Quick Install (แนะนำ - ง่ายที่สุด)

```bash
# 1. Clone repository
git clone https://github.com/donlasahachat1-sys/manus.git
cd manus

# 2. รันสคริปต์ติดตั้ง (จัดการ venv อัตโนมัติ)
chmod +x QUICK_INSTALL.sh
./QUICK_INSTALL.sh

# 3. Activate virtual environment
source venv/bin/activate

# 4. สร้าง .env
cp env.template .env

# 5. รัน server
python startup.py

# 6. เข้าใช้งาน
# API: http://localhost:8000
# Docs: http://localhost:8000/docs
```

---

### 🐳 วิธีที่ 2: Docker (ไม่ต้องจัดการ dependencies)

```bash
# 1. Clone repository
git clone https://github.com/donlasahachat1-sys/manus.git
cd manus

# 2. สร้าง .env
cp env.template .env

# 3. Build Docker image
docker build -t dlnk-platform .

# 4. รัน container
docker run -d \
  --name dlnk \
  -p 8000:8000 \
  -v $(pwd)/workspace:/app/workspace \
  -v $(pwd)/loot:/app/loot \
  --env-file .env \
  dlnk-platform

# 5. ตรวจสอบ logs
docker logs -f dlnk

# 6. เข้าใช้งาน
# API: http://localhost:8000
# Docs: http://localhost:8000/docs
```

---

### 🔧 วิธีที่ 3: Manual Install (สำหรับ Advanced Users)

```bash
# 1. Clone repository
git clone https://github.com/donlasahachat1-sys/manus.git
cd manus

# 2. ติดตั้ง Python 3.11 (ถ้ายังไม่มี)
sudo apt update
sudo apt install -y python3.11 python3.11-venv python3.11-dev

# 3. สร้าง virtual environment
python3.11 -m venv venv

# 4. Activate virtual environment
source venv/bin/activate

# 5. Upgrade pip
pip install --upgrade pip setuptools wheel

# 6. ติดตั้ง dependencies
pip install -r requirements-production.txt

# 7. สร้าง .env
cp env.template .env

# 8. รัน server
python startup.py

# หรือรันด้วย uvicorn
uvicorn api.main_api:app --host 0.0.0.0 --port 8000 --reload
```

---

### 💻 วิธีที่ 4: CLI Mode

```bash
# 1. ติดตั้งตามวิธีที่ 1 หรือ 3 ก่อน

# 2. Activate venv (ถ้ายังไม่ได้ activate)
source venv/bin/activate

# 3. ติดตั้ง CLI
chmod +x install_cli.sh
./install_cli.sh

# 4. ใช้งาน
dlnk --help
dlnk attack http://target-url.com
dlnk console
```

---

## 🔧 Configuration

### ไฟล์ .env ที่สำคัญ

```bash
# ============================================================================
# C2 Configuration (สำคัญ!)
# ============================================================================

# สำหรับรันบน localhost (เครื่องตัวเอง)
C2_DOMAIN=localhost:8000
C2_PROTOCOL=http

# สำหรับรันบน server จริง (มี public IP)
# C2_DOMAIN=your-public-ip:8000
# C2_PROTOCOL=http

# ถ้ามี domain name และ SSL
# C2_DOMAIN=your-domain.com
# C2_PROTOCOL=https

# ============================================================================
# Database (Optional - ถ้าไม่มีจะใช้ in-memory)
# ============================================================================
DATABASE_URL=postgresql://user:pass@localhost:5432/dlnk

# ============================================================================
# Redis (Optional - ถ้าไม่มีจะใช้ in-memory)
# ============================================================================
REDIS_URL=redis://localhost:6379/0

# ============================================================================
# AI/LLM (Optional - ถ้าต้องการ AI Planning)
# ============================================================================
MIXTRAL_API_KEY=your-api-key
OPENAI_API_KEY=your-api-key

# ============================================================================
# SMTP (Optional - สำหรับ email exfiltration)
# ============================================================================
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password
SMTP_FROM=your-email@gmail.com
SMTP_TO=your-email@gmail.com
```

---

## 📊 ตรวจสอบสถานะระบบ

### ตรวจสอบว่าระบบรันได้

```bash
# ตรวจสอบ API health
curl http://localhost:8000/health

# ตรวจสอบ version
curl http://localhost:8000/version

# ตรวจสอบ agents
curl http://localhost:8000/api/agents
```

### ตรวจสอบ logs

```bash
# ถ้ารันด้วย Docker
docker logs -f dlnk

# ถ้ารันแบบ manual
tail -f logs/dlnk.log
```

---

## 🎯 การใช้งานพื้นฐาน

### 1. ผ่าน Web UI
```
เปิดเบราว์เซอร์: http://localhost:8000
```

### 2. ผ่าน API
```bash
# สร้าง attack task
curl -X POST http://localhost:8000/api/v2/attack \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "http://target.com",
    "mode": "auto"
  }'
```

### 3. ผ่าน CLI
```bash
# Activate venv ก่อน
source venv/bin/activate

# Auto attack
dlnk attack http://target.com

# Stealth mode
dlnk attack http://target.com --mode stealth

# Follow progress
dlnk attack http://target.com --follow
```

---

## 🐛 Troubleshooting

### ปัญหา: externally-managed-environment

**สาเหตุ:** Ubuntu 24.04 ไม่อนุญาตให้ติดตั้ง pip packages ตรงๆ

**วิธีแก้:**
```bash
# ใช้ virtual environment
python3.11 -m venv venv
source venv/bin/activate
pip install -r requirements-production.txt
```

**หรือใช้ QUICK_INSTALL.sh:**
```bash
./QUICK_INSTALL.sh
```

---

### ปัญหา: Python 3.11 not found

```bash
# ติดตั้ง Python 3.11
sudo apt update
sudo apt install -y python3.11 python3.11-venv python3.11-dev
```

---

### ปัญหา: Import errors

```bash
# ตรวจสอบว่า activate venv แล้ว
source venv/bin/activate

# ติดตั้ง dependencies ใหม่
pip install -r requirements-production.txt
```

---

### ปัญหา: Database connection

```bash
# ตรวจสอบ PostgreSQL
pg_isready

# หรือใช้ in-memory mode (ไม่ต้องมี database)
# แก้ไข .env: DATABASE_URL=sqlite:///dlnk.db
```

---

### ปัญหา: Port already in use

```bash
# หา process ที่ใช้ port 8000
lsof -i :8000

# Kill process
kill -9 <PID>

# หรือเปลี่ยน port
uvicorn api.main_api:app --host 0.0.0.0 --port 8080
```

---

## 📚 เอกสารเพิ่มเติม

- **API Documentation:** http://localhost:8000/docs
- **README:** [README.md](README.md)
- **Completion Report:** [PROJECT_COMPLETION_REPORT.md](PROJECT_COMPLETION_REPORT.md)

---

## ✅ Verification Checklist

ก่อนใช้งาน ตรวจสอบ:

- [ ] Python 3.11 installed
- [ ] Virtual environment created (`venv/`)
- [ ] Virtual environment activated (`source venv/bin/activate`)
- [ ] Dependencies installed (`pip list`)
- [ ] `.env` file created
- [ ] `C2_DOMAIN` set correctly (localhost:8000 for local)
- [ ] API accessible (http://localhost:8000/health)

---

## 🎉 พร้อมใช้งาน!

### คำสั่งสรุป (Copy-Paste ได้เลย)

```bash
# ติดตั้งและรัน
git clone https://github.com/donlasahachat1-sys/manus.git
cd manus
chmod +x QUICK_INSTALL.sh
./QUICK_INSTALL.sh
source venv/bin/activate
cp env.template .env
python startup.py
```

### เข้าใช้งาน
- **Web UI:** http://localhost:8000
- **API Docs:** http://localhost:8000/docs
- **Health Check:** http://localhost:8000/health

**User แค่กรอก Target URL และระบบทำงานอัตโนมัติ!** 🚀

---

## 💡 Tips

1. **ใช้ Docker** ถ้าไม่อยากจัดการ dependencies
2. **ใช้ QUICK_INSTALL.sh** สำหรับ Ubuntu 24.04
3. **อย่าลืม activate venv** ก่อนรันทุกครั้ง
4. **C2_DOMAIN=localhost:8000** เหมาะกับการรันบนเครื่องตัวเอง
5. **ตรวจสอบ logs** ถ้ามีปัญหา

