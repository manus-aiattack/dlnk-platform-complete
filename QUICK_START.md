# Manus Quick Start Guide

## สำหรับผู้ใช้ที่รันบน WSL (Windows Subsystem for Linux)

### Path ที่คุณใช้งาน
```bash
/mnt/c/projecattack/manus
```

✅ **Path นี้ถูกต้อง!** - เป็น path ใน WSL ที่ mount จาก Windows drive C:

---

## การ Setup และรันโปรเจค

### 1. เข้าสู่ Directory โปรเจค

```bash
cd /mnt/c/projecattack/manus
```

---

### 2. สร้าง Virtual Environment (ครั้งแรกเท่านั้น)

```bash
# วิธีที่ 1: ใช้ setup script (แนะนำ)
./setup_environment.sh

# วิธีที่ 2: Manual setup
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

---

### 3. Activate Virtual Environment

**ทุกครั้งที่เปิด Terminal ใหม่ ต้อง activate ก่อน:**

```bash
source venv/bin/activate
```

เมื่อ activate สำเร็จจะเห็น `(venv)` ข้างหน้า prompt:
```bash
(venv) fuckukuy@dLHk:/mnt/c/projecattack/manus$
```

---

### 4. รัน API Server

```bash
# ตรวจสอบว่า activate venv แล้ว
source venv/bin/activate

# รัน API server
python3 api/main_integrated.py
```

**API จะรันที่:**
- http://localhost:8000
- API Docs: http://localhost:8000/docs
- Health Check: http://localhost:8000/health

---

### 5. รัน Frontend (Terminal ใหม่)

```bash
# เปิด Terminal ใหม่
cd /mnt/c/projecattack/manus/frontend

# Install dependencies (ครั้งแรกเท่านั้น)
npm install

# รัน development server
npm run dev
```

**Frontend จะรันที่:**
- http://localhost:5173

---

## คำสั่งที่ใช้บ่อย

### ตรวจสอบว่าอยู่ใน Virtual Environment หรือไม่

```bash
which python3
# ถ้าอยู่ใน venv จะแสดง: /mnt/c/projecattack/manus/venv/bin/python3
```

### Deactivate Virtual Environment

```bash
deactivate
```

### Update Dependencies

```bash
source venv/bin/activate
pip install --upgrade -r requirements.txt
```

### รัน Tests

```bash
source venv/bin/activate
pytest tests/test_e2e.py -v
```

---

## โครงสร้างโปรเจค

```
/mnt/c/projecattack/manus/
├── venv/                          # Virtual environment (สร้างใหม่)
├── api/                           # API Backend
│   ├── main_integrated.py        # Main API entry point
│   ├── routes/                   # API routes
│   │   ├── scan.py
│   │   ├── exploit.py
│   │   ├── ai.py
│   │   ├── knowledge.py
│   │   └── statistics.py
│   └── websocket_handler.py      # WebSocket handler
├── agents/                        # Core agents
│   ├── nmap_agent.py
│   ├── exploit_agent.py
│   ├── privilege_escalation_agent.py
│   └── ...
├── advanced_agents/               # Advanced agents
│   ├── keylogger.py
│   ├── screenshot.py
│   └── backdoor_installer.py
├── c2_infrastructure/             # C2 components
│   ├── c2_server.py
│   ├── agent_handler.py
│   └── protocols/
├── protocol_exploits/             # Protocol exploits
│   ├── ssh_exploit.py
│   ├── ftp_exploit.py
│   └── ...
├── frontend/                      # React frontend
│   ├── src/
│   │   ├── components/
│   │   │   ├── LogViewer.tsx
│   │   │   ├── Statistics.tsx
│   │   │   ├── KnowledgeBase.tsx
│   │   │   └── ...
│   │   └── services/
│   └── package.json
├── tests/                         # Test suite
│   └── test_e2e.py
├── requirements.txt               # Python dependencies
├── setup_environment.sh           # Setup script
└── QUICK_START.md                # This file
```

---

## การแก้ปัญหา

### ปัญหา: `python3: command not found`

**แก้ไข:**
```bash
# ติดตั้ง Python 3
sudo apt update
sudo apt install python3 python3-pip python3-venv
```

---

### ปัญหา: `pip: command not found`

**แก้ไข:**
```bash
sudo apt install python3-pip
```

---

### ปัญหา: Permission denied เมื่อรัน setup script

**แก้ไข:**
```bash
chmod +x setup_environment.sh
./setup_environment.sh
```

---

### ปัญหา: Port 8000 already in use

**แก้ไข:**
```bash
# หา process ที่ใช้ port 8000
lsof -i :8000

# Kill process
kill -9 <PID>

# หรือเปลี่ยน port ใน main_integrated.py
# แก้บรรทัด: uvicorn.run(app, host="0.0.0.0", port=8001)
```

---

### ปัญหา: Module not found

**แก้ไข:**
```bash
# ตรวจสอบว่า activate venv แล้ว
source venv/bin/activate

# ติดตั้ง dependencies ใหม่
pip install -r requirements.txt

# ถ้ายังไม่ได้ ติดตั้ง module เฉพาะ
pip install <module-name>
```

---

## Environment Variables

สร้างไฟล์ `.env` ใน root directory:

```bash
# API Configuration
API_HOST=0.0.0.0
API_PORT=8000

# Database
DATABASE_URL=postgresql://user:password@localhost/manus

# Security
SECRET_KEY=your-secret-key-here
JWT_SECRET=your-jwt-secret-here

# OpenAI (ถ้าใช้)
OPENAI_API_KEY=your-openai-api-key
```

---

## การใช้งาน API

### ตัวอย่าง: Quick Scan

```bash
curl -X POST "http://localhost:8000/api/scan/quick" \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.1"}'
```

### ตัวอย่าง: Get Statistics

```bash
curl "http://localhost:8000/api/statistics?range=7d"
```

### ตัวอย่าง: WebSocket Connection

```javascript
const ws = new WebSocket('ws://localhost:8000/ws/logs');

ws.onmessage = (event) => {
  const log = JSON.parse(event.data);
  console.log(log);
};
```

---

## Development Workflow

### 1. เริ่มต้นวัน (เปิด Terminal ใหม่)

```bash
cd /mnt/c/projecattack/manus
source venv/bin/activate
```

### 2. พัฒนา Code

```bash
# แก้ไข code ใน agents, api, frontend
# ใช้ editor ที่ชอบ (VSCode, vim, nano)
```

### 3. ทดสอบ

```bash
# รัน tests
pytest tests/ -v

# หรือรัน specific test
pytest tests/test_e2e.py::TestE2EWorkflows::test_full_attack_workflow -v
```

### 4. Commit Changes

```bash
git add .
git commit -m "Your commit message"
git push origin main
```

---

## Production Deployment

### ใช้ Gunicorn (Production WSGI Server)

```bash
# ติดตั้ง Gunicorn
pip install gunicorn

# รัน API with Gunicorn
gunicorn api.main_integrated:app \
  -w 4 \
  -k uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000
```

### ใช้ Docker (แนะนำสำหรับ Production)

```bash
# Build Docker image
docker build -t manus:latest .

# Run container
docker run -d -p 8000:8000 manus:latest
```

---

## ข้อมูลเพิ่มเติม

### Documentation
- **API Docs:** http://localhost:8000/docs
- **PHASE 1-4 Report:** `/mnt/c/projecattack/manus/PHASE_1-4_IMPLEMENTATION_REPORT.md`
- **PHASE 5-7 Report:** `/mnt/c/projecattack/manus/PHASE_5-7_COMPLETION_REPORT.md`
- **README:** `/mnt/c/projecattack/manus/PHASE_5-7_README.md`

### Support
- GitHub Issues: https://github.com/srhhsshdsrdgeseedh-max/manus/issues

---

## สรุป Commands สำหรับ WSL

```bash
# 1. เข้าโปรเจค
cd /mnt/c/projecattack/manus

# 2. Activate venv (ทุกครั้ง!)
source venv/bin/activate

# 3. รัน API
python3 api/main_integrated.py

# 4. รัน Frontend (Terminal ใหม่)
cd frontend && npm run dev

# 5. รัน Tests
pytest tests/test_e2e.py -v
```

---

**✅ Path ของคุณถูกต้องแล้ว!**

`/mnt/c/projecattack/manus` เป็น path ที่ถูกต้องสำหรับ WSL

แค่อย่าลืม **activate virtual environment** ทุกครั้งก่อนรันโปรเจค:

```bash
source venv/bin/activate
```

จากนั้นก็สามารถรัน API และ Frontend ได้เลย! 🚀

