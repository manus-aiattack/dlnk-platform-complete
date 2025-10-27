# Codespace Setup Guide

## คำสั่งสำหรับรันใน Codespace

### 1. Deployment แบบอัตโนมัติ (แนะนำ)

```bash
# รัน deployment script
./deploy_production.sh
```

Script นี้จะ:
- ✅ ตรวจสอบ system requirements
- ✅ ติดตั้ง Python dependencies
- ✅ สร้าง .env file
- ✅ สร้าง workspace directories
- ✅ Initialize database
- ✅ ติดตั้ง CLI wrapper
- ✅ Build frontend (ถ้ามี Node.js)
- ✅ แสดงสรุปและคำสั่งที่ใช้งาน

### 2. เริ่ม API Server

```bash
# วิธีที่ 1: ใช้ start script
./start_server.sh

# วิธีที่ 2: ใช้ CLI wrapper
./dlnk server

# วิธีที่ 3: ใช้ Python โดยตรง
python3 main.py server
```

API จะรันที่:
- **URL**: http://localhost:8000
- **Docs**: http://localhost:8000/docs
- **Health**: http://localhost:8000/health

### 3. Build Frontend

```bash
cd frontend

# ติดตั้ง dependencies
npm install

# Build production
npm run build

# Preview production build
npm run preview

# หรือ serve ด้วย Python
cd dist
python3 -m http.server 3000
```

Frontend จะรันที่:
- **URL**: http://localhost:3000

### 4. ทดสอบระบบ

```bash
# ทดสอบ API endpoints
python3 test_api_fixed.py

# ทดสอบ CLI
./dlnk --help
./dlnk agents

# ทดสอบ agent เดี่ยว
./dlnk agent sqlmap_agent scan --url https://testphp.vulnweb.com
```

### 5. ตั้งค่า Environment Variables

แก้ไขไฟล์ `.env`:

```bash
# แก้ไข .env
nano .env

# หรือใช้ VS Code
code .env
```

**ค่าสำคัญที่ต้องแก้:**

```bash
# Database (ใช้ SQLite สำหรับ Codespace)
DATABASE_URL=sqlite:///workspace/dlnk.db

# API
API_HOST=0.0.0.0
API_PORT=8000

# Security
SIMULATION_MODE=False
SECRET_KEY=your_secret_key_here

# Ollama (ถ้ามี)
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=mixtral:latest
```

### 6. Docker Deployment (ถ้าต้องการ)

```bash
# Build และ start services
docker compose -f docker-compose.complete.yml up -d

# ดู logs
docker compose -f docker-compose.complete.yml logs -f

# หยุด services
docker compose -f docker-compose.complete.yml down
```

## คำสั่งที่มีประโยชน์

### Git Commands

```bash
# Pull latest changes
git pull

# Check status
git status

# Commit changes
git add .
git commit -m "Your message"
git push
```

### Python Commands

```bash
# ติดตั้ง dependencies
pip3 install -r requirements.txt

# ติดตั้ง dependencies แบบเต็ม
pip3 install -r requirements-full.txt

# ตรวจสอบ Python version
python3 --version

# รัน Python script
python3 script.py
```

### System Commands

```bash
# ดู running processes
ps aux | grep python

# ดู port ที่ใช้
netstat -tuln | grep LISTEN

# ดู disk usage
df -h

# ดู memory usage
free -h

# Kill process
kill -9 <PID>
```

### Debugging

```bash
# ดู logs
tail -f logs/api.log

# ดู error logs
tail -f logs/error.log

# ตรวจสอบ database
sqlite3 workspace/dlnk.db
# ใน sqlite shell:
# .tables
# SELECT * FROM users;
# .quit
```

## Troubleshooting

### ปัญหา: Port already in use

```bash
# หา process ที่ใช้ port 8000
lsof -i :8000

# Kill process
kill -9 <PID>
```

### ปัญหา: Permission denied

```bash
# แก้ไข permissions
chmod +x deploy_production.sh
chmod +x start_server.sh
chmod +x dlnk
```

### ปัญหา: Module not found

```bash
# ตั้ง PYTHONPATH
export PYTHONPATH="$(pwd):$PYTHONPATH"

# หรือติดตั้ง dependencies ใหม่
pip3 install -r requirements.txt
```

### ปัญหา: Database error

```bash
# ลบ database เก่าและสร้างใหม่
rm workspace/dlnk.db
python3 startup.py
```

### ปัญหา: Frontend build failed

```bash
# ลบ node_modules และติดตั้งใหม่
cd frontend
rm -rf node_modules package-lock.json
npm install
npm run build
```

## Port Forwarding ใน Codespace

Codespace จะ forward ports อัตโนมัติ แต่คุณสามารถตรวจสอบได้ที่:

1. ไปที่ **PORTS** tab ใน VS Code
2. คลิก **Forward a Port**
3. ใส่ port number (8000 สำหรับ API, 3000 สำหรับ Frontend)
4. คลิก **Globe icon** เพื่อเปิดใน browser

## Environment Variables ใน Codespace

```bash
# ดู environment variables
env | grep -i dlnk

# ตั้ง environment variable
export VARIABLE_NAME=value

# ตั้งแบบถาวร (เพิ่มใน ~/.bashrc)
echo 'export VARIABLE_NAME=value' >> ~/.bashrc
source ~/.bashrc
```

## Production Deployment Checklist

- [ ] รัน `./deploy_production.sh`
- [ ] แก้ไข `.env` file
- [ ] เปลี่ยน default passwords
- [ ] เปลี่ยน SECRET_KEY
- [ ] ตั้งค่า PostgreSQL (ถ้าใช้)
- [ ] Build frontend
- [ ] ทดสอบ API endpoints
- [ ] ทดสอบ Frontend
- [ ] ตั้งค่า SSL/TLS (สำหรับ production จริง)
- [ ] ตั้งค่า Nginx reverse proxy (ถ้าต้องการ)
- [ ] Setup monitoring และ logging
- [ ] Backup database

## Quick Reference

| คำสั่ง | คำอธิบาย |
|:-------|:---------|
| `./deploy_production.sh` | Deploy ระบบทั้งหมด |
| `./start_server.sh` | เริ่ม API server |
| `./dlnk --help` | ดูคำสั่ง CLI ทั้งหมด |
| `./dlnk server` | เริ่ม API server |
| `./dlnk agents` | ดู agents ทั้งหมด |
| `python3 main.py server` | เริ่ม API server (แบบ direct) |
| `cd frontend && npm run build` | Build frontend |
| `python3 test_api_fixed.py` | ทดสอบ API |

## สรุป

**สำหรับการเริ่มต้นใช้งานครั้งแรก:**

```bash
# 1. Deploy ระบบ
./deploy_production.sh

# 2. เริ่ม API server
./start_server.sh

# 3. (Terminal ใหม่) Build และ start frontend
cd frontend && npm install && npm run build && npm run preview
```

**สำหรับการใช้งานปกติ:**

```bash
# เริ่ม API server
./start_server.sh

# หรือ
./dlnk server
```

---

**หมายเหตุ**: 
- Codespace มี resource จำกัด ไม่แนะนำให้รัน heavy tasks เช่น Ollama
- ใช้ SQLite สำหรับ development ใน Codespace
- สำหรับ production จริง ให้ deploy บน server ที่มี resources เพียงพอ

