# Docker Configuration Analysis Report

## วันที่: 24 ตุลาคม 2025

## 1. ปัญหาที่พบ (Identified Issues)

### 1.1 Repository Links ที่ล้าสมัย
- **ปัญหา**: ไฟล์ README.md, DEPLOYMENT_GUIDE.md และ WSL_INSTALLATION_GUIDE.md ยังคงอ้างอิงถึง repository เก่า
- **Repository เก่า**: `https://github.com/vtvx4myqq9-stack/Manus.git`
- **Repository ใหม่**: `https://github.com/donlasahachat1-sys/manus`
- **ไฟล์ที่ต้องแก้ไข**:
  - `/home/ubuntu/manus/README.md` (3 ตำแหน่ง)
  - `/home/ubuntu/manus/DEPLOYMENT_GUIDE.md` (2 ตำแหน่ง)
  - `/home/ubuntu/manus/WSL_INSTALLATION_GUIDE.md` (1 ตำแหน่ง)

### 1.2 Docker Configuration Issues

#### 1.2.1 Dockerfile
- **ปัญหา**: ไม่มีปัญหาร้ายแรง แต่มีจุดที่ควรปรับปรุง
- **จุดที่ควรแก้ไข**:
  - Health check ใช้ `requests` library ซึ่งอาจไม่ได้ติดตั้งในบาง context
  - ควรใช้ `curl` หรือ `wget` แทนเพื่อความเสถียร

#### 1.2.2 docker-compose.yml
- **ปัญหาหลัก**:
  1. **Database Name Inconsistency**: ใช้ชื่อ `dlnk_dlnk` ซึ่งดูซ้ำซ้อน
  2. **Missing Environment Variables**: ไม่มี `.env` file reference
  3. **Port Conflicts**: Metasploit service ใช้ port 5432 ซึ่งซ้ำกับ PostgreSQL
  4. **Command Path Issue**: `api/main.py` อาจไม่ถูกต้องในบาง context

#### 1.2.3 Dependencies Issues
- **requirements.txt**: มี dependencies น้อยเกินไป (เหมาะสำหรับ CLI เท่านั้น)
- **requirements-full.txt**: ครบถ้วนสำหรับ API server
- **Dockerfile ใช้ requirements.txt**: ซึ่งจะทำให้ API ไม่สามารถทำงานได้

### 1.3 API Structure Issues
- **ปัญหา**: มีไฟล์ API หลายเวอร์ชัน
  - `api/main.py` (ใช้ใน docker-compose.yml)
  - `api/main_api.py`
  - Routes มีทั้ง v1 และ v2
- **ผลกระทบ**: อาจทำให้เกิดความสับสนในการ deploy

### 1.4 WSL/Ubuntu Compatibility
- **ปัญหาที่อาจเกิดขึ้น**:
  - Line endings (CRLF vs LF) ในไฟล์ shell scripts
  - Permission issues กับ Docker volumes
  - Network configuration ใน WSL2

## 2. Root Cause Analysis

### 2.1 ทำไม Docker ถึงไม่ทำงาน?

**สาเหตุหลัก**:

1. **Missing Dependencies**: Dockerfile ใช้ `requirements.txt` ที่มี dependencies ไม่ครบ
   - FastAPI, uvicorn, asyncpg, psycopg2 ไม่ได้ติดตั้ง
   - API จะไม่สามารถ start ได้

2. **Database Connection Issues**: 
   - DATABASE_URL ใน docker-compose.yml อาจไม่ตรงกับที่ API ต้องการ
   - ไม่มี database initialization script

3. **Volume Permissions**:
   - WSL2 อาจมีปัญหาเรื่อง file permissions กับ Docker volumes
   - Workspace directories อาจไม่มี permission ที่ถูกต้อง

4. **Environment Variables**:
   - ไม่มี `.env` file ใน docker-compose
   - Environment variables จำนวนมากถูก hardcode

## 3. แนวทางแก้ไข (Solution Plan)

### 3.1 อัพเดท Repository Links
- แทนที่ URL ทั้งหมดจาก `vtvx4myqq9-stack/Manus` เป็น `donlasahachat1-sys/manus`
- อัพเดทเส้นทาง directory จาก `Manus/dlnk_dlnk_FINAL` เป็น `manus`

### 3.2 แก้ไข Dockerfile
```dockerfile
# เปลี่ยนจาก requirements.txt เป็น requirements-full.txt
COPY requirements-full.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# แก้ไข health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f localhost:8000/health || exit 1
```

### 3.3 แก้ไข docker-compose.yml
- เพิ่ม `.env` file support
- แก้ไข database name จาก `dlnk_dlnk` เป็น `manus_db`
- แก้ไข port conflict ของ Metasploit
- เพิ่ม volume permissions

### 3.4 สร้าง .env file
- Copy จาก `.env.example`
- ปรับค่าให้เหมาะสมกับ Docker environment

### 3.5 เพิ่ม Database Initialization
- สร้าง init script สำหรับ PostgreSQL
- เพิ่ม migration scripts

## 4. คำแนะนำสำหรับการ Deploy บน Ubuntu WSL

### 4.1 ก่อนรัน Docker
```bash
# ตรวจสอบ Docker service
sudo service docker status
sudo service docker start

# ตรวจสอบ permissions
sudo usermod -aG docker $USER
newgrp docker

# ทดสอบ Docker
docker run hello-world
```

### 4.2 การรัน Docker Compose
```bash
# สร้าง .env file
cp .env.example .env
nano .env  # แก้ไขค่าตามต้องการ

# Build และ start services
docker-compose build --no-cache
docker-compose up -d

# ตรวจสอบ logs
docker-compose logs -f

# ตรวจสอบ containers
docker-compose ps
```

### 4.3 Troubleshooting
```bash
# ถ้า container ไม่ start
docker-compose logs api
docker-compose logs db

# ถ้ามีปัญหา permission
chmod -R 755 workspace logs data reports config

# ถ้ามีปัญหา network
docker network ls
docker network inspect manus_dlnk-network

# รีสตาร์ท services
docker-compose restart
docker-compose down && docker-compose up -d
```

## 5. สรุป

ปัญหาหลักของ Docker configuration คือ:
1. ใช้ dependencies ไม่ครบ (requirements.txt แทน requirements-full.txt)
2. Repository links ล้าสมัย
3. ไม่มี proper environment configuration
4. Database configuration ไม่สมบูรณ์

การแก้ไขจะต้องทำทั้งหมดพร้อมกันเพื่อให้ระบบทำงานได้อย่างสมบูรณ์

