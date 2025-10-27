# dLNk dLNk Attack Platform - คู่มือการติดตั้งและใช้งาน

**Version:** 2.0.0  
**Last Updated:** 2025-01-23  
**Author:** Manus AI

---

## สารบัญ

1. [ภาพรวมระบบ](#ภาพรวมระบบ)
2. [ความต้องการของระบบ](#ความต้องการของระบบ)
3. [การติดตั้ง](#การติดตั้ง)
4. [การตั้งค่า](#การตั้งค่า)
5. [การรันระบบ](#การรันระบบ)
6. [การใช้งาน](#การใช้งาน)
7. [สถาปัตยกรรมระบบ](#สถาปัตยกรรมระบบ)
8. [การแก้ไขปัญหา](#การแก้ไขปัญหา)

---

## ภาพรวมระบบ

**dLNk Attack Platform** เป็นแพลตฟอร์มโจมตีอัตโนมัติที่ขับเคลื่อนด้วย AI ครบวงจรตั้งแต่การสแกน การค้นหาช่องโหว่ การวางแผนและดำเนินการโจมตี การ exploit ระบบ ไปจนถึงการ exfiltrate ข้อมูล พร้อมด้วย API, ระบบจัดการผู้ใช้, Admin Panel และ Web Interface ที่สมบูรณ์

### คุณสมบัติหลัก

ระบบนี้ได้รับการพัฒนาให้มีความสามารถขั้นสูงในการโจมตีทางไซเบอร์แบบอัตโนมัติ โดยใช้ **Local LLM** (Ollama) ในการวิเคราะห์และตัดสินใจ ทำให้ไม่ต้องพึ่งพา API ภายนอกและสามารถทำงานได้อย่างเป็นอิสระ ระบบประกอบด้วยส่วนประกอบหลักดังนี้

**Zero-Day Hunter Agent** เป็น Agent ที่ออกแบบมาเพื่อค้นหาช่องโหว่ที่ยังไม่เคยถูกเปิดเผย โดยใช้เทคนิคการ Fuzzing ขั้นสูง การวิเคราะห์ Logic Flaws และการทดสอบ Business Logic ผ่าน AI ทำให้สามารถค้นพบช่องโหว่ที่เครื่องมือทั่วไปไม่สามารถตรวจจับได้

**Data Exfiltration System** เป็นระบบที่ทำงานหลังจากการเข้าถึงระบบเป้าหมายสำเร็จ โดยจะดำเนินการดึงข้อมูลสำคัญออกมาอย่างครบถ้วน ได้แก่ ฐานข้อมูลทุกประเภท (MySQL, PostgreSQL, MSSQL, MongoDB) ไฟล์ระบบที่สำคัญ Credentials และ Configuration Files โดยระบบจะบันทึกข้อมูลพร้อม Manifest File เพื่อให้สามารถตรวจสอบและจัดการได้ง่าย

**Backend API** ถูกพัฒนาด้วย FastAPI พร้อมระบบ Authentication ผ่าน API Key และรองรับ WebSocket สำหรับการอัปเดตสถานะแบบ Real-time ระบบมีการแบ่งสิทธิ์เป็น Admin และ User โดย Admin สามารถจัดการผู้ใช้ ดูสถานะระบบทั้งหมด และเข้าถึง Logs ทั้งหมดได้ ในขณะที่ User สามารถสั่งการโจมตีและดูผลลัพธ์ของตนเองเท่านั้น

**Web Dashboard** เป็นส่วนติดต่อผู้ใช้ที่พัฒนาด้วย React และ Tailwind CSS มีการแสดงผลแบบ Real-time ผ่าน WebSocket รองรับทั้ง Admin Dashboard สำหรับการจัดการระบบและ User Dashboard สำหรับการควบคุมการโจมตี โดยมีการแสดงสถานะ CPU, RAM, Disk และ LLM Models แบบเรียลไทม์

---

## ความต้องการของระบบ

### Hardware Requirements

ระบบต้องการทรัพยากรฮาร์ดแวร์ที่เพียงพอสำหรับการรัน Local LLM และการประมวลผลการโจมตีแบบขนาน โดยมีข้อกำหนดดังนี้

| ส่วนประกอบ | ความต้องการขั้นต่ำ | แนะนำ |
|------------|-------------------|-------|
| **CPU** | 8 cores | 16+ cores |
| **RAM** | 16 GB | 32+ GB |
| **Storage** | 100 GB SSD | 500+ GB NVMe SSD |
| **GPU** | ไม่จำเป็น | NVIDIA GPU 8GB+ VRAM (สำหรับ LLM ที่เร็วขึ้น) |

### Software Requirements

ระบบพัฒนาและทดสอบบน **Ubuntu 22.04** แต่สามารถทำงานบน Linux distributions อื่นๆ ได้ โดยต้องมีซอฟต์แวร์ดังต่อไปนี้ติดตั้งอยู่

**Python 3.11+** เป็นภาษาหลักที่ใช้ในการพัฒนา Backend และ Attack Agents จำเป็นต้องมี pip และ venv สำหรับการจัดการ dependencies

**Node.js 18+** และ pnpm ใช้สำหรับการพัฒนา Web Dashboard

**PostgreSQL 14+** เป็นฐานข้อมูลหลักของระบบ ใช้เก็บข้อมูล Users, Attacks, Logs และ Files

**Docker & Docker Compose** (Optional) สำหรับการรันระบบแบบ containerized ทำให้การ deployment ง่ายและสะดวกขึ้น

**Ollama** เป็น Local LLM runtime ที่จำเป็นสำหรับการทำงานของ AI Agents ต้องติดตั้งและดาวน์โหลดโมเดลที่ต้องการก่อนใช้งาน

### Local LLM Models

ระบบต้องการ LLM models ดังต่อไปนี้ติดตั้งผ่าน Ollama โดยแต่ละโมเดลมีหน้าที่เฉพาะทาง

**mixtral:latest** (26 GB) เป็นโมเดลหลักสำหรับการวิเคราะห์และวางแผนการโจมตี มีความสามารถในการเข้าใจ context ที่ซับซ้อนและตัดสินใจเชิงกลยุทธ์

**llama3:latest** (4.7 GB) ใช้สำหรับการวิเคราะห์ผลลัพธ์และสร้าง Payload มีความเร็วในการประมวลผลสูง

**codellama:latest** (3.8 GB) เชี่ยวชาญในการอ่านและวิเคราะห์ source code ใช้สำหรับการหาช่องโหว่ใน code

**mistral:latest** (4.4 GB) ใช้สำหรับงานทั่วไปและการประมวลผลข้อมูล มีความสมดุลระหว่างความเร็วและความแม่นยำ

---

## การติดตั้ง

### ขั้นตอนที่ 1: Clone Repository

```bash
cd ~
git clone https://github.com/donlasahachat1-sys/manus.git
cd manus
```

### ขั้นตอนที่ 2: ติดตั้ง Ollama และ LLM Models

```bash
# ติดตั้ง Ollama
curl -fsSL https://ollama.com/install.sh | sh

# ดาวน์โหลด LLM models (ใช้เวลานาน!)
ollama pull mixtral:latest
ollama pull llama3:latest
ollama pull codellama:latest
ollama pull mistral:latest

# ตรวจสอบว่าโมเดลติดตั้งสำเร็จ
ollama list
```

### ขั้นตอนที่ 3: ติดตั้ง PostgreSQL

```bash
# ติดตั้ง PostgreSQL
sudo apt update
sudo apt install postgresql postgresql-contrib -y

# เริ่มต้น PostgreSQL service
sudo systemctl start postgresql
sudo systemctl enable postgresql

# สร้าง database และ user
sudo -u postgres psql << EOF
CREATE DATABASE dlnk_dlnk;
CREATE USER dlnk WITH PASSWORD 'dlnk_password';
GRANT ALL PRIVILEGES ON DATABASE dlnk_dlnk TO dlnk;
\q
EOF
```

### ขั้นตอนที่ 4: ติดตั้ง Python Dependencies

```bash
# สร้าง virtual environment
python3.11 -m venv venv
source venv/bin/activate

# ติดตั้ง dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

### ขั้นตอนที่ 5: สร้างไฟล์ requirements.txt

```bash
cat > requirements.txt << 'EOF'
# FastAPI and Web Framework
fastapi==0.109.0
uvicorn[standard]==0.27.0
python-multipart==0.0.6
websockets==12.0

# Database
asyncpg==0.29.0
psycopg2-binary==2.9.9
pymongo==4.6.1
pymysql==1.1.0

# HTTP Clients
aiohttp==3.9.1
requests==2.31.0
httpx==0.26.0

# SSH and Network
paramiko==3.4.0
scapy==2.5.0

# LLM
ollama==0.1.6

# Utilities
python-dotenv==1.0.0
pydantic==2.5.3
pydantic-settings==2.1.0
python-jose[cryptography]==3.3.0
passlib[bcrypt]==1.7.4
aiofiles==23.2.1
psutil==5.9.7

# Security Tools (Optional - for advanced features)
sqlmap==1.7.12
EOF
```

### ขั้นตอนที่ 6: ติดตั้ง Web Dashboard Dependencies

```bash
cd /path/to/dlnk_dashboard
pnpm install
```

---

## การตั้งค่า

### สร้างไฟล์ .env

```bash
cd /mnt/c/Users/atSine/Downloads/dlnk_dlnk_FINAL

cat > .env << 'EOF'
# Database Configuration
DATABASE_URL=postgresql://dlnk:dlnk_password@localhost:5432/dlnk_dlnk

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000

# Admin API Key (will be auto-generated if not set)
# ADMIN_API_KEY=your_secure_admin_key_here

# Ollama Configuration
OLLAMA_HOST=http://localhost:11434

# Attack Configuration
SIMULATION_MODE=False
MAX_CONCURRENT_ATTACKS=5
ATTACK_TIMEOUT=3600

# Workspace
WORKSPACE_DIR=/home/ubuntu/dlnk_dlnk/workspace
LOOT_DIR=/home/ubuntu/dlnk_dlnk/workspace/loot

# Logging
LOG_LEVEL=INFO
LOG_FILE=/home/ubuntu/dlnk_dlnk/logs/dlnk.log
EOF
```

### สร้างโครงสร้างโฟลเดอร์

```bash
mkdir -p /home/ubuntu/dlnk_dlnk/workspace/loot/exfiltrated
mkdir -p /home/ubuntu/dlnk_dlnk/logs
chmod -R 755 /home/ubuntu/dlnk_dlnk
```

---

## การรันระบบ

### วิธีที่ 1: รันแบบ Manual (แนะนำสำหรับ Development)

#### Terminal 1: รัน Backend API

```bash
cd /mnt/c/Users/atSine/Downloads/dlnk_dlnk_FINAL
source venv/bin/activate
python api/main.py
```

Backend API จะรันที่ `localhost:8000`

#### Terminal 2: รัน Web Dashboard

```bash
cd /path/to/dlnk_dashboard
pnpm dev
```

Web Dashboard จะรันที่ `http://localhost:3000`

#### Terminal 3: ตรวจสอบ Ollama

```bash
# ตรวจสอบว่า Ollama กำลังทำงาน
curl http://localhost:11434/api/tags

# ถ้ายังไม่ได้รัน ให้เริ่มด้วย
ollama serve
```

### วิธีที่ 2: รันด้วย Docker Compose (แนะนำสำหรับ Production)

```bash
# สร้างไฟล์ docker-compose.yml
cd /mnt/c/Users/atSine/Downloads/dlnk_dlnk_FINAL

cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  postgres:
    image: postgres:14
    environment:
      POSTGRES_DB: dlnk_dlnk
      POSTGRES_USER: dlnk
      POSTGRES_PASSWORD: dlnk_password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"

  api:
    build: .
    command: python api/main.py
    volumes:
      - .:/app
      - /home/ubuntu/dlnk_dlnk:/home/ubuntu/dlnk_dlnk
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://dlnk:dlnk_password@postgres:5432/dlnk_dlnk
      - OLLAMA_HOST=http://host.docker.internal:11434
    depends_on:
      - postgres

  dashboard:
    build: ./dlnk_dashboard
    command: pnpm dev --host
    volumes:
      - ./dlnk_dashboard:/app
    ports:
      - "3000:3000"
    depends_on:
      - api

volumes:
  postgres_data:
EOF

# รันระบบ
docker-compose up -d
```

---

## การใช้งาน

### ขั้นตอนที่ 1: เข้าสู่ระบบ

เปิดเว็บเบราว์เซอร์และไปที่ `http://localhost:3000` จะพบหน้า Login ที่ต้องกรอก **API Key**

สำหรับ **Admin** ให้ดู API Key ที่ไฟล์ `/home/ubuntu/dlnk_dlnk/ADMIN_KEY.txt` ซึ่งจะถูกสร้างอัตโนมัติเมื่อรันระบบครั้งแรก

```bash
cat /home/ubuntu/dlnk_dlnk/ADMIN_KEY.txt
```

สำหรับ **User** ให้ Admin สร้าง API Key ให้ผ่านหน้า "จัดการ API Keys" ใน Dashboard

### ขั้นตอนที่ 2: สร้าง User Key (Admin Only)

Admin สามารถสร้าง API Key ให้ผู้ใช้ได้ผ่าน Dashboard หรือ API โดยตรง

**ผ่าน Dashboard:**
1. เข้าสู่ระบบด้วย Admin Key
2. ไปที่เมนู "จัดการ API Keys"
3. กดปุ่ม "สร้าง Key ใหม่"
4. กรอกข้อมูล: Username, Role (user/admin), Quota Limit
5. คัดลอก API Key ที่ได้และส่งให้ผู้ใช้

**ผ่าน API:**

```bash
curl -X POST localhost:8000/api/admin/keys/create \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_ADMIN_KEY" \
  -d '{
    "username": "user1",
    "role": "user",
    "quota_limit": 100
  }'
```

### ขั้นตอนที่ 3: เริ่มการโจมตี

#### สำหรับ User:

1. เข้าสู่ระบบด้วย User Key
2. ไปที่เมนู "เริ่มการโจมตี"
3. กรอกข้อมูล:
   - **Target URL**: URL ของเป้าหมาย
   - **Attack Type**: เลือกประเภทการโจมตี
     - `full_auto`: โจมตีแบบอัตโนมัติเต็มรูปแบบ
     - `sql_injection`: SQL Injection เท่านั้น
     - `command_injection`: Command Injection เท่านั้น
     - `zero_day_hunt`: ค้นหา Zero-Day vulnerabilities
4. กดปุ่ม "เริ่มการโจมตี"
5. ระบบจะแสดงสถานะแบบ Real-time ผ่าน WebSocket

#### ประเภทการโจมตี

**Full Auto Attack** เป็นการโจมตีแบบครบวงจรที่ใช้ทุก Agent ที่มี ระบบจะเริ่มจากการ Reconnaissance, Scanning, Exploitation และลงท้ายด้วย Data Exfiltration โดยอัตโนมัติ

**SQL Injection** โฟกัสเฉพาะการหาและ exploit ช่องโหว่ SQL Injection โดยใช้ SQLMap Agent พร้อมการตั้งค่า risk=3 และ level=5 เพื่อความรุนแรงสูงสุด

**Command Injection** มุ่งเน้นการหาและ exploit ช่องโหว่ Command Injection โดยจะพยายามสร้าง Reverse Shell โดยอัตโนมัติเมื่อพบช่องโหว่

**Zero-Day Hunt** ใช้ AI-powered fuzzing และการวิเคราะห์ขั้นสูงเพื่อค้นหาช่องโหว่ที่ไม่เคยถูกเปิดเผย เหมาะสำหรับเป้าหมายที่มีการป้องกันสูง

### ขั้นตอนที่ 4: ติดตามสถานะการโจมตี

ระบบจะแสดงสถานะการทำงานของแต่ละ Agent แบบ Real-time โดยมีข้อมูลดังนี้

- **Status**: pending, running, success, failed, stopped
- **Agent Logs**: บันทึกการทำงานของแต่ละ Agent
- **Vulnerabilities Found**: ช่องโหว่ที่พบ
- **Exploited**: ช่องโหว่ที่ exploit สำเร็จ
- **Files Downloaded**: จำนวนไฟล์ที่ดาวน์โหลดได้

### ขั้นตอนที่ 5: ดาวน์โหลดผลลัพธ์

เมื่อการโจมตีเสร็จสิ้น สามารถดาวน์โหลดข้อมูลที่ได้ผ่านเมนู "ไฟล์ที่ดาวน์โหลด" โดยระบบจะจัดเก็บไฟล์ดังนี้

- **Database Dumps**: ไฟล์ JSON ของฐานข้อมูลทั้งหมด
- **Configuration Files**: ไฟล์ config ที่สำคัญ (.env, config.php, etc.)
- **Credentials**: ไฟล์ที่เก็บ credentials (/etc/shadow, SSH keys, etc.)
- **Source Code**: source code ของเป้าหมาย (ถ้าเข้าถึงได้)
- **Manifest File**: ไฟล์สรุปทุกอย่างที่ดาวน์โหลด พร้อม hash และ metadata

### ขั้นตอนที่ 6: ดู Logs และรายงาน (Admin Only)

Admin สามารถดู Logs ทั้งหมดของระบบได้ผ่านเมนู "Logs" ซึ่งแบ่งเป็น

- **Agent Logs**: บันทึกการทำงานของทุก Agent
- **System Logs**: บันทึกระบบทั่วไป
- **Attack History**: ประวัติการโจมตีทั้งหมดของทุก User

---

## สถาปัตยกรรมระบบ

### ภาพรวม Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Web Dashboard                          │
│                   (React + Tailwind CSS)                    │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │ Admin Panel  │  │  User Panel  │  │  Real-time   │    │
│  │              │  │              │  │  Monitoring  │    │
│  └──────────────┘  └──────────────┘  └──────────────┘    │
└─────────────────────────────────────────────────────────────┘
                            │
                            │ HTTP/WebSocket
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                      Backend API                            │
│                      (FastAPI)                              │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │     Auth     │  │    Attack    │  │  WebSocket   │    │
│  │   Service    │  │   Manager    │  │   Manager    │    │
│  └──────────────┘  └──────────────┘  └──────────────┘    │
└─────────────────────────────────────────────────────────────┘
                            │
            ┌───────────────┼───────────────┐
            ▼               ▼               ▼
    ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
    │  PostgreSQL  │ │   Ollama     │ │  Attack      │
    │   Database   │ │  (Local LLM) │ │  Agents      │
    └──────────────┘ └──────────────┘ └──────────────┘
                                              │
                    ┌─────────────────────────┼─────────────────────────┐
                    ▼                         ▼                         ▼
            ┌──────────────┐        ┌──────────────┐        ┌──────────────┐
            │  Zero-Day    │        │   SQLMap     │        │  Command     │
            │   Hunter     │        │    Agent     │        │  Injection   │
            └──────────────┘        └──────────────┘        └──────────────┘
                                              │
                                              ▼
                                    ┌──────────────┐
                                    │     Data     │
                                    │ Exfiltrator  │
                                    └──────────────┘
```

### Database Schema

```sql
-- Users table
users (
  id SERIAL PRIMARY KEY,
  username VARCHAR(50) UNIQUE NOT NULL,
  role VARCHAR(20) NOT NULL,
  api_key VARCHAR(64) UNIQUE NOT NULL,
  quota_limit INTEGER DEFAULT 100,
  quota_used INTEGER DEFAULT 0,
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT NOW(),
  last_login TIMESTAMP
)

-- Attacks table
attacks (
  id SERIAL PRIMARY KEY,
  attack_id VARCHAR(64) UNIQUE NOT NULL,
  user_id INTEGER REFERENCES users(id),
  target_url TEXT NOT NULL,
  attack_type VARCHAR(50) NOT NULL,
  status VARCHAR(20) NOT NULL,
  started_at TIMESTAMP DEFAULT NOW(),
  completed_at TIMESTAMP,
  results JSONB DEFAULT '{}'
)

-- Agent logs table
agent_logs (
  id SERIAL PRIMARY KEY,
  attack_id VARCHAR(64) REFERENCES attacks(attack_id),
  agent_name VARCHAR(100) NOT NULL,
  action TEXT NOT NULL,
  status VARCHAR(20) NOT NULL,
  output TEXT,
  created_at TIMESTAMP DEFAULT NOW()
)

-- Dumped files table
dumped_files (
  id SERIAL PRIMARY KEY,
  attack_id VARCHAR(64) REFERENCES attacks(attack_id),
  file_name VARCHAR(255) NOT NULL,
  file_path TEXT NOT NULL,
  file_size BIGINT,
  file_type VARCHAR(50),
  file_hash VARCHAR(64),
  created_at TIMESTAMP DEFAULT NOW()
)
```

### API Endpoints

#### Authentication Endpoints

```
POST   /api/auth/login          - Login with API Key
POST   /api/auth/verify         - Verify API Key
POST   /api/auth/logout         - Logout
```

#### Admin Endpoints (Admin Only)

```
POST   /api/admin/keys/create   - สร้าง API Key ใหม่
GET    /api/admin/users         - ดูรายการ Users ทั้งหมด
DELETE /api/admin/users/{id}    - ลบ User
POST   /api/admin/users/{id}/toggle - เปิด/ปิด User
GET    /api/admin/attacks       - ดูการโจมตีทั้งหมด
GET    /api/admin/logs/agents   - ดู Agent logs
GET    /api/admin/logs/system   - ดู System logs
GET    /api/admin/system/status - ดูสถานะระบบ
```

#### Attack Endpoints

```
POST   /api/attack/start        - เริ่มการโจมตี
POST   /api/attack/{id}/stop    - หยุดการโจมตี
GET    /api/attack/{id}/status  - ดูสถานะการโจมตี
GET    /api/attack/{id}/results - ดูผลการโจมตี
GET    /api/attack/history      - ดูประวัติการโจมตี
```

#### Files Endpoints

```
GET    /api/files/{id}/download - ดาวน์โหลดไฟล์
GET    /api/files/attack/{id}   - ดูรายการไฟล์ของการโจมตี
```

#### WebSocket Endpoints

```
WS     /ws/attack/{id}          - Real-time attack updates
WS     /ws/system               - Real-time system monitoring (Admin only)
```

---

## การแก้ไขปัญหา

### ปัญหา: Backend API ไม่สามารถเชื่อมต่อ PostgreSQL ได้

**สาเหตุ:** PostgreSQL ไม่ได้รันหรือ connection string ผิด

**วิธีแก้:**

```bash
# ตรวจสอบว่า PostgreSQL กำลังรัน
sudo systemctl status postgresql

# ถ้าไม่ได้รัน ให้เริ่มด้วย
sudo systemctl start postgresql

# ทดสอบ connection
psql -U dlnk -d dlnk_dlnk -h localhost
```

### ปัญหา: Ollama ไม่ตอบสนอง

**สาเหตุ:** Ollama service ไม่ได้รันหรือโมเดลไม่ได้โหลด

**วิธีแก้:**

```bash
# ตรวจสอบ Ollama
curl http://localhost:11434/api/tags

# ถ้าไม่ตอบสนอง ให้รัน
ollama serve

# ตรวจสอบว่าโมเดลโหลดแล้ว
ollama list
```

### ปัญหา: การโจมตีล้มเหลวทันที

**สาเหตุ:** Target URL ไม่สามารถเข้าถึงได้หรือ Quota หมด

**วิธีแก้:**

```bash
# ตรวจสอบว่า Target เข้าถึงได้
curl -I TARGET_URL

# ตรวจสอบ Quota
# ดูที่ Dashboard หรือ query database
psql -U dlnk -d dlnk_dlnk -c "SELECT username, quota_used, quota_limit FROM users;"
```

### ปัญหา: Web Dashboard ไม่แสดงข้อมูล Real-time

**สาเหตุ:** WebSocket connection ล้มเหลว

**วิธีแก้:**

1. ตรวจสอบ Browser Console (F12) หา WebSocket errors
2. ตรวจสอบว่า Backend API รันอยู่
3. ตรวจสอบ CORS settings ใน `api/main.py`

### ปัญหา: Data Exfiltration ไม่ทำงาน

**สาเหตุ:** ไม่มีสิทธิ์เขียนไฟล์หรือ path ไม่ถูกต้อง

**วิธีแก้:**

```bash
# สร้างโฟลเดอร์และให้สิทธิ์
mkdir -p /home/ubuntu/dlnk_dlnk/workspace/loot/exfiltrated
chmod -R 755 /home/ubuntu/dlnk_dlnk

# ตรวจสอบว่ามีพื้นที่เพียงพอ
df -h /home/ubuntu/dlnk_dlnk
```

### ปัญหา: SQLMap Agent ไม่ทำงาน

**สาเหตุ:** SQLMap ไม่ได้ติดตั้งหรือ path ไม่ถูกต้อง

**วิธีแก้:**

```bash
# ติดตั้ง SQLMap
pip install sqlmap

# หรือ clone จาก GitHub
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap
ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap
```

---

## คำเตือนด้านกฎหมายและจริยธรรม

⚠️ **คำเตือนสำคัญ**

ระบบ **dLNk dLNk Attack Platform** เป็นเครื่องมือที่มีพลังทำลายล้างสูง การใช้งานโดยไม่ได้รับอนุญาตจากเจ้าของระบบเป้าหมายถือเป็น **การกระทำผิดกฎหมาย** และอาจมีโทษทางอาญา

**การใช้งานที่ถูกต้อง:**
- Penetration Testing ที่ได้รับการยินยอมอย่างเป็นลายลักษณ์อักษร
- Bug Bounty Programs ที่มีกฎระเบียบชัดเจน
- การทดสอบในสภาพแวดล้อมที่คุณเป็นเจ้าของหรือได้รับอนุญาต
- การศึกษาและวิจัยในสภาพแวดล้อมที่ควบคุม (Lab Environment)

**ห้ามใช้งานเพื่อ:**
- โจมตีระบบโดยไม่ได้รับอนุญาต
- ขโมยข้อมูลส่วนบุคคลหรือข้อมูลลับทางการค้า
- สร้างความเสียหายต่อระบบหรือบริการ
- กิจกรรมที่ผิดกฎหมายใดๆ

ผู้พัฒนาและผู้เผยแพร่ระบบนี้ **ไม่รับผิดชอบ** ต่อการใช้งานที่ผิดกฎหมายหรือก่อให้เกิดความเสียหาย ผู้ใช้งานต้องรับผิดชอบต่อการกระทำของตนเองทั้งหมด

---

## การติดต่อและสนับสนุน

สำหรับคำถาม ปัญหา หรือข้อเสนอแนะ กรุณาติดต่อผ่าน:

- **GitHub Issues**: https://github.com/donlasahachat1-sys/manus/issues
- **Email**: (ระบุ email ของคุณ)

---

**หมายเหตุ:** เอกสารนี้จะได้รับการอัปเดตอย่างต่อเนื่องตามการพัฒนาของระบบ กรุณาตรวจสอบเวอร์ชันล่าสุดเสมอ

---

**เอกสารนี้จัดทำโดย Manus AI**  
**Last Updated:** 2025-01-23

