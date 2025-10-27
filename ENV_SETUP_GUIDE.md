# Environment Setup Guide

## การตั้งค่า Environment Variables สำหรับ Docker

เนื่องจากไฟล์ `.env` ถูก ignore โดย Git (เพื่อความปลอดภัย) คุณจะต้องสร้างไฟล์นี้ด้วยตนเองก่อนรัน Docker

### วิธีที่ 1: Copy จากไฟล์ Template (แนะนำ)

```bash
cd ~/manus
cp .env.docker .env
```

### วิธีที่ 2: สร้างด้วย nano

```bash
cd ~/manus
nano .env
```

จากนั้นคัดลอกเนื้อหาด้านล่างนี้ลงไปในไฟล์:

```bash
# Manus Attack Platform - Docker Environment Configuration
# Created: 2025-10-24

# ===== Database Configuration =====
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
POSTGRES_DB=manus_db

# ===== Logging =====
LOG_LEVEL=INFO
LOG_FILE=logs/manus.log
JSON_LOG_FILE=logs/manus.json

# ===== API Configuration =====
API_HOST=0.0.0.0
API_PORT=8000
API_DEBUG=False

# ===== Web Dashboard Configuration =====
WEB_HOST=0.0.0.0
WEB_PORT=3000
WEB_DEBUG=False

# ===== Database URL =====
DATABASE_URL=postgresql://postgres:postgres@db:5432/manus_db
REDIS_URL=redis://redis:6379/0

# ===== Security =====
SECRET_KEY=manus-secret-key-change-in-production
JWT_ALGORITHM=HS256
JWT_EXPIRATION_HOURS=24

# ===== Agent Configuration =====
MAX_CONCURRENT_AGENTS=5
AGENT_TIMEOUT=300
AGENT_RETRY_ATTEMPTS=3

# ===== Workflow Configuration =====
WORKFLOW_TIMEOUT=3600
TARGET_TIMEOUT=600
MAX_TARGETS=100
MAX_CONCURRENT_ATTACKS=5

# ===== External Tools =====
NMAP_PATH=nmap
METASPLOIT_PATH=/usr/share/metasploit-framework
NUCLEI_PATH=nuclei
SQLMAP_PATH=sqlmap
WPSCAN_PATH=wpscan

# ===== LLM Configuration =====
LLM_PROVIDER=ollama
OLLAMA_HOST=http://ollama:11434
OLLAMA_MODEL=mixtral:latest
LLM_TEMPERATURE=0.7

# ===== Feature Flags =====
SIMULATION_MODE=False
ENABLE_PERSISTENCE=True
ENABLE_LATERAL_MOVEMENT=True
ENABLE_DATA_EXFILTRATION=True
ENABLE_PRIVILEGE_ESCALATION=True

# ===== Performance =====
CACHE_ENABLED=True
CACHE_TTL=3600

# ===== Reporting =====
REPORT_FORMAT=html
REPORT_INCLUDE_PAYLOADS=False
REPORT_INCLUDE_LOGS=True

# ===== Proxy Configuration =====
PROXY_ENABLED=False
PROXY_URL=
PROXY_USERNAME=
PROXY_PASSWORD=

# ===== Rate Limiting =====
RATE_LIMIT_ENABLED=True
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=60

# ===== Notifications (Optional) =====
NOTIFICATION_ENABLED=False
NOTIFICATION_CHANNELS=
NOTIFICATION_WEBHOOK=
NOTIFICATION_EMAIL=

# Email Configuration (Optional)
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=
EMAIL_FROM=
EMAIL_TO=

# Telegram Configuration (Optional)
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=

# Discord Configuration (Optional)
DISCORD_WEBHOOK_URL=

# ===== Workspace =====
WORKSPACE_DIR=/app/workspace
LOOT_DIR=/app/workspace/loot
```

กด `Ctrl+O` เพื่อบันทึก จากนั้นกด `Enter` และกด `Ctrl+X` เพื่อออก

### วิธีที่ 3: ใช้คำสั่งเดียว (Quick Setup)

```bash
cd ~/manus
cat > .env << 'EOF'
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
POSTGRES_DB=manus_db
LOG_LEVEL=INFO
LOG_FILE=logs/manus.log
JSON_LOG_FILE=logs/manus.json
API_HOST=0.0.0.0
API_PORT=8000
API_DEBUG=False
WEB_HOST=0.0.0.0
WEB_PORT=3000
WEB_DEBUG=False
DATABASE_URL=postgresql://postgres:postgres@db:5432/manus_db
REDIS_URL=redis://redis:6379/0
SECRET_KEY=manus-secret-key-change-in-production
JWT_ALGORITHM=HS256
JWT_EXPIRATION_HOURS=24
MAX_CONCURRENT_AGENTS=5
AGENT_TIMEOUT=300
AGENT_RETRY_ATTEMPTS=3
WORKFLOW_TIMEOUT=3600
TARGET_TIMEOUT=600
MAX_TARGETS=100
MAX_CONCURRENT_ATTACKS=5
NMAP_PATH=nmap
METASPLOIT_PATH=/usr/share/metasploit-framework
NUCLEI_PATH=nuclei
SQLMAP_PATH=sqlmap
WPSCAN_PATH=wpscan
LLM_PROVIDER=ollama
OLLAMA_HOST=http://ollama:11434
OLLAMA_MODEL=mixtral:latest
LLM_TEMPERATURE=0.7
SIMULATION_MODE=False
ENABLE_PERSISTENCE=True
ENABLE_LATERAL_MOVEMENT=True
ENABLE_DATA_EXFILTRATION=True
ENABLE_PRIVILEGE_ESCALATION=True
CACHE_ENABLED=True
CACHE_TTL=3600
REPORT_FORMAT=html
REPORT_INCLUDE_PAYLOADS=False
REPORT_INCLUDE_LOGS=True
PROXY_ENABLED=False
RATE_LIMIT_ENABLED=True
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=60
NOTIFICATION_ENABLED=False
WORKSPACE_DIR=/app/workspace
LOOT_DIR=/app/workspace/loot
EOF
```

## การตรวจสอบว่าไฟล์ .env ถูกสร้างแล้ว

```bash
# ตรวจสอบว่าไฟล์มีอยู่
ls -la .env

# ดูเนื้อหาในไฟล์
cat .env
```

## ค่าที่สำคัญที่ควรเปลี่ยนในการใช้งานจริง

| ตัวแปร | ค่าเริ่มต้น | คำแนะนำ |
|--------|------------|---------|
| `POSTGRES_PASSWORD` | `postgres` | **ควรเปลี่ยน** เป็นรหัสผ่านที่แข็งแกร่งกว่า |
| `SECRET_KEY` | `manus-secret-key-change-in-production` | **ต้องเปลี่ยน** เป็น random string ที่ยาวและซับซ้อน |
| `SIMULATION_MODE` | `False` | ตั้งเป็น `True` สำหรับการทดสอบ, `False` สำหรับการโจมตีจริง |

### วิธีสร้าง SECRET_KEY ที่ปลอดภัย

```bash
# ใช้ OpenSSL
openssl rand -hex 32

# ใช้ Python
python3 -c "import secrets; print(secrets.token_hex(32))"

# ใช้ /dev/urandom
head -c 32 /dev/urandom | base64
```

จากนั้นนำค่าที่ได้ไปแทนที่ใน `.env`:

```bash
SECRET_KEY=<ค่าที่ได้จากคำสั่งข้างบน>
```

## ขั้นตอนต่อไปหลังจากสร้าง .env

```bash
# 1. ตรวจสอบว่าทุกอย่างพร้อม
./validate-docker-setup.sh

# 2. Build Docker images
docker compose build --no-cache

# 3. Start services
docker compose up -d

# 4. ตรวจสอบ logs
docker compose logs -f

# 5. ดาวน์โหลด LLM models (ในอีก terminal)
docker exec -it manus-ollama ollama pull mixtral:latest
```

## Troubleshooting

### ปัญหา: ไฟล์ .env ไม่ถูกอ่าน

```bash
# ตรวจสอบ permissions
chmod 644 .env

# ตรวจสอบว่าไม่มี BOM หรือ special characters
file .env
```

### ปัญหา: Environment variables ไม่ถูกโหลด

```bash
# ทดสอบว่า docker-compose อ่านไฟล์ได้
docker compose config

# ดู environment variables ใน container
docker compose exec api env | grep POSTGRES
```

## หมายเหตุสำคัญ

- ไฟล์ `.env` **ไม่ควร** commit ขึ้น Git เพราะมีข้อมูลที่ sensitive
- ไฟล์ `.env.docker` เป็น template ที่ถูก commit ไว้ใน repository
- สำหรับการ deploy ในสภาพแวดล้อมจริง ควรใช้ secret management tools เช่น Docker Secrets หรือ HashiCorp Vault

---

**สร้างโดย**: Manus AI  
**วันที่**: 24 ตุลาคม 2025

