# Deployment Commands - dLNk Attack Platform

คำสั่งสำหรับ Deploy โปรเจกต์ dLNk Attack Platform

---

## 🚀 Quick Deploy (Recommended)

### Option 1: Docker Compose - Production Stack (แนะนำ)

```bash
# 1. Clone repository
git clone https://github.com/srhhsshdsrdgeseedh-max/manus.git
cd manus

# 2. สร้างไฟล์ .env
cp env.template .env

# 3. แก้ไขค่า environment variables
nano .env
# หรือ
vim .env

# 4. Start ทุก services (PostgreSQL, Redis, Ollama, API, Frontend, Monitoring)
docker-compose -f docker-compose.complete.yml up -d

# 5. ตรวจสอบสถานะ
docker-compose -f docker-compose.complete.yml ps

# 6. ดู logs
docker-compose -f docker-compose.complete.yml logs -f

# 7. ทดสอบ API
curl http://localhost:8000/health

# 8. เข้าถึง services
# - Frontend: http://localhost
# - API: http://localhost:8000
# - Grafana: http://localhost:3000
# - Prometheus: http://localhost:9090
```

---

## 📝 Environment Variables (.env)

สร้างไฟล์ `.env` ด้วยค่าเหล่านี้:

```bash
# Database
DB_PASSWORD=your_secure_db_password_here

# Redis
REDIS_PASSWORD=your_secure_redis_password_here

# Ollama
OLLAMA_MODEL=mixtral:latest

# API
SECRET_KEY=your_very_long_random_secret_key_here
SIMULATION_MODE=False

# Frontend
VITE_API_URL=http://localhost:8000
VITE_WS_URL=ws://localhost:8000/ws

# Grafana
GRAFANA_PASSWORD=admin
```

**สร้าง SECRET_KEY:**
```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

---

## 🔧 Manual Deploy (Without Docker)

### 1. ติดตั้ง Dependencies

```bash
# System packages
sudo apt update
sudo apt install -y python3.11 python3.11-venv python3.11-dev \
    postgresql postgresql-contrib libpq-dev \
    build-essential libssl-dev libffi-dev \
    curl git

# Ollama
curl -fsSL https://ollama.com/install.sh | sh
ollama pull mixtral:latest
```

### 2. ตั้งค่า PostgreSQL

```bash
# Start PostgreSQL
sudo systemctl start postgresql
sudo systemctl enable postgresql

# สร้าง database และ user
sudo -u postgres psql << EOF
CREATE DATABASE dlnk_attack_platform;
CREATE USER dlnk WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE dlnk_attack_platform TO dlnk;
ALTER DATABASE dlnk_attack_platform OWNER TO dlnk;
\q
EOF

# Import schema (ถ้ามี)
# psql -U dlnk -d dlnk_attack_platform -h localhost -f database/schema.sql
```

### 3. ติดตั้ง Python Dependencies

```bash
# Clone repository
git clone https://github.com/srhhsshdsrdgeseedh-max/manus.git
cd manus

# สร้าง virtual environment
python3.11 -m venv venv
source venv/bin/activate

# ติดตั้ง packages
pip install --upgrade pip
pip install -r requirements-production.txt
```

### 4. ตั้งค่า Environment

```bash
# สร้างไฟล์ .env
cp env.template .env

# แก้ไข .env
nano .env
```

ใส่ค่าเหล่านี้:
```bash
DATABASE_URL=postgresql://dlnk:your_password@localhost:5432/dlnk_attack_platform
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=mixtral:latest
API_HOST=0.0.0.0
API_PORT=8000
SECRET_KEY=your_secret_key_here
SIMULATION_MODE=False
```

### 5. Initialize Database

```bash
# รัน startup script
python3 startup.py

# จะสร้าง admin key และบันทึกไว้ใน workspace/ADMIN_KEY.txt
```

### 6. Start API Server

```bash
# Development mode
uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload

# Production mode (with Gunicorn)
gunicorn api.main:app \
    --workers 4 \
    --worker-class uvicorn.workers.UvicornWorker \
    --bind 0.0.0.0:8000 \
    --access-logfile - \
    --error-logfile - \
    --log-level info
```

### 7. Setup Frontend (Optional)

```bash
cd frontend

# ติดตั้ง dependencies
pnpm install

# Build for production
pnpm build

# Serve with Nginx หรือ static server
# dist/ folder จะมีไฟล์ที่ build เสร็จ
```

---

## 🌐 Deploy to Production Server

### Option 1: Deploy to VPS/Cloud Server

```bash
# 1. SSH เข้า server
ssh user@your-server-ip

# 2. Clone repository
git clone https://github.com/srhhsshdsrdgeseedh-max/manus.git
cd manus

# 3. ติดตั้ง Docker (ถ้ายังไม่มี)
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# 4. ติดตั้ง Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/download/v2.20.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# 5. สร้าง .env file
cp env.template .env
nano .env

# 6. Start services
docker-compose -f docker-compose.complete.yml up -d

# 7. ตั้งค่า Nginx reverse proxy (optional)
sudo apt install nginx
sudo nano /etc/nginx/sites-available/dlnk
```

**Nginx Configuration:**
```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://localhost:80;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /api {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /ws {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

```bash
# Enable site
sudo ln -s /etc/nginx/sites-available/dlnk /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

### Option 2: Deploy to GitHub Codespaces

```bash
# 1. เปิด Codespace จาก GitHub repository

# 2. ใน Codespace terminal
cd /workspaces/manus

# 3. Start services
docker-compose -f docker-compose.complete.yml up -d

# 4. Forward ports (Codespace จะทำอัตโนมัติ)
# - 8000 (API)
# - 80 (Frontend)
# - 3000 (Grafana)
```

---

## 🧪 Testing After Deployment

```bash
# 1. Health check
curl http://localhost:8000/health

# 2. รัน API tests
python3 test_api_fixed.py

# 3. ตรวจสอบ services
docker-compose -f docker-compose.complete.yml ps

# 4. ดู logs
docker-compose -f docker-compose.complete.yml logs -f api

# 5. ทดสอบ Frontend
curl http://localhost/
```

---

## 📊 Monitoring

### Access Monitoring Tools

```bash
# Grafana (Dashboards)
http://localhost:3000
# Username: admin
# Password: (ตามที่ตั้งใน .env)

# Prometheus (Metrics)
http://localhost:9090

# API Health
http://localhost:8000/health

# Frontend
http://localhost/
```

---

## 🔄 Update/Redeploy

```bash
# 1. Pull latest code
cd manus
git pull origin main

# 2. Rebuild และ restart
docker-compose -f docker-compose.complete.yml down
docker-compose -f docker-compose.complete.yml build
docker-compose -f docker-compose.complete.yml up -d

# 3. ตรวจสอบ
docker-compose -f docker-compose.complete.yml ps
```

---

## 🛑 Stop Services

```bash
# Stop all services
docker-compose -f docker-compose.complete.yml down

# Stop และลบ volumes (⚠️ จะลบข้อมูลทั้งหมด)
docker-compose -f docker-compose.complete.yml down -v

# Stop specific service
docker-compose -f docker-compose.complete.yml stop api
```

---

## 🔍 Troubleshooting

### ตรวจสอบ logs

```bash
# All services
docker-compose -f docker-compose.complete.yml logs -f

# Specific service
docker-compose -f docker-compose.complete.yml logs -f api
docker-compose -f docker-compose.complete.yml logs -f postgres
docker-compose -f docker-compose.complete.yml logs -f ollama
```

### Restart service

```bash
docker-compose -f docker-compose.complete.yml restart api
```

### เข้าไปใน container

```bash
docker-compose -f docker-compose.complete.yml exec api bash
docker-compose -f docker-compose.complete.yml exec postgres psql -U dlnk -d dlnk_attack_platform
```

### ตรวจสอบ resource usage

```bash
docker stats
```

---

## 💾 Backup

### Backup Database

```bash
# PostgreSQL backup
docker-compose -f docker-compose.complete.yml exec postgres pg_dump -U dlnk dlnk_attack_platform > backup_$(date +%Y%m%d).sql

# Backup workspace
tar -czf workspace_backup_$(date +%Y%m%d).tar.gz workspace/
```

### Restore Database

```bash
# Restore PostgreSQL
cat backup_20250126.sql | docker-compose -f docker-compose.complete.yml exec -T postgres psql -U dlnk dlnk_attack_platform
```

---

## 🔐 Security Checklist

- [ ] เปลี่ยน default passwords ทั้งหมด
- [ ] ตั้งค่า firewall (UFW)
- [ ] Enable SSL/TLS (Let's Encrypt)
- [ ] ตั้งค่า rate limiting
- [ ] Backup อัตโนมัติ
- [ ] Monitor logs
- [ ] Update ระบบเป็นประจำ

---

## 📞 Support

หากพบปัญหา:

1. ตรวจสอบ logs: `docker-compose logs -f`
2. รัน health check: `curl http://localhost:8000/health`
3. รัน tests: `python3 test_api_fixed.py`
4. ดู documentation: `docs/` folder
5. Create GitHub issue

---

**Happy Deploying! 🚀**

