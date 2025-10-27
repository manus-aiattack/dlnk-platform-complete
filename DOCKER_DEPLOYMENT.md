# Docker Deployment Guide - Manus Attack Platform

## ข้อมูลทั่วไป

เอกสารนี้อธิบายวิธีการ deploy Manus Attack Platform โดยใช้ Docker และ Docker Compose บน Ubuntu/WSL

**อัพเดทล่าสุด**: 24 ตุลาคม 2025

---

## ความต้องการของระบบ

### Software Requirements

- **Docker**: 20.10 หรือสูงกว่า
- **Docker Compose**: 2.0 หรือสูงกว่า
- **Ubuntu/WSL**: 22.04 หรือ 24.04 LTS
- **RAM**: อย่างน้อย 8GB (แนะนำ 16GB+)
- **Disk Space**: อย่างน้อย 50GB

### การติดตั้ง Docker บน Ubuntu/WSL

```bash
# อัพเดท package list
sudo apt update

# ติดตั้ง dependencies
sudo apt install -y apt-transport-https ca-certificates curl software-properties-common

# เพิ่ม Docker GPG key
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

# เพิ่ม Docker repository
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# ติดตั้ง Docker
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# เพิ่ม user ไปยัง docker group
sudo usermod -aG docker $USER
newgrp docker

# ทดสอบ Docker
docker run hello-world
```

---

## การ Deploy

### ขั้นตอนที่ 1: Clone Repository

```bash
cd ~
git clone https://github.com/donlasahachat1-sys/manus.git
cd manus
```

### ขั้นตอนที่ 2: ตั้งค่า Environment Variables

ไฟล์ `.env` ถูกสร้างไว้แล้ว แต่คุณสามารถแก้ไขได้ตามต้องการ:

```bash
nano .env
```

**ค่าที่สำคัญ**:
- `POSTGRES_PASSWORD`: รหัสผ่านฐานข้อมูล (ควรเปลี่ยนในการใช้งานจริง)
- `SECRET_KEY`: Secret key สำหรับ JWT (ควรเปลี่ยนในการใช้งานจริง)
- `SIMULATION_MODE`: ตั้งเป็น `True` สำหรับการทดสอบ, `False` สำหรับการโจมตีจริง

### ขั้นตอนที่ 3: Build Docker Images

```bash
# Build images (ใช้เวลาประมาณ 5-10 นาที)
docker-compose build --no-cache
```

### ขั้นตอนที่ 4: Start Services

```bash
# Start all services
docker-compose up -d

# ตรวจสอบสถานะ
docker-compose ps
```

### ขั้นตอนที่ 5: ตรวจสอบ Logs

```bash
# ดู logs ทั้งหมด
docker-compose logs -f

# ดู logs ของ service เฉพาะ
docker-compose logs -f api
docker-compose logs -f db
docker-compose logs -f ollama
```

### ขั้นตอนที่ 6: ดาวน์โหลด LLM Models

```bash
# เข้าไปใน Ollama container
docker exec -it manus-ollama bash

# ดาวน์โหลด models (ใช้เวลานาน!)
ollama pull mixtral:latest
ollama pull llama3:latest
ollama pull codellama:latest
ollama pull mistral:latest

# ออกจาก container
exit
```

### ขั้นตอนที่ 7: ดึง Admin API Key

```bash
# ดู logs ของ API เพื่อหา admin API key
docker-compose logs api | grep -i "api key"

# หรือเข้าไปใน database
docker exec -it manus-db psql -U postgres -d manus_db -c "SELECT username, api_key FROM users WHERE role='admin';"
```

---

## การเข้าถึง Services

หลังจาก start services สำเร็จ คุณสามารถเข้าถึงได้ที่:

- **API Server**: localhost:8000
- **API Documentation**: localhost:8000/docs
- **Health Check**: localhost:8000/health
- **PostgreSQL**: localhost:5432
- **Redis**: localhost:6379
- **Ollama**: http://localhost:11434

---

## การใช้งาน API

### 1. ทดสอบ Health Check

```bash
curl localhost:8000/health
```

### 2. เริ่มการโจมตี

```bash
# แทนที่ YOUR_API_KEY ด้วย API key ที่ได้จากขั้นตอนที่ 7
curl -X POST localhost:8000/api/attack/start \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "localhost:8000",
    "attack_type": "scan"
  }'
```

### 3. ตรวจสอบสถานะการโจมตี

```bash
curl localhost:8000/api/attack/{attack_id}/status \
  -H "X-API-Key: YOUR_API_KEY"
```

---

## การจัดการ Services

### หยุด Services

```bash
# หยุด services ทั้งหมด
docker-compose down

# หยุดและลบ volumes (ระวัง: จะลบข้อมูลทั้งหมด!)
docker-compose down -v
```

### รีสตาร์ท Services

```bash
# รีสตาร์ท service เฉพาะ
docker-compose restart api

# รีสตาร์ททั้งหมด
docker-compose restart
```

### ดู Resource Usage

```bash
# ดูการใช้ทรัพยากร
docker stats

# ดูเฉพาะ Manus containers
docker stats manus-api manus-db manus-redis manus-ollama
```

### ทำความสะอาด

```bash
# ลบ containers ที่หยุดแล้ว
docker container prune -f

# ลบ images ที่ไม่ใช้
docker image prune -f

# ลบ volumes ที่ไม่ใช้
docker volume prune -f

# ลบทุกอย่างที่ไม่ใช้
docker system prune -a --volumes -f
```

---

## Troubleshooting

### ปัญหา: Container ไม่ start

```bash
# ตรวจสอบ logs
docker-compose logs api

# ตรวจสอบ container status
docker-compose ps

# รีสตาร์ท service
docker-compose restart api
```

### ปัญหา: Database connection failed

```bash
# ตรวจสอบว่า database พร้อมใช้งาน
docker exec -it manus-db pg_isready -U postgres

# เข้าไปใน database
docker exec -it manus-db psql -U postgres -d manus_db

# ตรวจสอบ tables
\dt

# ออกจาก psql
\q
```

### ปัญหา: Permission denied บน WSL

```bash
# แก้ไข permissions
cd /home/ubuntu/manus
sudo chmod -R 755 workspace logs data reports config

# ถ้ายังไม่ได้ ให้ลอง
sudo chown -R $USER:$USER workspace logs data reports config
```

### ปัญหา: Port already in use

```bash
# ตรวจสอบ process ที่ใช้ port
sudo lsof -i :8000
sudo lsof -i :5432

# หยุด process
sudo kill -9 <PID>

# หรือเปลี่ยน port ใน docker-compose.yml
```

### ปัญหา: Out of memory

```bash
# เพิ่ม swap space
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile

# ตรวจสอบ memory
free -h
```

### ปัญหา: Ollama ไม่ทำงาน

```bash
# ตรวจสอบ Ollama logs
docker-compose logs ollama

# ทดสอบ Ollama
curl http://localhost:11434/api/tags

# รีสตาร์ท Ollama
docker-compose restart ollama
```

---

## การ Backup และ Restore

### Backup Database

```bash
# Backup database
docker exec -t manus-db pg_dump -U postgres manus_db > backup_$(date +%Y%m%d_%H%M%S).sql

# Backup volumes
docker run --rm -v manus_postgres_data:/data -v $(pwd):/backup ubuntu tar czf /backup/postgres_backup.tar.gz /data
```

### Restore Database

```bash
# Restore database
cat backup.sql | docker exec -i manus-db psql -U postgres -d manus_db

# Restore volumes
docker run --rm -v manus_postgres_data:/data -v $(pwd):/backup ubuntu tar xzf /backup/postgres_backup.tar.gz -C /
```

---

## การ Scale Services

### เพิ่ม API Instances

```bash
# Scale API service
docker-compose up -d --scale api=3

# ใช้ nginx เป็น load balancer (ต้องตั้งค่าเพิ่มเติม)
```

---

## Security Best Practices

1. **เปลี่ยนรหัสผ่านเริ่มต้น**: แก้ไข `POSTGRES_PASSWORD` และ `SECRET_KEY` ใน `.env`
2. **ใช้ HTTPS**: ตั้งค่า reverse proxy (nginx/traefik) พร้อม SSL certificate
3. **จำกัด Network Access**: ใช้ firewall จำกัดการเข้าถึง ports
4. **อัพเดท Images**: อัพเดท Docker images เป็นประจำ
5. **Backup ข้อมูล**: ทำ backup database และ volumes เป็นประจำ
6. **Monitor Logs**: ตรวจสอบ logs เพื่อหาพฤติกรรมผิดปกติ

---

## การอัพเดท

```bash
# Pull latest code
git pull origin main

# Rebuild images
docker-compose build --no-cache

# Restart services
docker-compose down
docker-compose up -d
```

---

## เพิ่มเติม

สำหรับข้อมูลเพิ่มเติม กรุณาดูที่:

- **README.md**: ข้อมูลทั่วไปเกี่ยวกับโปรเจกต์
- **DEPLOYMENT_GUIDE.md**: คู่มือการ deploy แบบ manual
- **DOCKER_ANALYSIS.md**: การวิเคราะห์ปัญหา Docker configuration
- **GitHub**: https://github.com/donlasahachat1-sys/manus

---

**สร้างโดย**: Manus AI  
**วันที่**: 24 ตุลาคม 2025

