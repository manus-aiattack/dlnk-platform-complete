# Production Readiness Checklist

**Project**: dLNk Attack Platform  
**Date**: October 25, 2025  
**Status**: 🔄 In Progress

---

## ✅ Phase 1-4: System Integration (COMPLETED)

- ✅ Project cleanup and consolidation
- ✅ Unified service layer created
- ✅ Modern CLI implemented
- ✅ API standardization completed
- ✅ Documentation consolidated
- ✅ All PRs merged to main

---

## 🔄 Critical Steps for Production Deployment

### 1. Environment Setup ⚙️

#### 1.1 Pull Latest Code
```bash
cd /mnt/c/projecattack/manus
git checkout main
git pull origin main
```

#### 1.2 Install Dependencies
```bash
# Update requirements.txt first
pip install -r requirements.txt

# New dependencies needed:
pip install httpx rich questionary pyyaml psutil
```

#### 1.3 Configure Environment Variables
```bash
# Copy example env file
cp .env.example.new .env

# Edit .env with your settings
nano .env
```

**Critical environment variables**:
```env
# Database
DATABASE_URL=postgresql://user:password@localhost:5432/dlnk
REDIS_URL=redis://localhost:6379/0

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
SECRET_KEY=<generate-random-key>

# LLM Configuration
OLLAMA_HOST=http://localhost:11434
OPENAI_API_KEY=<your-key>

# Security
ALLOWED_ORIGINS=http://localhost:3000,https://yourdomain.com
RATE_LIMIT_PER_MINUTE=60

# Notifications (optional)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=<app-password>
TELEGRAM_BOT_TOKEN=<your-token>
DISCORD_WEBHOOK_URL=<your-webhook>
```

---

### 2. Database Setup 💾

#### 2.1 Install PostgreSQL
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install postgresql postgresql-contrib

# Start PostgreSQL
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

#### 2.2 Create Database
```bash
sudo -u postgres psql

# In PostgreSQL prompt:
CREATE DATABASE dlnk;
CREATE USER dlnk_user WITH PASSWORD 'your_secure_password';
GRANT ALL PRIVILEGES ON DATABASE dlnk TO dlnk_user;
\q
```

#### 2.3 Run Migrations
```bash
# Initialize database schema
python3 -m core.database.init_db

# Or use Alembic if available
alembic upgrade head
```

#### 2.4 Test Database Connection
```bash
python3 test_db_fixed.py
```

---

### 3. Redis Setup 🔴

#### 3.1 Install Redis
```bash
# Ubuntu/Debian
sudo apt install redis-server

# Start Redis
sudo systemctl start redis
sudo systemctl enable redis
```

#### 3.2 Test Redis Connection
```bash
redis-cli ping
# Should return: PONG
```

---

### 4. LLM Setup 🤖

#### 4.1 Install Ollama
```bash
# Download and install
curl -fsSL https://ollama.com/install.sh | sh

# Start Ollama
ollama serve
```

#### 4.2 Pull Required Models
```bash
# In another terminal
ollama pull llama3.2
ollama pull mistral
ollama pull codellama
```

#### 4.3 Test LLM Connection
```bash
python3 llm_config_new.py
```

---

### 5. Validate Configuration ✔️

```bash
# Run configuration validation script
python3 scripts/validate_config.py

# Should show all green checkmarks
```

---

### 6. Start Services 🚀

#### 6.1 Start API Server
```bash
# Development mode
python3 -m uvicorn api.main:app --reload --host 0.0.0.0 --port 8000

# Production mode (with Gunicorn)
gunicorn api.main:app \
  --workers 4 \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000 \
  --access-logfile logs/access.log \
  --error-logfile logs/error.log
```

#### 6.2 Start Web Frontend (if available)
```bash
cd web/
npm install
npm run build
npm start
```

#### 6.3 Test CLI
```bash
# Configure CLI
dlnk auth login --api-key <your-api-key>

# Test commands
dlnk system status
dlnk attack list
```

---

### 7. Security Hardening 🔒

#### 7.1 Generate Secure Keys
```bash
# Generate SECRET_KEY
python3 -c "import secrets; print(secrets.token_urlsafe(32))"

# Generate API keys
python3 -c "import secrets; print('DLNK-' + secrets.token_hex(16))"
```

#### 7.2 Configure Firewall
```bash
# Allow only necessary ports
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 8000/tcp  # API
sudo ufw allow 3000/tcp  # Web (if needed)
sudo ufw enable
```

#### 7.3 Set File Permissions
```bash
chmod 600 .env
chmod 700 logs/
chmod 700 data/
```

#### 7.4 Disable Debug Mode
```bash
# In .env
DEBUG=false
LOG_LEVEL=INFO
```

---

### 8. Monitoring & Logging 📊

#### 8.1 Create Log Directories
```bash
mkdir -p logs/
mkdir -p logs/attacks/
mkdir -p logs/api/
mkdir -p logs/system/
```

#### 8.2 Configure Log Rotation
```bash
# Create /etc/logrotate.d/dlnk
sudo nano /etc/logrotate.d/dlnk
```

Content:
```
/path/to/manus/logs/*.log {
    daily
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 dlnk dlnk
    sharedscripts
}
```

#### 8.3 Set Up System Monitoring
```bash
# Install monitoring tools
pip install prometheus-client grafana-api

# Start monitoring endpoint
python3 -m core.monitoring.prometheus_exporter
```

---

### 9. Backup Strategy 💾

#### 9.1 Database Backups
```bash
# Create backup script
cat > backup_db.sh << 'EOF'
#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
pg_dump -U dlnk_user dlnk > backups/db_$DATE.sql
gzip backups/db_$DATE.sql
# Keep only last 30 days
find backups/ -name "db_*.sql.gz" -mtime +30 -delete
EOF

chmod +x backup_db.sh

# Add to crontab (daily at 2 AM)
crontab -e
# Add: 0 2 * * * /path/to/manus/backup_db.sh
```

#### 9.2 File Backups
```bash
# Backup exfiltrated files and reports
rsync -av --delete data/ backups/data_$(date +%Y%m%d)/
```

---

### 10. Testing 🧪

#### 10.1 Unit Tests
```bash
pytest tests/
```

#### 10.2 Integration Tests
```bash
pytest tests/integration/
```

#### 10.3 End-to-End Tests
```bash
# Test full attack workflow
python3 tests/e2e/test_full_workflow.py
```

#### 10.4 Load Testing
```bash
# Install locust
pip install locust

# Run load tests
locust -f tests/load/locustfile.py --host=http://localhost:8000
```

---

### 11. Docker Deployment (Recommended) 🐳

#### 11.1 Build Docker Images
```bash
# Build API image
docker build -t dlnk-api:latest -f docker/Dockerfile.api .

# Build Web image
docker build -t dlnk-web:latest -f docker/Dockerfile.web .
```

#### 11.2 Docker Compose
```bash
# Start all services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f
```

#### 11.3 Docker Compose Configuration
```yaml
# docker-compose.yml
version: '3.8'

services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: dlnk
      POSTGRES_USER: dlnk_user
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data

  api:
    image: dlnk-api:latest
    depends_on:
      - postgres
      - redis
    environment:
      DATABASE_URL: postgresql://dlnk_user:${DB_PASSWORD}@postgres:5432/dlnk
      REDIS_URL: redis://redis:6379/0
    ports:
      - "8000:8000"
    volumes:
      - ./data:/app/data
      - ./logs:/app/logs

  web:
    image: dlnk-web:latest
    depends_on:
      - api
    ports:
      - "3000:3000"
    environment:
      API_URL: http://api:8000

volumes:
  postgres_data:
  redis_data:
```

---

### 12. Production Checklist ✅

Before going live, verify:

- [ ] All environment variables configured
- [ ] Database created and migrated
- [ ] Redis running and accessible
- [ ] LLM models downloaded and working
- [ ] API server starts without errors
- [ ] CLI commands work correctly
- [ ] All tests passing
- [ ] Logs directory created and writable
- [ ] Backups configured and tested
- [ ] Firewall rules configured
- [ ] SSL/TLS certificates installed (if public)
- [ ] Monitoring and alerting set up
- [ ] Documentation updated
- [ ] Security audit completed
- [ ] Load testing passed

---

## 📝 Quick Start Commands

```bash
# 1. Setup
git pull origin main
pip install -r requirements.txt
cp .env.example.new .env
# Edit .env with your settings

# 2. Database
sudo systemctl start postgresql redis
python3 -m core.database.init_db

# 3. Validate
python3 scripts/validate_config.py

# 4. Start
python3 -m uvicorn api.main:app --host 0.0.0.0 --port 8000

# 5. Test
dlnk auth login
dlnk system status
```

---

## 🆘 Troubleshooting

### Database Connection Error
```bash
# Check PostgreSQL status
sudo systemctl status postgresql

# Check connection
psql -U dlnk_user -d dlnk -h localhost
```

### Redis Connection Error
```bash
# Check Redis status
sudo systemctl status redis

# Test connection
redis-cli ping
```

### LLM Connection Error
```bash
# Check Ollama status
ps aux | grep ollama

# Restart Ollama
killall ollama
ollama serve
```

### Permission Denied
```bash
# Fix permissions
chmod +x scripts/*.py
chmod 600 .env
chown -R $USER:$USER data/ logs/
```

---

## 📞 Support

For issues or questions:
1. Check logs in `logs/` directory
2. Run validation script: `python3 scripts/validate_config.py`
3. Review documentation in `docs/`
4. Check GitHub Issues

---

**Status**: Ready for production deployment after completing checklist above.

