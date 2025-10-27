# คู่มือการรัน Production - dLNk Attack Platform

## วิธีการรัน Production บนเครื่อง Local (WSL2)

### ขั้นตอนที่ 1: Pull โค้ดล่าสุดจาก GitHub

```bash
cd /mnt/c/projecattack/manus
git pull origin main
```

### ขั้นตอนที่ 2: รันสคริปต์ Deployment

```bash
bash deploy_local_production.sh
```

สคริปต์จะทำงานดังนี้:
1. ✓ ตรวจสอบ environment (WSL2, Ollama)
2. ✓ Activate virtual environment
3. ✓ ติดตั้ง dependencies
4. ✓ สร้าง directories (logs, data)
5. ✓ สร้างไฟล์ .env configuration
6. ✓ ทดสอบการเชื่อมต่อ Ollama
7. ✓ ทดสอบ system imports
8. ✓ เริ่มต้น production server

### ขั้นตอนที่ 3: เข้าใช้งานระบบ

**Web Interface:**
- Local: http://localhost:8000
- Network: http://172.26.203.21:8000
- Dashboard: http://localhost:8000/dashboard
- API Docs: http://localhost:8000/docs

**CLI Interface:**
```bash
cd /mnt/c/projecattack/manus
source venv/bin/activate
python main.py --help
```

---

## การตั้งค่า LLM (Ollama)

### Models ที่มีอยู่:
- `mixtral:latest` (26 GB) - แนะนำสำหรับ production
- `llama3:8b-instruct-fp16` (16 GB) - ประสิทธิภาพสูง
- `llama3:latest` (4.7 GB) - เร็ว แต่ความสามารถน้อยกว่า
- `codellama:latest` (3.8 GB) - สำหรับ code generation
- `mistral:latest` (4.4 GB) - สมดุลระหว่างความเร็วและความสามารถ

### เปลี่ยน Model:
แก้ไขไฟล์ `.env`:
```bash
LOCALAI_MODEL=mixtral:latest
# หรือ
LOCALAI_MODEL=llama3:8b-instruct-fp16
```

### ตรวจสอบ Ollama:
```bash
# ดู models ที่มี
ollama list

# ทดสอบ model
ollama run mixtral "Hello, test response"

# เริ่ม Ollama service
ollama serve
```

---

## การตั้งค่า Environment Variables

ไฟล์ `.env` จะถูกสร้างอัตโนมัติ แต่คุณสามารถแก้ไขได้:

### LLM Configuration
```bash
LLM_PROVIDER=localai              # ใช้ Ollama
LOCALAI_BASE_URL=http://localhost:11434/v1
LOCALAI_MODEL=mixtral:latest      # เปลี่ยนได้
LOCALAI_API_KEY=ollama
```

### Server Configuration
```bash
HOST=0.0.0.0                      # Listen on all interfaces
PORT=8000                         # Port สำหรับ web server
DEBUG=false                       # Production mode
WORKERS=4                         # จำนวน worker processes
```

### Attack Configuration
```bash
MAX_CONCURRENT_ATTACKS=5          # จำนวน attacks พร้อมกัน
ATTACK_TIMEOUT=3600               # Timeout (วินาที)
ENABLE_AUTO_EXPLOIT=true          # Auto exploit vulnerabilities
```

### Network Configuration
```bash
HTTP_TIMEOUT=30
MAX_RETRIES=3
USER_AGENT=Mozilla/5.0 (Windows NT 10.0; Win64; x64)
```

---

## การใช้งาน CLI

### เริ่มต้น Attack
```bash
# Activate venv
source venv/bin/activate

# Full attack workflow
python main.py attack --target https://example.com --workflow full

# Specific attack type
python main.py attack --target https://example.com --type sqli

# With custom options
python main.py attack --target https://example.com \
  --workflow full \
  --max-depth 3 \
  --threads 10 \
  --output report.json
```

### ดู Reports
```bash
# List all reports
python main.py reports list

# View specific report
python main.py reports view <report_id>

# Export report
python main.py reports export <report_id> --format pdf
```

### จัดการ Sessions
```bash
# List active sessions
python main.py sessions list

# Resume session
python main.py sessions resume <session_id>

# Stop session
python main.py sessions stop <session_id>
```

---

## การใช้งาน Web Interface

### Dashboard
- URL: http://localhost:8000/dashboard
- Features:
  - Real-time attack monitoring
  - Vulnerability statistics
  - System status
  - Recent findings

### API Endpoints

**Start Attack:**
```bash
curl -X POST http://localhost:8000/api/attack/start \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://example.com",
    "workflow": "full",
    "options": {
      "max_depth": 3,
      "enable_auto_exploit": true
    }
  }'
```

**Get Status:**
```bash
curl http://localhost:8000/api/attack/status/<attack_id>
```

**List Vulnerabilities:**
```bash
curl http://localhost:8000/api/vulnerabilities
```

---

## Troubleshooting

### Ollama ไม่ทำงาน
```bash
# เริ่ม Ollama service
ollama serve

# ตรวจสอบ process
ps aux | grep ollama

# ทดสอบ API
curl http://localhost:11434/api/tags
```

### Import Errors
```bash
# ติดตั้ง dependencies ใหม่
source venv/bin/activate
pip install -r requirements.txt

# ทดสอบ imports
python3 -c "from core.orchestrator import Orchestrator; print('OK')"
```

### Port Already in Use
```bash
# หา process ที่ใช้ port 8000
lsof -i :8000

# Kill process
kill -9 <PID>

# หรือเปลี่ยน port ใน .env
PORT=8001
```

### Permission Errors
```bash
# ตรวจสอบ permissions
ls -la /mnt/c/projecattack/manus

# แก้ไข permissions (ถ้าจำเป็น)
chmod -R 755 /mnt/c/projecattack/manus
```

### Network Issues (AIS Blocking)
```bash
# ใช้ DNS อื่น
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf

# ใช้ VPN หรือ Proxy (ถ้ามี)
export HTTP_PROXY=http://proxy:port
export HTTPS_PROXY=http://proxy:port

# หรือตั้งค่าใน .env
HTTP_PROXY=http://proxy:port
HTTPS_PROXY=http://proxy:port
```

---

## Monitoring & Logs

### ดู Logs
```bash
# Real-time logs
tail -f logs/dlnk.log

# Error logs only
grep ERROR logs/dlnk.log

# Last 100 lines
tail -n 100 logs/dlnk.log
```

### System Status
```bash
# Check running processes
ps aux | grep python

# Check memory usage
free -h

# Check disk usage
df -h
```

---

## Performance Tuning

### เพิ่มประสิทธิภาพ

**1. เพิ่ม Workers:**
แก้ไข `.env`:
```bash
WORKERS=8  # เพิ่มจาก 4 เป็น 8
```

**2. ใช้ Model ที่เร็วกว่า:**
```bash
LOCALAI_MODEL=llama3:latest  # เร็วกว่า mixtral
```

**3. เพิ่ม Concurrent Attacks:**
```bash
MAX_CONCURRENT_ATTACKS=10  # เพิ่มจาก 5 เป็น 10
```

**4. ลด Timeout:**
```bash
HTTP_TIMEOUT=15  # ลดจาก 30 เป็น 15
```

---

## Security Considerations

### Production Security Checklist

- [ ] เปลี่ยน SECRET_KEY และ JWT_SECRET ใน .env
- [ ] ตั้งค่า ALLOWED_HOSTS ให้เฉพาะเจาะจง
- [ ] ปิด DEBUG mode (DEBUG=false)
- [ ] ใช้ HTTPS (ถ้าเป็น public server)
- [ ] ตั้งค่า firewall rules
- [ ] ใช้ strong passwords สำหรับ database
- [ ] Enable rate limiting
- [ ] Monitor logs regularly

---

## Backup & Recovery

### Backup
```bash
# Backup data directory
tar -czf backup_$(date +%Y%m%d).tar.gz data/ logs/ .env

# Backup database (ถ้าใช้ PostgreSQL)
pg_dump dlnk > backup_$(date +%Y%m%d).sql
```

### Recovery
```bash
# Restore data
tar -xzf backup_20250126.tar.gz

# Restore database
psql dlnk < backup_20250126.sql
```

---

## Support

หากพบปัญหาหรือต้องการความช่วยเหลือ:

1. ตรวจสอบ logs: `tail -f logs/dlnk.log`
2. ดู error messages
3. ตรวจสอบ system requirements
4. ทดสอบ Ollama connection
5. ตรวจสอบ network connectivity

---

## Next Steps

หลังจากรันสำเร็จแล้ว:

1. ทดสอบด้วย target ทดสอบ (test environment)
2. ปรับแต่ง configuration ตามความต้องการ
3. ตั้งค่า monitoring และ alerting
4. สร้าง backup schedule
5. Review security settings

---

**ระบบพร้อมใช้งาน Production แล้ว!** 🚀

