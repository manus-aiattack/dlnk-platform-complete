# Quick Start: ใช้งาน Local AI (Ollama) กับ dLNk Attack Platform
## เริ่มต้นใช้งานภายใน 5 นาที - ฟรี 100%

---

## 📋 สิ่งที่คุณมีอยู่แล้ว

✅ Ollama ติดตั้งแล้ว  
✅ Models พร้อมใช้งาน:
- mixtral:latest (26GB)
- llama3:8b-instruct-fp16 (16GB)
- llama3:latest (4.7GB)
- codellama:latest (3.8GB)
- mistral:latest (4.4GB)

---

## 🚀 เริ่มต้นใช้งาน

### Step 1: ตรวจสอบ Ollama

```bash
# ตรวจสอบว่า Ollama ทำงาน
curl http://localhost:11434/api/tags

# ทดสอบ model
ollama run mixtral:latest "สวัสดี"
```

### Step 2: Clone Repository

```bash
git clone https://github.com/donlasahachat1-sys/manus.git
cd manus
```

### Step 3: ตั้งค่า Environment

```bash
# Copy environment file
cp .env.production .env

# แก้ไข .env
nano .env
```

**แก้ไขเฉพาะส่วนที่จำเป็น**:
```bash
# Database
POSTGRES_PASSWORD=your_strong_password

# Redis
REDIS_PASSWORD=your_redis_password

# C2
C2_ENCRYPTION_KEY=your_32_character_encryption_key_here

# Grafana
GRAFANA_ADMIN_PASSWORD=your_grafana_password

# LLM (ใช้ Ollama - ฟรี)
LLM_PROVIDER=ollama  # default อยู่แล้ว
```

**ไม่ต้องตั้งค่า**:
- ❌ OPENAI_API_KEY (ไม่ต้องใช้)
- ❌ SLACK_WEBHOOK_URL (optional)
- ❌ DISCORD_WEBHOOK_URL (optional)
- ❌ TELEGRAM_BOT_TOKEN (optional)

### Step 4: เลือก Ollama Model

แก้ไขไฟล์ `llm_config.py`:

```python
# เลือก model ตาม RAM ที่มี
OLLAMA_MODEL = "mixtral:latest"  # แนะนำ (ถ้ามี RAM 32GB+)
# หรือ
OLLAMA_MODEL = "llama3:latest"  # ถ้ามี RAM น้อย (8-16GB)
```

### Step 5: Start Services

```bash
# Build และ start
docker-compose -f docker-compose.production.yml up -d

# ตรวจสอบสถานะ
docker-compose -f docker-compose.production.yml ps
```

### Step 6: ตรวจสอบว่าทำงาน

```bash
# API Health
curl localhost:8000/health

# Ollama Health
curl http://localhost:11434/api/tags

# Prometheus
curl http://localhost:9090/-/healthy
```

---

## 🎯 การใช้งาน

### เข้าถึง Services

| Service | URL | Description |
|---------|-----|-------------|
| Frontend | http://localhost | Web UI |
| API | localhost:8000 | REST API |
| API Docs | localhost:8000/docs | Swagger UI |
| Grafana | http://localhost:3000 | Monitoring |
| Prometheus | http://localhost:9090 | Metrics |
| Kibana | http://localhost:5601 | Logs |

### ทดสอบ AI Integration

```bash
# ทดสอบผ่าน API
curl -X POST localhost:8000/api/ai/chat \
  -H "Content-Type: application/json" \
  -d '{
    "message": "วิเคราะห์ช่องโหว่ SQL Injection"
  }'
```

### ทดสอบ Attack

```bash
# ส่ง attack request
curl -X POST localhost:8000/api/attack \
  -H "Content-Type: application/json" \
  -d '{
    "target": "localhost:8000",
    "attack_type": "web_application"
  }'
```

---

## 🔧 การเปลี่ยน Model

### วิธีที่ 1: แก้ไข llm_config.py

```python
# แก้ไขบรรทัดนี้
OLLAMA_MODEL = "llama3:latest"  # เปลี่ยนเป็น model ที่ต้องการ
```

### วิธีที่ 2: ใช้ Environment Variable

```bash
# ใน .env
OLLAMA_MODEL=llama3:latest
```

### วิธีที่ 3: Runtime (ผ่าน API)

```python
from llm_config import get_llm_config

# Override model
config = get_llm_config()
config['model'] = 'llama3:latest'
```

---

## 📊 การเลือก Model ตาม Use Case

### สำหรับ Vulnerability Analysis (ต้องการความแม่นยำ)
```python
OLLAMA_MODEL = "mixtral:latest"  # Best accuracy
# หรือ
OLLAMA_MODEL = "llama3:8b-instruct-fp16"  # High quality
```

### สำหรับ Code Generation
```python
OLLAMA_MODEL = "codellama:latest"  # Specialized for code
```

### สำหรับ Fast Response (ต้องการความเร็ว)
```python
OLLAMA_MODEL = "llama3:latest"  # Fastest
# หรือ
OLLAMA_MODEL = "mistral:latest"  # Good balance
```

### สำหรับ Development/Testing
```python
OLLAMA_MODEL = "mistral:latest"  # ประหยัด RAM
```

---

## 🎓 ตัวอย่างการใช้งาน

### 1. Vulnerability Scanning with AI

```python
from core.ai_integration import AIOrchestrator

# Initialize with Ollama
orchestrator = AIOrchestrator()

# Analyze target
result = await orchestrator.analyze_target("https://localhost:8000")
print(result)
```

### 2. AI-Powered Exploit Generation

```python
from advanced_agents.exploit_generator import ExploitGenerator

generator = ExploitGenerator()

# Generate exploit
exploit = await generator.generate_exploit(
    vulnerability_type="SQL Injection",
    target_info={"url": "https://localhost:8000/login"}
)
```

### 3. Reinforcement Learning Attack

```python
from core.rl_attack_agent import RLAttackOrchestrator

orchestrator = RLAttackOrchestrator()

# Train (ครั้งแรก)
await orchestrator.train(episodes=100)

# Attack with RL
result = await orchestrator.attack_with_rl("https://localhost:8000")
```

---

## 🐛 Troubleshooting

### Ollama ไม่ทำงาน

```bash
# ตรวจสอบ process
ps aux | grep ollama

# Restart Ollama
docker-compose -f docker-compose.production.yml restart ollama

# ตรวจสอบ logs
docker-compose -f docker-compose.production.yml logs ollama
```

### Model ไม่โหลด

```bash
# ตรวจสอบว่ามี model
ollama list

# ดาวน์โหลด model ใหม่
ollama pull mixtral:latest

# ทดสอบ model
ollama run mixtral:latest "test"
```

### API ไม่ตอบสนอง

```bash
# ตรวจสอบ logs
docker-compose -f docker-compose.production.yml logs api

# Restart API
docker-compose -f docker-compose.production.yml restart api
```

### Out of Memory

```bash
# ใช้ model เล็กลง
OLLAMA_MODEL=llama3:latest  # 4.7GB

# หรือ
OLLAMA_MODEL=mistral:latest  # 4.4GB

# Restart services
docker-compose -f docker-compose.production.yml restart
```

---

## 💡 Tips & Tricks

### 1. ประหยัด RAM

```bash
# ปิด services ที่ไม่ใช้
docker-compose -f docker-compose.production.yml stop grafana kibana

# ใช้ model เล็ก
OLLAMA_MODEL=mistral:latest
```

### 2. เพิ่มความเร็ว

```bash
# ใช้ model เล็ก
OLLAMA_MODEL=llama3:latest

# เพิ่ม CPU cores ให้ Ollama
# แก้ไข docker-compose.production.yml:
services:
  ollama:
    deploy:
      resources:
        limits:
          cpus: '8'  # เพิ่มจาก 4
```

### 3. เพิ่มความแม่นยำ

```bash
# ใช้ model ใหญ่
OLLAMA_MODEL=mixtral:latest

# ปรับ temperature
# ใน llm_config.py:
TEMPERATURE = 0.3  # ลดจาก 0.7 เพื่อความแม่นยำ
```

### 4. Warm-up Model

```bash
# โหลด model ล่วงหน้า
ollama run mixtral:latest "warm up"

# หรือผ่าน API
curl http://localhost:11434/api/generate \
  -d '{"model": "mixtral:latest", "prompt": "warm up"}'
```

---

## 📈 Performance Benchmarks

### Model Comparison (บน Server 32GB RAM)

| Model | Load Time | Response Time | Quality | RAM Usage |
|-------|-----------|---------------|---------|-----------|
| mixtral:latest | 30s | 5-10s | ⭐⭐⭐⭐⭐ | 26GB |
| llama3:8b-instruct-fp16 | 20s | 3-7s | ⭐⭐⭐⭐ | 16GB |
| llama3:latest | 10s | 2-5s | ⭐⭐⭐ | 5GB |
| codellama:latest | 10s | 2-5s | ⭐⭐⭐ (code) | 4GB |
| mistral:latest | 10s | 2-5s | ⭐⭐⭐ | 5GB |

---

## 🎯 Next Steps

1. **ทดสอบ Attack Scenarios**:
```bash
# ดู examples
ls examples/

# รัน example
python examples/sql_injection_test.py
```

2. **ตั้งค่า Notifications** (Optional):
```bash
# แก้ไข .env
SLACK_WEBHOOK_URL=your_webhook
DISCORD_WEBHOOK_URL=your_webhook
```

3. **ดู Monitoring**:
- Grafana: http://localhost:3000
- Prometheus: http://localhost:9090
- Kibana: http://localhost:5601

4. **อ่าน Documentation เพิ่มเติม**:
- `docs/FREE_TOOLS_SETUP.md` - รายละเอียดเครื่องมือฟรี
- `docs/DEVELOPMENT_SUMMARY.md` - สรุปการพัฒนา
- `docs/CRITICAL_POINTS_ANALYSIS.md` - จุดสำคัญ

---

## ✅ Checklist

- [x] Ollama ทำงาน
- [x] Models พร้อมใช้งาน
- [x] Docker Compose start แล้ว
- [x] API ตอบสนอง
- [x] Frontend เข้าถึงได้
- [ ] ทดสอบ attack (ขั้นตอนถัดไป)
- [ ] ตั้งค่า notifications (optional)
- [ ] ดู monitoring dashboards

---

## 🎉 สรุป

คุณพร้อมใช้งาน dLNk Attack Platform แล้ว!

✅ ใช้ Local AI (Ollama) - ฟรี 100%  
✅ ไม่ต้องเสียเงิน API  
✅ ประสิทธิภาพสูง  
✅ Privacy & Security  

**Happy Hacking! 🚀**

---

**หากมีปัญหา**:
1. ตรวจสอบ logs: `docker-compose logs -f`
2. อ่าน Troubleshooting ด้านบน
3. ดู documentation ใน `docs/`

