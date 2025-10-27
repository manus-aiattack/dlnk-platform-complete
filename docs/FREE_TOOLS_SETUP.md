# การใช้เครื่องมือฟรีทั้งหมด - dLNk Attack Platform
## 100% Free & Open Source - ไม่ต้องเสียเงินเลย

**หลักการ**: ระบบนี้ออกแบบให้ใช้เครื่องมือฟรีและ open source ทั้งหมด ไม่ต้องพึ่งพา API ที่เสียเงิน

---

## 🤖 AI/LLM - ใช้ Ollama (Local AI)

### ✅ Ollama (ฟรี 100%)

**ที่มาของ Models**:
คุณมี Ollama ติดตั้งไว้แล้วพร้อม models:
```bash
ollama list
# NAME                       SIZE      
# llama3:8b-instruct-fp16    16 GB     - คุณภาพสูง
# mixtral:latest             26 GB     - ดีที่สุดสำหรับงานซับซ้อน
# llama3:latest              4.7 GB    - เร็วและประหยัด
# codellama:latest           3.8 GB    - ดีสำหรับ code generation
# mistral:latest             4.4 GB    - สมดุลดี
```

### การตั้งค่า

**1. ตรวจสอบว่า Ollama ทำงาน**:
```bash
# ตรวจสอบ service
curl http://localhost:11434/api/tags

# ทดสอบ model
ollama run mixtral:latest "Hello, how are you?"
```

**2. เลือก Model ใน `llm_config.py`**:
```python
# แก้ไขบรรทัดนี้
OLLAMA_MODEL = "mixtral:latest"  # เปลี่ยนเป็น model ที่ต้องการ

# ตัวเลือก:
# - mixtral:latest (26GB) - ดีที่สุด แต่ใช้ RAM เยอะ
# - llama3:8b-instruct-fp16 (16GB) - คุณภาพสูง
# - llama3:latest (4.7GB) - แนะนำสำหรับ RAM น้อย
# - codellama:latest (3.8GB) - สำหรับ code generation
# - mistral:latest (4.4GB) - สมดุลดี
```

**3. ตั้งค่า Environment Variable**:
```bash
# ใน .env
LLM_PROVIDER=ollama  # default อยู่แล้ว
OLLAMA_HOST=http://localhost:11434
```

**4. ใน Docker**:
```yaml
# docker-compose.production.yml มี Ollama service อยู่แล้ว
services:
  ollama:
    image: ollama/ollama:latest
    volumes:
      - ollama_data:/root/.ollama
    ports:
      - "11434:11434"
```

### คำแนะนำการเลือก Model

| Model | RAM ที่ต้องการ | ความเร็ว | คุณภาพ | แนะนำสำหรับ |
|-------|----------------|----------|--------|-------------|
| mixtral:latest | 32GB+ | ช้า | ดีที่สุด | Server ที่มี RAM เยอะ |
| llama3:8b-instruct-fp16 | 20GB+ | ปานกลาง | สูง | งานที่ต้องการคุณภาพ |
| llama3:latest | 8GB+ | เร็ว | ดี | การใช้งานทั่วไป |
| codellama:latest | 8GB+ | เร็ว | ดี (code) | Code generation |
| mistral:latest | 8GB+ | เร็ว | ดี | สมดุลดี |

---

## 📢 Notifications - ใช้ Webhook ฟรี

### ✅ Slack (ฟรี)

**วิธีตั้งค่า**:
1. ไปที่ https://api.slack.com/apps
2. สร้าง App ใหม่
3. เปิดใช้งาน "Incoming Webhooks"
4. สร้าง Webhook URL
5. คัดลอก URL มาใส่ใน `.env`:
```bash
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

**ไม่มีค่าใช้จ่าย**: Webhook ฟรีตลอดกาล

### ✅ Discord (ฟรี)

**วิธีตั้งค่า**:
1. เปิด Discord Server
2. ไปที่ Server Settings → Integrations → Webhooks
3. สร้าง Webhook ใหม่
4. คัดลอก Webhook URL
5. ใส่ใน `.env`:
```bash
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/YOUR/WEBHOOK/URL
```

**ไม่มีค่าใช้จ่าย**: ฟรีตลอดกาล

### ✅ Telegram (ฟรี)

**วิธีตั้งค่า**:
1. สร้าง Bot ผ่าน @BotFather
2. รับ Bot Token
3. หา Chat ID:
```bash
# ส่งข้อความไปที่ bot แล้วเรียก API
curl https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates
```
4. ใส่ใน `.env`:
```bash
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id
```

**ไม่มีค่าใช้จ่าย**: Telegram Bot API ฟรี

---

## 📊 SIEM - ใช้ Open Source

### ✅ Elasticsearch (Open Source - ฟรี)

**วิธีติดตั้ง**:
```bash
# มีใน docker-compose.production.yml อยู่แล้ว
docker-compose -f docker-compose.production.yml up -d elasticsearch
```

**ตั้งค่า**:
```bash
# ใน .env
ELASTICSEARCH_URL=http://elasticsearch:9200
```

**ไม่มีค่าใช้จ่าย**: Open source ฟรี

### ✅ Splunk Free (ฟรี - จำกัด 500MB/วัน)

**ถ้าต้องการใช้ Splunk**:
1. ดาวน์โหลด Splunk Free: https://www.splunk.com/en_us/download/splunk-enterprise.html
2. ติดตั้งและเปิดใช้งาน HEC (HTTP Event Collector)
3. สร้าง HEC Token
4. ใส่ใน `.env`:
```bash
SPLUNK_HEC_URL=https://localhost:8088
SPLUNK_HEC_TOKEN=your_hec_token
```

**ไม่มีค่าใช้จ่าย**: Splunk Free จำกัด 500MB/วัน (เพียงพอสำหรับใช้งานทั่วไป)

---

## 📈 Monitoring - ใช้ Open Source

### ✅ Prometheus (Open Source - ฟรี)

**มีใน Docker Compose อยู่แล้ว**:
```yaml
services:
  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
```

**เข้าถึง**: http://localhost:9090

**ไม่มีค่าใช้จ่าย**: Open source ฟรี

### ✅ Grafana (Open Source - ฟรี)

**มีใน Docker Compose อยู่แล้ว**:
```yaml
services:
  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
```

**เข้าถึง**: http://localhost:3000  
**Default Login**: admin / (ตั้งใน .env)

**ไม่มีค่าใช้จ่าย**: Open source ฟรี

### ✅ ELK Stack (Open Source - ฟรี)

**มีใน Docker Compose อยู่แล้ว**:
- Elasticsearch: http://localhost:9200
- Kibana: http://localhost:5601
- Logstash: (internal)

**ไม่มีค่าใช้จ่าย**: Open source ฟรีทั้งหมด

---

## 🔧 Fuzzing Tools - ใช้ Open Source

### ✅ AFL++ (Open Source - ฟรี)

**วิธีติดตั้ง**:
```bash
# ใน Docker container หรือ local
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus
make
sudo make install
```

**ไม่มีค่าใช้จ่าย**: Open source ฟรี

### ✅ angr (Open Source - ฟรี)

**ติดตั้งผ่าน pip**:
```bash
pip install angr
```

**ไม่มีค่าใช้จ่าย**: Open source ฟรี

### ✅ pwntools (Open Source - ฟรี)

**ติดตั้งผ่าน pip**:
```bash
pip install pwntools
```

**ไม่มีค่าใช้จ่าย**: Open source ฟรี

---

## 🗄️ Database & Cache - ใช้ Open Source

### ✅ PostgreSQL (Open Source - ฟรี)

**มีใน Docker Compose อยู่แล้ว**:
```yaml
services:
  db:
    image: postgres:15-alpine
```

**ไม่มีค่าใช้จ่าย**: Open source ฟรี

### ✅ Redis (Open Source - ฟรี)

**มีใน Docker Compose อยู่แล้ว**:
```yaml
services:
  redis:
    image: redis:7-alpine
```

**ไม่มีค่าใช้จ่าย**: Open source ฟรี

---

## 🚀 สรุป: ค่าใช้จ่ายทั้งหมด

| Component | Tool | ค่าใช้จ่าย |
|-----------|------|-----------|
| AI/LLM | Ollama | **ฟรี 100%** |
| Notifications | Slack/Discord/Telegram Webhooks | **ฟรี 100%** |
| SIEM | Elasticsearch | **ฟรี 100%** |
| SIEM (Optional) | Splunk Free | **ฟรี (500MB/วัน)** |
| Monitoring | Prometheus + Grafana | **ฟรี 100%** |
| Logging | ELK Stack | **ฟรี 100%** |
| Fuzzing | AFL++, angr, pwntools | **ฟรี 100%** |
| Database | PostgreSQL | **ฟรี 100%** |
| Cache | Redis | **ฟรี 100%** |
| Web Server | Nginx | **ฟรี 100%** |

**รวมทั้งหมด: 0 บาท (ฟรี 100%)**

---

## ⚠️ สิ่งที่ไม่ควรใช้ (เสียเงิน)

### ❌ OpenAI API
- GPT-4: $0.03/1K tokens
- GPT-3.5: $0.002/1K tokens
- **ใช้แทน**: Ollama (ฟรี)

### ❌ Anthropic Claude API
- Claude 3: $0.015/1K tokens
- **ใช้แทน**: Ollama (ฟรี)

### ❌ Google Cloud AI
- Gemini Pro: $0.00025/1K tokens
- **ใช้แทน**: Ollama (ฟรี)

### ❌ AWS Services
- SageMaker, Bedrock, etc.
- **ใช้แทน**: Local tools (ฟรี)

### ❌ Paid SIEM
- Splunk Enterprise (แพง)
- **ใช้แทน**: Elasticsearch (ฟรี) หรือ Splunk Free

---

## 📋 Checklist การตั้งค่าเครื่องมือฟรี

- [x] Ollama ติดตั้งและทำงาน
- [x] Models ดาวน์โหลดแล้ว (mixtral, llama3, etc.)
- [ ] Slack Webhook (ถ้าต้องการ)
- [ ] Discord Webhook (ถ้าต้องการ)
- [ ] Telegram Bot (ถ้าต้องการ)
- [x] Docker Compose พร้อมใช้งาน
- [x] PostgreSQL
- [x] Redis
- [x] Prometheus
- [x] Grafana
- [x] Elasticsearch
- [x] Kibana

---

## 🎯 คำแนะนำการใช้งาน

### สำหรับ RAM น้อย (8-16GB)
```bash
# ใช้ model เล็ก
OLLAMA_MODEL=llama3:latest  # 4.7GB
# หรือ
OLLAMA_MODEL=mistral:latest  # 4.4GB
```

### สำหรับ RAM ปานกลาง (16-32GB)
```bash
# ใช้ model ขนาดกลาง
OLLAMA_MODEL=llama3:8b-instruct-fp16  # 16GB
```

### สำหรับ RAM เยอะ (32GB+)
```bash
# ใช้ model ใหญ่
OLLAMA_MODEL=mixtral:latest  # 26GB
```

### ประหยัด Resources
```bash
# ปิด services ที่ไม่ใช้
docker-compose -f docker-compose.production.yml stop grafana kibana

# ใช้แค่ที่จำเป็น
docker-compose -f docker-compose.production.yml up -d api db redis ollama
```

---

## 🔍 การตรวจสอบว่าใช้เครื่องมือฟรี

```bash
# ตรวจสอบว่าไม่มี API key ที่เสียเงิน
grep -r "OPENAI_API_KEY\|ANTHROPIC\|GOOGLE_API" .env
# ควรไม่พบหรือเป็นค่าว่าง

# ตรวจสอบว่าใช้ Ollama
grep "LLM_PROVIDER" .env
# ควรเป็น: LLM_PROVIDER=ollama

# ตรวจสอบ Ollama ทำงาน
curl http://localhost:11434/api/tags
```

---

## 💡 Tips

1. **Ollama Model Management**:
```bash
# ดู models ที่มี
ollama list

# ดาวน์โหลด model ใหม่
ollama pull llama3.2

# ลบ model ที่ไม่ใช้
ollama rm <model-name>
```

2. **ประหยัด Disk Space**:
```bash
# ลบ Docker images ที่ไม่ใช้
docker system prune -a

# ลบ Ollama models ที่ไม่ใช้
ollama rm <unused-model>
```

3. **Optimize Performance**:
```bash
# ใช้ model เล็กสำหรับ development
OLLAMA_MODEL=mistral:latest

# ใช้ model ใหญ่สำหรับ production
OLLAMA_MODEL=mixtral:latest
```

---

## ✅ สรุป

ระบบ dLNk Attack Platform ใช้เครื่องมือฟรีทั้งหมด:
- ✅ ไม่ต้องเสียเงินเลย (0 บาท)
- ✅ ไม่ต้องพึ่งพา API ที่เสียเงิน
- ✅ ใช้ Local AI (Ollama) แทน OpenAI
- ✅ ใช้ Open Source tools ทั้งหมด
- ✅ พร้อมใช้งาน production ได้เลย

**คำขวัญ**: "100% Free & Open Source - No API Fees, Ever!"

