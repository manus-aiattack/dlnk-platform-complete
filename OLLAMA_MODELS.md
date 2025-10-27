# Ollama Models - Local LLM (ฟรี 100%)

## Models ที่คุณมี

```bash
ollama list
```

| Model | ID | Size | Use Case |
|-------|-----|------|----------|
| **llama3:8b-instruct-fp16** | c666fe422df7 | 16 GB | ⭐ **แนะนำ** - High quality instruction following |
| **mixtral:latest** | a3b6bef0f836 | 26 GB | Best for complex tasks, reasoning |
| **llama3:latest** | 365c0bd3c000 | 4.7 GB | Fast and efficient, general purpose |
| **codellama:latest** | 8fdf8f752f6e | 3.8 GB | Best for code generation |
| **mistral:latest** | 6577803aa9a0 | 4.4 GB | Good balance, fast |

---

## การตั้งค่า Model

### ใน `.env` file:

```bash
# LLM Provider - ใช้ Ollama เท่านั้น (ฟรี 100%)
LLM_PROVIDER=ollama

# Ollama Configuration
OLLAMA_HOST=localhost
OLLAMA_PORT=11434
OLLAMA_MODEL=llama3:8b-instruct-fp16  # เปลี่ยนได้ตามต้องการ

# Generation Settings
LLM_TEMPERATURE=0.7
LLM_MAX_TOKENS=4000
LLM_TOP_P=0.9
OLLAMA_TIMEOUT=600
```

---

## แนะนำการใช้งาน

### สำหรับ Attack Planning & Strategy
```bash
OLLAMA_MODEL=mixtral:latest
```
- ขนาด: 26 GB
- ความสามารถ: Complex reasoning, multi-step planning
- เหมาะกับ: AI-driven attack strategy, exploit generation

### สำหรับ General Operations (แนะนำ)
```bash
OLLAMA_MODEL=llama3:8b-instruct-fp16
```
- ขนาด: 16 GB
- ความสามารถ: High quality instruction following
- เหมาะกับ: Agent operations, general tasks

### สำหรับ Code Generation
```bash
OLLAMA_MODEL=codellama:latest
```
- ขนาด: 3.8 GB
- ความสามารถ: Code generation, exploit writing
- เหมาะกับ: Payload generation, script writing

### สำหรับ Fast Operations
```bash
OLLAMA_MODEL=llama3:latest
```
- ขนาด: 4.7 GB
- ความสามารถ: Fast response, efficient
- เหมาะกับ: Quick analysis, rapid response

### สำหรับ Balanced Performance
```bash
OLLAMA_MODEL=mistral:latest
```
- ขนาด: 4.4 GB
- ความสามารถ: Good balance of speed and quality
- เหมาะกับ: General purpose, mixed tasks

---

## การเปลี่ยน Model

### วิธีที่ 1: แก้ไขใน `.env`
```bash
nano .env
# เปลี่ยน OLLAMA_MODEL=...
```

### วิธีที่ 2: Export environment variable
```bash
export OLLAMA_MODEL=llama3:8b-instruct-fp16
```

### วิธีที่ 3: ระบุตอน runtime
```python
import os
os.environ["OLLAMA_MODEL"] = "mixtral:latest"
```

---

## ทดสอบ Ollama

```bash
# ตรวจสอบว่า Ollama ทำงาน
curl http://localhost:11434/api/tags

# ทดสอบ generation
ollama run llama3:8b-instruct-fp16 "Explain SQL injection"
```

---

## Performance Tips

### 1. เลือก Model ตาม RAM
- **16+ GB RAM:** llama3:8b-instruct-fp16 หรือ mixtral:latest
- **8-16 GB RAM:** llama3:latest หรือ mistral:latest
- **< 8 GB RAM:** codellama:latest

### 2. เลือก Model ตาม Task
- **Complex reasoning:** mixtral:latest
- **Code generation:** codellama:latest
- **Fast response:** llama3:latest
- **Balanced:** llama3:8b-instruct-fp16 ⭐

### 3. Timeout Settings
```bash
# สำหรับ complex tasks
OLLAMA_TIMEOUT=900  # 15 minutes

# สำหรับ normal tasks
OLLAMA_TIMEOUT=600  # 10 minutes (default)

# สำหรับ quick tasks
OLLAMA_TIMEOUT=300  # 5 minutes
```

---

## ข้อดีของ Ollama (Local LLM)

✅ **ฟรี 100%** - ไม่มีค่าใช้จ่าย  
✅ **Privacy** - ข้อมูลไม่ออกจากเครื่อง  
✅ **No Rate Limits** - ใช้ได้ไม่จำกัด  
✅ **Offline** - ทำงานได้โดยไม่ต้องต่อ Internet  
✅ **Customizable** - ปรับแต่งได้เต็มที่  

---

## การอัปเดต Models

```bash
# อัปเดต model
ollama pull llama3:8b-instruct-fp16

# ดาวน์โหลด model ใหม่
ollama pull llama3.1:latest

# ลบ model ที่ไม่ใช้
ollama rm <model-name>
```

---

## Integration กับ dLNk Attack Platform

### ใน `llm_config.py`:
```python
# คุณใช้ Ollama (Local LLM) เท่านั้น - ฟรี 100%
LLM_PROVIDER = "ollama"

# Ollama Configuration
OLLAMA_HOST = "localhost"
OLLAMA_PORT = "11434"
OLLAMA_MODEL = "llama3:8b-instruct-fp16"  # แนะนำ
OLLAMA_TIMEOUT = 600
```

### ใน AI Agents:
```python
from llm_config import get_llm_config

config = get_llm_config()
# จะใช้ Ollama โดยอัตโนมัติ
```

---

## Troubleshooting

### Ollama ไม่ทำงาน
```bash
# ตรวจสอบ service
systemctl status ollama

# เริ่ม service
systemctl start ollama

# หรือ run manually
ollama serve
```

### Model ไม่พบ
```bash
# ตรวจสอบ models
ollama list

# ดาวน์โหลด model
ollama pull llama3:8b-instruct-fp16
```

### Timeout
```bash
# เพิ่ม timeout ใน .env
OLLAMA_TIMEOUT=900
```

---

**สรุป:** คุณใช้ Ollama (Local LLM) ซึ่ง**ฟรี 100%** ไม่มีค่าใช้จ่าย และมี 5 models พร้อมใช้งาน แนะนำใช้ `llama3:8b-instruct-fp16` สำหรับงานทั่วไป และ `mixtral:latest` สำหรับงานที่ซับซ้อน

