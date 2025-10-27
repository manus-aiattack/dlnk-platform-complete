# 🤖 Local LLM Guide - dLNk dLNk Framework

## คุณมี Mixtral แล้ว! ใช้งานได้เลย

### ✅ Quick Start

```bash
# 1. ตรวจสอบ Ollama
ollama list

# 2. รัน Ollama server (ถ้ายังไม่ได้รัน)
ollama serve

# 3. ทดสอบ AI System
python3 dlnk_ai_system_local.py
```

### 📋 Configuration

แก้ไขไฟล์ `llm_config.py`:

```python
# เลือก Provider
LLM_PROVIDER = "ollama"  # หรือ "openai", "lmstudio", "localai"

# Ollama Settings
OLLAMA_BASE_URL = "http://localhost:11434/v1"
OLLAMA_MODEL = "mixtral:latest"  # คุณมี model นี้แล้ว!
```

### 🎯 ใช้งาน AI System

#### 1. Attack Planning

```python
from dlnk_ai_system_local import dLNkAISystem

ai = dLNkAISystem()

result = ai.generate_attack_plan({
    "target": "https://target.com",
    "type": "Web Application",
    "technology": "PHP + MySQL"
})

print(result['content'])
```

#### 2. Vulnerability Analysis

```python
result = ai.analyze_vulnerability({
    "type": "SQL Injection",
    "details": "Parameter 'id' vulnerable",
    "severity": "Critical"
})

print(result['content'])
```

#### 3. Report Generation

```python
result = ai.generate_report({
    "vulnerabilities": [...],
    "exploits": [...],
    "findings": [...]
})

print(result['content'])
```

### 🔧 เปลี่ยน LLM Provider

#### ใช้ OpenAI

```python
# llm_config.py
LLM_PROVIDER = "openai"
OPENAI_API_KEY = "sk-..."
OPENAI_MODEL = "gpt-4.1-mini"
```

```bash
export OPENAI_API_KEY="sk-..."
python3 dlnk_ai_system_local.py
```

#### ใช้ LM Studio

```python
# llm_config.py
LLM_PROVIDER = "lmstudio"
LMSTUDIO_BASE_URL = "http://localhost:1234/v1"
```

#### ใช้ LocalAI

```python
# llm_config.py
LLM_PROVIDER = "localai"
LOCALAI_BASE_URL = "http://localhost:8080/v1"
```

### 📊 Models แนะนำสำหรับ Offensive Security

#### Ollama Models

```bash
# Code & Security focused
ollama pull codellama:34b
ollama pull deepseek-coder:33b

# General purpose (good for Thai)
ollama pull mixtral:latest  # ✅ คุณมีแล้ว!
ollama pull llama3.2:latest

# Lightweight
ollama pull mistral:latest
ollama pull phi3:latest
```

#### Model Comparison

| Model | Size | Speed | Quality | Thai Support |
|-------|------|-------|---------|--------------|
| **mixtral:latest** | 26GB | Medium | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| codellama:34b | 19GB | Medium | ⭐⭐⭐⭐ | ⭐⭐⭐ |
| llama3.2:latest | 4.7GB | Fast | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| mistral:latest | 4.1GB | Fast | ⭐⭐⭐ | ⭐⭐⭐ |

### 🚀 Performance Tips

#### 1. GPU Acceleration

```bash
# ตรวจสอบ GPU
nvidia-smi

# Ollama จะใช้ GPU อัตโนมัติ
```

#### 2. Adjust Temperature

```python
# llm_config.py
TEMPERATURE = 0.7  # สูง = creative, ต่ำ = precise
```

#### 3. Adjust Max Tokens

```python
# llm_config.py
MAX_TOKENS = 4000  # เพิ่มถ้าต้องการคำตอบยาว
```

### 🔍 Troubleshooting

#### Ollama ไม่ทำงาน

```bash
# ตรวจสอบ service
ps aux | grep ollama

# รัน Ollama
ollama serve

# ทดสอบ
curl http://localhost:11434/api/tags
```

#### Model ช้า

```bash
# ลด context window
ollama run mixtral:latest --num-ctx 2048

# หรือใช้ model เล็กกว่า
ollama pull mistral:latest
```

#### Out of Memory

```bash
# ใช้ quantized version
ollama pull mixtral:8x7b-instruct-v0.1-q4_0

# หรือใช้ model เล็กกว่า
ollama pull llama3.2:latest
```

### 📚 Integration with Framework

#### ใช้ใน Agents

```python
# agents/your_agent.py
from dlnk_ai_system_local import dLNkAISystem

class YourAgent(BaseAgent):
    def __init__(self):
        super().__init__()
        self.ai = dLNkAISystem()
    
    async def execute(self, directive, context):
        # ใช้ AI วางแผน
        plan = self.ai.generate_attack_plan(context)
        
        # Execute based on plan
        ...
```

#### ใช้ใน Workflows

```yaml
# workflows/ai_powered_attack.yaml
phases:
  - name: "AI Planning"
    agents:
      - name: "ai_planner"
        directive: "Generate attack plan using AI"
  
  - name: "Execute Plan"
    agents:
      - name: "executor"
        directive: "Execute AI-generated plan"
```

### 🎯 Best Practices

1. **ใช้ Mixtral สำหรับ complex tasks** - คุณมีแล้ว!
2. **ใช้ Mistral สำหรับ simple tasks** - เร็วกว่า
3. **Cache responses** - ประหยัดเวลา
4. **Validate AI output** - ตรวจสอบก่อนใช้
5. **Monitor performance** - ดู response time

### 📖 Examples

#### Example 1: Reconnaissance Planning

```python
ai = dLNkAISystem()

result = ai.generate_attack_plan({
    "target": "https://localhost:8000",
    "type": "Web Application",
    "technology": "React + Node.js + MongoDB"
})

# ได้ plan ครบ 3 phases
# - Reconnaissance
# - Exploitation  
# - Post-Exploitation
```

#### Example 2: Exploit Generation

```python
result = ai.analyze_vulnerability({
    "type": "IDOR",
    "details": "User ID in API endpoint not validated",
    "severity": "High"
})

# ได้ exploit method + payload
```

#### Example 3: Report Writing

```python
result = ai.generate_report({
    "target": "localhost:8000",
    "vulnerabilities": [
        {"type": "SQL Injection", "severity": "Critical"},
        {"type": "XSS", "severity": "Medium"}
    ],
    "findings": "..."
})

# ได้รายงานแบบสมบูรณ์
```

### ✅ Summary

**คุณพร้อมใช้งาน Local LLM แล้ว!**

- ✅ Mixtral installed (26GB)
- ✅ Configuration ready
- ✅ AI System ready
- ✅ Examples provided

**เริ่มใช้งาน:**

```bash
python3 dlnk_ai_system_local.py
```

---

**Powered by dLNk Framework** 🌈

**Made with ❤️ for Offensive Security**

