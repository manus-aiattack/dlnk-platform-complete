# 🚀 dLNk dLNk Framework - เริ่มใช้งาน

**Powered by dLNk Framework** 🌈

---

## ⚡ Quick Start (คำสั่งเดียวจบ)

```bash
# ติดตั้ง
./install.sh

# ทดสอบทุกอย่าง (คำสั่งเดียว)
python3 test_all.py
```

**เท่านี้เอง!**

---

## 📋 สิ่งที่ test_all.py จะทดสอบ

1. ✅ **Ollama** - ตรวจสอบว่า Ollama ทำงานอยู่หรือไม่
2. ✅ **Agents** - โหลด agents ทั้งหมด (113 agents)
3. ✅ **AI System** - ทดสอบ Mixtral ตอบคำถาม
4. ✅ **Workflow** - ตรวจสอบ workflow engine

---

## 🎯 ถ้าผ่านทุก Test

```bash
# ใช้ AI System
python3 dlnk_ai_system_local.py

# ใช้ Framework
python3 main.py --help
```

---

## ⚠️ ถ้า Test ไม่ผ่าน

### Ollama ไม่ทำงาน

```bash
# รัน Ollama (terminal ใหม่)
ollama serve
```

### ไม่มี Mixtral

```bash
# ดาวน์โหลด Mixtral
ollama pull mixtral:latest
```

---

## 📚 ไฟล์สำคัญ

- `test_all.py` - **ทดสอบทุกอย่าง (รันไฟล์นี้)**
- `dlnk_ai_system_local.py` - ใช้ AI System
- `llm_config.py` - Config LLM
- `main.py` - Framework entry point

---

## 🎉 สรุป

**คำสั่งเดียวทดสอบทุกอย่าง:**

```bash
python3 test_all.py
```

**เท่านี้คุณจะรู้ว่า:**
- Framework ทำงานหรือไม่
- AI ใช้งานได้หรือไม่
- Agents โหลดครบหรือไม่
- Workflow พร้อมหรือไม่

---

**Made with ❤️ for Offensive Security**

