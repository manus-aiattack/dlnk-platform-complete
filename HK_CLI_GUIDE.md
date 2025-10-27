# HK CLI - Hacker Knowledge Command Line Interface

## ภาพรวม

`hk` คือ AI Assistant แบบ CLI สำหรับโปรเจค dLNk Attack Platform ที่ออกแบบมาเพื่อใช้งานใน Sandbox โดยตรง

## เวอร์ชันที่มี

### 1. hk_stream.py (เวอร์ชันปัจจุบัน) ⭐

**วิธีการทำงาน:**
- ใช้ **stdin/stdout** สื่อสารกับ Manus AI โดยตรง
- ไม่ต้องใช้ API key
- ทำงานผ่าน IPC (Inter-Process Communication)

**Flow:**
```
User → hk → stdout (JSON) → Manus AI → stdin (JSON) → hk → User
```

**การใช้งาน:**
```bash
hk
```

**ข้อดี:**
- ✅ ไม่ต้องใช้ API key
- ✅ คุยกับ Manus AI โดยตรง
- ✅ บันทึกประวัติอัตโนมัติ
- ✅ ใช้งานได้เฉพาะใน Sandbox

**ข้อเสีย:**
- ❌ ต้องมี Manus AI รับ/ส่งข้อมูลผ่าน stdin/stdout
- ❌ ใช้งานได้เฉพาะใน Sandbox environment

---

### 2. hk_cli.py (Full AI Assistant)

**วิธีการทำงาน:**
- ใช้ OpenAI API (gpt-4.1-mini)
- รองรับ function calling (สร้างไฟล์, รันคำสั่ง)
- Streaming response

**การใช้งาน:**
```bash
# ต้องตั้งค่า OPENAI_API_KEY ก่อน
export OPENAI_API_KEY="your-key"
hk
```

**ข้อดี:**
- ✅ ทำงานได้เต็มรูปแบบ
- ✅ สามารถสร้าง/แก้ไขไฟล์
- ✅ รันคำสั่ง shell
- ✅ ใช้งานได้ทุกที่

**ข้อเสีย:**
- ❌ ต้องใช้ API key
- ❌ เสียค่าใช้จ่าย OpenAI

---

### 3. hk_simple.py (Manual Logger)

**วิธีการทำงาน:**
- User พิมพ์คำถาม
- คัดลอกไปถาม Manus ในหน้าต่างหลัก
- วางคำตอบกลับมา
- บันทึกการสนทนา

**การใช้งาน:**
```bash
hk
You: สรุปโปรเจค dLNk
[คัดลอกไปถาม Manus]
Manus Answer (paste here): [วางคำตอบ]
```

**ข้อดี:**
- ✅ ไม่ต้องใช้ API key
- ✅ ง่ายที่สุด
- ✅ บันทึกประวัติ

**ข้อเสีย:**
- ❌ ต้องคัดลอก/วางด้วยตนเอง
- ❌ ไม่มี automation

---

## คำสั่งที่ใช้ได้ทุกเวอร์ชัน

### คำสั่งพื้นฐาน

```bash
# เริ่มใช้งาน
hk

# ออกจากโปรแกรม
You: exit
You: quit
You: q

# ล้างประวัติการสนทนา
You: clear

# แสดงความช่วยเหลือ
You: help

# แสดงประวัติการสนทนา
You: history

# ส่งออกประวัติเป็น Markdown
You: export
```

### ตัวอย่างการใช้งาน

**💬 พูดคุยทั่วไป:**
```
You: สรุปภาพรวมโปรเจค dLNk
You: อธิบาย SQL injection
You: วิธีใช้ Docker
```

**📝 สร้างและแก้ไขไฟล์:** (เฉพาะ hk_cli.py)
```
You: สร้างไฟล์ test.py ที่ print hello world
You: แก้ไข config.json เพิ่ม timeout เป็น 30
You: เขียน script Python สำหรับ scan ports
```

**⚡ รันคำสั่ง:** (เฉพาะ hk_cli.py)
```
You: ตรวจสอบ process ที่ทำงานอยู่
You: ติดตั้ง package requests
You: restart service dlnk-platform
```

**🎯 ระบบ dLNk:**
```
You: ตรวจสอบสถานะระบบ
You: สร้าง reverse shell payload
You: วิธีใช้งาน C2
You: เริ่มโจมตี target.com
```

---

## ไฟล์ประวัติ

ประวัติการสนทนาจะถูกเก็บที่:

```
~/.hk_history/
├── conversation.json          # ประวัติการสนทนา (JSON)
└── export_YYYYMMDD_HHMMSS.md  # ไฟล์ export (Markdown)
```

### โครงสร้างไฟล์ประวัติ

```json
{
  "timestamp": "2025-10-26T19:30:00",
  "messages": [
    {
      "role": "user",
      "content": "สรุปโปรเจค dLNk",
      "timestamp": "2025-10-26 19:30:00"
    },
    {
      "role": "assistant",
      "content": "โปรเจค dLNk คือ...",
      "timestamp": "2025-10-26 19:30:15"
    }
  ]
}
```

---

## การติดตั้ง

### ติดตั้งอัตโนมัติ

```bash
cd /home/ubuntu/aiprojectattack
chmod +x hk_stream.py
sudo ln -sf /home/ubuntu/aiprojectattack/hk_stream.py /usr/local/bin/hk
```

### ติดตั้ง dependencies

```bash
pip3 install rich
```

---

## การพัฒนาต่อ

### เพิ่มคำสั่งใหม่

แก้ไขฟังก์ชัน `execute_command()`:

```python
def execute_command(self, command: str) -> bool:
    cmd = command.strip().lower()
    
    if cmd == 'mycommand':
        # ทำอะไรสักอย่าง
        return True
    
    return None
```

### เพิ่มฟีเจอร์ใหม่

1. เพิ่ม method ใหม่ใน class
2. เรียกใช้จาก `run()` loop
3. บันทึกประวัติด้วย `_save_history()`

---

## Troubleshooting

### ปัญหา: hk ไม่ทำงาน

```bash
# ตรวจสอบว่าติดตั้งแล้ว
which hk

# ตรวจสอบ permissions
ls -la /usr/local/bin/hk

# ติดตั้งใหม่
sudo ln -sf /home/ubuntu/aiprojectattack/hk_stream.py /usr/local/bin/hk
```

### ปัญหา: API key error (hk_cli.py)

```bash
# ตรวจสอบ API key
echo $OPENAI_API_KEY

# ตั้งค่า API key
export OPENAI_API_KEY="your-key"
```

### ปัญหา: ไม่สามารถบันทึกประวัติ

```bash
# ตรวจสอบ permissions
ls -la ~/.hk_history/

# สร้างโฟลเดอร์ใหม่
mkdir -p ~/.hk_history
chmod 755 ~/.hk_history
```

---

## สรุป

| เวอร์ชัน | API Key | Automation | ใช้งานที่ | แนะนำ |
|---------|---------|-----------|----------|------|
| **hk_stream.py** | ❌ | ✅ | Sandbox | ⭐⭐⭐⭐⭐ |
| **hk_cli.py** | ✅ | ✅ | ทุกที่ | ⭐⭐⭐⭐ |
| **hk_simple.py** | ❌ | ❌ | ทุกที่ | ⭐⭐⭐ |

**แนะนำ:** ใช้ `hk_stream.py` สำหรับงานใน Sandbox เพราะไม่ต้องใช้ API key และคุยกับ Manus AI โดยตรง

---

## ตัวอย่างการใช้งานจริง

### Scenario 1: ตรวจสอบสถานะโปรเจค

```bash
$ hk

You: ตรวจสอบสถานะโปรเจค dLNk ทั้งหมด

🤖 Manus AI:
โปรเจค dLNk Attack Platform มีความคืบหน้า 89.6%

**ส่วนที่เสร็จแล้ว:**
- Database (PostgreSQL) - 100%
- Backend API - 100% (122 endpoints)
- AI Agents - 98% (74/75 agents)
- C2 Infrastructure - 100%
- Zero-Day Hunter - 100%
- LLM Integration - 100%

**ส่วนที่ยังไม่เสร็จ:**
- Frontend - 33% (ขาดไฟล์ CSS/JS)
- Self-Healing - 75% (ขาด health check)
```

### Scenario 2: สร้างไฟล์

```bash
You: สร้างไฟล์ test_exploit.py สำหรับ SQL injection

🤖 Manus AI:
สร้างไฟล์ /home/ubuntu/aiprojectattack/test_exploit.py แล้ว

[แสดงโค้ด]
```

### Scenario 3: Export ประวัติ

```bash
You: export

✓ ส่งออกประวัติไปยัง: ~/.hk_history/export_20251026_193000.md
```

---

**Last Updated:** 2025-10-26
**Version:** 1.0.0
**Author:** dLNk Team

