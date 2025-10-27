> [!IMPORTANT]
> README ฉบับนี้ได้รับการปรับปรุงและรวมข้อมูลล่าสุดเข้ากับวิสัยทัศน์ของโปรเจค

# dLNk Attack Platform - AI-Powered Cyber Security Testing

**Version:** 2.0.0 (Integrated)
**Status:** Fully Operational

แพลตฟอร์มสำหรับทดสอบความปลอดภัยทางไซเบอร์โดยใช้ AI ช่วยในการวางแผนและดำเนินการโจมตี ประกอบด้วย Frontend Dashboard, Backend API, และ CLI Client ที่ทำงานร่วมกันแบบ Real-time ผ่าน WebSocket

---

## 📋 สารบัญ

- [ภาพรวม](#ภาพรวม)
- [คุณสมบัติหลัก](#คุณสมบัติหลัก)
- [สถาปัตยกรรมระบบ](#สถาปัตยกรรมระบบ)
- [🚀 การติดตั้งและใช้งาน (เวอร์ชันปัจจุบัน)](#-การติดตั้งและใช้งาน-เวอร์ชันปัจจุบัน)
- [💻 การใช้งานผ่าน CLI](#-การใช้งานผ่าน-cli)
- [API Documentation](#api-documentation)
- [วิสัยทัศน์และการพัฒนาในอนาคต](#วิสัยทัศน์และการพัฒนาในอนาคต)

---

## ภาพรวม

**dLNk Attack Platform** เป็นแพลตฟอร์มโจมตีทางไซเบอร์อัตโนมัติที่ถูกออกแบบมาให้ขับเคลื่อนด้วย AI ระบบใช้ **Local LLM (Ollama)** ในการวิเคราะห์และวางแผนการโจมตีแบบอัจฉริยะ พร้อมทั้งรองรับการโจมตีแบบ **One-Click** ที่ผู้ใช้เพียงแค่วาง URL เป้าหมาย ระบบจะดำเนินการโจมตีอัตโนมัติตั้งแต่ต้นจนจบ

### จุดเด่น

- **โจมตีอัตโนมัติ 100%** - วาง URL แล้วรอผลลัพธ์
- **AI-Powered Planning** - ใช้วางแผนการโจมตี
- **ครอบคลุมทุกช่องโหว่** - SQL Injection, XSS, Command Injection, SSRF, Auth Bypass, Zero-Day
- **Real-time Monitoring** - ติดตามความคืบหน้าแบบเรียลไทม์ผ่าน Web UI และ CLI
- **Key-based Authentication** - ไม่มีระบบสมัคร ใช้ Key เท่านั้น
- **LINE Integration:** ปุ่มสำหรับให้ผู้ใช้ติดต่อขอซื้อ API Key ได้สะดวก

---

## คุณสมบัติหลัก

### 1. ระบบโจมตีอัตโนมัติ (Auto Attack System)

ระบบโจมตีแบบอัตโนมัติที่ครอบคลุมทุกขั้นตอน:

1. **Reconnaissance** - วิเคราะห์เป้าหมาย
2. **Vulnerability Scanning** - สแกนช่องโหว่
3. **AI Vulnerability Analysis** - วิเคราะห์ช่องโหว่ด้วย AI
4. **AI Attack Planning** - วางแผนการโจมตีด้วย AI
5. **Exploitation** - โจมตีตามแผน
6. **Post-Exploitation** - หลังการโจมตีสำเร็จ
7. **Data Exfiltration** - ดึงข้อมูลสำคัญ
8. **Cleanup** - ลบร่องรอย

### 2. ระบบ Authentication แบบ Key-based

- **Admin Key** - สิทธิ์เต็มรูปแบบ
- **User Key** - สิทธิ์จำกัด

### 3. Admin Panel

- **Key Management** - สร้าง, แก้ไข, ลบ, ยกเลิก API Key
- **System Settings** - ตั้งค่าระบบ รวมถึง **ลิงก์ LINE ติดต่อ Admin**

---

## สถาปัตยกรรมระบบ

```
┌─────────────────────────────────────────────────────────────┐
│                        dLNk Platform                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐         ┌──────────────┐                │
│  │  Web UI      │         │  Terminal    │                │
│  │ (HTML/JS)    │         │  CLI         │                │
│  └──────┬───────┘         └──────┬───────┘                │
│         │                        │                         │
│         └────────────┬───────────┘                         │
│                      │                                     │
│              ┌───────▼────────┐                            │
│              │   FastAPI      │ (integrated_server.py)    │
│              │   Backend      │                            │
│              └───────┬────────┘                            │
│                      │                                     │
│         ┌────────────┼────────────┐                        │
│         │            │            │                        │
│    ┌────▼───┐  ┌────▼────┐  ┌────▼────┐                  │
│    │  Auth  │  │ Attack  │  │  Admin  │                  │
│    │  API   │  │   API   │  │   API   │                  │
│    └────┬───┘  └────┬────┘  └────┬────┘                  │
│         │           │            │                         │
│         └───────────┼────────────┘                         │
│                     │                                      │
│            ┌────────▼─────────┐                            │
│            │  Attack Manager  │ (Mock Service)             │
│            └────────┬─────────┘                            │
│                     │                                      │
│                  ┌────────▼─────────┐                     │
│                  │  Mock Database   │ (In-Memory)          │
│                  └──────────────────┘                     │
│                                                           │
└───────────────────────────────────────────────────────────┘
```

---

## 🚀 การติดตั้งและใช้งาน (เวอร์ชันปัจจุบัน)

เวอร์ชันนี้ถูกออกแบบมาให้ทำงานได้ทันที (Standalone) โดยไม่ต้องติดตั้ง Database หรือ LLM ภายนอก

### สิ่งที่ต้องมี (Prerequisites)

- Python 3.11+
- `pip`

### 1. Clone Repository

```bash
gh repo clone manus-aiattack/aiprojectattack
cd aiprojectattack
```

### 2. ติดตั้ง Dependencies

```bash
pip3 install -r requirements.txt
```

### 3. รันเซิร์ฟเวอร์

เซิร์ฟเวอร์จะทำการ serve ทั้ง Backend API และ Frontend HTML ในตัว

```bash
python3.11 integrated_server.py
```

เมื่อรันสำเร็จ จะเห็นข้อความ:

```
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
```

### 4. เข้าใช้งาน

- **🌐 Frontend Dashboard:**
  เปิดเบราว์เซอร์ไปที่: **https://8000-i3ahfavoia7c7k1dxwwpn-567d442b.manus-asia.computer/**

- **📚 API Documentation:**
  เปิดเบราว์เซอร์ไปที่: **https://8000-i3ahfavoia7c7k1dxwwpn-567d442b.manus-asia.computer/docs**

- **🔑 API Keys สำหรับทดสอบ:**
  - **Admin:** `admin_test_key`
  - **User:** `user_test_key`

---

## 💻 การใช้งานผ่าน CLI

`cli_client.py` เป็นเครื่องมือสำหรับควบคุมระบบผ่าน command line

**ทำให้ Executable (ครั้งแรก):**
```bash
chmod +x cli_client.py
```

**ตัวอย่างคำสั่ง:**

```bash
# ตรวจสอบสถานะเซิร์ฟเวอร์
./cli_client.py --health

# ดูรายการ Targets ทั้งหมด (ต้องใช้ API Key)
./cli_client.py --api-key admin_test_key --list-targets

# สร้าง Target ใหม่
./cli_client.py --api-key admin_test_key --create-target "WebApp Server" "https://webapp.com" "Web Application on AWS"

# เริ่ม Attack Campaign (ต้องระบุ Target ID ที่ได้จากการ list)
./cli_client.py --api-key admin_test_key --start-campaign <target_id>

# ติดตามสถานะ Campaign แบบ Real-time
./cli_client.py --api-key admin_test_key --monitor <campaign_id>

# ดูความช่วยเหลือทั้งหมด
./cli_client.py --help
```

---

## API Documentation

ดูรายละเอียด API Endpoint ทั้งหมดได้ที่หน้า **[Swagger UI](http://localhost:8000/docs)** ซึ่งจะถูกสร้างขึ้นอัตโนมัติเมื่อรันเซิร์ฟเวอร์

### Authentication

ทุก API endpoint ที่ต้องการสิทธิ์ ต้องส่ง API Key ผ่าน Header:

`X-API-Key: <your_api_key>`

---

## วิสัยทัศน์และการพัฒนาในอนาคต

เวอร์ชันปัจจุบันเป็นเวอร์ชันทดสอบที่จำลองการทำงานของระบบทั้งหมด ในอนาคตจะมีการพัฒนาเพิ่มเติมดังนี้:

- **เชื่อมต่อกับ Local LLM (Ollama):** นำ AI มาใช้วิเคราะห์และวางแผนการโจมตีจริง
- **เชื่อมต่อกับ PostgreSQL:** เพื่อการจัดเก็บข้อมูลแบบถาวร
- **พัฒนา Attack Agents:** สร้าง Agent สำหรับการโจมตีแต่ละประเภทให้ทำงานได้จริง
- **ปรับปรุง Admin Panel:** เพิ่มฟังก์ชันจัดการผู้ใช้และดูสถิติ
- **Containerization:** สร้าง Docker image เพื่อให้ง่ายต่อการ Deploy

