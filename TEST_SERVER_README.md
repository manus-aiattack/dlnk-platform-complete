# Standalone Test Server - Quick Start Guide

## การรัน Test Server

### 1. ติดตั้ง Dependencies

```bash
pip install fastapi uvicorn pydantic
```

### 2. เริ่ม Server

```bash
cd /home/ubuntu/aiprojectattack
python3 standalone_test_server.py
```

Server จะรันที่ `http://localhost:8000`

### 3. เข้าถึงเอกสาร API

เปิดเบราว์เซอร์และเข้าไปที่:
- **Swagger UI:** http://localhost:8000/docs
- **Homepage:** http://localhost:8000/

## API Keys สำหรับทดสอบ

ใช้ API Keys เหล่านี้ในการทดสอบ (ใส่ใน Header `X-API-Key`):

- **Admin:** `admin_test_key`
- **User:** `user_test_key`

## ตัวอย่างการใช้งาน API

### 1. สร้าง Target

```bash
curl -X POST "http://localhost:8000/api/targets?name=MyTarget&url=http://example.com&description=Test" \
  -H "X-API-Key: admin_test_key"
```

**Response:**
```json
{
    "target_id": "uuid-here",
    "name": "MyTarget",
    "url": "http://example.com/",
    "description": "Test",
    "created_at": "2025-10-26T..."
}
```

### 2. ดูรายการ Targets

```bash
curl -X GET "http://localhost:8000/api/targets" \
  -H "X-API-Key: admin_test_key"
```

### 3. เริ่ม Attack Campaign

```bash
curl -X POST "http://localhost:8000/api/campaigns/start?target_id=<target_id>&campaign_name=MyCampaign" \
  -H "X-API-Key: admin_test_key"
```

**Response:**
```json
{
    "campaign_id": "uuid-here",
    "name": "MyCampaign",
    "status": "running",
    "current_phase": "reconnaissance",
    "progress": 0.0,
    "started_at": "..."
}
```

### 4. ตรวจสอบสถานะ Campaign

```bash
curl -X GET "http://localhost:8000/api/campaigns/<campaign_id>/status" \
  -H "X-API-Key: admin_test_key"
```

**Response (หลังจากรันเสร็จ ~6 วินาที):**
```json
{
    "campaign_id": "uuid-here",
    "status": "completed",
    "current_phase": "exploitation",
    "progress": 100.0
}
```

### 5. ดูผลลัพธ์ Campaign

```bash
curl -X GET "http://localhost:8000/api/campaigns/<campaign_id>" \
  -H "X-API-Key: admin_test_key"
```

**Response:**
```json
{
    "campaign_id": "uuid-here",
    "status": "completed",
    "progress": 100.0,
    "results": {
        "vulnerabilities_found": 3,
        "exploits_successful": 1,
        "summary": "Mock attack completed successfully"
    }
}
```

## การทำงานของ Mock Campaign

Campaign จะผ่าน 3 phases:
1. **Reconnaissance** (2 วินาที)
2. **Vulnerability Discovery** (2 วินาที)
3. **Exploitation** (2 วินาที)

รวมเวลาทั้งหมด ~6 วินาที และจะส่งผลลัพธ์ที่เป็น mock data กลับมา

## API Endpoints ที่ใช้งานได้

### Target Management
- `POST /api/targets` - สร้าง target ใหม่
- `GET /api/targets` - ดูรายการ targets ทั้งหมด
- `GET /api/targets/{target_id}` - ดูรายละเอียด target
- `DELETE /api/targets/{target_id}` - ลบ target

### Campaign Management
- `POST /api/campaigns/start` - เริ่ม campaign ใหม่
- `GET /api/campaigns` - ดูรายการ campaigns ทั้งหมด
- `GET /api/campaigns/{campaign_id}` - ดูรายละเอียด campaign
- `GET /api/campaigns/{campaign_id}/status` - ดูสถานะ campaign
- `POST /api/campaigns/{campaign_id}/stop` - หยุด campaign

### System
- `GET /health` - ตรวจสอบสถานะระบบ
- `GET /` - หน้าแรก (HTML)

## หมายเหตุ

- นี่เป็น Test Server ที่ใช้ Mock Services ไม่มีการโจมตีจริง
- ข้อมูลจะถูกเก็บใน Memory เท่านั้น จะหายเมื่อปิด Server
- เหมาะสำหรับการพัฒนาและทดสอบ API

