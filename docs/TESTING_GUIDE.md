# Testing Guide

คู่มือการทดสอบสำหรับ dLNk Attack Platform

---

## ภาพรวม

คู่มือนี้ครอบคลุมการทดสอบทุกระดับ:

- **Unit Testing** - ทดสอบ functions และ classes แต่ละตัว
- **Integration Testing** - ทดสอบการทำงานร่วมกันของ components
- **API Testing** - ทดสอบ REST API endpoints
- **Agent Testing** - ทดสอบ attack agents
- **Load Testing** - ทดสอบประสิทธิภาพภายใต้ load สูง
- **End-to-End Testing** - ทดสอบ workflow ทั้งหมด

---

## ความต้องการของระบบ

```bash
# ติดตั้ง testing dependencies
pip install pytest pytest-asyncio pytest-cov httpx faker locust
```

---

## Unit Testing

### โครงสร้างไฟล์

```
tests/
├── unit/
│   ├── test_database.py
│   ├── test_auth.py
│   ├── test_agents.py
│   └── test_utils.py
├── integration/
│   ├── test_api.py
│   └── test_workflow.py
└── conftest.py
```

### ตัวอย่าง Unit Test

```python
# tests/unit/test_database.py
import pytest
from api.services.database_sqlite import DatabaseSQLite

@pytest.mark.asyncio
async def test_create_user():
    db = DatabaseSQLite()
    await db.connect()
    
    # Create user
    api_key = await db.create_user("testuser", "user", 100)
    
    # Verify
    user = await db.get_user_by_api_key(api_key)
    assert user is not None
    assert user["username"] == "testuser"
    assert user["role"] == "user"
    
    await db.disconnect()

@pytest.mark.asyncio
async def test_create_attack():
    db = DatabaseSQLite()
    await db.connect()
    
    # Create user first
    api_key = await db.create_user("testuser", "user", 100)
    user = await db.get_user_by_api_key(api_key)
    
    # Create attack
    attack_data = {
        "attack_id": "test-123",
        "user_id": user["id"],
        "target_url": "https://example.com",
        "attack_type": "full_auto",
        "status": "pending"
    }
    
    attack_id = await db.create_attack(attack_data)
    assert attack_id > 0
    
    # Verify
    attack = await db.get_attack("test-123")
    assert attack is not None
    assert attack["target_url"] == "https://example.com"
    
    await db.disconnect()
```

### รัน Unit Tests

```bash
# รันทุก tests
pytest tests/unit/

# รันแบบมี coverage report
pytest tests/unit/ --cov=api --cov-report=html

# รัน specific test file
pytest tests/unit/test_database.py

# รันแบบ verbose
pytest tests/unit/ -v
```

---

## API Testing

### ตัวอย่าง API Test

```python
# tests/integration/test_api.py
import pytest
from httpx import AsyncClient
from api.main import app

@pytest.mark.asyncio
async def test_health_check():
    async with AsyncClient(app=app, base_url="http://test") as client:
        response = await client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"

@pytest.mark.asyncio
async def test_start_attack_unauthorized():
    async with AsyncClient(app=app, base_url="http://test") as client:
        response = await client.post("/api/attack/start", json={
            "target_url": "https://example.com",
            "attack_type": "full_auto"
        })
        assert response.status_code == 401

@pytest.mark.asyncio
async def test_start_attack_with_key():
    # สร้าง test API key
    from api.services.database_sqlite import DatabaseSQLite
    db = DatabaseSQLite()
    await db.connect()
    api_key = await db.create_user("testuser", "user", 100)
    await db.disconnect()
    
    async with AsyncClient(app=app, base_url="http://test") as client:
        response = await client.post(
            "/api/attack/start",
            json={
                "target_url": "https://example.com",
                "attack_type": "full_auto"
            },
            headers={"X-API-Key": api_key}
        )
        assert response.status_code == 200
        assert "attack_id" in response.json()
```

### รัน API Tests

```bash
pytest tests/integration/test_api.py -v
```

---

## Agent Testing

### ทดสอบ Agent แต่ละตัว

```python
# tests/unit/test_agents.py
import pytest
from agents.sqlmap_agent import SQLMapAgent

@pytest.mark.asyncio
async def test_sqlmap_agent():
    agent = SQLMapAgent()
    
    # Test initialization
    assert agent.name == "SQLMapAgent"
    assert agent.description is not None
    
    # Test scan (simulation mode)
    result = await agent.scan("https://example.com?id=1", simulation=True)
    assert result is not None
    assert "vulnerabilities" in result

@pytest.mark.asyncio
async def test_xss_hunter():
    from agents.xss_hunter import XSSHunter
    agent = XSSHunter()
    
    result = await agent.scan("https://example.com", simulation=True)
    assert result is not None
```

### ทดสอบ Agent Integration

```bash
# สร้างไฟล์ test_agent_integration.py
python3 tests/test_agent_integration.py
```

---

## Load Testing

### ใช้ Locust

สร้างไฟล์ `locustfile.py`:

```python
from locust import HttpUser, task, between

class DLNkUser(HttpUser):
    wait_time = between(1, 3)
    
    def on_start(self):
        # Login และรับ API key
        self.api_key = "your-test-api-key"
    
    @task(3)
    def health_check(self):
        self.client.get("/health")
    
    @task(1)
    def start_attack(self):
        self.client.post(
            "/api/attack/start",
            json={
                "target_url": "https://example.com",
                "attack_type": "full_auto"
            },
            headers={"X-API-Key": self.api_key}
        )
    
    @task(2)
    def get_history(self):
        self.client.get(
            "/api/attack/history",
            headers={"X-API-Key": self.api_key}
        )
```

### รัน Load Test

```bash
# เริ่ม API server
uvicorn api.main:app --host 0.0.0.0 --port 8000

# รัน Locust
locust -f locustfile.py --host=http://localhost:8000

# เปิด Web UI ที่ http://localhost:8089
```

### Load Test แบบ Headless

```bash
# 100 users, spawn rate 10/sec, run for 60 seconds
locust -f locustfile.py --host=http://localhost:8000 \
    --users 100 --spawn-rate 10 --run-time 60s --headless
```

---

## Performance Testing

### Benchmark API Endpoints

```python
# tests/performance/test_benchmark.py
import asyncio
import time
from httpx import AsyncClient

async def benchmark_endpoint(url, requests=100):
    async with AsyncClient() as client:
        start = time.time()
        
        tasks = [client.get(url) for _ in range(requests)]
        responses = await asyncio.gather(*tasks)
        
        end = time.time()
        duration = end - start
        
        print(f"Requests: {requests}")
        print(f"Duration: {duration:.2f}s")
        print(f"RPS: {requests/duration:.2f}")
        print(f"Avg latency: {duration/requests*1000:.2f}ms")

# Run
asyncio.run(benchmark_endpoint("http://localhost:8000/health", 1000))
```

---

## End-to-End Testing

### Full Workflow Test

```python
# tests/e2e/test_full_workflow.py
import pytest
from httpx import AsyncClient

@pytest.mark.asyncio
async def test_full_attack_workflow():
    """ทดสอบ workflow ทั้งหมด: สร้าง user -> start attack -> check status -> get results"""
    
    # 1. สร้าง user
    from api.services.database_sqlite import DatabaseSQLite
    db = DatabaseSQLite()
    await db.connect()
    api_key = await db.create_user("e2e_user", "user", 100)
    
    async with AsyncClient(base_url="http://localhost:8000") as client:
        # 2. Start attack
        response = await client.post(
            "/api/attack/start",
            json={
                "target_url": "https://example.com",
                "attack_type": "full_auto"
            },
            headers={"X-API-Key": api_key}
        )
        assert response.status_code == 200
        attack_id = response.json()["attack_id"]
        
        # 3. Check status
        response = await client.get(
            f"/api/attack/{attack_id}/status",
            headers={"X-API-Key": api_key}
        )
        assert response.status_code == 200
        
        # 4. Get logs
        response = await client.get(
            f"/api/attack/{attack_id}/logs",
            headers={"X-API-Key": api_key}
        )
        assert response.status_code == 200
        
        # 5. Get files
        response = await client.get(
            f"/api/attack/{attack_id}/files",
            headers={"X-API-Key": api_key}
        )
        assert response.status_code == 200
    
    await db.disconnect()
```

---

## Continuous Integration (CI)

### GitHub Actions

สร้างไฟล์ `.github/workflows/test.yml`:

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v2
    
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: 3.11
    
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
        pip install pytest pytest-asyncio pytest-cov
    
    - name: Run tests
      run: |
        pytest tests/ --cov=api --cov-report=xml
    
    - name: Upload coverage
      uses: codecov/codecov-action@v2
      with:
        file: ./coverage.xml
```

---

## Test Coverage

### Generate Coverage Report

```bash
# HTML report
pytest tests/ --cov=api --cov-report=html

# เปิดดู report
open htmlcov/index.html
```

### Coverage Goals

- **Overall:** > 80%
- **Critical modules:** > 90%
- **API routes:** > 85%
- **Database:** > 90%

---

## Debugging Tests

### ใช้ pytest debugger

```bash
# รันแบบ debug mode
pytest tests/ --pdb

# Stop on first failure
pytest tests/ -x

# Show print statements
pytest tests/ -s
```

### ใช้ VS Code

สร้างไฟล์ `.vscode/launch.json`:

```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Python: Pytest",
            "type": "python",
            "request": "launch",
            "module": "pytest",
            "args": ["tests/", "-v"],
            "console": "integratedTerminal"
        }
    ]
}
```

---

## Best Practices

1. **ใช้ Fixtures** - สร้าง reusable test data
2. **Mock External Services** - ไม่ควรเรียก external APIs จริง
3. **Test Isolation** - แต่ละ test ต้องไม่ depend กัน
4. **Descriptive Names** - ตั้งชื่อ test ให้ชัดเจน
5. **Fast Tests** - Unit tests ควรรันเร็ว (< 1s per test)
6. **CI Integration** - รัน tests อัตโนมัติทุก commit

---

## Troubleshooting

### Tests Fail Randomly

- ตรวจสอบ race conditions
- ใช้ `pytest-xdist` สำหรับ parallel testing
- เพิ่ม delays ใน async tests

### Database Conflicts

- ใช้ separate test database
- Clean up หลังแต่ละ test
- ใช้ transactions และ rollback

### Slow Tests

- ใช้ `pytest-benchmark` เพื่อหา bottlenecks
- Mock slow operations
- ใช้ in-memory database สำหรับ tests

---

## การติดต่อ

หากพบปัญหา:

- **GitHub Issues:** [Repository Issues](https://github.com/yourusername/dlnk-platform/issues)
- **Documentation:** [Full Docs](../README.md)

---

**อัพเดทล่าสุด:** 2025-10-26  
**Version:** 2.0.0

