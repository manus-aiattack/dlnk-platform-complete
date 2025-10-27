# Testing Guide - Agents และ Load Testing

## ภาพรวม

คู่มือนี้อธิบายวิธีการทดสอบ Agents ทั้งหมด และการทำ Load Testing สำหรับระบบ dLNk Attack Platform

## 1. การทดสอบ Agents แต่ละตัว

### ดูรายชื่อ Agents ทั้งหมด

```bash
cd manus
./dlnk agents
```

### ทดสอบ Agent เดี่ยว

```bash
# ทดสอบ SQLMap Agent
./dlnk agent sqlmap_agent scan --url https://testphp.vulnweb.com

# ทดสอบ XSS Hunter
./dlnk agent xss_hunter scan --url https://xss-game.appspot.com

# ทดสอบ Command Injection
./dlnk agent command_injection_exploiter scan --url http://vulnerable-site.com

# ทดสอบ SSRF Agent
./dlnk agent ssrf_agent scan --url http://vulnerable-site.com

# ทดสอบ Auth Bypass Agent
./dlnk agent authentication_bypass_agent scan --url http://vulnerable-site.com

# ทดสอบ Zero-Day Hunter
./dlnk agent zero_day_hunter full_zero_day_hunt --url http://target-site.com
```

### สร้าง Test Script สำหรับทดสอบทุก Agent

สร้างไฟล์ `test_all_agents.py`:

```python
#!/usr/bin/env python3
"""
Test all agents against safe test targets
"""

import asyncio
import sys
from core.orchestrator import Orchestrator
from agents.sqlmap_agent import SqlmapAgent
from agents.xss_hunter import XSSHunter
from agents.command_injection_exploiter import CommandInjectionExploiter
from agents.ssrf_agent_weaponized import SSRFAgentWeaponized
from agents.authentication_bypass_agent import AuthenticationBypassAgent
from advanced_agents.zero_day_hunter import ZeroDayHunterAgent

# Safe test targets
TEST_TARGETS = {
    "sql_injection": "https://testphp.vulnweb.com",
    "xss": "https://xss-game.appspot.com",
    "general": "http://testhtml5.vulnweb.com"
}

async def test_agent(agent_name, agent_class, action, target_url):
    """Test a single agent"""
    print(f"\n{'='*60}")
    print(f"Testing: {agent_name}")
    print(f"Target: {target_url}")
    print(f"Action: {action}")
    print(f"{'='*60}")
    
    try:
        agent = agent_class()
        context = {"url": target_url}
        
        result = await agent.run(action, context)
        
        if result.success:
            print(f"✅ {agent_name} - SUCCESS")
            print(f"   Data: {str(result.data)[:200]}...")
        else:
            print(f"⚠️  {agent_name} - FAILED")
            print(f"   Error: {result.error}")
        
        return result.success
        
    except Exception as e:
        print(f"❌ {agent_name} - ERROR: {e}")
        return False

async def test_all_agents():
    """Test all agents"""
    print("\n" + "="*60)
    print("dLNk Attack Platform - Agent Testing")
    print("="*60)
    
    results = {}
    
    # Test SQLMap Agent
    results["SQLMap"] = await test_agent(
        "SQLMap Agent",
        SqlmapAgent,
        "scan",
        TEST_TARGETS["sql_injection"]
    )
    
    # Test XSS Hunter
    results["XSS Hunter"] = await test_agent(
        "XSS Hunter",
        XSSHunter,
        "scan",
        TEST_TARGETS["xss"]
    )
    
    # Test Command Injection
    results["Command Injection"] = await test_agent(
        "Command Injection Exploiter",
        CommandInjectionExploiter,
        "scan",
        TEST_TARGETS["general"]
    )
    
    # Test SSRF Agent
    results["SSRF"] = await test_agent(
        "SSRF Agent",
        SSRFAgentWeaponized,
        "scan",
        TEST_TARGETS["general"]
    )
    
    # Test Auth Bypass
    results["Auth Bypass"] = await test_agent(
        "Authentication Bypass Agent",
        AuthenticationBypassAgent,
        "scan",
        TEST_TARGETS["general"]
    )
    
    # Test Zero-Day Hunter
    results["Zero-Day Hunter"] = await test_agent(
        "Zero-Day Hunter",
        ZeroDayHunterAgent,
        "quick_scan",
        TEST_TARGETS["general"]
    )
    
    # Summary
    print("\n" + "="*60)
    print("Test Summary")
    print("="*60)
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for agent, success in results.items():
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} - {agent}")
    
    print(f"\nTotal: {passed}/{total} passed")
    print("="*60)
    
    return passed == total

if __name__ == "__main__":
    result = asyncio.run(test_all_agents())
    sys.exit(0 if result else 1)
```

รันทดสอบ:

```bash
python3 test_all_agents.py
```

## 2. การทดสอบ Full Workflow

### ทดสอบ Full Auto Attack

```bash
# ใช้ CLI
./dlnk attack https://testphp.vulnweb.com --type full_auto --follow

# หรือใช้ Python
./dlnk run --target https://testphp.vulnweb.com --workflow config/attack_full_auto_workflow.yaml
```

### ทดสอบผ่าน API

สร้างไฟล์ `test_full_workflow_api.py`:

```python
#!/usr/bin/env python3
"""
Test full workflow via API
"""

import asyncio
import aiohttp
import time

API_BASE = "http://localhost:8000"
ADMIN_KEY = "your_admin_key_here"  # อ่านจาก workspace/ADMIN_KEY.txt

async def test_full_workflow():
    """Test full attack workflow"""
    
    async with aiohttp.ClientSession() as session:
        headers = {"X-API-Key": ADMIN_KEY}
        
        # 1. Start attack
        print("Starting attack...")
        async with session.post(
            f"{API_BASE}/api/attack/start",
            json={
                "target_url": "https://testphp.vulnweb.com",
                "attack_type": "full_auto",
                "options": {}
            },
            headers=headers
        ) as resp:
            result = await resp.json()
            attack_id = result["attack_id"]
            print(f"Attack started: {attack_id}")
        
        # 2. Monitor progress
        print("\nMonitoring progress...")
        for i in range(30):  # Monitor for 5 minutes
            await asyncio.sleep(10)
            
            async with session.get(
                f"{API_BASE}/api/attack/{attack_id}/status",
                headers=headers
            ) as resp:
                status = await resp.json()
                print(f"[{i*10}s] Status: {status['attack']['status']}")
                
                if status['attack']['status'] in ['success', 'failed', 'stopped']:
                    break
        
        # 3. Get results
        print("\nGetting results...")
        async with session.get(
            f"{API_BASE}/api/attack/{attack_id}/results",
            headers=headers
        ) as resp:
            results = await resp.json()
            print(f"Results: {results}")
        
        # 4. Get logs
        print("\nGetting logs...")
        async with session.get(
            f"{API_BASE}/api/attack/{attack_id}/logs",
            headers=headers
        ) as resp:
            logs = await resp.json()
            print(f"Logs: {len(logs['logs'])} entries")

if __name__ == "__main__":
    asyncio.run(test_full_workflow())
```

## 3. Load Testing

### ติดตั้ง Load Testing Tools

```bash
# ติดตั้ง locust
pip3 install locust

# หรือ
pip3 install pytest-benchmark
```

### สร้าง Load Test Script

สร้างไฟล์ `locustfile.py`:

```python
from locust import HttpUser, task, between
import random

class DLNkUser(HttpUser):
    wait_time = between(1, 5)
    
    def on_start(self):
        """Called when a user starts"""
        # อ่าน admin key
        with open("workspace/ADMIN_KEY.txt", "r") as f:
            self.api_key = f.read().strip()
        
        self.headers = {"X-API-Key": self.api_key}
    
    @task(3)
    def get_attack_history(self):
        """Get attack history (most common operation)"""
        self.client.get("/api/attack/history", headers=self.headers)
    
    @task(2)
    def get_attack_status(self):
        """Get attack status"""
        # Use a random attack ID (will return 404 but tests the endpoint)
        attack_id = f"test-{random.randint(1000, 9999)}"
        self.client.get(f"/api/attack/{attack_id}/status", headers=self.headers)
    
    @task(1)
    def start_attack(self):
        """Start a new attack (less frequent)"""
        self.client.post(
            "/api/attack/start",
            json={
                "target_url": "https://testphp.vulnweb.com",
                "attack_type": "sql_injection",
                "options": {}
            },
            headers=self.headers
        )
    
    @task(1)
    def health_check(self):
        """Health check"""
        self.client.get("/health")
```

### รัน Load Test

```bash
# เริ่ม API server ก่อน
python3 main.py server

# รัน load test (terminal ใหม่)
locust -f locustfile.py --host=http://localhost:8000

# เปิด browser ไปที่ http://localhost:8089
# ตั้งค่า:
# - Number of users: 10-100
# - Spawn rate: 1-10 users/second
```

### Load Test แบบ CLI (ไม่ใช้ Web UI)

```bash
# ทดสอบ 50 users, spawn rate 5/sec, รัน 60 วินาที
locust -f locustfile.py --host=http://localhost:8000 \
  --users 50 --spawn-rate 5 --run-time 60s --headless
```

## 4. Performance Benchmarking

### สร้าง Benchmark Script

สร้างไฟล์ `benchmark.py`:

```python
#!/usr/bin/env python3
"""
Performance benchmark for dLNk API
"""

import asyncio
import aiohttp
import time
from statistics import mean, median, stdev

API_BASE = "http://localhost:8000"
ADMIN_KEY = "your_admin_key_here"

async def benchmark_endpoint(session, endpoint, method="GET", json_data=None):
    """Benchmark a single endpoint"""
    headers = {"X-API-Key": ADMIN_KEY}
    
    times = []
    
    for i in range(100):  # 100 requests
        start = time.time()
        
        if method == "GET":
            async with session.get(f"{API_BASE}{endpoint}", headers=headers) as resp:
                await resp.read()
        elif method == "POST":
            async with session.post(f"{API_BASE}{endpoint}", json=json_data, headers=headers) as resp:
                await resp.read()
        
        elapsed = (time.time() - start) * 1000  # ms
        times.append(elapsed)
    
    return {
        "endpoint": endpoint,
        "mean": mean(times),
        "median": median(times),
        "stdev": stdev(times),
        "min": min(times),
        "max": max(times)
    }

async def run_benchmarks():
    """Run all benchmarks"""
    print("="*60)
    print("dLNk API Performance Benchmark")
    print("="*60)
    
    async with aiohttp.ClientSession() as session:
        # Benchmark health check
        result = await benchmark_endpoint(session, "/health")
        print(f"\n/health:")
        print(f"  Mean: {result['mean']:.2f}ms")
        print(f"  Median: {result['median']:.2f}ms")
        print(f"  Stdev: {result['stdev']:.2f}ms")
        print(f"  Min: {result['min']:.2f}ms")
        print(f"  Max: {result['max']:.2f}ms")
        
        # Benchmark attack history
        result = await benchmark_endpoint(session, "/api/attack/history")
        print(f"\n/api/attack/history:")
        print(f"  Mean: {result['mean']:.2f}ms")
        print(f"  Median: {result['median']:.2f}ms")
        print(f"  Stdev: {result['stdev']:.2f}ms")
        
        # Add more endpoints as needed...
    
    print("\n" + "="*60)

if __name__ == "__main__":
    asyncio.run(run_benchmarks())
```

รัน benchmark:

```bash
python3 benchmark.py
```

## 5. Integration Testing

### ทดสอบ End-to-End

สร้างไฟล์ `test_integration.py`:

```python
#!/usr/bin/env python3
"""
Integration test - Full end-to-end workflow
"""

import asyncio
import aiohttp

async def integration_test():
    """Test complete workflow from start to finish"""
    
    print("Starting integration test...")
    
    # 1. Health check
    # 2. Authentication
    # 3. Start attack
    # 4. Monitor progress
    # 5. Get results
    # 6. Get logs
    # 7. Cleanup
    
    # (Implementation similar to test_full_workflow_api.py)
    
    print("Integration test complete!")

if __name__ == "__main__":
    asyncio.run(integration_test())
```

## สรุป

**การทดสอบที่แนะนำ:**

1. **Unit Testing** - ทดสอบ Agent แต่ละตัว
2. **Integration Testing** - ทดสอบ workflow ทั้งหมด
3. **Load Testing** - ทดสอบประสิทธิภาพภายใต้ load
4. **Performance Benchmarking** - วัดความเร็วของ API endpoints

**เป้าหมายประสิทธิภาพ:**

- API response time: < 100ms (health check)
- Attack start: < 500ms
- Status check: < 200ms
- Concurrent users: 50-100 users
- Throughput: 100+ requests/second

**หมายเหตุ:**

- ใช้ safe test targets เท่านั้น (testphp.vulnweb.com, xss-game.appspot.com)
- **อย่า**ทดสอบกับเว็บไซต์จริงที่ไม่ได้รับอนุญาต
- Load testing ควรทำบน staging environment ก่อน production

