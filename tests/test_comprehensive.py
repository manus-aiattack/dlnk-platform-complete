"""
Comprehensive Test Suite
Complete testing for dLNk Attack Platform
"""

import pytest
import asyncio
from datetime import datetime
from typing import Dict, Any
import json


# ============================================================================
# Unit Tests
# ============================================================================

class TestAPIEndpoints:
    """Test API endpoints"""
    
    @pytest.mark.asyncio
    async def test_health_check(self, client):
        """Test health check endpoint"""
        response = await client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
    
    @pytest.mark.asyncio
    async def test_create_attack(self, client, api_key):
        """Test attack creation"""
        headers = {"X-API-Key": api_key}
        payload = {
            "target_url": "https://example.com",
            "mode": "auto"
        }
        
        response = await client.post("/api/v1/attacks", json=payload, headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert "attack_id" in data
        assert data["target_url"] == payload["target_url"]
    
    @pytest.mark.asyncio
    async def test_get_attack_status(self, client, api_key, attack_id):
        """Test getting attack status"""
        headers = {"X-API-Key": api_key}
        
        response = await client.get(f"/api/v1/attacks/{attack_id}", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == attack_id
        assert "status" in data
    
    @pytest.mark.asyncio
    async def test_list_attacks(self, client, api_key):
        """Test listing attacks"""
        headers = {"X-API-Key": api_key}
        
        response = await client.get("/api/v1/attacks", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
    
    @pytest.mark.asyncio
    async def test_unauthorized_access(self, client):
        """Test unauthorized access"""
        response = await client.get("/api/v1/attacks")
        assert response.status_code == 401


class TestAuthentication:
    """Test authentication"""
    
    @pytest.mark.asyncio
    async def test_valid_api_key(self, client, api_key):
        """Test valid API key"""
        headers = {"X-API-Key": api_key}
        response = await client.get("/api/v1/auth/verify", headers=headers)
        assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_invalid_api_key(self, client):
        """Test invalid API key"""
        headers = {"X-API-Key": "invalid_key"}
        response = await client.get("/api/v1/auth/verify", headers=headers)
        assert response.status_code == 401
    
    @pytest.mark.asyncio
    async def test_missing_api_key(self, client):
        """Test missing API key"""
        response = await client.get("/api/v1/auth/verify")
        assert response.status_code == 401


class TestAdminEndpoints:
    """Test admin endpoints"""
    
    @pytest.mark.asyncio
    async def test_create_api_key(self, client, admin_key):
        """Test API key creation"""
        headers = {"X-API-Key": admin_key}
        payload = {
            "name": "Test Key",
            "role": "user"
        }
        
        response = await client.post("/api/v1/admin/keys", json=payload, headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert "key" in data
    
    @pytest.mark.asyncio
    async def test_list_api_keys(self, client, admin_key):
        """Test listing API keys"""
        headers = {"X-API-Key": admin_key}
        
        response = await client.get("/api/v1/admin/keys", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
    
    @pytest.mark.asyncio
    async def test_get_statistics(self, client, admin_key):
        """Test getting statistics"""
        headers = {"X-API-Key": admin_key}
        
        response = await client.get("/api/v1/admin/stats", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert "total_attacks" in data


# ============================================================================
# Integration Tests
# ============================================================================

class TestAttackWorkflow:
    """Test complete attack workflow"""
    
    @pytest.mark.asyncio
    async def test_full_attack_lifecycle(self, client, api_key):
        """Test full attack lifecycle"""
        headers = {"X-API-Key": api_key}
        
        # 1. Create attack
        payload = {
            "target_url": "https://example.com",
            "mode": "auto"
        }
        response = await client.post("/api/v1/attacks", json=payload, headers=headers)
        assert response.status_code == 200
        attack_id = response.json()["attack_id"]
        
        # 2. Check status
        response = await client.get(f"/api/v1/attacks/{attack_id}", headers=headers)
        assert response.status_code == 200
        assert response.json()["status"] in ["pending", "running", "completed"]
        
        # 3. Wait for completion (with timeout)
        max_wait = 60
        waited = 0
        while waited < max_wait:
            response = await client.get(f"/api/v1/attacks/{attack_id}", headers=headers)
            status = response.json()["status"]
            
            if status in ["completed", "failed"]:
                break
            
            await asyncio.sleep(5)
            waited += 5
        
        # 4. Verify results
        response = await client.get(f"/api/v1/attacks/{attack_id}", headers=headers)
        data = response.json()
        assert data["status"] in ["completed", "failed"]
        assert "vulnerabilities" in data


class TestWebSocketConnection:
    """Test WebSocket connections"""
    
    @pytest.mark.asyncio
    async def test_websocket_connection(self, websocket_client):
        """Test WebSocket connection"""
        async with websocket_client.websocket_connect("/ws") as websocket:
            # Send message
            await websocket.send_json({"type": "ping"})
            
            # Receive response
            response = await websocket.receive_json()
            assert response["type"] == "pong"
    
    @pytest.mark.asyncio
    async def test_websocket_attack_updates(self, websocket_client, api_key):
        """Test receiving attack updates via WebSocket"""
        async with websocket_client.websocket_connect("/ws") as websocket:
            # Subscribe to attack updates
            await websocket.send_json({
                "type": "subscribe",
                "channel": "attacks"
            })
            
            # Create attack
            headers = {"X-API-Key": api_key}
            payload = {"target_url": "https://example.com", "mode": "auto"}
            response = await client.post("/api/v1/attacks", json=payload, headers=headers)
            attack_id = response.json()["attack_id"]
            
            # Receive update
            update = await websocket.receive_json()
            assert update["type"] == "attack_update"
            assert update["attack_id"] == attack_id


# ============================================================================
# Performance Tests
# ============================================================================

class TestPerformance:
    """Test performance"""
    
    @pytest.mark.asyncio
    async def test_concurrent_requests(self, client, api_key):
        """Test handling concurrent requests"""
        headers = {"X-API-Key": api_key}
        
        # Create 10 concurrent requests
        tasks = []
        for i in range(10):
            task = client.get("/api/v1/attacks", headers=headers)
            tasks.append(task)
        
        responses = await asyncio.gather(*tasks)
        
        # All should succeed
        for response in responses:
            assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_response_time(self, client, api_key):
        """Test response time"""
        import time
        
        headers = {"X-API-Key": api_key}
        
        start = time.time()
        response = await client.get("/api/v1/attacks", headers=headers)
        duration = time.time() - start
        
        assert response.status_code == 200
        assert duration < 1.0  # Should respond within 1 second


# ============================================================================
# Security Tests
# ============================================================================

class TestSecurity:
    """Test security"""
    
    @pytest.mark.asyncio
    async def test_sql_injection(self, client, api_key):
        """Test SQL injection protection"""
        headers = {"X-API-Key": api_key}
        
        # Try SQL injection in query parameter
        response = await client.get(
            "/api/v1/attacks?id=' OR '1'='1",
            headers=headers
        )
        
        # Should not cause error or expose data
        assert response.status_code in [200, 400, 404]
    
    @pytest.mark.asyncio
    async def test_xss_protection(self, client, api_key):
        """Test XSS protection"""
        headers = {"X-API-Key": api_key}
        payload = {
            "target_url": "<script>alert('XSS')</script>",
            "mode": "auto"
        }
        
        response = await client.post("/api/v1/attacks", json=payload, headers=headers)
        
        # Should sanitize or reject
        if response.status_code == 200:
            data = response.json()
            assert "<script>" not in str(data)
    
    @pytest.mark.asyncio
    async def test_rate_limiting(self, client, api_key):
        """Test rate limiting"""
        headers = {"X-API-Key": api_key}
        
        # Make many requests quickly
        responses = []
        for i in range(150):  # Exceed typical rate limit
            response = await client.get("/api/v1/attacks", headers=headers)
            responses.append(response)
        
        # Should eventually hit rate limit
        rate_limited = any(r.status_code == 429 for r in responses)
        assert rate_limited


# ============================================================================
# Database Tests
# ============================================================================

class TestDatabase:
    """Test database operations"""
    
    @pytest.mark.asyncio
    async def test_database_connection(self, db):
        """Test database connection"""
        result = await db.execute("SELECT 1")
        assert result is not None
    
    @pytest.mark.asyncio
    async def test_create_record(self, db):
        """Test creating database record"""
        query = """
            INSERT INTO attacks (target_url, status, created_at)
            VALUES (:url, :status, :created_at)
            RETURNING id
        """
        params = {
            "url": "https://example.com",
            "status": "pending",
            "created_at": datetime.utcnow()
        }
        
        result = await db.execute(query, params)
        assert result["id"] is not None
    
    @pytest.mark.asyncio
    async def test_query_records(self, db):
        """Test querying database records"""
        query = "SELECT * FROM attacks LIMIT 10"
        results = await db.fetch_all(query)
        assert isinstance(results, list)


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
async def client():
    """HTTP client fixture"""
    from httpx import AsyncClient
    from api.main import app
    
    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client


@pytest.fixture
async def websocket_client():
    """WebSocket client fixture"""
    from httpx import AsyncClient
    from api.main import app
    
    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client


@pytest.fixture
def api_key():
    """API key fixture"""
    return "test_api_key_user"


@pytest.fixture
def admin_key():
    """Admin API key fixture"""
    return "test_api_key_admin"


@pytest.fixture
def attack_id():
    """Attack ID fixture"""
    return "test_attack_123"


@pytest.fixture
async def db():
    """Database fixture"""
    from api.services.database import Database
    
    db = Database()
    await db.connect()
    
    yield db
    
    await db.disconnect()


# ============================================================================
# Test Configuration
# ============================================================================

def pytest_configure(config):
    """Configure pytest"""
    config.addinivalue_line(
        "markers", "asyncio: mark test as async"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as integration test"
    )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

