#!/usr/bin/env python3
"""
Authentication Test Script for dLNk Attack Platform
Tests all authentication endpoints and verifies functionality
"""

import asyncio
import aiohttp
import json
from datetime import datetime

API_URL = "http://localhost:8000"
# Production API key format: dlnk_live_<64_hex_chars>
TEST_API_KEY = "dlnk_live_invalid_key_for_testing"  # This should fail
ADMIN_API_KEY = None  # Will be set after generation from server


async def test_endpoint(session, method, endpoint, data=None, headers=None, expected_status=200):
    """Test a single endpoint"""
    try:
        if method == 'GET':
            async with session.get(f"{API_URL}{endpoint}", headers=headers) as response:
                result = await response.text()
                try:
                    json_result = json.loads(result)
                except:
                    json_result = result

                print(f"  {method} {endpoint}: {response.status} - {json_result}")
                return response.status == expected_status, json_result
        elif method == 'POST':
            async with session.post(f"{API_URL}{endpoint}", json=data, headers=headers) as response:
                result = await response.text()
                try:
                    json_result = json.loads(result)
                except:
                    json_result = result

                print(f"  {method} {endpoint}: {response.status} - {json_result}")
                return response.status == expected_status, json_result
    except Exception as e:
        print(f"  {method} {endpoint}: ERROR - {e}")
        return False, str(e)


async def test_authentication():
    """Test all authentication endpoints"""
    print("🧪 Testing Authentication Endpoints...")
    print("=" * 50)

    async with aiohttp.ClientSession() as session:
        # Test 1: Generate Admin Key
        print("\n1. Testing Admin Key Generation:")
        success, result = await test_endpoint(
            session, 'POST', '/api/auth/generate-admin-key',
            expected_status=200
        )

        if success and result.get('success'):
            global ADMIN_API_KEY
            ADMIN_API_KEY = result.get('admin_key')
            print(f"  ✅ Admin key generated: {ADMIN_API_KEY[:20]}...")
        else:
            print("  ❌ Failed to generate admin key")

        # Test 2: Test Invalid API Key
        print("\n2. Testing Invalid API Key:")
        invalid_key_data = {"api_key": TEST_API_KEY}
        await test_endpoint(
            session, 'POST', '/api/auth/login',
            data=invalid_key_data,
            expected_status=401
        )

        # Test 3: Test Valid Admin Login (if we have admin key)
        if ADMIN_API_KEY:
            print("\n3. Testing Valid Admin Login:")
            valid_key_data = {"api_key": ADMIN_API_KEY}
            success, result = await test_endpoint(
                session, 'POST', '/api/auth/login',
                data=valid_key_data,
                expected_status=200
            )

            if success and result.get('success'):
                user_data = result.get('user', {})
                print(f"  ✅ Login successful!")
                print(f"  📊 User: {user_data.get('username')} ({user_data.get('role')})")
                print(f"  🔢 Quota: {user_data.get('remaining_quota')} remaining")

        # Test 4: Test API Key Verification
        if ADMIN_API_KEY:
            print("\n4. Testing API Key Verification:")
            verify_data = {"api_key": ADMIN_API_KEY}
            await test_endpoint(
                session, 'POST', '/api/auth/verify',
                data=verify_data,
                expected_status=200
            )

        # Test 5: Test Logout
        print("\n5. Testing Logout:")
        await test_endpoint(
            session, 'POST', '/api/auth/logout',
            expected_status=200
        )

        # Test 6: Test Health Endpoint
        print("\n6. Testing Health Endpoint:")
        await test_endpoint(
            session, 'GET', '/health',
            expected_status=200
        )

        # Test 7: Test Status Endpoint with Admin Key
        if ADMIN_API_KEY:
            print("\n7. Testing Status Endpoint with Admin Key:")
            headers = {"X-API-Key": ADMIN_API_KEY}
            await test_endpoint(
                session, 'GET', '/api/status',
                headers=headers,
                expected_status=200
            )

    print("\n" + "=" * 50)
    print("✅ Authentication testing completed!")


if __name__ == "__main__":
    asyncio.run(test_authentication())