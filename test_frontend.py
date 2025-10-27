#!/usr/bin/env python3
"""
Frontend Function Test Script for dLNk Attack Platform
Tests all frontend API calls and verifies functionality
"""

import asyncio
import aiohttp
import json
from datetime import datetime

API_URL = "http://localhost:8000"


async def test_api_endpoint(session, method, endpoint, data=None, expected_success=True):
    """Test a single API endpoint"""
    try:
        if method == 'GET':
            async with session.get(f"{API_URL}{endpoint}") as response:
                result = await response.text()
                try:
                    json_result = json.loads(result)
                except:
                    json_result = result

                print(f"  {method} {endpoint}: {response.status} - {json_result}")

                if expected_success:
                    return response.status == 200 and json_result.get('success', False), json_result
                else:
                    return response.status != 401, json_result

        elif method == 'POST':
            async with session.post(f"{API_URL}{endpoint}", json=data) as response:
                result = await response.text()
                try:
                    json_result = json.loads(result)
                except:
                    json_result = result

                print(f"  {method} {endpoint}: {response.status} - {json_result}")

                if expected_success:
                    return response.status == 200 and json_result.get('success', False), json_result
                else:
                    return response.status != 401, json_result

    except Exception as e:
        print(f"  {method} {endpoint}: ERROR - {e}")
        return False, str(e)


async def test_frontend_functions():
    """Test all frontend API functions"""
    print("🧪 Testing Frontend API Functions...")
    print("=" * 60)

    async with aiohttp.ClientSession() as session:
        # Test 1: Test Agent Listing
        print("\n1. Testing Agent Listing (/agents):")
        success, result = await test_api_endpoint(
            session, 'GET', '/agents',
            expected_success=True
        )
        if success:
            agents_count = result.get('count', 0)
            print(f"  ✅ Loaded {agents_count} agents")
        else:
            print(f"  ❌ Failed to load agents")

        # Test 2: Test Workflow Execution
        print("\n2. Testing Workflow Execution (/workflows/execute):")
        workflow_data = {
            "workflow_path": "config/default_workflow.yaml",
            "target": {
                "name": "Test Target",
                "url": "https://example.com"
            }
        }
        success, result = await test_api_endpoint(
            session, 'POST', '/workflows/execute',
            data=workflow_data,
            expected_success=True
        )
        if success:
            workflow_id = result.get('workflow_id', 'N/A')
            attack_id = result.get('attack_id', 'N/A')
            print(f"  ✅ Workflow started - ID: {workflow_id}, Attack: {attack_id}")
        else:
            print(f"  ❌ Failed to start workflow")

        # Test 3: Test Agent Execution
        print("\n3. Testing Agent Execution (/agents/execute):")
        agent_data = {
            "agent_name": "NmapScanAgent",
            "directive": "Scan target for open ports",
            "context": {
                "target": "https://example.com",
                "ports": "1-1000"
            }
        }
        success, result = await test_api_endpoint(
            session, 'POST', '/agents/execute',
            data=agent_data,
            expected_success=True
        )
        if success:
            execution_id = result.get('execution_id', 'N/A')
            print(f"  ✅ Agent executed - ID: {execution_id}")
        else:
            print(f"  ❌ Failed to execute agent")

        # Test 4: Test Status Endpoints
        print("\n4. Testing Status Endpoints:")

        # Test basic status
        success, result = await test_api_endpoint(
            session, 'GET', '/api/status',
            expected_success=True
        )
        if success:
            print(f"  ✅ System status retrieved")
        else:
            print(f"  ❌ Failed to get system status")

        # Test health check
        success, result = await test_api_endpoint(
            session, 'GET', '/health',
            expected_success=True
        )
        if success:
            print(f"  ✅ Health check passed")
        else:
            print(f"  ❌ Health check failed")

        # Test 5: Test Auth Endpoints (without valid key)
        print("\n5. Testing Authentication Endpoints:")

        # Test login without key
        login_data = {"api_key": "invalid_key"}
        success, result = await test_api_endpoint(
            session, 'POST', '/api/auth/login',
            data=login_data,
            expected_success=False
        )
        if not success:
            print(f"  ✅ Login correctly rejected invalid key")
        else:
            print(f"  ❌ Login should have been rejected")

        # Test verify without key
        verify_data = {"api_key": "invalid_key"}
        success, result = await test_api_endpoint(
            session, 'POST', '/api/auth/verify',
            data=verify_data,
            expected_success=False
        )
        if not success:
            print(f"  ✅ Verify correctly rejected invalid key")
        else:
            print(f"  ❌ Verify should have been rejected")

    print("\n" + "=" * 60)
    print("✅ Frontend function testing completed!")


async def test_websocket_integration():
    """Test WebSocket integration"""
    print("\n🔗 Testing WebSocket Integration...")
    print("=" * 40)

    try:
        import websockets

        # Test logs WebSocket
        try:
            async with websockets.connect(f"ws://localhost:8000/ws/logs") as websocket:
                await websocket.send(json.dumps({"test": "ping"}))
                response = await websocket.recv()
                print(f"  ✅ Logs WebSocket connected and responding")
        except Exception as e:
            print(f"  ❌ Logs WebSocket failed: {e}")

        # Test system WebSocket
        try:
            async with websockets.connect(f"ws://localhost:8000/ws/system") as websocket:
                await websocket.send(json.dumps({"test": "ping"}))
                response = await websocket.recv()
                print(f"  ✅ System WebSocket connected and responding")
        except Exception as e:
            print(f"  ❌ System WebSocket failed: {e}")

    except ImportError:
        print("⚠️  websockets library not available, skipping WebSocket tests")
    except Exception as e:
        print(f"❌ WebSocket testing failed: {e}")


async def main():
    """Run all tests"""
    await test_frontend_functions()
    await test_websocket_integration()

    print("\n" + "=" * 60)
    print("🎉 All tests completed!")
    print("\nNext steps:")
    print("1. Start the API server: python api/main.py")
    print("2. Test the web interface: http://localhost:8000")
    print("3. Monitor logs and adjust as needed")


if __name__ == "__main__":
    asyncio.run(main())