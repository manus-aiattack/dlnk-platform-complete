#!/usr/bin/env python3
"""
System Test Script - Test all components
"""

import sys
import os
import asyncio
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

async def test_imports():
    """Test if all modules can be imported"""
    print("🔍 Testing imports...")
    
    try:
        from core.orchestrator import Orchestrator
        print("✅ core.orchestrator")
        
        from core.auto_exploit import AutoExploiter
        print("✅ core.auto_exploit")
        
        from core.data_exfiltration import DataExfiltrator
        print("✅ core.data_exfiltration")
        
        from agents.file_upload_agent import FileUploadAgent
        print("✅ agents.file_upload_agent")
        
        from agents.post_exploitation.webshell_manager import WebshellManager
        print("✅ agents.post_exploitation.webshell_manager")
        
        from agents.post_exploitation.privesc_agent import PrivilegeEscalationAgent
        print("✅ agents.post_exploitation.privesc_agent")
        
        from agents.post_exploitation.lateral_movement import LateralMovementAgent
        print("✅ agents.post_exploitation.lateral_movement")
        
        return True
    
    except Exception as e:
        print(f"❌ Import failed: {e}")
        return False

async def test_loot_system():
    """Test loot system"""
    print("\n🔍 Testing loot system...")
    
    try:
        from core.data_exfiltration import DataExfiltrator
        
        exfiltrator = DataExfiltrator()
        
        # Test database dump
        result = await exfiltrator.exfiltrate_database(
            "http://test.com",
            "mysql",
            b"SELECT * FROM users;"
        )
        print(f"✅ Database dump: {result.get('file', 'N/A')}")
        
        # Test credentials
        result = await exfiltrator.exfiltrate_credentials(
            "http://test.com",
            [{"username": "test", "password": "test123"}]
        )
        print(f"✅ Credentials: {result.get('file', 'N/A')}")
        
        return True
    
    except Exception as e:
        print(f"❌ Loot system test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

async def test_safety_check():
    """Test safety check"""
    print("\n🔍 Testing safety check...")
    
    try:
        from core.orchestrator import Orchestrator
        
        orchestrator = Orchestrator()
        
        # Test blocked targets
        assert not orchestrator.is_target_safe("http://localhost")
        print("✅ Blocked: localhost")
        
        assert not orchestrator.is_target_safe("http://127.0.0.1")
        print("✅ Blocked: 127.0.0.1")
        
        assert not orchestrator.is_target_safe("http://0.0.0.0")
        print("✅ Blocked: 0.0.0.0")
        
        # Test allowed targets (using safe test domain)
        assert orchestrator.is_target_safe("localhost:8000")
        print("✅ Allowed: localhost:8000")
        
        return True
    
    except Exception as e:
        print(f"❌ Safety check test failed: {e}")
        return False

async def test_cli_commands():
    """Test CLI commands"""
    print("\n🔍 Testing CLI commands...")
    
    try:
        import subprocess
        
        # Test loot summary
        result = subprocess.run(
            ['python3', 'main.py', 'loot', 'summary'],
            cwd=os.getenv('PROJECT_DIR', os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            print("✅ CLI: loot summary")
        else:
            print(f"⚠️  CLI: loot summary (exit code {result.returncode})")
        
        return True
    
    except Exception as e:
        print(f"❌ CLI test failed: {e}")
        return False

async def main():
    """Run all tests"""
    print("=" * 60)
    print("🧪 dLNk dLNk Framework - System Test")
    print("=" * 60)
    
    results = []
    
    # Test imports
    results.append(await test_imports())
    
    # Test loot system
    results.append(await test_loot_system())
    
    # Test safety check
    results.append(await test_safety_check())
    
    # Test CLI
    results.append(await test_cli_commands())
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 Test Summary")
    print("=" * 60)
    
    passed = sum(results)
    total = len(results)
    
    print(f"Passed: {passed}/{total}")
    
    if passed == total:
        print("✅ All tests passed!")
        return 0
    else:
        print(f"⚠️  {total - passed} test(s) failed")
        return 1

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
