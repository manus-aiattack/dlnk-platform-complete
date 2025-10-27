#!/usr/bin/env python3.11
"""Simple startup test"""
import sys
sys.path.insert(0, '.')

print("Testing imports...")

try:
    print("1. Testing core modules...")
    from core.base_agent import BaseAgent
    print("   ✅ core.base_agent")
    
    print("2. Testing agents...")
    from agents.advanced_c2_agent import AdvancedC2Agent
    print("   ✅ agents.advanced_c2_agent")
    
    print("3. Testing exploitation agents...")
    from agents.exploitation.ssrf_agent import SSRFAgent
    print("   ✅ agents.exploitation.ssrf_agent")
    
    print("\n✅ All critical imports successful!")
    print("Note: API imports skipped (requires full dependencies)")
    
except Exception as e:
    print(f"\n❌ Import failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
