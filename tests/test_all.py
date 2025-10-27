#!/usr/bin/env python3
"""
dLNk dLNk Framework - Complete Test Suite
รันไฟล์เดียวทดสอบทุกอย่าง
"""

import sys
import time
from pathlib import Path

# Add to path
sys.path.insert(0, str(Path(__file__).parent))

def print_header(text):
    print("\n" + "=" * 80)
    print(f"  {text}")
    print("=" * 80 + "\n")

def test_1_ollama():
    """Test 1: ตรวจสอบ Ollama"""
    print_header("TEST 1: ตรวจสอบ Ollama")
    
    try:
        import requests
        response = requests.get("http://localhost:11434/api/tags", timeout=5)
        if response.status_code == 200:
            models = response.json().get('models', [])
            print(f"✅ Ollama ทำงานอยู่")
            print(f"📦 Models: {len(models)} models")
            for m in models:
                print(f"   - {m['name']}")
            return True
        else:
            print("❌ Ollama ไม่ตอบสนอง")
            return False
    except Exception as e:
        print(f"❌ Ollama ไม่ทำงาน: {e}")
        print("💡 รัน: ollama serve")
        return False

def test_2_agents():
    """Test 2: ตรวจสอบ Agents"""
    print_header("TEST 2: ตรวจสอบ Agents Loading")
    
    try:
        from core.agent_registry import AgentRegistry
        
        registry = AgentRegistry()
        agents = registry.auto_discover_agents()
        
        print(f"✅ Agent Registry ทำงานได้")
        print(f"📦 Loaded: {len(agents)} agents")
        
        # Count by category
        categories = {}
        for agent_name, agent_class in agents.items():
            cat = getattr(agent_class, 'category', 'other')
            categories[cat] = categories.get(cat, 0) + 1
        
        print(f"\n📊 Categories:")
        for cat, count in sorted(categories.items()):
            print(f"   - {cat}: {count} agents")
        
        return True
    except Exception as e:
        print(f"❌ Agent loading failed: {e}")
        return False

def test_3_ai_system():
    """Test 3: ทดสอบ AI System"""
    print_header("TEST 3: ทดสอบ AI System (Mixtral)")
    
    try:
        from openai import OpenAI
        
        print("🔌 เชื่อมต่อ Ollama...")
        client = OpenAI(
            base_url="http://localhost:11434/v1",
            api_key="ollama"
        )
        
        print("🤖 ทดสอบ Mixtral...")
        print("📝 คำถาม: วิธีการ exploit SQL Injection คืออะไร")
        print()
        
        start = time.time()
        response = client.chat.completions.create(
            model="mixtral:latest",
            messages=[
                {"role": "system", "content": "คุณเป็น Offensive Security Expert"},
                {"role": "user", "content": "อธิบายวิธีการ exploit SQL Injection แบบสั้นๆ 3-4 ประโยค"}
            ],
            max_tokens=200,
            temperature=0.7
        ,
                timeout=120)
        elapsed = time.time() - start
        
        content = response.choices[0].message.content
        
        print(f"✅ AI ตอบแล้ว! ({elapsed:.2f}s)")
        print()
        print("-" * 80)
        print(content)
        print("-" * 80)
        print()
        
        return True
    except Exception as e:
        print(f"❌ AI System failed: {e}")
        return False

def test_4_workflow():
    """Test 4: ทดสอบ Workflow Engine"""
    print_header("TEST 4: ทดสอบ Workflow Engine")
    
    try:
        import yaml
        
        workflow_file = Path("workflows/test_minimal.yaml")
        if workflow_file.exists():
            with open(workflow_file) as f:
                workflow = yaml.safe_load(f)
            
            print(f"✅ Workflow loaded: {workflow.get('name', 'Unknown')}")
            print(f"📋 Phases: {len(workflow.get('phases', []))}")
            
            for phase in workflow.get('phases', []):
                print(f"   - {phase.get('name', 'Unknown')}")
            
            return True
        else:
            print("⚠️  Workflow file not found")
            return False
    except Exception as e:
        print(f"❌ Workflow test failed: {e}")
        return False

def main():
    """รันการทดสอบทั้งหมด"""
    
    print("""
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║    ██████╗ ██╗     ███╗   ██╗██╗  ██╗                        ║
║    ██╔══██╗██║     ████╗  ██║██║ ██╔╝                        ║
║    ██║  ██║██║     ██╔██╗ ██║█████╔╝                         ║
║    ██║  ██║██║     ██║╚██╗██║██╔═██╗                         ║
║    ██████╔╝███████╗██║ ╚████║██║  ██╗                        ║
║    ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝                        ║
║                                                               ║
║         ADVANCED PENETRATION ATTACK PLATFORM                 ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

                    Powered by dLNk Framework
                    
                    🧪 COMPLETE TEST SUITE
    """)
    
    results = []
    
    # Run tests
    results.append(("Ollama", test_1_ollama()))
    results.append(("Agents", test_2_agents()))
    results.append(("AI System", test_3_ai_system()))
    results.append(("Workflow", test_4_workflow()))
    
    # Summary
    print_header("SUMMARY")
    
    passed = sum(1 for _, r in results if r)
    total = len(results)
    
    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}  {name}")
    
    print()
    print(f"📊 Results: {passed}/{total} tests passed ({passed*100//total}%)")
    print()
    
    if passed == total:
        print("🎉 ทุกอย่างทำงานได้สมบูรณ์!")
        print()
        print("🚀 เริ่มใช้งาน:")
        print("   python3 dlnk_ai_system_local.py")
        print()
    else:
        print("⚠️  บางส่วนยังไม่ทำงาน กรุณาตรวจสอบ error ข้างบน")
        print()

if __name__ == "__main__":
    main()
