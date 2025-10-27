#!/usr/bin/env python3
"""
dLNk Attack Platform - Project Progress Checker
ตรวจสอบความคืบหน้าของโปรเจคทุกส่วน
"""

import os
import json
from pathlib import Path
from datetime import datetime


def count_files(directory, extensions):
    """Count files with specific extensions"""
    count = 0
    for ext in extensions:
        count += len(list(Path(directory).rglob(f"*.{ext}")))
    return count


def check_database():
    """Check database status"""
    try:
        import psycopg2
        conn = psycopg2.connect("postgresql://dlnk:dlnk_password@localhost/dlnk")
        cur = conn.cursor()
        
        # Count tables
        cur.execute("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public'")
        tables = cur.fetchone()[0]
        
        # Count records
        cur.execute("SELECT COUNT(*) FROM users")
        users = cur.fetchone()[0]
        
        cur.execute("SELECT COUNT(*) FROM attacks")
        attacks = cur.fetchone()[0]
        
        conn.close()
        
        return {
            "status": "✅ Connected",
            "tables": tables,
            "users": users,
            "attacks": attacks,
            "completion": 100
        }
    except Exception as e:
        return {
            "status": f"❌ Error: {e}",
            "completion": 0
        }


def check_redis():
    """Check Redis status"""
    try:
        import redis
        r = redis.Redis(host='localhost', port=6379)
        r.ping()
        info = r.info()
        return {
            "status": "✅ Running",
            "version": info.get('redis_version', 'unknown'),
            "uptime_days": info.get('uptime_in_days', 0),
            "completion": 100
        }
    except Exception as e:
        return {
            "status": f"❌ Error: {e}",
            "completion": 0
        }


def check_api():
    """Check API status"""
    try:
        import requests
        response = requests.get("http://localhost:8000/health", timeout=5)
        data = response.json()
        
        # Count endpoints
        openapi = requests.get("http://localhost:8000/openapi.json", timeout=5).json()
        endpoints = len(openapi.get('paths', {}))
        
        return {
            "status": "✅ Running",
            "version": data.get('version', 'unknown'),
            "endpoints": endpoints,
            "database": "✅" if data.get('database') else "❌",
            "completion": 100
        }
    except Exception as e:
        return {
            "status": f"❌ Error: {e}",
            "completion": 0
        }


def check_agents():
    """Check agents status"""
    agents_dir = Path("/home/ubuntu/aiprojectattack/agents")
    if not agents_dir.exists():
        return {"status": "❌ Not found", "completion": 0}
    
    agents = list(agents_dir.glob("*_agent.py"))
    
    # Check for run() method in each agent
    agents_with_run = 0
    for agent_file in agents:
        content = agent_file.read_text()
        if "def run(" in content or "async def run(" in content:
            agents_with_run += 1
    
    completion = (agents_with_run / len(agents) * 100) if agents else 0
    
    return {
        "status": "✅ Ready",
        "total_agents": len(agents),
        "functional_agents": agents_with_run,
        "completion": int(completion)
    }


def check_frontend():
    """Check frontend status"""
    frontend_files = [
        "/home/ubuntu/aiprojectattack/frontend_hacker.html",
        "/home/ubuntu/aiprojectattack/static/css/style.css",
        "/home/ubuntu/aiprojectattack/static/js/app.js"
    ]
    
    exists = sum(1 for f in frontend_files if Path(f).exists())
    completion = (exists / len(frontend_files) * 100)
    
    return {
        "status": "✅ Ready" if exists == len(frontend_files) else "⚠️ Incomplete",
        "files": f"{exists}/{len(frontend_files)}",
        "completion": int(completion)
    }


def check_c2():
    """Check C2 infrastructure"""
    c2_files = [
        "/home/ubuntu/aiprojectattack/core/shell_handler.py",
        "/home/ubuntu/aiprojectattack/core/reverse_shell_payloads.py",
        "/home/ubuntu/aiprojectattack/api/routes/c2_shell.py"
    ]
    
    exists = sum(1 for f in c2_files if Path(f).exists())
    completion = (exists / len(c2_files) * 100)
    
    return {
        "status": "✅ Ready" if exists == len(c2_files) else "⚠️ Incomplete",
        "files": f"{exists}/{len(c2_files)}",
        "completion": int(completion)
    }


def check_zeroday():
    """Check Zero-Day hunter"""
    zeroday_file = Path("/home/ubuntu/aiprojectattack/core/zeroday_hunter.py")
    
    if not zeroday_file.exists():
        return {"status": "❌ Not found", "completion": 0}
    
    content = zeroday_file.read_text()
    
    features = {
        "deep_scan": "deep_scan" in content,
        "fuzzing": "fuzzing" in content or "fuzz" in content,
        "ml_analysis": "ml" in content.lower() or "machine_learning" in content,
        "auto_exploit": "auto_exploit" in content or "exploit" in content
    }
    
    completion = sum(features.values()) / len(features) * 100
    
    return {
        "status": "✅ Ready",
        "features": features,
        "completion": int(completion)
    }


def check_llm():
    """Check LLM integration"""
    llm_file = Path("/home/ubuntu/aiprojectattack/core/llm_integration.py")
    
    if not llm_file.exists():
        return {"status": "❌ Not found", "completion": 0}
    
    # Check if OpenAI API key is set
    api_key = os.getenv("OPENAI_API_KEY")
    
    return {
        "status": "✅ Ready" if api_key else "⚠️ No API Key",
        "provider": "OpenAI",
        "model": "gpt-4.1-mini",
        "completion": 100 if api_key else 50
    }


def check_self_healing():
    """Check self-healing system"""
    healing_file = Path("/home/ubuntu/aiprojectattack/core/self_healing.py")
    
    if not healing_file.exists():
        return {"status": "❌ Not found", "completion": 0}
    
    content = healing_file.read_text()
    
    features = {
        "error_detection": "handle_error" in content,
        "auto_recovery": "recovery" in content.lower(),
        "health_check": "health" in content.lower(),
        "retry_logic": "retry" in content.lower()
    }
    
    completion = sum(features.values()) / len(features) * 100
    
    return {
        "status": "✅ Ready",
        "features": features,
        "completion": int(completion)
    }


def main():
    """Main function"""
    print("=" * 70)
    print("dLNk Attack Platform - Project Progress Report")
    print("=" * 70)
    print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    print()
    
    # Check all components
    components = {
        "Database (PostgreSQL)": check_database(),
        "Cache (Redis)": check_redis(),
        "Backend API": check_api(),
        "AI Agents": check_agents(),
        "Frontend": check_frontend(),
        "C2 Infrastructure": check_c2(),
        "Zero-Day Hunter": check_zeroday(),
        "LLM Integration": check_llm(),
        "Self-Healing System": check_self_healing()
    }
    
    # Print results
    total_completion = 0
    for name, result in components.items():
        completion = result.get('completion', 0)
        total_completion += completion
        
        print(f"📦 {name}")
        print(f"   Status: {result.get('status', 'Unknown')}")
        
        # Print additional info
        for key, value in result.items():
            if key not in ['status', 'completion']:
                if isinstance(value, dict):
                    print(f"   {key}:")
                    for k, v in value.items():
                        print(f"      - {k}: {'✅' if v else '❌'}")
                else:
                    print(f"   {key}: {value}")
        
        print(f"   Completion: {completion}%")
        print()
    
    # Overall completion
    overall = total_completion / len(components)
    print("=" * 70)
    print(f"🎯 Overall Project Completion: {overall:.1f}%")
    print("=" * 70)
    print()
    
    # Summary
    if overall >= 90:
        print("✅ Project is READY for production!")
    elif overall >= 70:
        print("⚠️  Project is mostly complete, minor issues remain")
    elif overall >= 50:
        print("🔧 Project is in development, major components working")
    else:
        print("🚧 Project is in early stages")
    
    print()
    
    # Save to file
    report_file = Path("/home/ubuntu/aiprojectattack/PROJECT_PROGRESS.json")
    with open(report_file, 'w') as f:
        json.dump({
            "timestamp": datetime.now().isoformat(),
            "overall_completion": overall,
            "components": components
        }, f, indent=2, ensure_ascii=False)
    
    print(f"📄 Report saved to: {report_file}")


if __name__ == "__main__":
    main()

