#!/usr/bin/env python3
"""
Automated Quality Check Script
Comprehensive quality assurance for dLNk Attack Platform
"""

import os
import sys
import json
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any

class QualityChecker:
    """Automated quality checking system"""
    
    def __init__(self):
        self.base_path = Path("/home/ubuntu/aiprojectattack")
        self.results = {
            "timestamp": datetime.utcnow().isoformat(),
            "checks": {},
            "summary": {},
            "issues": []
        }
    
    def run_all_checks(self):
        """Run all quality checks"""
        print("🔍 Starting Comprehensive Quality Check")
        print("=" * 60)
        
        self.check_mock_data()
        self.check_database_usage()
        self.check_ai_integration()
        self.check_agent_structure()
        self.check_code_quality()
        self.check_security()
        
        self.generate_report()
    
    def check_mock_data(self):
        """Check for mock data"""
        print("\n1️⃣ Checking for Mock Data...")
        
        mock_patterns = [
            "mock", "Mock", "MOCK",
            "fake", "Fake", "FAKE",
            "dummy", "Dummy", "DUMMY",
            "test_key", "test_api", "admin_test", "user_test",
            "simulate", "simulation"
        ]
        
        issues = []
        
        for pattern in mock_patterns:
            try:
                result = subprocess.run(
                    ["grep", "-r", pattern, "--include=*.py", str(self.base_path)],
                    capture_output=True,
                    text=True
                )
                
                if result.stdout:
                    lines = result.stdout.strip().split('\n')
                    # Filter out comments and docstrings
                    real_issues = [
                        line for line in lines 
                        if not line.strip().startswith('#') 
                        and '"""' not in line 
                        and "'''" not in line
                    ]
                    
                    if real_issues:
                        issues.append({
                            "pattern": pattern,
                            "count": len(real_issues),
                            "examples": real_issues[:3]
                        })
            except:
                pass
        
        self.results["checks"]["mock_data"] = {
            "status": "PASS" if not issues else "FAIL",
            "issues_found": len(issues),
            "details": issues
        }
        
        if issues:
            print(f"  ❌ Found {len(issues)} mock data patterns")
            for issue in issues[:5]:
                print(f"     - {issue['pattern']}: {issue['count']} occurrences")
        else:
            print("  ✅ No mock data found")
    
    def check_database_usage(self):
        """Check database usage patterns"""
        print("\n2️⃣ Checking Database Usage...")
        
        db_checks = {
            "postgresql": ["postgresql://", "psycopg2", "asyncpg"],
            "sqlite": ["sqlite:///", "sqlite3"],
            "in_memory": [":memory:", "in-memory"],
            "hardcoded_data": ["= []", "= {}"]
        }
        
        findings = {}
        
        for db_type, patterns in db_checks.items():
            count = 0
            for pattern in patterns:
                try:
                    result = subprocess.run(
                        ["grep", "-r", pattern, "--include=*.py", str(self.base_path)],
                        capture_output=True,
                        text=True
                    )
                    if result.stdout:
                        count += len(result.stdout.strip().split('\n'))
                except:
                    pass
            
            findings[db_type] = count
        
        # PostgreSQL should be present, others should be minimal
        status = "PASS" if (
            findings["postgresql"] > 0 and 
            findings["sqlite"] == 0 and 
            findings["in_memory"] == 0
        ) else "WARN"
        
        self.results["checks"]["database"] = {
            "status": status,
            "findings": findings
        }
        
        print(f"  PostgreSQL: {findings['postgresql']} files")
        print(f"  SQLite: {findings['sqlite']} files {'❌' if findings['sqlite'] > 0 else '✅'}")
        print(f"  In-Memory: {findings['in_memory']} files {'❌' if findings['in_memory'] > 0 else '✅'}")
    
    def check_ai_integration(self):
        """Check AI integration"""
        print("\n3️⃣ Checking AI Integration...")
        
        ai_patterns = {
            "vanchin": ["vanchin", "VanchinMultiClient"],
            "llm_service": ["llm_service", "LLMService"],
            "ai_analysis": ["ai_analyze", "ai_analysis"]
        }
        
        findings = {}
        
        for category, patterns in ai_patterns.items():
            count = 0
            for pattern in patterns:
                try:
                    result = subprocess.run(
                        ["grep", "-r", pattern, "--include=*.py", str(self.base_path)],
                        capture_output=True,
                        text=True
                    )
                    if result.stdout:
                        count += len(result.stdout.strip().split('\n'))
                except:
                    pass
            findings[category] = count
        
        status = "PASS" if all(count > 0 for count in findings.values()) else "WARN"
        
        self.results["checks"]["ai_integration"] = {
            "status": status,
            "findings": findings
        }
        
        for category, count in findings.items():
            status_icon = "✅" if count > 0 else "⚠️"
            print(f"  {status_icon} {category}: {count} occurrences")
    
    def check_agent_structure(self):
        """Check agent structure compliance"""
        print("\n4️⃣ Checking Agent Structure...")
        
        agent_dirs = [
            self.base_path / "agents",
            self.base_path / "advanced_agents"
        ]
        
        total_agents = 0
        compliant_agents = 0
        issues = []
        
        for agent_dir in agent_dirs:
            if not agent_dir.exists():
                continue
            
            for agent_file in agent_dir.rglob("*.py"):
                if agent_file.name.startswith("__"):
                    continue
                
                total_agents += 1
                
                try:
                    content = agent_file.read_text()
                    
                    # Check for required components
                    has_base_agent = "BaseAgent" in content
                    has_execute = "async def execute" in content
                    has_agent_data = "AgentData" in content
                    
                    if has_base_agent and has_execute and has_agent_data:
                        compliant_agents += 1
                    else:
                        issues.append({
                            "file": str(agent_file.relative_to(self.base_path)),
                            "missing": [
                                "BaseAgent" if not has_base_agent else None,
                                "execute()" if not has_execute else None,
                                "AgentData" if not has_agent_data else None
                            ]
                        })
                except:
                    pass
        
        compliance_rate = (compliant_agents / total_agents * 100) if total_agents > 0 else 0
        
        self.results["checks"]["agent_structure"] = {
            "status": "PASS" if compliance_rate > 90 else "WARN",
            "total_agents": total_agents,
            "compliant_agents": compliant_agents,
            "compliance_rate": compliance_rate,
            "issues": issues[:10]
        }
        
        print(f"  Total Agents: {total_agents}")
        print(f"  Compliant: {compliant_agents} ({compliance_rate:.1f}%)")
        
        if compliance_rate < 100:
            print(f"  ⚠️ {total_agents - compliant_agents} agents need updates")
    
    def check_code_quality(self):
        """Check code quality metrics"""
        print("\n5️⃣ Checking Code Quality...")
        
        # Count Python files
        py_files = list(self.base_path.rglob("*.py"))
        total_lines = 0
        
        for py_file in py_files:
            try:
                total_lines += len(py_file.read_text().split('\n'))
            except:
                pass
        
        self.results["checks"]["code_quality"] = {
            "status": "INFO",
            "total_files": len(py_files),
            "total_lines": total_lines,
            "avg_lines_per_file": total_lines // len(py_files) if py_files else 0
        }
        
        print(f"  Python Files: {len(py_files)}")
        print(f"  Total Lines: {total_lines:,}")
        print(f"  Avg Lines/File: {total_lines // len(py_files) if py_files else 0}")
    
    def check_security(self):
        """Check for security issues"""
        print("\n6️⃣ Checking Security...")
        
        security_patterns = {
            "hardcoded_passwords": ["password = ", "PASSWORD = "],
            "hardcoded_keys": ["api_key = \"", "API_KEY = \""],
            "sql_injection": ["execute(f\"", "execute(\""],
            "command_injection": ["os.system(f\"", "subprocess.run(f\""]
        }
        
        findings = {}
        
        for issue_type, patterns in security_patterns.items():
            count = 0
            for pattern in patterns:
                try:
                    result = subprocess.run(
                        ["grep", "-r", pattern, "--include=*.py", str(self.base_path)],
                        capture_output=True,
                        text=True
                    )
                    if result.stdout:
                        count += len(result.stdout.strip().split('\n'))
                except:
                    pass
            findings[issue_type] = count
        
        total_issues = sum(findings.values())
        
        self.results["checks"]["security"] = {
            "status": "PASS" if total_issues == 0 else "WARN",
            "findings": findings,
            "total_issues": total_issues
        }
        
        for issue_type, count in findings.items():
            if count > 0:
                print(f"  ⚠️ {issue_type}: {count} occurrences")
        
        if total_issues == 0:
            print("  ✅ No obvious security issues found")
    
    def generate_report(self):
        """Generate final report"""
        print("\n" + "=" * 60)
        print("📊 Quality Check Summary")
        print("=" * 60)
        
        # Count statuses
        statuses = {
            "PASS": 0,
            "WARN": 0,
            "FAIL": 0,
            "INFO": 0
        }
        
        for check_name, check_data in self.results["checks"].items():
            status = check_data.get("status", "INFO")
            statuses[status] += 1
        
        self.results["summary"] = statuses
        
        print(f"\n✅ PASS: {statuses['PASS']}")
        print(f"⚠️  WARN: {statuses['WARN']}")
        print(f"❌ FAIL: {statuses['FAIL']}")
        print(f"ℹ️  INFO: {statuses['INFO']}")
        
        # Overall status
        if statuses["FAIL"] > 0:
            overall = "❌ FAILED"
        elif statuses["WARN"] > 0:
            overall = "⚠️  NEEDS ATTENTION"
        else:
            overall = "✅ PASSED"
        
        print(f"\nOverall Status: {overall}")
        
        # Save report
        report_file = self.base_path / "quality_report.json"
        with open(report_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\n📄 Detailed report saved to: {report_file}")
        
        # Return exit code
        return 0 if statuses["FAIL"] == 0 else 1

def main():
    checker = QualityChecker()
    exit_code = checker.run_all_checks()
    sys.exit(exit_code)

if __name__ == "__main__":
    main()

