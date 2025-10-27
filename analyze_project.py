#!/usr/bin/env python3
"""
Project Structure Analyzer
Analyze entire project structure and identify issues
"""

import os
import json
from pathlib import Path
from collections import defaultdict

def analyze_directory_structure():
    """Analyze project directory structure"""
    base_path = Path("/home/ubuntu/aiprojectattack")
    
    structure = {
        "directories": {},
        "file_counts": {},
        "total_files": 0,
        "python_files": 0,
        "config_files": 0,
        "html_files": 0
    }
    
    # Directories to analyze
    dirs_to_check = [
        "advanced_agents", "agents", "api", "c2_infrastructure", "cli",
        "config", "core", "data_exfiltration", "database", "deploy",
        "docker", "docs", "frontend", "integrations", "k8s", "models",
        "monitoring", "protocol_exploits", "scripts", "services",
        "setup", "systemd", "tests", "web"
    ]
    
    for dir_name in dirs_to_check:
        dir_path = base_path / dir_name
        if dir_path.exists():
            files = list(dir_path.rglob("*"))
            py_files = list(dir_path.rglob("*.py"))
            
            structure["directories"][dir_name] = {
                "exists": True,
                "total_files": len([f for f in files if f.is_file()]),
                "python_files": len(py_files),
                "subdirs": len([f for f in files if f.is_dir()]),
                "path": str(dir_path)
            }
            
            structure["file_counts"][dir_name] = len(py_files)
            structure["total_files"] += len([f for f in files if f.is_file()])
            structure["python_files"] += len(py_files)
        else:
            structure["directories"][dir_name] = {
                "exists": False,
                "total_files": 0,
                "python_files": 0,
                "subdirs": 0,
                "path": str(dir_path)
            }
    
    return structure

def find_mock_data():
    """Find potential mock data in files"""
    base_path = Path("/home/ubuntu/aiprojectattack")
    mock_patterns = [
        "mock", "Mock", "MOCK",
        "fake", "Fake", "FAKE",
        "dummy", "Dummy", "DUMMY",
        "test_key", "test_api",
        "simulate", "simulation"
    ]
    
    mock_findings = []
    
    for py_file in base_path.rglob("*.py"):
        try:
            content = py_file.read_text()
            for pattern in mock_patterns:
                if pattern in content:
                    mock_findings.append({
                        "file": str(py_file.relative_to(base_path)),
                        "pattern": pattern,
                        "lines": [i+1 for i, line in enumerate(content.split('\n')) if pattern in line]
                    })
        except:
            pass
    
    return mock_findings

def check_database_connections():
    """Check for database connection patterns"""
    base_path = Path("/home/ubuntu/aiprojectattack")
    db_patterns = {
        "postgresql": ["postgresql://", "psycopg2", "asyncpg"],
        "sqlite": ["sqlite:///", "sqlite3"],
        "in_memory": [":memory:", "in-memory"]
    }
    
    db_findings = defaultdict(list)
    
    for py_file in base_path.rglob("*.py"):
        try:
            content = py_file.read_text()
            for db_type, patterns in db_patterns.items():
                for pattern in patterns:
                    if pattern in content:
                        db_findings[db_type].append(str(py_file.relative_to(base_path)))
        except:
            pass
    
    return dict(db_findings)

def main():
    print("🔍 Analyzing Project Structure...")
    print("=" * 60)
    
    # Analyze structure
    structure = analyze_directory_structure()
    
    print(f"\n📊 Project Statistics:")
    print(f"  Total Files: {structure['total_files']}")
    print(f"  Python Files: {structure['python_files']}")
    
    print(f"\n📁 Directory Analysis:")
    for dir_name, info in sorted(structure['directories'].items()):
        status = "✅" if info['exists'] else "❌"
        if info['exists']:
            print(f"  {status} {dir_name:20s} - {info['python_files']:3d} Python files, {info['subdirs']:2d} subdirs")
        else:
            print(f"  {status} {dir_name:20s} - NOT FOUND")
    
    # Find mock data
    print(f"\n🔍 Searching for Mock Data...")
    mock_findings = find_mock_data()
    print(f"  Found {len(mock_findings)} potential mock data occurrences")
    
    if mock_findings:
        print(f"\n  Top 10 files with mock data:")
        for finding in mock_findings[:10]:
            print(f"    - {finding['file']} (pattern: {finding['pattern']})")
    
    # Check database connections
    print(f"\n💾 Database Connection Analysis:")
    db_findings = check_database_connections()
    for db_type, files in db_findings.items():
        print(f"  {db_type.upper():12s}: {len(files)} files")
        for f in files[:5]:
            print(f"    - {f}")
    
    # Save results
    results = {
        "structure": structure,
        "mock_findings": mock_findings,
        "database_findings": db_findings
    }
    
    output_file = "/home/ubuntu/project_analysis_results.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n✅ Analysis complete! Results saved to: {output_file}")

if __name__ == "__main__":
    main()
