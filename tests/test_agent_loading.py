#!/usr/bin/env python3
"""
Test Agent Loading
Tests that all agent files can be loaded and have correct structure
"""
import os
import sys
import importlib
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

def test_load_all_agents():
    """Test loading all agent files"""
    agents_dir = Path("agents")
    total = 0
    success = 0
    failed = []
    
    print("=" * 80)
    print("Testing Agent Loading")
    print("=" * 80)
    print()
    
    # Test main agents directory
    for py_file in agents_dir.glob("*.py"):
        if py_file.name.startswith("_"):
            continue
        
        total += 1
        module_name = f"agents.{py_file.stem}"
        print(f"Testing: {module_name}...")
        
        try:
            module = importlib.import_module(module_name)
            
            # Find agent class
            found_agent = False
            for name in dir(module):
                if name.endswith("Agent") and name != "BaseAgent":
                    agent_class = getattr(module, name)
                    print(f"  ✓ Found: {name}")
                    
                    # Check if inherits from BaseAgent
                    try:
                        from core.base_agent import BaseAgent
                        if issubclass(agent_class, BaseAgent):
                            print(f"    ✓ Inherits from BaseAgent")
                        else:
                            print(f"    ⚠ Does not inherit from BaseAgent")
                    except:
                        pass
                    
                    found_agent = True
                    break
            
            if found_agent:
                success += 1
            else:
                print(f"  ⚠ No agent class found")
                failed.append((module_name, "No agent class found"))
                
        except Exception as e:
            print(f"  ✗ Error: {e}")
            failed.append((module_name, str(e)))
    
    # Test subdirectories
    for subdir in agents_dir.iterdir():
        if not subdir.is_dir() or subdir.name.startswith("_"):
            continue
        
        for py_file in subdir.glob("*.py"):
            if py_file.name.startswith("_"):
                continue
            
            total += 1
            module_name = f"agents.{subdir.name}.{py_file.stem}"
            print(f"Testing: {module_name}...")
            
            try:
                module = importlib.import_module(module_name)
                
                # Find agent class
                found_agent = False
                for name in dir(module):
                    if name.endswith("Agent") and name != "BaseAgent":
                        agent_class = getattr(module, name)
                        print(f"  ✓ Found: {name}")
                        found_agent = True
                        break
                
                if found_agent:
                    success += 1
                else:
                    print(f"  ⚠ No agent class found")
                    failed.append((module_name, "No agent class found"))
                    
            except Exception as e:
                print(f"  ✗ Error: {e}")
                failed.append((module_name, str(e)))
    
    # Summary
    print()
    print("=" * 80)
    print("Summary")
    print("=" * 80)
    print(f"Total agents tested: {total}")
    print(f"Successfully loaded: {success}")
    print(f"Failed: {len(failed)}")
    print(f"Success rate: {(success/total*100) if total > 0 else 0:.1f}%")
    
    if failed:
        print()
        print("Failed agents:")
        for module_name, error in failed:
            print(f"  - {module_name}: {error}")
    
    print()
    return success, total, failed

if __name__ == "__main__":
    success, total, failed = test_load_all_agents()
    sys.exit(0 if len(failed) == 0 else 1)

