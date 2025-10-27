"""
Tool Verification Service
ตรวจสอบว่าเครื่องมือทั้งหมดพร้อมใช้งาน
"""

import subprocess
import shutil
import os
from typing import Dict, List, Tuple
import requests


class ToolVerifier:
    """Service สำหรับตรวจสอบเครื่องมือ"""
    
    def __init__(self):
        self.required_tools = {
            "nmap": {"command": "nmap --version", "type": "system"},
            "sqlmap": {"command": "sqlmap --version", "type": "system"},
            "python3": {"command": "python3 --version", "type": "system"},
            "git": {"command": "git --version", "type": "system"},
        }
        
        # Package name mapping: display_name -> import_name
        self.required_python_packages = {
            "requests": "requests",
            "aiohttp": "aiohttp",
            "beautifulsoup4": "bs4",
            "pyyaml": "yaml",
            "asyncpg": "asyncpg",
            "fastapi": "fastapi",
            "uvicorn": "uvicorn",
        }
    
    def verify_all(self) -> Dict[str, any]:
        """ตรวจสอบทุกอย่าง"""
        
        results = {
            "overall_status": "healthy",
            "tools": {},
            "python_packages": {},
            "ollama": {},
            "database": {},
            "issues": []
        }
        
        # Check system tools
        for tool_name, tool_info in self.required_tools.items():
            status, message = self._check_tool(tool_name, tool_info["command"])
            results["tools"][tool_name] = {
                "status": status,
                "message": message
            }
            
            if not status:
                results["issues"].append(f"Tool '{tool_name}' not found or not working")
                results["overall_status"] = "degraded"
        
        # Check Python packages
        for display_name, import_name in self.required_python_packages.items():
            status, version = self._check_python_package(import_name)
            results["python_packages"][display_name] = {
                "status": status,
                "version": version if status else None
            }
            
            if not status:
                results["issues"].append(f"Python package '{display_name}' not installed")
                results["overall_status"] = "degraded"
        
        # Check Ollama
        ollama_status = self._check_ollama()
        results["ollama"] = ollama_status
        
        if not ollama_status["available"]:
            results["issues"].append("Ollama is not available")
            results["overall_status"] = "degraded"
        
        # Check Database
        db_status = self._check_database()
        results["database"] = db_status
        
        if not db_status["available"]:
            results["issues"].append("Database is not available")
            results["overall_status"] = "unhealthy"
        
        return results
    
    def _check_tool(self, tool_name: str, command: str) -> Tuple[bool, str]:
        """ตรวจสอบเครื่องมือ"""
        
        # Check if tool exists in PATH
        if not shutil.which(tool_name):
            return False, f"{tool_name} not found in PATH"
        
        # Try to run command
        try:
            result = subprocess.run(
                command.split(),
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                # Get version from output
                version = result.stdout.strip().split('\n')[0]
                return True, version
            else:
                return False, f"Command failed: {result.stderr}"
        
        except subprocess.TimeoutExpired:
            return False, "Command timeout"
        except Exception as e:
            return False, f"Error: {str(e)}"
    
    def _check_python_package(self, package_name: str) -> Tuple[bool, str]:
        """ตรวจสอบ Python package"""
        
        try:
            import importlib
            module = importlib.import_module(package_name)
            
            # Try to get version
            version = "unknown"
            if hasattr(module, '__version__'):
                version = module.__version__
            elif hasattr(module, 'VERSION'):
                version = module.VERSION
            
            return True, version
        
        except ImportError:
            return False, None
        except Exception as e:
            return False, str(e)
    
    def _check_ollama(self) -> Dict:
        """ตรวจสอบ Ollama"""
        
        ollama_host = os.getenv("OLLAMA_HOST", "localhost")
        ollama_port = os.getenv("OLLAMA_PORT", "11434")
        ollama_base_url = f"http://{ollama_host}:{ollama_port}"
        
        result = {
            "available": False,
            "host": ollama_base_url,
            "models": [],
            "error": None
        }
        
        try:
            # Check if Ollama is running
            response = requests.get(f"{ollama_base_url}/api/tags", timeout=5)
            
            if response.status_code == 200:
                result["available"] = True
                
                # Get models
                data = response.json()
                models = data.get("models", [])
                result["models"] = [model.get("name") for model in models]
            else:
                result["error"] = f"HTTP {response.status_code}"
        
        except requests.exceptions.ConnectionError:
            result["error"] = "Connection refused - Ollama not running?"
        except requests.exceptions.Timeout:
            result["error"] = "Connection timeout"
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def _check_database(self) -> Dict:
        """ตรวจสอบ Database"""
        
        database_url = os.getenv("DATABASE_URL", "")
        
        result = {
            "available": False,
            "url": database_url.split("@")[-1] if "@" in database_url else "not configured",
            "error": None
        }
        
        if not database_url:
            result["error"] = "DATABASE_URL not configured"
            return result
        
        try:
            import asyncpg
            import asyncio
            
            async def test_connection():
                conn = await asyncpg.connect(database_url)
                await conn.close()
            
            # Run async test
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(test_connection())
            loop.close()
            
            result["available"] = True
        
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def verify_agent_dependencies(self, agent_name: str) -> Dict:
        """ตรวจสอบ dependencies ของ Agent"""
        
        # This would check specific requirements for each agent
        # For now, return basic check
        return {
            "agent": agent_name,
            "dependencies_met": True,
            "missing_dependencies": []
        }
    
    def get_system_info(self) -> Dict:
        """ดูข้อมูลระบบ"""
        
        import platform
        import psutil
        
        return {
            "platform": platform.system(),
            "platform_version": platform.version(),
            "python_version": platform.python_version(),
            "cpu_count": psutil.cpu_count(),
            "memory_total_gb": round(psutil.virtual_memory().total / (1024**3), 2),
            "disk_total_gb": round(psutil.disk_usage('/').total / (1024**3), 2),
        }


# Global tool verifier instance
tool_verifier = ToolVerifier()


def get_tool_verifier() -> ToolVerifier:
    """Get global tool verifier instance"""
    return tool_verifier

