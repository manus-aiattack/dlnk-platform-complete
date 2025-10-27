#!/usr/bin/env python3
"""
Advanced Vanchin AI Agent (AOA)
Full-featured AI agent with file access, shell execution, and self-healing
"""

import os
import subprocess
import json
from typing import List, Dict, Any, Optional
from pathlib import Path
from loguru import logger

from core.vanchin_client import vanchin_client


class AdvancedVanchinAgent:
    """
    Advanced Vanchin AI Agent with full system access
    
    Capabilities:
    - File read/write/edit
    - Shell command execution
    - Package installation
    - Git operations
    - Self-healing
    - System monitoring
    """
    
    def __init__(self, project_root: str = "/home/ubuntu/aiprojectattack"):
        self.project_root = Path(project_root)
        self.conversation_history = []
        self.system_prompt = self._build_system_prompt()
        
    def _build_system_prompt(self) -> str:
        """Build comprehensive system prompt for AOA"""
        return f"""You are an Advanced Offensive Agent (AOA) with full access to the dLNk Attack Platform.

**Your Capabilities:**
1. **File Operations:**
   - read_file(path) - Read any file
   - write_file(path, content) - Write/create files
   - edit_file(path, changes) - Edit existing files
   - list_files(directory) - List directory contents
   
2. **Shell Operations:**
   - execute_command(cmd) - Run any shell command
   - install_package(package) - Install Python/system packages
   
3. **Git Operations:**
   - git_status() - Check git status
   - git_commit(message) - Commit changes
   - git_push() - Push to GitHub
   
4. **System Operations:**
   - check_system_health() - Monitor system status
   - restart_service(service) - Restart services
   - fix_issue(issue) - Auto-fix problems

**Project Root:** {self.project_root}

**Your Mission:**
- Understand user requests fully
- Execute operations using available tools
- Report results clearly
- Fix issues automatically
- Maintain system health

**Response Format:**
When you need to use a tool, respond with JSON:
```json
{{
    "thought": "Why I'm doing this",
    "action": "tool_name",
    "parameters": {{"param": "value"}},
    "response": "What I'll tell the user"
}}
```

When answering normally:
```json
{{
    "thought": "My reasoning",
    "response": "My answer to the user"
}}
```

**Important:**
- Always explain what you're doing
- Use tools when needed
- Report errors clearly
- Be proactive in fixing issues
"""
    
    def read_file(self, path: str) -> str:
        """Read file content"""
        try:
            full_path = self.project_root / path if not Path(path).is_absolute() else Path(path)
            with open(full_path, 'r', encoding='utf-8') as f:
                content = f.read()
            logger.info(f"[AOA] Read file: {full_path} ({len(content)} bytes)")
            return content
        except Exception as e:
            logger.error(f"[AOA] Failed to read {path}: {e}")
            raise
    
    def write_file(self, path: str, content: str) -> str:
        """Write file content"""
        try:
            full_path = self.project_root / path if not Path(path).is_absolute() else Path(path)
            full_path.parent.mkdir(parents=True, exist_ok=True)
            with open(full_path, 'w', encoding='utf-8') as f:
                f.write(content)
            logger.success(f"[AOA] Wrote file: {full_path} ({len(content)} bytes)")
            return f"✅ File written: {full_path}"
        except Exception as e:
            logger.error(f"[AOA] Failed to write {path}: {e}")
            raise
    
    def execute_command(self, cmd: str, timeout: int = 30) -> Dict[str, Any]:
        """Execute shell command"""
        try:
            logger.info(f"[AOA] Executing: {cmd}")
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(self.project_root)
            )
            
            output = {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
                "success": result.returncode == 0
            }
            
            if output["success"]:
                logger.success(f"[AOA] Command succeeded: {cmd}")
            else:
                logger.warning(f"[AOA] Command failed: {cmd} (code: {result.returncode})")
            
            return output
        except subprocess.TimeoutExpired:
            logger.error(f"[AOA] Command timeout: {cmd}")
            return {"error": "Timeout", "success": False}
        except Exception as e:
            logger.error(f"[AOA] Command error: {e}")
            return {"error": str(e), "success": False}
    
    def list_files(self, directory: str = ".") -> List[str]:
        """List files in directory"""
        try:
            full_path = self.project_root / directory if not Path(directory).is_absolute() else Path(directory)
            files = []
            for item in full_path.iterdir():
                files.append(str(item.relative_to(self.project_root)))
            logger.info(f"[AOA] Listed {len(files)} files in {directory}")
            return files
        except Exception as e:
            logger.error(f"[AOA] Failed to list {directory}: {e}")
            raise
    
    def git_commit(self, message: str) -> str:
        """Commit changes to git"""
        try:
            # Add all changes
            self.execute_command("git add -A")
            # Commit
            result = self.execute_command(f'git commit -m "{message}"')
            # Push
            self.execute_command("git push origin main")
            logger.success(f"[AOA] Git commit & push: {message}")
            return f"✅ Committed and pushed: {message}"
        except Exception as e:
            logger.error(f"[AOA] Git commit failed: {e}")
            raise
    
    def check_system_health(self) -> Dict[str, Any]:
        """Check system health"""
        health = {}
        
        # Check services
        services = ["dlnk-platform", "postgresql", "redis-server"]
        for service in services:
            result = self.execute_command(f"systemctl is-active {service}")
            health[service] = result["stdout"].strip() == "active"
        
        # Check disk space
        result = self.execute_command("df -h / | tail -1 | awk '{print $5}'")
        health["disk_usage"] = result["stdout"].strip()
        
        # Check memory
        result = self.execute_command("free -h | grep Mem | awk '{print $3\"/\"$2}'")
        health["memory_usage"] = result["stdout"].strip()
        
        logger.info(f"[AOA] System health check: {health}")
        return health
    
    async def chat(self, user_message: str) -> str:
        """
        Chat with user and execute actions
        
        Flow:
        1. Add user message to history
        2. Send to Vanchin AI with system prompt
        3. Parse AI response
        4. Execute tools if needed
        5. Return response to user
        """
        # Add user message
        self.conversation_history.append({
            "role": "user",
            "content": user_message
        })
        
        # Build messages for AI
        messages = [
            {"role": "system", "content": self.system_prompt}
        ] + self.conversation_history
        
        # Get AI response
        ai_response = vanchin_client.chat(messages=messages, max_tokens=2000)
        
        # Try to parse as JSON (tool call)
        try:
            response_json = json.loads(ai_response)
            
            # Check if it's a tool call
            if "action" in response_json:
                action = response_json["action"]
                params = response_json.get("parameters", {})
                thought = response_json.get("thought", "")
                
                logger.info(f"[AOA] Action: {action}, Thought: {thought}")
                
                # Execute tool
                tool_result = await self._execute_tool(action, params)
                
                # Add tool result to conversation
                self.conversation_history.append({
                    "role": "assistant",
                    "content": f"[Tool: {action}] {tool_result}"
                })
                
                # Get final response
                final_response = response_json.get("response", tool_result)
                
            else:
                # Normal response
                final_response = response_json.get("response", ai_response)
        
        except json.JSONDecodeError:
            # Not JSON, treat as normal response
            final_response = ai_response
        
        # Add AI response to history
        self.conversation_history.append({
            "role": "assistant",
            "content": final_response
        })
        
        return final_response
    
    async def _execute_tool(self, action: str, params: Dict[str, Any]) -> str:
        """Execute tool action"""
        try:
            if action == "read_file":
                return self.read_file(params["path"])
            
            elif action == "write_file":
                return self.write_file(params["path"], params["content"])
            
            elif action == "execute_command":
                result = self.execute_command(params["cmd"])
                return f"Exit code: {result['returncode']}\nOutput: {result['stdout']}\nError: {result['stderr']}"
            
            elif action == "list_files":
                files = self.list_files(params.get("directory", "."))
                return "\n".join(files)
            
            elif action == "git_commit":
                return self.git_commit(params["message"])
            
            elif action == "check_system_health":
                health = self.check_system_health()
                return json.dumps(health, indent=2)
            
            else:
                return f"❌ Unknown action: {action}"
        
        except Exception as e:
            logger.error(f"[AOA] Tool execution failed: {e}")
            return f"❌ Error: {str(e)}"


# Global instance
advanced_agent = AdvancedVanchinAgent()

