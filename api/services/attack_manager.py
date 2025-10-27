"""
Attack Manager Service
จัดการการโจมตีและเรียกใช้ Agents
"""

import asyncio
import uuid
from typing import Dict, Any, Optional
from datetime import datetime
from core.logger import log
from core.orchestrator import Orchestrator
from data_exfiltration.exfiltrator import DataExfiltrator


class AttackManager:
    """Attack Manager - จัดการการโจมตีทั้งหมด"""
    
    def __init__(self, db, ws_manager):
        self.db = db
        self.ws_manager = ws_manager
        self.active_attacks = {}  # attack_id -> task
        self.orchestrator = Orchestrator()
    
    async def start_attack(self, user_id: int, user_key: str, target_url: str, attack_type: str, options: Dict = None) -> Dict:
        """เริ่มการโจมตี"""
        # Generate attack ID
        attack_id = str(uuid.uuid4())
        
        # Create attack record
        await self.db.create_attack({
            "attack_id": attack_id,
            "user_id": user_id,
            "target_url": target_url,
            "attack_type": attack_type,
            "status": "pending"
        })
        
        # Log
        log.info(f"[AttackManager] Starting attack {attack_id} on {target_url}")
        await self.db.add_agent_log(attack_id, "AttackManager", "INFO", f"Starting {attack_type} attack")
        
        # Start attack in background
        task = asyncio.create_task(
            self._execute_attack(attack_id, user_id, user_key, target_url, attack_type, options or {})
        )
        self.active_attacks[attack_id] = task
        
        # Send WebSocket notification
        await self.ws_manager.broadcast_to_attack(attack_id, {
            "type": "attack_started",
            "attack_id": attack_id,
            "target_url": target_url,
            "attack_type": attack_type,
            "timestamp": datetime.now().isoformat()
        })
        
        return {
            "success": True,
            "attack_id": attack_id,
            "status": "pending",
            "message": "Attack started"
        }
    
    async def _execute_attack(self, attack_id: str, user_id: int, user_key: str, target_url: str, attack_type: str, options: Dict):
        """Execute attack (runs in background)"""
        try:
            # Update status to running
            await self.db.update_attack_status(attack_id, "running")
            await self.ws_manager.broadcast_to_attack(attack_id, {
                "type": "status_update",
                "status": "running",
                "timestamp": datetime.now().isoformat()
            })
            
            # Execute based on attack type
            if attack_type == "full_auto":
                result = await self._execute_full_auto(attack_id, target_url, options)
            elif attack_type == "sql_injection":
                result = await self._execute_sql_injection(attack_id, target_url, options)
            elif attack_type == "command_injection":
                result = await self._execute_command_injection(attack_id, target_url, options)
            elif attack_type == "zero_day_hunt":
                result = await self._execute_zero_day_hunt(attack_id, target_url, options)
            else:
                result = {"success": False, "error": f"Unknown attack type: {attack_type}"}
            
            # If successful, start data exfiltration
            if result.get("success") and result.get("access_gained"):
                await self._execute_exfiltration(attack_id, user_key, result.get("access_context", {}))
            
            # Update status
            status = "success" if result.get("success") else "failed"
            await self.db.update_attack_status(attack_id, status, result)
            
            # Send final notification
            await self.ws_manager.broadcast_to_attack(attack_id, {
                "type": "attack_completed",
                "status": status,
                "results": result,
                "timestamp": datetime.now().isoformat()
            })
            
            log.success(f"[AttackManager] Attack {attack_id} completed with status: {status}")
            
        except Exception as e:
            log.error(f"[AttackManager] Attack {attack_id} failed: {e}")
            await self.db.update_attack_status(attack_id, "failed", {"error": str(e)})
            await self.ws_manager.broadcast_to_attack(attack_id, {
                "type": "attack_failed",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            })
        
        finally:
            # Remove from active attacks
            if attack_id in self.active_attacks:
                del self.active_attacks[attack_id]
    
    async def _execute_full_auto(self, attack_id: str, target_url: str, options: Dict) -> Dict:
        """Execute full auto attack"""
        log.info(f"[AttackManager] Executing full auto attack on {target_url}")
        
        await self.db.add_agent_log(attack_id, "Orchestrator", "INFO", "Starting full auto attack")
        await self.ws_manager.broadcast_to_attack(attack_id, {
            "type": "agent_update",
            "agent": "Orchestrator",
            "action": "Starting full auto attack",
            "timestamp": datetime.now().isoformat()
        })
        
        # Use orchestrator to run full attack
        workflow_path = "config/attack_full_auto_workflow.yaml"
        target_context = {
            "attack_id": attack_id,
            "target_url": target_url,
            **options
        }
        
        try:
            result = await self.orchestrator.execute_workflow(workflow_path, target_context)
            return {
                "success": True,
                "message": "Attack workflow completed",
                "attack_id": attack_id,
                "target_url": target_url,
                "results": result,
                "vulnerabilities": [],
                "access_gained": False
            }
        except Exception as e:
            log.error(f"[AttackManager] Workflow execution failed: {e}")
            # Return simulated result as fallback
            result = {
                "success": False,
                "message": f"Workflow execution failed: {str(e)}",
                "attack_id": attack_id,
                "target_url": target_url,
                "vulnerabilities": [],
                "access_gained": False
            }
        
        return result
    
    async def _execute_sql_injection(self, attack_id: str, target_url: str, options: Dict) -> Dict:
        """Execute SQL injection attack"""
        log.info(f"[AttackManager] Executing SQL injection on {target_url}")
        
        from agents.sqlmap_agent import SqlmapAgent
        
        agent = SqlmapAgent()
        
        await self.db.add_agent_log(attack_id, "SqlmapAgent", "INFO", "Starting SQL injection")
        await self.ws_manager.broadcast_to_attack(attack_id, {
            "type": "agent_update",
            "agent": "SqlmapAgent",
            "action": "Starting SQL injection",
            "timestamp": datetime.now().isoformat()
        })
        
        context = {
            "url": target_url,
            **options
        }
        
        result = await agent.run("full_auto", context)
        
        await self.db.add_agent_log(
            attack_id,
            "SqlmapAgent",
            "INFO",
            f"SQL injection completed: {'success' if result.success else 'failed'}"
        )
        
        return {
            "success": result.success,
            "data": result.data,
            "access_gained": result.success and result.data.get("databases")
        }
    
    async def _execute_command_injection(self, attack_id: str, target_url: str, options: Dict) -> Dict:
        """Execute command injection attack"""
        log.info(f"[AttackManager] Executing command injection on {target_url}")
        
        from agents.command_injection_exploiter import CommandInjectionExploiter
        
        agent = CommandInjectionExploiter()
        
        await self.db.add_agent_log(attack_id, "CommandInjectionExploiter", "INFO", "Starting command injection")
        await self.ws_manager.broadcast_to_attack(attack_id, {
            "type": "agent_update",
            "agent": "CommandInjectionExploiter",
            "action": "Starting command injection",
            "timestamp": datetime.now().isoformat()
        })
        
        context = {
            "url": target_url,
            **options
        }
        
        result = await agent.run("scan", context)
        
        # If vulnerable, try to exploit
        if result.success and result.data.get("vulnerabilities"):
            exploit_result = await agent.run("reverse_shell", context)
            result.data["exploit"] = exploit_result.data
        
        await self.db.add_agent_log(
            attack_id,
            "CommandInjectionExploiter",
            "INFO",
            f"Command injection completed: {'success' if result.success else 'failed'}"
        )
        
        return {
            "success": result.success,
            "data": result.data,
            "access_gained": result.success and result.data.get("exploit", {}).get("shell_spawned"),
            "access_context": {
                "shell_access": result.data.get("exploit", {})
            }
        }
    
    async def _execute_zero_day_hunt(self, attack_id: str, target_url: str, options: Dict) -> Dict:
        """Execute zero-day hunt"""
        log.info(f"[AttackManager] Executing zero-day hunt on {target_url}")
        
        from advanced_agents.zero_day_hunter import ZeroDayHunterAgent
        
        agent = ZeroDayHunterAgent()
        
        await self.db.add_agent_log(attack_id, "ZeroDayHunterAgent", "INFO", "Starting zero-day hunt")
        await self.ws_manager.broadcast_to_attack(attack_id, {
            "type": "agent_update",
            "agent": "ZeroDayHunterAgent",
            "action": "Starting zero-day hunt",
            "timestamp": datetime.now().isoformat()
        })
        
        context = {
            "url": target_url,
            **options
        }
        
        result = await agent.run("full_zero_day_hunt", context)
        
        await self.db.add_agent_log(
            attack_id,
            "ZeroDayHunterAgent",
            "INFO",
            f"Zero-day hunt completed: {'success' if result.success else 'failed'}"
        )
        
        return {
            "success": result.success,
            "data": result.data,
            "access_gained": result.success and len(result.data.get("phases", {}).get("fuzzing", {}).get("vulnerabilities", [])) > 0
        }
    
    async def _execute_exfiltration(self, attack_id: str, user_key: str, access_context: Dict):
        """Execute data exfiltration"""
        log.info(f"[AttackManager] Starting data exfiltration for attack {attack_id}")
        
        await self.db.add_agent_log(attack_id, "DataExfiltrator", "INFO", "Starting data exfiltration")
        await self.ws_manager.broadcast_to_attack(attack_id, {
            "type": "agent_update",
            "agent": "DataExfiltrator",
            "action": "Starting data exfiltration",
            "timestamp": datetime.now().isoformat()
        })
        
        exfiltrator = DataExfiltrator(attack_id, user_key)
        result = await exfiltrator.exfiltrate_all(access_context)
        
        # Save file records to database
        for file_info in result.get("manifest", {}).get("files", []):
            await self.db.add_dumped_file(
                attack_id,
                file_info["remote_path"],
                file_info["local_path"],
                file_info["size"],
                "file",
                file_info["hash"]
            )
        
        for db_info in result.get("manifest", {}).get("databases", []):
            await self.db.add_dumped_file(
                attack_id,
                db_info["name"],
                db_info["file"],
                db_info["size"],
                db_info["type"],
                ""
            )
        
        await self.db.add_agent_log(
            attack_id,
            "DataExfiltrator",
            "INFO",
            f"Exfiltration completed: {result.get('total_files', 0)} files - {'success' if result.get('success') else 'failed'}"
        )
        
        await self.ws_manager.broadcast_to_attack(attack_id, {
            "type": "exfiltration_completed",
            "total_files": result.get("total_files", 0),
            "total_size": result.get("total_size", 0),
            "timestamp": datetime.now().isoformat()
        })
    
    def _log_callback(self, attack_id: str):
        """Create log callback for orchestrator"""
        async def callback(agent_name: str, action: str, status: str, output: str = None):
            await self.db.add_agent_log(attack_id, agent_name, status, action)
            await self.ws_manager.broadcast_to_attack(attack_id, {
                "type": "agent_update",
                "agent": agent_name,
                "action": action,
                "status": status,
                "output": output,
                "timestamp": datetime.now().isoformat()
            })
        return callback
    
    async def stop_attack(self, attack_id: str) -> Dict:
        """Stop running attack"""
        if attack_id in self.active_attacks:
            task = self.active_attacks[attack_id]
            task.cancel()
            
            await self.db.update_attack_status(attack_id, "stopped")
            await self.ws_manager.broadcast_to_attack(attack_id, {
                "type": "attack_stopped",
                "timestamp": datetime.now().isoformat()
            })
            
            log.info(f"[AttackManager] Attack {attack_id} stopped")
            
            return {"success": True, "message": "Attack stopped"}
        else:
            return {"success": False, "message": "Attack not found or already completed"}
    
    async def get_attack_status(self, attack_id: str) -> Dict:
        """Get attack status"""
        attack = await self.db.get_attack(attack_id)
        
        if not attack:
            return {"success": False, "error": "Attack not found"}
        
        logs = await self.db.get_attack_logs(attack_id)
        files = await self.db.get_attack_files(attack_id)
        
        return {
            "success": True,
            "attack": attack,
            "logs": logs,
            "files": files,
            "is_active": attack_id in self.active_attacks
        }

