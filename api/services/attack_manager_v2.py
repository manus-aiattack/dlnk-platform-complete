"""
Attack Manager Service v2
จัดการการโจมตีและเรียกใช้ Agents ผ่าน Agent Executor
"""

import asyncio
import uuid
import yaml
from typing import Dict, Any, Optional, List
from datetime import datetime
from pathlib import Path
import sys

# Add project root to path
project_root = Path(__file__).parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from api.services.agent_executor import get_agent_executor
from api.services.notification import NotificationService
from data_exfiltration.exfiltrator import DataExfiltrator


class AttackManagerV2:
    """Attack Manager v2 - จัดการการโจมตีผ่าน Agent Executor"""
    
    def __init__(self, db, ws_manager):
        self.db = db
        self.ws_manager = ws_manager
        self.active_attacks = {}  # attack_id -> task
        self.executor = get_agent_executor()
        self.notification = NotificationService()
        self.workflows_dir = project_root / "config"
    
    async def start_attack(
        self, 
        user_id: int, 
        user_key: str, 
        target_url: str, 
        attack_type: str, 
        options: Dict = None
    ) -> Dict:
        """เริ่มการโจมตี"""
        
        # Generate attack ID
        attack_id = str(uuid.uuid4())
        
        # Create attack record in database
        await self.db.create_attack(attack_id, user_id, target_url, attack_type)
        
        # Log
        print(f"[AttackManager] Starting attack {attack_id} on {target_url}")
        await self.db.add_agent_log(attack_id, "AttackManager", f"Starting {attack_type} attack", "pending")
        
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
        
        # Send notification
        await self.notification.send_attack_started(attack_id, target_url, attack_type)
        
        return {
            "attack_id": attack_id,
            "status": "started",
            "target_url": target_url,
            "attack_type": attack_type
        }
    
    async def _execute_attack(
        self,
        attack_id: str,
        user_id: int,
        user_key: str,
        target_url: str,
        attack_type: str,
        options: Dict
    ):
        """รันการโจมตีจริง"""
        
        try:
            # Update status to running
            await self.db.update_attack_status(attack_id, "running")
            
            # Determine which workflow to use
            workflow_file = self._get_workflow_file(attack_type)
            
            if workflow_file:
                # Execute workflow
                result = await self._execute_workflow(attack_id, target_url, workflow_file, options)
            else:
                # Execute single agent
                result = await self._execute_single_agent(attack_id, target_url, attack_type, options)
            
            # Data exfiltration (if enabled)
            if result.get("success") and options.get("exfiltrate_data", True):
                await self._perform_data_exfiltration(attack_id, target_url, result)
            
            # Update final status
            final_status = "completed" if result.get("success") else "failed"
            await self.db.update_attack_status(attack_id, final_status)
            
            # Save results
            await self.db.save_attack_results(attack_id, result)
            
            # Send completion notification
            await self.ws_manager.broadcast_to_attack(attack_id, {
                "type": "attack_completed",
                "attack_id": attack_id,
                "status": final_status,
                "vulnerabilities_found": result.get("total_vulnerabilities", 0),
                "timestamp": datetime.now().isoformat()
            })
            
            # Send notification
            await self.notification.send_attack_completed(attack_id, target_url, result)
            
        except Exception as e:
            print(f"[AttackManager] Error in attack {attack_id}: {e}")
            await self.db.update_attack_status(attack_id, "error")
            await self.db.add_agent_log(attack_id, "AttackManager", f"Error: {str(e)}", "error")
            
            # Send error notification
            await self.ws_manager.broadcast_to_attack(attack_id, {
                "type": "attack_error",
                "attack_id": attack_id,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            })
            
            await self.notification.send_attack_error(attack_id, target_url, str(e))
        
        finally:
            # Remove from active attacks
            if attack_id in self.active_attacks:
                del self.active_attacks[attack_id]
    
    def _get_workflow_file(self, attack_type: str) -> Optional[Path]:
        """หา workflow file ตาม attack type"""
        
        workflow_mapping = {
            "full_auto": "attack_full_auto_workflow.yaml",
            "scan": "attack_scan_workflow.yaml",
            "exploit": "attack_exploit_workflow.yaml",
            "post_exploit": "attack_post_exploit_workflow.yaml"
        }
        
        filename = workflow_mapping.get(attack_type)
        if filename:
            filepath = self.workflows_dir / filename
            if filepath.exists():
                return filepath
        
        return None
    
    async def _execute_workflow(
        self,
        attack_id: str,
        target_url: str,
        workflow_file: Path,
        options: Dict
    ) -> Dict:
        """รัน workflow"""
        
        # Load workflow config
        with open(workflow_file, 'r') as f:
            workflow_config = yaml.safe_load(f)
        
        # Log
        await self.db.add_agent_log(
            attack_id, 
            "WorkflowExecutor", 
            f"Executing workflow: {workflow_config.get('name')}", 
            "running"
        )
        
        # Execute workflow
        result = await self.executor.execute_workflow(workflow_config, target_url, attack_id)
        
        # Log results
        for phase in result.get("phases", []):
            phase_name = phase.get("name")
            vulns = phase.get("vulnerabilities_found", 0)
            
            await self.db.add_agent_log(
                attack_id,
                f"Phase: {phase_name}",
                f"Completed. Found {vulns} vulnerabilities",
                "completed"
            )
            
            # Log each agent result
            for agent_result in phase.get("results", []):
                agent_name = agent_result.get("agent")
                agent_success = agent_result.get("success")
                agent_vulns = len(agent_result.get("vulnerabilities", []))
                
                status = "completed" if agent_success else "failed"
                message = f"Found {agent_vulns} vulnerabilities" if agent_success else agent_result.get("error", "Failed")
                
                await self.db.add_agent_log(attack_id, agent_name, message, status)
                
                # Send WebSocket update
                await self.ws_manager.broadcast_to_attack(attack_id, {
                    "type": "agent_completed",
                    "agent": agent_name,
                    "success": agent_success,
                    "vulnerabilities": agent_vulns,
                    "timestamp": datetime.now().isoformat()
                })
                
                # Send vulnerability notifications
                if agent_vulns > 0:
                    for vuln in agent_result.get("vulnerabilities", []):
                        await self.notification.send_vulnerability_found(
                            attack_id,
                            target_url,
                            vuln
                        )
        
        return result
    
    async def _execute_single_agent(
        self,
        attack_id: str,
        target_url: str,
        agent_name: str,
        options: Dict
    ) -> Dict:
        """รัน Agent เดียว"""
        
        await self.db.add_agent_log(attack_id, agent_name, "Starting agent", "running")
        
        # Execute agent
        result = await self.executor.execute_agent(agent_name, target_url, options, attack_id)
        
        # Log result
        status = "completed" if result.get("success") else "failed"
        vulns = len(result.get("vulnerabilities", []))
        message = f"Found {vulns} vulnerabilities" if result.get("success") else result.get("error", "Failed")
        
        await self.db.add_agent_log(attack_id, agent_name, message, status)
        
        # Send WebSocket update
        await self.ws_manager.broadcast_to_attack(attack_id, {
            "type": "agent_completed",
            "agent": agent_name,
            "success": result.get("success"),
            "vulnerabilities": vulns,
            "timestamp": datetime.now().isoformat()
        })
        
        # Send vulnerability notifications
        if vulns > 0:
            for vuln in result.get("vulnerabilities", []):
                await self.notification.send_vulnerability_found(attack_id, target_url, vuln)
        
        return {
            "success": result.get("success"),
            "total_vulnerabilities": vulns,
            "agents": [result]
        }
    
    async def _perform_data_exfiltration(
        self,
        attack_id: str,
        target_url: str,
        attack_result: Dict
    ):
        """ดึงข้อมูลจากเป้าหมาย"""
        
        try:
            await self.db.add_agent_log(attack_id, "DataExfiltrator", "Starting data exfiltration", "running")
            
            # Create exfiltrator
            exfiltrator = DataExfiltrator(
                target_url=target_url,
                workspace_dir=f"workspace/attacks/{attack_id}"
            )
            
            # Perform exfiltration
            exfil_result = await exfiltrator.exfiltrate_all()
            
            # Log result
            files_count = exfil_result.get("files_dumped", 0)
            await self.db.add_agent_log(
                attack_id,
                "DataExfiltrator",
                f"Exfiltrated {files_count} files",
                "completed"
            )
            
            # Send notification
            if files_count > 0:
                await self.notification.send_data_exfiltrated(attack_id, target_url, exfil_result)
            
            # Update attack result
            attack_result["data_exfiltration"] = exfil_result
            
        except Exception as e:
            print(f"[AttackManager] Data exfiltration error: {e}")
            await self.db.add_agent_log(attack_id, "DataExfiltrator", f"Error: {str(e)}", "error")
    
    async def stop_attack(self, attack_id: str) -> bool:
        """หยุดการโจมตี"""
        
        if attack_id in self.active_attacks:
            task = self.active_attacks[attack_id]
            task.cancel()
            
            await self.db.update_attack_status(attack_id, "stopped")
            await self.db.add_agent_log(attack_id, "AttackManager", "Attack stopped by user", "stopped")
            
            # Send WebSocket notification
            await self.ws_manager.broadcast_to_attack(attack_id, {
                "type": "attack_stopped",
                "attack_id": attack_id,
                "timestamp": datetime.now().isoformat()
            })
            
            del self.active_attacks[attack_id]
            return True
        
        return False
    
    async def get_attack_status(self, attack_id: str) -> Optional[Dict]:
        """ดูสถานะการโจมตี"""
        return await self.db.get_attack(attack_id)
    
    async def get_attack_results(self, attack_id: str) -> Optional[Dict]:
        """ดูผลลัพธ์การโจมตี"""
        return await self.db.get_attack_results(attack_id)
    
    async def get_attack_logs(self, attack_id: str) -> List[Dict]:
        """ดู logs การโจมตี"""
        return await self.db.get_agent_logs(attack_id)
    
    def get_active_attacks(self) -> List[str]:
        """ดูรายการการโจมตีที่กำลังรัน"""
        return list(self.active_attacks.keys())

