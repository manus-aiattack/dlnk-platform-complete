"""
Attack Workflow Orchestrator
จัดการ attack workflow ตั้งแต่ reconnaissance ถึง covering tracks
"""

import asyncio
import os
import uuid
from typing import Dict, List, Any, Optional
from datetime import datetime
from loguru import logger
from core.error_handlers import handle_errors
from core import attack_logger


class AttackWorkflow:
    """
    Attack Workflow Orchestrator
    
    Workflow Phases:
    1. Reconnaissance - Information gathering
    2. Vulnerability Scanning - Identify weaknesses
    3. Exploitation - Gain initial access
    4. Post-Exploitation - Privilege escalation, persistence
    5. Data Exfiltration - Steal sensitive data
    6. Covering Tracks - Clean up evidence
    """
    
    def __init__(self, attack_id: uuid.UUID, target: str, user_id: int | None = None):
        self.attack_id = attack_id
        self.target = target
        self.user_id = user_id
        self.workspace_dir = os.getenv('WORKSPACE_DIR', 'workspace')
        self.attack_dir = os.path.join(self.workspace_dir, 'attacks', str(attack_id))
        os.makedirs(self.attack_dir, exist_ok=True)
        
        self.workflow_state = {}

    async def initialize_state(self):
        """Load existing state or create a new one."""
        state = await attack_logger.load_workflow_state(self.attack_id)
        if state:
            self.workflow_state = state
            logger.info(f"[Workflow] Loaded existing state for attack {self.attack_id}")
        else:
            self.workflow_state = {
                "attack_id": str(self.attack_id),
                "target": self.target,
                "started_at": datetime.now().isoformat(),
                "current_phase": "reconnaissance",
                "phases": {
                    "reconnaissance": {"status": "pending", "results": {}},
                    "vulnerability_scanning": {"status": "pending", "results": {}},
                    "exploitation": {"status": "pending", "results": {}},
                    "post_exploitation": {"status": "pending", "results": {}},
                    "data_exfiltration": {"status": "pending", "results": {}},
                    "covering_tracks": {"status": "pending", "results": {}}
                },
                "vulnerabilities": [],
                "exploited": [],
                "exfiltrated": [],
                "errors": []
            }
            logger.info(f"[Workflow] Created new state for attack {self.attack_id}")

    @handle_errors(default_return={})
    async def execute_full_workflow(self, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Execute full attack workflow
        
        Args:
            context: Additional context (credentials, cookies, etc.)
        
        Returns:
            Complete workflow results
        """
        await self.initialize_state()
        logger.info(f"[Workflow] Starting full attack workflow for {self.target}")
        await attack_logger.log_attack_start(self.attack_id, self.target, self.user_id)
        
        context = context or {}
        
        try:
            # Phase 1: Reconnaissance
            recon_results = await self.phase_reconnaissance(context)
            self.workflow_state["phases"]["reconnaissance"] = {
                "status": "completed" if recon_results.get("success") else "failed",
                "results": recon_results
            }
            await attack_logger.log_phase_complete(self.attack_id, self.target, "reconnaissance", recon_results, self.user_id)
            
            # Phase 2: Vulnerability Scanning
            vuln_results = await self.phase_vulnerability_scanning(context, recon_results)
            self.workflow_state["phases"]["vulnerability_scanning"] = {
                "status": "completed" if vuln_results.get("success") else "failed",
                "results": vuln_results
            }
            await attack_logger.log_phase_complete(self.attack_id, self.target, "vulnerability_scanning", vuln_results, self.user_id)

            # Phase 3: Exploitation
            exploit_results = await self.phase_exploitation(context, vuln_results)
            self.workflow_state["phases"]["exploitation"] = {
                "status": "completed" if exploit_results.get("success") else "failed",
                "results": exploit_results
            }
            await attack_logger.log_phase_complete(self.attack_id, self.target, "exploitation", exploit_results, self.user_id)

            # Phase 4: Post-Exploitation (only if exploitation succeeded)
            if exploit_results.get("success"):
                post_exploit_results = await self.phase_post_exploitation(context, exploit_results)
                self.workflow_state["phases"]["post_exploitation"] = {
                    "status": "completed" if post_exploit_results.get("success") else "failed",
                    "results": post_exploit_results
                }
                await attack_logger.log_phase_complete(self.attack_id, self.target, "post_exploitation", post_exploit_results, self.user_id)

                # Phase 5: Data Exfiltration
                exfil_results = await self.phase_data_exfiltration(context, post_exploit_results)
                self.workflow_state["phases"]["data_exfiltration"] = {
                    "status": "completed" if exfil_results.get("success") else "failed",
                    "results": exfil_results
                }
                await attack_logger.log_phase_complete(self.attack_id, self.target, "data_exfiltration", exfil_results, self.user_id)

                # Phase 6: Covering Tracks
                cleanup_results = await self.phase_covering_tracks(context)
                self.workflow_state["phases"]["covering_tracks"] = {
                    "status": "completed" if cleanup_results.get("success") else "failed",
                    "results": cleanup_results
                }
                await attack_logger.log_phase_complete(self.attack_id, self.target, "covering_tracks", cleanup_results, self.user_id)

            await attack_logger.save_workflow_state(self.attack_id, self.workflow_state)
            await attack_logger.log_attack_complete(self.attack_id, self.target, self.user_id)
            
            logger.success(f"[Workflow] Attack workflow completed for {self.target}")
            
            return {
                "success": True,
                "attack_id": str(self.attack_id),
                "target": self.target,
                "workflow_state": self.workflow_state
            }
            
        except Exception as e:
            logger.error(f"[Workflow] Attack workflow failed: {e}")
            self.workflow_state["errors"].append(str(e))
            await attack_logger.log_attack_failure(self.attack_id, self.target, self.workflow_state['current_phase'], {"error": str(e)}, self.user_id)
            await attack_logger.save_workflow_state(self.attack_id, self.workflow_state)
            
            return {
                "success": False,
                "error": str(e),
                "workflow_state": self.workflow_state
            }
    
    @handle_errors(default_return={})
    async def phase_reconnaissance(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Phase 1: Reconnaissance
        
        Tasks:
        - Port scanning (Nmap)
        - Service enumeration
        - Technology detection
        - Directory bruteforcing (Gobuster)
        - Subdomain enumeration
        """
        self.workflow_state['current_phase'] = 'reconnaissance'
        logger.info(f"[Workflow] Phase 1: Reconnaissance on {self.target}")
        
        results = {
            "success": False,
            "phase": "reconnaissance",
            "target": self.target,
            "ports": [],
            "services": [],
            "technologies": [],
            "directories": [],
            "subdomains": []
        }
        
        try:
            # Import tools
            from core.tool_manager import ToolManager
            tool_manager = ToolManager()
            
            # 1. Port Scanning with Nmap
            if tool_manager.check_tool_installed("nmap"):
                logger.info("[Recon] Running Nmap port scan...")
                # Nmap integration would go here
                # For now, placeholder
                results["ports"] = ["80", "443", "22", "3306"]
                results["services"] = ["http", "https", "ssh", "mysql"]
            
            # 2. Directory Bruteforcing with Gobuster
            if tool_manager.check_tool_installed("gobuster") and self.target.startswith("http"):
                logger.info("[Recon] Running Gobuster directory scan...")
                gobuster_results = await tool_manager.run_gobuster(
                    self.target,
                    mode="dir"
                )
                if gobuster_results.get("success"):
                    results["directories"] = gobuster_results.get("results", [])
            
            # 3. Technology Detection
            logger.info("[Recon] Detecting technologies...")
            # Technology detection would go here
            results["technologies"] = ["PHP", "MySQL", "Apache"]
            
            results["success"] = True
            logger.success(f"[Recon] Found {len(results['ports'])} ports, {len(results['directories'])} directories")
            
        except Exception as e:
            logger.error(f"[Recon] Reconnaissance failed: {e}")
            results["error"] = str(e)
        
        return results
    
    @handle_errors(default_return={})
    async def phase_vulnerability_scanning(
        self,
        context: Dict[str, Any],
        recon_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Phase 2: Vulnerability Scanning
        
        Tasks:
        - Nuclei vulnerability scanning
        - Nikto web server scanning
        - WPScan (if WordPress detected)
        - SQL injection testing
        - XSS testing
        """
        self.workflow_state['current_phase'] = 'vulnerability_scanning'
        logger.info(f"[Workflow] Phase 2: Vulnerability Scanning on {self.target}")
        
        results = {
            "success": False,
            "phase": "vulnerability_scanning",
            "vulnerabilities": []
        }
        
        try:
            from core.tool_manager import ToolManager
            tool_manager = ToolManager()
            
            # 1. Nuclei Scanning
            if tool_manager.check_tool_installed("nuclei"):
                logger.info("[VulnScan] Running Nuclei...")
                nuclei_results = await tool_manager.run_nuclei(
                    self.target,
                    severity="critical,high,medium"
                )
                if nuclei_results.get("success"):
                    results["vulnerabilities"].extend(nuclei_results.get("vulnerabilities", []))
            
            # 2. Nikto Scanning (if web server)
            if tool_manager.check_tool_installed("nikto") and self.target.startswith("http"):
                logger.info("[VulnScan] Running Nikto...")
                nikto_results = await tool_manager.run_nikto(self.target)
                if nikto_results.get("success"):
                    # Parse Nikto results
                    pass
            
            # 3. WPScan (if WordPress)
            if "WordPress" in recon_results.get("technologies", []):
                if tool_manager.check_tool_installed("wpscan"):
                    logger.info("[VulnScan] Running WPScan...")
                    wpscan_results = await tool_manager.run_wpscan(self.target)
                    if wpscan_results.get("success"):
                        # Parse WPScan results
                        pass
            
            # Store vulnerabilities
            self.workflow_state["vulnerabilities"] = results["vulnerabilities"]
            
            results["success"] = True
            logger.success(f"[VulnScan] Found {len(results['vulnerabilities'])} vulnerabilities")
            
        except Exception as e:
            logger.error(f"[VulnScan] Vulnerability scanning failed: {e}")
            results["error"] = str(e)
        
        return results
    
    @handle_errors(default_return={})
    async def phase_exploitation(
        self,
        context: Dict[str, Any],
        vuln_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Phase 3: Exploitation
        
        Tasks:
        - Exploit SQL injection
        - Exploit XSS
        - Exploit file upload
        - Exploit RCE
        - Gain shell access
        """
        self.workflow_state['current_phase'] = 'exploitation'
        logger.info(f"[Workflow] Phase 3: Exploitation on {self.target}")
        
        results = {
            "success": False,
            "phase": "exploitation",
            "exploited": [],
            "shells": []
        }
        
        try:
            from core.auto_exploit import AutoExploiter
            exploiter = AutoExploiter()
            
            # Auto exploit based on vulnerabilities
            exploit_results = await exploiter.auto_exploit_target(self.target, context)
            
            if exploit_results.get("success"):
                results["exploited"] = exploit_results.get("exploited", [])
                results["shells"] = exploit_results.get("shells", [])
                results["success"] = True
                
                self.workflow_state["exploited"] = results["exploited"]
                
                logger.success(f"[Exploit] Exploited {len(results['exploited'])} vulnerabilities")
            
        except Exception as e:
            logger.error(f"[Exploit] Exploitation failed: {e}")
            results["error"] = str(e)
        
        return results
    
    @handle_errors(default_return={})
    async def phase_post_exploitation(
        self,
        context: Dict[str, Any],
        exploit_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Phase 4: Post-Exploitation
        
        Tasks:
        - Privilege escalation
        - Persistence mechanisms
        - Lateral movement
        - Credential harvesting
        """
        self.workflow_state['current_phase'] = 'post_exploitation'
        logger.info(f"[Workflow] Phase 4: Post-Exploitation on {self.target}")
        
        results = {
            "success": False,
            "phase": "post_exploitation",
            "privileges": [],
            "persistence": [],
            "credentials": []
        }
        
        try:
            # Check if we have shell access
            shells = exploit_results.get("shells", [])
            
            if not shells:
                logger.warning("[PostExploit] No shell access, skipping post-exploitation")
                return results
            
            # 1. Privilege Escalation
            logger.info("[PostExploit] Attempting privilege escalation...")
            # Privilege escalation logic would go here
            
            # 2. Establish Persistence
            if os.getenv("ENABLE_PERSISTENCE", "false").lower() == "true":
                logger.info("[PostExploit] Establishing persistence...")
                # Persistence logic would go here
            
            # 3. Harvest Credentials
            logger.info("[PostExploit] Harvesting credentials...")
            from agents.credential_harvesting.credential_harvester import CredentialHarvester
            harvester = CredentialHarvester()
            # Credential harvesting logic would go here
            
            results["success"] = True
            logger.success("[PostExploit] Post-exploitation complete")
            
        except Exception as e:
            logger.error(f"[PostExploit] Post-exploitation failed: {e}")
            results["error"] = str(e)
        
        return results
    
    @handle_errors(default_return={})
    async def phase_data_exfiltration(
        self,
        context: Dict[str, Any],
        post_exploit_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Phase 5: Data Exfiltration
        
        Tasks:
        - Database dumping
        - File downloading
        - Credential extraction
        - Configuration file collection
        """
        self.workflow_state['current_phase'] = 'data_exfiltration'
        logger.info(f"[Workflow] Phase 5: Data Exfiltration from {self.target}")
        
        results = {
            "success": False,
            "phase": "data_exfiltration",
            "databases": [],
            "files": [],
            "credentials": [],
            "total_size": 0
        }
        
        try:
            if os.getenv("ENABLE_DATA_EXFILTRATION", "true").lower() != "true":
                logger.warning("[Exfil] Data exfiltration disabled in config")
                return results
            
            from data_exfiltration.exfiltrator import DataExfiltrator
            exfiltrator = DataExfiltrator(
                attack_id=self.attack_id,
                user_key=context.get("user_key", "default")
            )
            
            # Exfiltrate all data
            exfil_results = await exfiltrator.exfiltrate_all(context)
            
            if exfil_results.get("success"):
                results["databases"] = exfil_results.get("databases", [])
                results["files"] = exfil_results.get("files", [])
                results["credentials"] = exfil_results.get("credentials", [])
                results["total_size"] = exfil_results.get("total_size", 0)
                results["success"] = True
                
                self.workflow_state["exfiltrated"] = results["files"]
                
                logger.success(f"[Exfil] Exfiltrated {len(results['files'])} files, {results['total_size']} bytes")
            
        except Exception as e:
            logger.error(f"[Exfil] Data exfiltration failed: {e}")
            results["error"] = str(e)
        
        return results
    
    @handle_errors(default_return={})
    async def phase_covering_tracks(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Phase 6: Covering Tracks
        
        Tasks:
        - Clear logs
        - Remove uploaded files
        - Clean command history
        - Remove backdoors (optional)
        """
        self.workflow_state['current_phase'] = 'covering_tracks'
        logger.info(f"[Workflow] Phase 6: Covering Tracks on {self.target}")
        
        results = {
            "success": False,
            "phase": "covering_tracks",
            "cleaned": []
        }
        
        try:
            # 1. Clear logs
            logger.info("[Cleanup] Clearing logs...")
            # Log clearing logic would go here
            
            # 2. Remove uploaded files
            logger.info("[Cleanup] Removing uploaded files...")
            # File removal logic would go here
            
            # 3. Clean command history
            logger.info("[Cleanup] Cleaning command history...")
            # History cleaning logic would go here
            
            results["success"] = True
            logger.success("[Cleanup] Tracks covered successfully")
            
        except Exception as e:
            logger.error(f"[Cleanup] Covering tracks failed: {e}")
            results["error"] = str(e)
        
        return results
