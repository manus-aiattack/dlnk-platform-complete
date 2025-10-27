"""
Real Campaign Executor
Executes real attack campaigns using actual attack agents
"""

import sys
sys.path.insert(0, '/home/ubuntu/aiprojectattack')

import asyncio
import importlib
import os
from typing import Dict, Any, List
from datetime import datetime
from sqlalchemy.orm import Session
from models.database_models import Campaign, Task, Vulnerability, AttackPhase, TaskStatus, SeverityLevel
from core.logger import log
import traceback


class RealCampaignExecutor:
    """Execute real attack campaigns with actual agents"""
    
    def __init__(self):
        self.agents_path = "/home/ubuntu/aiprojectattack/agents"
        self.available_agents = self._discover_agents()
    
    def _discover_agents(self) -> Dict[str, str]:
        """Discover all available attack agents"""
        agents = {}
        
        if not os.path.exists(self.agents_path):
            log.warning(f"Agents path not found: {self.agents_path}")
            return agents
        
        for file in os.listdir(self.agents_path):
            if file.endswith("_agent.py") and not file.startswith("__"):
                agent_name = file.replace(".py", "")
                agents[agent_name] = f"agents.{agent_name}"
        
        # Also check subdirectories
        for subdir in ["active_directory", "cloud/aws", "cloud/azure", "cloud/gcp", "web", "network"]:
            subdir_path = os.path.join(self.agents_path, subdir)
            if os.path.exists(subdir_path):
                for file in os.listdir(subdir_path):
                    if file.endswith("_agent.py") and not file.startswith("__"):
                        agent_name = file.replace(".py", "")
                        module_path = f"agents.{subdir.replace('/', '.')}.{agent_name}"
                        agents[agent_name] = module_path
        
        log.info(f"Discovered {len(agents)} attack agents")
        return agents
    
    async def execute_campaign(self, campaign_id: str, db: Session):
        """Execute a real attack campaign"""
        try:
            campaign = db.query(Campaign).filter(Campaign.id == campaign_id).first()
            if not campaign:
                log.error(f"Campaign {campaign_id} not found")
                return
            
            target = campaign.target
            log.info(f"Starting real attack campaign: {campaign.name} against {target.url}")
            
            # Phase 1: Reconnaissance
            await self._execute_phase(
                campaign, 
                AttackPhase.RECONNAISSANCE,
                [
                    "ai_network_scanner",
                    "network_scanner_agent",
                ],
                db
            )
            
            # Phase 2: Vulnerability Discovery
            await self._execute_phase(
                campaign,
                AttackPhase.VULNERABILITY_DISCOVERY,
                [
                    "api_fuzzer_agent",
                    "sql_injection_agent",
                    "xss_agent",
                    "command_injection_exploiter",
                ],
                db
            )
            
            # Phase 3: Exploitation
            await self._execute_phase(
                campaign,
                AttackPhase.EXPLOITATION,
                [
                    "bola_agent_weaponized",
                    "file_upload_agent",
                ],
                db
            )
            
            # Phase 4: Post-Exploitation
            await self._execute_phase(
                campaign,
                AttackPhase.POST_EXPLOITATION,
                [
                    "credential_harvester_agent",
                    "data_exfiltration_agent",
                    "persistence_agent",
                ],
                db
            )
            
            # Mark campaign as completed
            campaign.status = TaskStatus.COMPLETED
            campaign.completed_at = datetime.utcnow()
            campaign.progress = 100.0
            
            # Summarize results
            vulnerabilities = db.query(Vulnerability).filter(
                Vulnerability.campaign_id == campaign_id
            ).all()
            
            campaign.results = {
                "vulnerabilities_found": len(vulnerabilities),
                "critical_count": len([v for v in vulnerabilities if v.severity == SeverityLevel.CRITICAL]),
                "high_count": len([v for v in vulnerabilities if v.severity == SeverityLevel.HIGH]),
                "medium_count": len([v for v in vulnerabilities if v.severity == SeverityLevel.MEDIUM]),
                "low_count": len([v for v in vulnerabilities if v.severity == SeverityLevel.LOW]),
                "summary": f"Campaign completed successfully. Found {len(vulnerabilities)} vulnerabilities.",
                "phases_completed": [
                    AttackPhase.RECONNAISSANCE.value,
                    AttackPhase.VULNERABILITY_DISCOVERY.value,
                    AttackPhase.EXPLOITATION.value,
                    AttackPhase.POST_EXPLOITATION.value
                ]
            }
            
            db.commit()
            log.success(f"Campaign {campaign.name} completed successfully")
            
        except Exception as e:
            log.error(f"Campaign execution failed: {e}")
            log.error(traceback.format_exc())
            
            campaign.status = TaskStatus.FAILED
            campaign.completed_at = datetime.utcnow()
            campaign.results = {
                "error": str(e),
                "traceback": traceback.format_exc()
            }
            db.commit()
    
    async def _execute_phase(
        self,
        campaign: Campaign,
        phase: AttackPhase,
        agent_names: List[str],
        db: Session
    ):
        """Execute a single attack phase"""
        log.info(f"Executing phase: {phase.value}")
        
        campaign.current_phase = phase
        db.commit()
        
        for agent_name in agent_names:
            await self._execute_agent(campaign, agent_name, phase, db)
        
        # Update progress
        phase_progress = {
            AttackPhase.RECONNAISSANCE: 25.0,
            AttackPhase.VULNERABILITY_DISCOVERY: 50.0,
            AttackPhase.EXPLOITATION: 75.0,
            AttackPhase.POST_EXPLOITATION: 90.0
        }
        
        campaign.progress = phase_progress.get(phase, 0.0)
        db.commit()
    
    async def _execute_agent(
        self,
        campaign: Campaign,
        agent_name: str,
        phase: AttackPhase,
        db: Session
    ):
        """Execute a single attack agent"""
        try:
            # Create task record
            task = Task(
                campaign_id=campaign.id,
                agent_name=agent_name,
                phase=phase,
                status=TaskStatus.RUNNING,
                started_at=datetime.utcnow()
            )
            db.add(task)
            db.commit()
            db.refresh(task)
            
            log.info(f"Executing agent: {agent_name}")
            
            # Try to load and execute the agent
            if agent_name in self.available_agents:
                module_path = self.available_agents[agent_name]
                
                try:
                    # Import the agent module
                    module = importlib.import_module(module_path)
                    
                    # Find the agent class (usually named like NetworkScannerAgent)
                    agent_class = None
                    for attr_name in dir(module):
                        attr = getattr(module, attr_name)
                        if (isinstance(attr, type) and 
                            attr_name.endswith('Agent') and 
                            attr_name != 'BaseAgent'):
                            agent_class = attr
                            break
                    
                    if agent_class:
                        # Instantiate and execute the agent
                        agent = agent_class()
                        
                        # Prepare context
                        context = {
                            'target_host': campaign.target.url,
                            'target_url': campaign.target.url,
                            'campaign_id': campaign.id,
                            'task_id': task.id
                        }
                        
                        # Execute agent (different agents have different interfaces)
                        result = None
                        if hasattr(agent, 'execute'):
                            # Try async execute
                            if asyncio.iscoroutinefunction(agent.execute):
                                from core.data_models import Strategy
                                strategy = Strategy(context=context)
                                result = await agent.execute(strategy)
                            else:
                                result = agent.execute(context)
                        elif hasattr(agent, 'run'):
                            # Try run method
                            if asyncio.iscoroutinefunction(agent.run):
                                result = await agent.run(campaign.target.url)
                            else:
                                result = agent.run(campaign.target.url)
                        
                        # Process results
                        if result:
                            task.results = self._process_agent_result(result)
                            
                            # Extract vulnerabilities if found
                            vulnerabilities = self._extract_vulnerabilities(result, campaign.id, task.id)
                            for vuln in vulnerabilities:
                                db.add(vuln)
                            
                            task.status = TaskStatus.COMPLETED
                            log.success(f"Agent {agent_name} completed successfully")
                        else:
                            task.status = TaskStatus.COMPLETED
                            task.results = {"message": "Agent executed but returned no results"}
                            log.warning(f"Agent {agent_name} returned no results")
                    
                    else:
                        task.status = TaskStatus.FAILED
                        task.results = {"error": "Agent class not found in module"}
                        log.error(f"Agent class not found in {module_path}")
                
                except ImportError as e:
                    task.status = TaskStatus.FAILED
                    task.results = {"error": f"Failed to import agent: {str(e)}"}
                    log.error(f"Failed to import {module_path}: {e}")
                
                except Exception as e:
                    task.status = TaskStatus.FAILED
                    task.results = {"error": str(e), "traceback": traceback.format_exc()}
                    log.error(f"Agent {agent_name} execution failed: {e}")
            
            else:
                task.status = TaskStatus.FAILED
                task.results = {"error": "Agent not found"}
                log.error(f"Agent {agent_name} not found in available agents")
            
            task.completed_at = datetime.utcnow()
            db.commit()
            
        except Exception as e:
            log.error(f"Task execution failed: {e}")
            log.error(traceback.format_exc())
    
    def _process_agent_result(self, result: Any) -> Dict[str, Any]:
        """Process agent result into storable format"""
        if hasattr(result, '__dict__'):
            return {k: str(v) for k, v in result.__dict__.items()}
        elif isinstance(result, dict):
            return result
        else:
            return {"result": str(result)}
    
    def _extract_vulnerabilities(
        self,
        result: Any,
        campaign_id: str,
        task_id: str
    ) -> List[Vulnerability]:
        """Extract vulnerabilities from agent results"""
        vulnerabilities = []
        
        try:
            # Try to extract vulnerabilities from result
            if hasattr(result, 'context') and isinstance(result.context, dict):
                findings = result.context.get('findings', [])
                
                if isinstance(findings, list):
                    for finding in findings:
                        if isinstance(finding, dict):
                            vuln = Vulnerability(
                                campaign_id=campaign_id,
                                task_id=task_id,
                                name=finding.get('name', 'Unknown Vulnerability'),
                                description=finding.get('description', ''),
                                severity=self._parse_severity(finding.get('severity', 'medium')),
                                cvss_score=finding.get('cvss_score', 0.0),
                                cve_id=finding.get('cve_id'),
                                exploit_available=finding.get('exploit_available', False),
                                details_json=finding
                            )
                            vulnerabilities.append(vuln)
        
        except Exception as e:
            log.error(f"Failed to extract vulnerabilities: {e}")
        
        return vulnerabilities
    
    def _parse_severity(self, severity: str) -> SeverityLevel:
        """Parse severity string to enum"""
        severity_map = {
            'critical': SeverityLevel.CRITICAL,
            'high': SeverityLevel.HIGH,
            'medium': SeverityLevel.MEDIUM,
            'low': SeverityLevel.LOW
        }
        return severity_map.get(severity.lower(), SeverityLevel.MEDIUM)


# Singleton instance
real_campaign_executor = RealCampaignExecutor()

