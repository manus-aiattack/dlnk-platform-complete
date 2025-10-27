"""
Evolution Cycle System - Autonomous Self-Improvement

This system creates a continuous evolution cycle where:
1. Agents perform attacks
2. Results are analyzed
3. Poorly performing agents are improved
4. New agents are created for discovered vulnerabilities
5. The cycle repeats

This achieves true autonomy - the system improves itself over time.
"""

import asyncio
from typing import Dict, List, Optional, Any
from loguru import logger
from datetime import datetime, timedelta
import json

from agents.code_writer_agent import CodeWriterAgent
from api.database.db_service import db


class EvolutionSystem:
    """
    Autonomous evolution system for continuous self-improvement.
    
    Monitors agent performance and automatically improves or replaces
    underperforming agents.
    """
    
    def __init__(
        self,
        evolution_interval: int = 3600,  # 1 hour
        min_attempts_before_evolution: int = 10,
        success_rate_threshold: float = 0.3  # 30%
    ):
        """
        Initialize Evolution System.
        
        Args:
            evolution_interval: Seconds between evolution cycles
            min_attempts_before_evolution: Minimum attempts before evolving
            success_rate_threshold: Minimum success rate to avoid evolution
        """
        self.evolution_interval = evolution_interval
        self.min_attempts = min_attempts_before_evolution
        self.success_threshold = success_rate_threshold
        
        self.code_writer = CodeWriterAgent()
        self.running = False
        
        self.evolution_history = []
        self.agent_performance = {}
    
    async def start(self):
        """
        Start the evolution cycle.
        
        Runs continuously, monitoring and improving agents.
        """
        logger.info("🧬 Starting Evolution System")
        logger.info(f"   Evolution Interval: {self.evolution_interval}s")
        logger.info(f"   Min Attempts: {self.min_attempts}")
        logger.info(f"   Success Threshold: {self.success_threshold * 100}%")
        
        self.running = True
        
        try:
            while self.running:
                await self._evolution_cycle()
                
                logger.info(f"⏳ Waiting {self.evolution_interval}s before next evolution...")
                await asyncio.sleep(self.evolution_interval)
                
        except KeyboardInterrupt:
            logger.info("⚠️  Stopping Evolution System (Ctrl+C)")
            self.running = False
            
        except Exception as e:
            logger.error(f"❌ Evolution System error: {e}")
            raise
    
    async def _evolution_cycle(self):
        """
        Single evolution cycle:
        1. Analyze agent performance
        2. Identify underperforming agents
        3. Improve or replace them
        4. Create new agents for new vulnerabilities
        """
        try:
            logger.info("🔄 Starting evolution cycle")
            
            # Step 1: Analyze performance
            logger.info("📊 Step 1: Analyzing agent performance")
            performance = await self._analyze_agent_performance()
            
            # Step 2: Identify underperformers
            logger.info("🔍 Step 2: Identifying underperforming agents")
            underperformers = self._identify_underperformers(performance)
            
            if underperformers:
                logger.info(f"⚠️  Found {len(underperformers)} underperforming agents")
                
                # Step 3: Improve underperformers
                logger.info("🔧 Step 3: Improving underperforming agents")
                for agent_name, metrics in underperformers.items():
                    await self._improve_agent(agent_name, metrics)
            else:
                logger.info("✅ All agents performing well")
            
            # Step 4: Discover new vulnerability types
            logger.info("🔍 Step 4: Discovering new vulnerability types")
            new_vulns = await self._discover_new_vulnerabilities()
            
            if new_vulns:
                logger.info(f"🆕 Found {len(new_vulns)} new vulnerability types")
                
                # Step 5: Create agents for new vulnerabilities
                logger.info("🤖 Step 5: Creating agents for new vulnerabilities")
                for vuln in new_vulns:
                    await self._create_agent_for_vulnerability(vuln)
            
            logger.info("✅ Evolution cycle completed")
            
        except Exception as e:
            logger.error(f"❌ Evolution cycle failed: {e}")
            import traceback
            logger.error(traceback.format_exc())
    
    async def _analyze_agent_performance(self) -> Dict[str, Dict]:
        """
        Analyze performance of all agents.
        
        Returns:
            Dictionary of agent_name -> performance metrics
        """
        performance = {}
        
        try:
            # Get attack history from database
            # In production, this would query the actual database
            # For now, we'll use simulated data
            
            # Simulated agent performance data
            agents = [
                'sqlmap_agent',
                'xss_hunter',
                'command_injection_exploiter',
                'ssrf_agent_weaponized',
                'auth_bypass_agent'
            ]
            
            for agent_name in agents:
                # Get metrics from database
                metrics = await self._get_agent_metrics(agent_name)
                performance[agent_name] = metrics
            
            logger.info(f"📊 Analyzed {len(performance)} agents")
            
        except Exception as e:
            logger.error(f"Performance analysis failed: {e}")
        
        return performance
    
    async def _get_agent_metrics(self, agent_name: str) -> Dict:
        """Get performance metrics for an agent."""
        
        # In production, query from database
        # For now, return simulated data
        
        import random
        
        total_attempts = random.randint(10, 100)
        successes = random.randint(0, total_attempts)
        success_rate = successes / total_attempts if total_attempts > 0 else 0
        
        return {
            'agent_name': agent_name,
            'total_attempts': total_attempts,
            'successes': successes,
            'failures': total_attempts - successes,
            'success_rate': success_rate,
            'avg_response_time': random.uniform(1.0, 10.0),
            'last_success': datetime.now() - timedelta(hours=random.randint(1, 48)),
            'error_types': ['timeout', 'waf_blocked', 'connection_error']
        }
    
    def _identify_underperformers(
        self,
        performance: Dict[str, Dict]
    ) -> Dict[str, Dict]:
        """
        Identify agents that need improvement.
        
        Args:
            performance: Performance metrics for all agents
            
        Returns:
            Dictionary of underperforming agents
        """
        underperformers = {}
        
        for agent_name, metrics in performance.items():
            # Check if agent has enough attempts
            if metrics['total_attempts'] < self.min_attempts:
                continue
            
            # Check success rate
            if metrics['success_rate'] < self.success_threshold:
                logger.warning(f"⚠️  {agent_name}: Success rate {metrics['success_rate']*100:.1f}% (threshold: {self.success_threshold*100}%)")
                underperformers[agent_name] = metrics
        
        return underperformers
    
    async def _improve_agent(self, agent_name: str, metrics: Dict):
        """
        Improve an underperforming agent.
        
        Args:
            agent_name: Agent to improve
            metrics: Performance metrics
        """
        logger.info(f"🔧 Improving {agent_name}")
        logger.info(f"   Current success rate: {metrics['success_rate']*100:.1f}%")
        logger.info(f"   Total attempts: {metrics['total_attempts']}")
        
        try:
            # Get failure logs
            failure_logs = await self._get_failure_logs(agent_name)
            
            # Use CodeWriterAgent to improve
            result = await self.code_writer.improve_agent_from_failures(
                agent_name,
                failure_logs
            )
            
            if result and result['status'] == 'modified':
                logger.info(f"✅ {agent_name} improved successfully")
                
                # Record evolution
                self.evolution_history.append({
                    'type': 'improvement',
                    'agent_name': agent_name,
                    'timestamp': datetime.now().isoformat(),
                    'old_success_rate': metrics['success_rate'],
                    'reason': 'underperformance',
                    'backup_path': result.get('backup_path')
                })
                
                # Test improved agent
                test_result = await self.code_writer.test_agent(
                    agent_name,
                    'https://localhost:8000'
                )
                
                if test_result['status'] == 'success':
                    logger.info(f"✅ {agent_name} test passed")
                else:
                    logger.warning(f"⚠️  {agent_name} test failed: {test_result.get('error')}")
            else:
                logger.error(f"❌ Failed to improve {agent_name}")
                
        except Exception as e:
            logger.error(f"Agent improvement failed: {e}")
    
    async def _get_failure_logs(self, agent_name: str) -> List[Dict]:
        """Get failure logs for an agent."""
        
        # In production, query from database
        # For now, return simulated data
        
        return [
            {'error': 'TimeoutError: Request timeout', 'success': False},
            {'error': 'WAFBlocked: Request blocked by WAF', 'success': False},
            {'error': 'ConnectionError: Connection refused', 'success': False},
            {'error': 'PayloadBlocked: Payload detected', 'success': False},
        ]
    
    async def _discover_new_vulnerabilities(self) -> List[Dict]:
        """
        Discover new vulnerability types from recent attacks.
        
        Returns:
            List of new vulnerability types
        """
        new_vulns = []
        
        try:
            # In production, analyze attack results to find new vulnerability patterns
            # For now, return simulated discoveries
            
            # Check if we've seen these vulnerabilities before
            known_vulns = set(self.agent_performance.keys())
            
            # Simulated new vulnerability discoveries
            potential_vulns = [
                {
                    'type': 'graphql_injection',
                    'description': 'GraphQL injection vulnerability',
                    'severity': 'high',
                    'examples': ['{ user(id: "1 OR 1=1") { name } }']
                },
                {
                    'type': 'jwt_confusion',
                    'description': 'JWT algorithm confusion attack',
                    'severity': 'critical',
                    'examples': ['Modified JWT with "alg":"none"']
                }
            ]
            
            for vuln in potential_vulns:
                agent_name = f"{vuln['type']}_agent"
                if agent_name not in known_vulns:
                    new_vulns.append(vuln)
            
        except Exception as e:
            logger.error(f"Vulnerability discovery failed: {e}")
        
        return new_vulns
    
    async def _create_agent_for_vulnerability(self, vuln: Dict):
        """
        Create a new agent for a discovered vulnerability type.
        
        Args:
            vuln: Vulnerability information
        """
        agent_name = f"{vuln['type']}_agent"
        
        logger.info(f"🤖 Creating agent for {vuln['type']}")
        
        try:
            result = await self.code_writer.create_new_agent(
                agent_name=agent_name,
                purpose=vuln['description'],
                target_vulnerability=vuln['type'],
                example_exploits=[{'payload': ex} for ex in vuln.get('examples', [])]
            )
            
            if result and result['status'] == 'created':
                logger.info(f"✅ Created {agent_name}")
                
                # Record evolution
                self.evolution_history.append({
                    'type': 'creation',
                    'agent_name': agent_name,
                    'timestamp': datetime.now().isoformat(),
                    'vulnerability_type': vuln['type'],
                    'reason': 'new_vulnerability_discovered'
                })
                
                # Test new agent
                test_result = await self.code_writer.test_agent(
                    agent_name,
                    'https://localhost:8000'
                )
                
                if test_result['status'] == 'success':
                    logger.info(f"✅ {agent_name} test passed")
                else:
                    logger.warning(f"⚠️  {agent_name} test failed")
            else:
                logger.error(f"❌ Failed to create {agent_name}")
                
        except Exception as e:
            logger.error(f"Agent creation failed: {e}")
    
    def stop(self):
        """Stop the evolution system."""
        logger.info("🛑 Stopping Evolution System...")
        self.running = False
    
    def get_status(self) -> Dict[str, Any]:
        """Get current status of evolution system."""
        return {
            'running': self.running,
            'total_evolutions': len(self.evolution_history),
            'evolution_interval': self.evolution_interval,
            'min_attempts': self.min_attempts,
            'success_threshold': self.success_threshold,
            'recent_evolutions': self.evolution_history[-5:]  # Last 5
        }
    
    def get_evolution_history(self) -> List[Dict]:
        """Get complete evolution history."""
        return self.evolution_history


async def main():
    """Run the Evolution System."""
    
    # Initialize database connection
    await db.connect()
    
    try:
        # Create evolution system
        evolution = EvolutionSystem(
            evolution_interval=3600,  # 1 hour
            min_attempts_before_evolution=10,
            success_rate_threshold=0.3  # 30%
        )
        
        # Start evolution
        await evolution.start()
        
    finally:
        await db.disconnect()


if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)
    
    asyncio.run(main())

