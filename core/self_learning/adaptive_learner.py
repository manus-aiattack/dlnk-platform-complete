"""
Adaptive Learning Engine
Learns from successes and failures to improve attack strategies
"""

import asyncio
import json
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from collections import defaultdict
from pathlib import Path
import logging

log = logging.getLogger(__name__)


class AdaptiveLearner:
    """
    Adaptive Learning Engine
    
    Features:
    - Learn from attack successes/failures
    - Adapt strategies based on feedback
    - Build knowledge base
    - Improve over time
    """
    
    def __init__(self, knowledge_base_path: str = "/tmp/dlnk_knowledge"):
        self.knowledge_base_path = Path(knowledge_base_path)
        self.knowledge_base_path.mkdir(parents=True, exist_ok=True)
        
        self.attack_history = []
        self.success_patterns = defaultdict(list)
        self.failure_patterns = defaultdict(list)
        self.learned_strategies = {}
        
        # Performance tracking
        self.strategy_performance = defaultdict(lambda: {'successes': 0, 'failures': 0, 'avg_time': 0.0})
    
    async def learn_from_attack(
        self,
        attack_data: Dict,
        result: Dict
    ):
        """
        Learn from attack attempt
        
        Args:
            attack_data: Attack configuration and parameters
            result: Attack result
        """
        log.info(f"[AdaptiveLearner] Learning from attack: {attack_data.get('type', 'unknown')}")
        
        # Record attack
        attack_record = {
            'timestamp': datetime.now().isoformat(),
            'attack_type': attack_data.get('type'),
            'target': attack_data.get('target'),
            'strategy': attack_data.get('strategy'),
            'parameters': attack_data.get('parameters', {}),
            'success': result.get('success', False),
            'execution_time': result.get('execution_time', 0),
            'error': result.get('error'),
            'vulnerabilities_found': result.get('vulnerabilities', [])
        }
        
        self.attack_history.append(attack_record)
        
        # Update patterns
        if attack_record['success']:
            await self._learn_success_pattern(attack_record)
        else:
            await self._learn_failure_pattern(attack_record)
        
        # Update strategy performance
        await self._update_strategy_performance(attack_record)
        
        # Adapt strategies
        await self._adapt_strategies()
        
        # Save knowledge
        await self._save_knowledge()
    
    async def _learn_success_pattern(self, attack_record: Dict):
        """Learn from successful attack"""
        
        attack_type = attack_record['attack_type']
        strategy = attack_record['strategy']
        
        pattern = {
            'strategy': strategy,
            'parameters': attack_record['parameters'],
            'execution_time': attack_record['execution_time'],
            'vulnerabilities': attack_record['vulnerabilities_found']
        }
        
        self.success_patterns[attack_type].append(pattern)
        
        log.info(f"[AdaptiveLearner] Learned success pattern for {attack_type}")
    
    async def _learn_failure_pattern(self, attack_record: Dict):
        """Learn from failed attack"""
        
        attack_type = attack_record['attack_type']
        strategy = attack_record['strategy']
        
        pattern = {
            'strategy': strategy,
            'parameters': attack_record['parameters'],
            'error': attack_record['error']
        }
        
        self.failure_patterns[attack_type].append(pattern)
        
        log.info(f"[AdaptiveLearner] Learned failure pattern for {attack_type}")
    
    async def _update_strategy_performance(self, attack_record: Dict):
        """Update strategy performance metrics"""
        
        strategy = attack_record['strategy']
        
        if attack_record['success']:
            self.strategy_performance[strategy]['successes'] += 1
        else:
            self.strategy_performance[strategy]['failures'] += 1
        
        # Update average execution time
        current_avg = self.strategy_performance[strategy]['avg_time']
        total_attempts = (self.strategy_performance[strategy]['successes'] + 
                         self.strategy_performance[strategy]['failures'])
        
        new_avg = ((current_avg * (total_attempts - 1) + attack_record['execution_time']) / 
                   total_attempts)
        
        self.strategy_performance[strategy]['avg_time'] = new_avg
    
    async def _adapt_strategies(self):
        """Adapt strategies based on learned patterns"""
        
        for attack_type, success_patterns in self.success_patterns.items():
            if len(success_patterns) >= 5:  # Need enough data
                # Find best performing strategy
                best_strategy = await self._find_best_strategy(attack_type)
                
                if best_strategy:
                    self.learned_strategies[attack_type] = best_strategy
                    log.info(f"[AdaptiveLearner] Adapted strategy for {attack_type}: {best_strategy['name']}")
    
    async def _find_best_strategy(self, attack_type: str) -> Optional[Dict]:
        """Find best performing strategy for attack type"""
        
        success_patterns = self.success_patterns[attack_type]
        
        if not success_patterns:
            return None
        
        # Group by strategy
        strategy_stats = defaultdict(lambda: {'count': 0, 'total_time': 0.0, 'vulns': []})
        
        for pattern in success_patterns:
            strategy = pattern['strategy']
            strategy_stats[strategy]['count'] += 1
            strategy_stats[strategy]['total_time'] += pattern['execution_time']
            strategy_stats[strategy]['vulns'].extend(pattern['vulnerabilities'])
        
        # Calculate scores
        best_strategy = None
        best_score = 0.0
        
        for strategy, stats in strategy_stats.items():
            # Score based on success rate, speed, and vulnerabilities found
            success_rate = stats['count'] / len(success_patterns)
            avg_time = stats['total_time'] / stats['count']
            vuln_count = len(stats['vulns'])
            
            # Calculate score (higher is better)
            score = (success_rate * 0.5 + 
                    (1.0 / (avg_time + 1)) * 0.3 + 
                    (vuln_count / 10.0) * 0.2)
            
            if score > best_score:
                best_score = score
                best_strategy = {
                    'name': strategy,
                    'score': score,
                    'success_rate': success_rate,
                    'avg_time': avg_time,
                    'avg_vulns': vuln_count / stats['count']
                }
        
        return best_strategy
    
    async def recommend_strategy(
        self,
        attack_type: str,
        target_info: Dict
    ) -> Dict:
        """
        Recommend best strategy for attack
        
        Args:
            attack_type: Type of attack
            target_info: Information about target
        
        Returns:
            Recommended strategy
        """
        log.info(f"[AdaptiveLearner] Recommending strategy for {attack_type}")
        
        # Check if we have learned strategy
        if attack_type in self.learned_strategies:
            learned = self.learned_strategies[attack_type]
            
            return {
                'strategy': learned['name'],
                'confidence': learned['score'],
                'source': 'learned',
                'expected_success_rate': learned['success_rate'],
                'expected_time': learned['avg_time']
            }
        
        # Check historical data
        if attack_type in self.success_patterns and self.success_patterns[attack_type]:
            # Use most recent successful strategy
            recent_success = self.success_patterns[attack_type][-1]
            
            return {
                'strategy': recent_success['strategy'],
                'confidence': 0.6,
                'source': 'historical',
                'parameters': recent_success['parameters']
            }
        
        # No learned data, use default
        return {
            'strategy': 'default',
            'confidence': 0.3,
            'source': 'default'
        }
    
    async def predict_success_probability(
        self,
        attack_type: str,
        strategy: str,
        target_info: Dict
    ) -> float:
        """
        Predict probability of success
        
        Args:
            attack_type: Type of attack
            strategy: Attack strategy
            target_info: Target information
        
        Returns:
            Success probability (0.0 - 1.0)
        """
        # Check strategy performance
        if strategy in self.strategy_performance:
            perf = self.strategy_performance[strategy]
            total = perf['successes'] + perf['failures']
            
            if total > 0:
                success_rate = perf['successes'] / total
                
                # Adjust based on target characteristics
                # (In production, use ML model)
                
                return success_rate
        
        # No data, return neutral probability
        return 0.5
    
    async def get_learning_statistics(self) -> Dict:
        """Get learning statistics"""
        
        stats = {
            'total_attacks': len(self.attack_history),
            'learned_strategies': len(self.learned_strategies),
            'attack_types_learned': list(self.learned_strategies.keys()),
            'strategy_performance': {}
        }
        
        # Calculate overall success rates
        for strategy, perf in self.strategy_performance.items():
            total = perf['successes'] + perf['failures']
            success_rate = perf['successes'] / total if total > 0 else 0.0
            
            stats['strategy_performance'][strategy] = {
                'success_rate': success_rate,
                'total_attempts': total,
                'avg_time': perf['avg_time']
            }
        
        return stats
    
    async def export_knowledge_base(self, output_path: str):
        """Export knowledge base"""
        
        log.info(f"[AdaptiveLearner] Exporting knowledge base to {output_path}")
        
        knowledge = {
            'attack_history': self.attack_history[-100:],  # Last 100 attacks
            'learned_strategies': self.learned_strategies,
            'strategy_performance': dict(self.strategy_performance),
            'success_patterns': {k: v[-10:] for k, v in self.success_patterns.items()},
            'failure_patterns': {k: v[-10:] for k, v in self.failure_patterns.items()}
        }
        
        output_file = Path(output_path)
        with open(output_file, 'w') as f:
            json.dump(knowledge, f, indent=2, default=str)
        
        log.info(f"[AdaptiveLearner] Knowledge base exported")
    
    async def import_knowledge_base(self, input_path: str):
        """Import knowledge base"""
        
        log.info(f"[AdaptiveLearner] Importing knowledge base from {input_path}")
        
        input_file = Path(input_path)
        
        if not input_file.exists():
            log.error(f"[AdaptiveLearner] Knowledge base file not found: {input_path}")
            return
        
        try:
            with open(input_file, 'r') as f:
                knowledge = json.load(f)
            
            self.attack_history.extend(knowledge.get('attack_history', []))
            self.learned_strategies.update(knowledge.get('learned_strategies', {}))
            
            # Merge strategy performance
            for strategy, perf in knowledge.get('strategy_performance', {}).items():
                if strategy in self.strategy_performance:
                    # Merge data
                    pass
                else:
                    self.strategy_performance[strategy] = perf
            
            log.info(f"[AdaptiveLearner] Knowledge base imported")
            
        except Exception as e:
            log.error(f"[AdaptiveLearner] Failed to import knowledge base: {e}")
    
    async def _save_knowledge(self):
        """Save knowledge base to disk"""
        
        knowledge_file = self.knowledge_base_path / 'knowledge.json'
        
        try:
            await self.export_knowledge_base(str(knowledge_file))
        except Exception as e:
            log.error(f"[AdaptiveLearner] Failed to save knowledge: {e}")
    
    async def optimize_parameters(
        self,
        attack_type: str,
        current_parameters: Dict
    ) -> Dict:
        """
        Optimize attack parameters based on learned patterns
        
        Args:
            attack_type: Type of attack
            current_parameters: Current parameters
        
        Returns:
            Optimized parameters
        """
        log.info(f"[AdaptiveLearner] Optimizing parameters for {attack_type}")
        
        if attack_type not in self.success_patterns:
            return current_parameters
        
        # Find most successful parameters
        success_patterns = self.success_patterns[attack_type]
        
        if not success_patterns:
            return current_parameters
        
        # Use parameters from most recent successful attack
        best_pattern = success_patterns[-1]
        optimized = best_pattern['parameters'].copy()
        
        # Merge with current parameters
        optimized.update(current_parameters)
        
        log.info(f"[AdaptiveLearner] Parameters optimized")
        
        return optimized


if __name__ == '__main__':
    async def test():
        learner = AdaptiveLearner()
        
        # Simulate learning from attacks
        for i in range(10):
            attack_data = {
                'type': 'sql_injection',
                'target': 'http://test.com',
                'strategy': 'union_based' if i % 2 == 0 else 'blind',
                'parameters': {'timeout': 5}
            }
            
            result = {
                'success': i % 3 != 0,  # 66% success rate
                'execution_time': 2.5 + i * 0.1,
                'vulnerabilities': ['SQLi'] if i % 3 != 0 else []
            }
            
            await learner.learn_from_attack(attack_data, result)
        
        # Get recommendation
        recommendation = await learner.recommend_strategy('sql_injection', {})
        
        print("Strategy Recommendation:")
        print(f"  Strategy: {recommendation['strategy']}")
        print(f"  Confidence: {recommendation['confidence']:.2f}")
        print(f"  Source: {recommendation['source']}")
        
        # Get statistics
        stats = await learner.get_learning_statistics()
        
        print(f"\nLearning Statistics:")
        print(f"  Total Attacks: {stats['total_attacks']}")
        print(f"  Learned Strategies: {stats['learned_strategies']}")
        print(f"  Strategy Performance:")
        for strategy, perf in stats['strategy_performance'].items():
            print(f"    {strategy}: {perf['success_rate']:.1%} success rate")
    
    asyncio.run(test())

