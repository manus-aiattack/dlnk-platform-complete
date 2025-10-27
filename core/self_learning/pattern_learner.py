"""
Self-Learning Pattern Recognition System
Learns from attack successes and failures to improve future attacks
"""

import asyncio
import json
import os
from typing import Dict, List, Optional
from datetime import datetime
from pathlib import Path
import logging

log = logging.getLogger(__name__)


class PatternLearner:
    """
    Self-Learning Pattern Recognition
    
    Features:
    - Success/failure pattern extraction
    - Attack strategy optimization
    - Target-specific adaptation
    - Technique effectiveness scoring
    - Knowledge base auto-update
    """
    
    def __init__(self, knowledge_base_path: str = "/tmp/knowledge_base.json"):
        self.knowledge_base_path = Path(knowledge_base_path)
        self.knowledge_base = self._load_knowledge_base()
        self.attack_history = []
    
    async def run(self, target: Dict) -> Dict:
        """
        Main entry point for pattern learning
        
        Args:
            target: Dict containing:
                - attack_result: Result of attack to learn from
                - update_knowledge: Update knowledge base
        
        Returns:
            Dict with learning results
        """
        attack_result = target.get('attack_result')
        update_knowledge = target.get('update_knowledge', True)
        
        if not attack_result:
            return {
                'success': False,
                'error': 'No attack_result provided'
            }
        
        try:
            # Learn from attack result
            patterns = await self.learn_from_attack(attack_result)
            
            # Update knowledge base
            if update_knowledge:
                await self.update_knowledge_base(patterns)
            
            return {
                'success': True,
                'patterns_learned': len(patterns),
                'patterns': patterns
            }
        
        except Exception as e:
            log.error(f"[PatternLearner] Error: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def learn_from_attack(self, attack_result: Dict) -> List[Dict]:
        """
        Learn patterns from attack result
        
        Args:
            attack_result: Attack result data
        
        Returns:
            List of learned patterns
        """
        log.info("[PatternLearner] Learning from attack result")
        
        patterns = []
        
        # Extract attack metadata
        target_url = attack_result.get('target_url')
        attack_type = attack_result.get('attack_type')
        success = attack_result.get('success', False)
        techniques_used = attack_result.get('techniques', [])
        response_time = attack_result.get('response_time', 0)
        error_message = attack_result.get('error')
        
        # Pattern 1: Success/Failure by attack type
        pattern_1 = {
            'type': 'attack_success_rate',
            'attack_type': attack_type,
            'success': success,
            'timestamp': datetime.now().isoformat()
        }
        patterns.append(pattern_1)
        
        # Pattern 2: Technique effectiveness
        for technique in techniques_used:
            pattern_2 = {
                'type': 'technique_effectiveness',
                'technique': technique,
                'attack_type': attack_type,
                'success': success,
                'response_time': response_time
            }
            patterns.append(pattern_2)
        
        # Pattern 3: Target characteristics
        if target_url:
            target_tech = attack_result.get('target_technology', 'unknown')
            pattern_3 = {
                'type': 'target_vulnerability',
                'target_technology': target_tech,
                'attack_type': attack_type,
                'success': success
            }
            patterns.append(pattern_3)
        
        # Pattern 4: Error patterns (for failures)
        if not success and error_message:
            pattern_4 = {
                'type': 'failure_pattern',
                'attack_type': attack_type,
                'error': error_message,
                'techniques': techniques_used
            }
            patterns.append(pattern_4)
        
        # Store in history
        self.attack_history.append(attack_result)
        
        return patterns
    
    async def update_knowledge_base(self, patterns: List[Dict]):
        """Update knowledge base with learned patterns"""
        
        log.info("[PatternLearner] Updating knowledge base")
        
        for pattern in patterns:
            pattern_type = pattern.get('type')
            
            if pattern_type not in self.knowledge_base:
                self.knowledge_base[pattern_type] = []
            
            self.knowledge_base[pattern_type].append(pattern)
        
        # Save to disk
        self._save_knowledge_base()
    
    async def get_recommendations(self, target: Dict) -> Dict:
        """
        Get attack recommendations based on learned patterns
        
        Args:
            target: Target information
        
        Returns:
            Dict with recommendations
        """
        log.info("[PatternLearner] Generating recommendations")
        
        target_tech = target.get('technology', 'unknown')
        attack_type = target.get('attack_type')
        
        recommendations = {
            'recommended_techniques': [],
            'success_probability': 0.0,
            'optimal_attack_sequence': [],
            'warnings': []
        }
        
        # Analyze technique effectiveness
        technique_scores = self._analyze_technique_effectiveness(attack_type)
        
        # Get top techniques
        sorted_techniques = sorted(
            technique_scores.items(),
            key=lambda x: x[1],
            reverse=True
        )
        
        recommendations['recommended_techniques'] = [
            {'technique': t, 'score': s} for t, s in sorted_techniques[:5]
        ]
        
        # Calculate success probability
        success_rate = self._calculate_success_rate(attack_type, target_tech)
        recommendations['success_probability'] = success_rate
        
        # Get warnings from failure patterns
        warnings = self._get_failure_warnings(attack_type)
        recommendations['warnings'] = warnings
        
        return recommendations
    
    def _analyze_technique_effectiveness(self, attack_type: str) -> Dict[str, float]:
        """Analyze effectiveness of techniques"""
        
        technique_scores = {}
        
        patterns = self.knowledge_base.get('technique_effectiveness', [])
        
        for pattern in patterns:
            if pattern.get('attack_type') == attack_type:
                technique = pattern.get('technique')
                success = pattern.get('success', False)
                
                if technique not in technique_scores:
                    technique_scores[technique] = {'success': 0, 'total': 0}
                
                technique_scores[technique]['total'] += 1
                if success:
                    technique_scores[technique]['success'] += 1
        
        # Calculate success rates
        scores = {}
        for technique, stats in technique_scores.items():
            if stats['total'] > 0:
                scores[technique] = stats['success'] / stats['total']
        
        return scores
    
    def _calculate_success_rate(self, attack_type: str, target_tech: str) -> float:
        """Calculate success rate for attack type and target"""
        
        patterns = self.knowledge_base.get('attack_success_rate', [])
        
        successes = 0
        total = 0
        
        for pattern in patterns:
            if pattern.get('attack_type') == attack_type:
                total += 1
                if pattern.get('success'):
                    successes += 1
        
        if total == 0:
            return 0.5  # Default 50% for unknown
        
        return successes / total
    
    def _get_failure_warnings(self, attack_type: str) -> List[str]:
        """Get warnings from failure patterns"""
        
        warnings = []
        
        patterns = self.knowledge_base.get('failure_pattern', [])
        
        # Get common failure reasons
        failure_reasons = {}
        
        for pattern in patterns:
            if pattern.get('attack_type') == attack_type:
                error = pattern.get('error', 'unknown')
                failure_reasons[error] = failure_reasons.get(error, 0) + 1
        
        # Generate warnings for common failures
        for error, count in failure_reasons.items():
            if count >= 3:  # If failed 3+ times with same error
                warnings.append(f"Common failure: {error} (occurred {count} times)")
        
        return warnings
    
    async def optimize_strategy(self, current_strategy: Dict) -> Dict:
        """
        Optimize attack strategy based on learned patterns
        
        Args:
            current_strategy: Current attack strategy
        
        Returns:
            Optimized strategy
        """
        log.info("[PatternLearner] Optimizing strategy")
        
        attack_type = current_strategy.get('attack_type')
        techniques = current_strategy.get('techniques', [])
        
        # Get technique effectiveness
        technique_scores = self._analyze_technique_effectiveness(attack_type)
        
        # Replace low-performing techniques
        optimized_techniques = []
        
        for technique in techniques:
            score = technique_scores.get(technique, 0.5)
            
            if score >= 0.6:  # Keep high-performing techniques
                optimized_techniques.append(technique)
            else:
                # Replace with better technique
                better_techniques = [
                    t for t, s in technique_scores.items()
                    if s > score and t not in optimized_techniques
                ]
                if better_techniques:
                    optimized_techniques.append(better_techniques[0])
        
        optimized_strategy = current_strategy.copy()
        optimized_strategy['techniques'] = optimized_techniques
        optimized_strategy['optimized'] = True
        
        return optimized_strategy
    
    def _load_knowledge_base(self) -> Dict:
        """Load knowledge base from disk"""
        
        if self.knowledge_base_path.exists():
            try:
                with open(self.knowledge_base_path, 'r') as f:
                    return json.load(f)
            except:
                pass
        
        return {}
    
    def _save_knowledge_base(self):
        """Save knowledge base to disk"""
        
        try:
            with open(self.knowledge_base_path, 'w') as f:
                json.dump(self.knowledge_base, f, indent=2)
        except Exception as e:
            log.error(f"[PatternLearner] Failed to save knowledge base: {e}")


if __name__ == '__main__':
    async def test():
        learner = PatternLearner()
        
        # Simulate attack result
        attack_result = {
            'target_url': 'http://example.com',
            'attack_type': 'sql_injection',
            'success': True,
            'techniques': ['union_based', 'time_based'],
            'response_time': 1.5,
            'target_technology': 'MySQL'
        }
        
        result = await learner.run({
            'attack_result': attack_result,
            'update_knowledge': True
        })
        
        print(f"Learning result: {result}")
        
        # Get recommendations
        recommendations = await learner.get_recommendations({
            'technology': 'MySQL',
            'attack_type': 'sql_injection'
        })
        
        print(f"Recommendations: {recommendations}")
    
    asyncio.run(test())

