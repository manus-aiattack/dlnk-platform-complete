"""
Enhanced Adaptive Learner with Online Learning
ตามแผนการพัฒนา Manus AI Attack Platform Phase 1
"""

import asyncio
import json
import numpy as np
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
import pickle
import hashlib

from .logger import log


@dataclass
class Pattern:
    """Learned pattern"""
    id: str
    pattern_type: str  # success, failure, optimization
    data: Dict[str, Any]
    confidence: float
    timestamp: str
    context: Dict[str, Any]


@dataclass
class LearningResult:
    """Result of learning process"""
    patterns_learned: int
    knowledge_updated: bool
    strategies_optimized: int
    performance_improvement: float
    execution_time_ms: int


@dataclass
class StrategyOptimization:
    """Optimized strategy"""
    name: str
    original_strategy: Dict[str, Any]
    optimized_strategy: Dict[str, Any]
    improvement_score: float
    confidence: float


class PatternLearner:
    """Advanced pattern recognition system"""

    def __init__(self):
        self.pattern_database = {}
        self.similarity_threshold = 0.7
        self.learning_rate = 0.1

    def extract_patterns(
        self,
        attack_result: Dict[str, Any],
        context: Dict[str, Any]
    ) -> List[Pattern]:
        """Extract patterns from attack results"""
        patterns = []

        try:
            # Extract success/failure patterns
            outcome = attack_result.get('outcome', 'unknown')
            if outcome == 'success':
                patterns.extend(self._extract_success_patterns(attack_result, context))
            elif outcome == 'failure':
                patterns.extend(self._extract_failure_patterns(attack_result, context))

            # Extract optimization patterns
            patterns.extend(self._extract_optimization_patterns(attack_result, context))

            # Extract behavioral patterns
            patterns.extend(self._extract_behavioral_patterns(attack_result, context))

            return patterns

        except Exception as e:
            log.error(f"Failed to extract patterns: {e}")
            return []

    def _extract_success_patterns(
        self,
        attack_result: Dict[str, Any],
        context: Dict[str, Any]
    ) -> List[Pattern]:
        """Extract patterns from successful attacks"""
        patterns = []

        try:
            # Extract agent performance patterns
            successful_agents = attack_result.get('successful_agents', [])
            for agent in successful_agents:
                pattern_data = {
                    'agent_type': agent.get('type'),
                    'execution_time': agent.get('execution_time'),
                    'resource_usage': agent.get('resource_usage'),
                    'target_type': context.get('target_type'),
                    'phase': context.get('phase')
                }

                pattern = Pattern(
                    id=self._generate_pattern_id(pattern_data),
                    pattern_type='success',
                    data=pattern_data,
                    confidence=0.8,
                    timestamp=datetime.now().isoformat(),
                    context=context
                )
                patterns.append(pattern)

        except Exception as e:
            log.error(f"Failed to extract success patterns: {e}")

        return patterns

    def _extract_failure_patterns(
        self,
        attack_result: Dict[str, Any],
        context: Dict[str, Any]
    ) -> List[Pattern]:
        """Extract patterns from failed attacks"""
        patterns = []

        try:
            # Extract failure cause patterns
            failed_agents = attack_result.get('failed_agents', [])
            for agent in failed_agents:
                pattern_data = {
                    'agent_type': agent.get('type'),
                    'failure_reason': agent.get('failure_reason'),
                    'execution_time': agent.get('execution_time'),
                    'target_type': context.get('target_type'),
                    'phase': context.get('phase')
                }

                pattern = Pattern(
                    id=self._generate_pattern_id(pattern_data),
                    pattern_type='failure',
                    data=pattern_data,
                    confidence=0.9,
                    timestamp=datetime.now().isoformat(),
                    context=context
                )
                patterns.append(pattern)

        except Exception as e:
            log.error(f"Failed to extract failure patterns: {e}")

        return patterns

    def _extract_optimization_patterns(
        self,
        attack_result: Dict[str, Any],
        context: Dict[str, Any]
    ) -> List[Pattern]:
        """Extract optimization patterns"""
        patterns = []

        try:
            # Extract timing optimization patterns
            timing_data = attack_result.get('timing_data', {})
            if timing_data:
                pattern_data = {
                    'optimization_type': 'timing',
                    'original_duration': timing_data.get('original_duration'),
                    'actual_duration': timing_data.get('actual_duration'),
                    'improvement_percentage': timing_data.get('improvement_percentage'),
                    'target_type': context.get('target_type')
                }

                pattern = Pattern(
                    id=self._generate_pattern_id(pattern_data),
                    pattern_type='optimization',
                    data=pattern_data,
                    confidence=0.7,
                    timestamp=datetime.now().isoformat(),
                    context=context
                )
                patterns.append(pattern)

        except Exception as e:
            log.error(f"Failed to extract optimization patterns: {e}")

        return patterns

    def _extract_behavioral_patterns(
        self,
        attack_result: Dict[str, Any],
        context: Dict[str, Any]
    ) -> List[Pattern]:
        """Extract behavioral patterns"""
        patterns = []

        try:
            # Extract team coordination patterns
            coordination_data = attack_result.get('coordination_data', {})
            if coordination_data:
                pattern_data = {
                    'pattern_type': 'coordination',
                    'agent_count': coordination_data.get('agent_count'),
                    'parallel_execution_rate': coordination_data.get('parallel_execution_rate'),
                    'success_rate': coordination_data.get('success_rate'),
                    'target_complexity': context.get('target_complexity')
                }

                pattern = Pattern(
                    id=self._generate_pattern_id(pattern_data),
                    pattern_type='behavioral',
                    data=pattern_data,
                    confidence=0.6,
                    timestamp=datetime.now().isoformat(),
                    context=context
                )
                patterns.append(pattern)

        except Exception as e:
            log.error(f"Failed to extract behavioral patterns: {e}")

        return patterns

    def _generate_pattern_id(self, data: Dict[str, Any]) -> str:
        """Generate unique ID for pattern"""
        data_str = json.dumps(data, sort_keys=True)
        return hashlib.md5(data_str.encode()).hexdigest()

    def find_similar_patterns(
        self,
        new_pattern: Pattern,
        max_results: int = 10
    ) -> List[Pattern]:
        """Find similar patterns in database"""
        similar_patterns = []

        try:
            for existing_pattern in self.pattern_database.values():
                similarity = self._calculate_pattern_similarity(new_pattern, existing_pattern)

                if similarity > self.similarity_threshold:
                    similar_patterns.append(existing_pattern)

            return similar_patterns[:max_results]

        except Exception as e:
            log.error(f"Failed to find similar patterns: {e}")
            return []

    def _calculate_pattern_similarity(self, pattern1: Pattern, pattern2: Pattern) -> float:
        """Calculate similarity between two patterns"""
        try:
            # Simple similarity calculation based on data keys
            keys1 = set(pattern1.data.keys())
            keys2 = set(pattern2.data.keys())

            if not keys1 or not keys2:
                return 0.0

            # Jaccard similarity for keys
            intersection = keys1.intersection(keys2)
            union = keys1.union(keys2)
            key_similarity = len(intersection) / len(union) if union else 0.0

            # Data value similarity (simple heuristic)
            value_similarity = 0.0
            common_keys = intersection
            if common_keys:
                for key in common_keys:
                    val1 = pattern1.data[key]
                    val2 = pattern2.data[key]

                    if isinstance(val1, (int, float)) and isinstance(val2, (int, float)):
                        # Numerical similarity
                        max_val = max(abs(val1), abs(val2), 1)
                        value_similarity += 1 - abs(val1 - val2) / max_val
                    elif str(val1) == str(val2):
                        # String equality
                        value_similarity += 1.0

                value_similarity /= len(common_keys)

            return (key_similarity + value_similarity) / 2

        except Exception as e:
            log.error(f"Failed to calculate pattern similarity: {e}")
            return 0.0

    def update_pattern_confidence(
        self,
        pattern_id: str,
        new_confidence: float
    ):
        """Update pattern confidence based on new evidence"""
        if pattern_id in self.pattern_database:
            pattern = self.pattern_database[pattern_id]
            # Exponential moving average
            pattern.confidence = (
                pattern.confidence * (1 - self.learning_rate) +
                new_confidence * self.learning_rate
            )


class KnowledgeBase:
    """Knowledge base for storing and retrieving learned knowledge"""

    def __init__(self, storage_path: str = "workspace/knowledge_base.db"):
        self.storage_path = storage_path
        self.patterns: Dict[str, Pattern] = {}
        self.strategy_knowledge = {}
        self.performance_metrics = {}
        self._load_knowledge_base()

    def _load_knowledge_base(self):
        """Load knowledge base from storage"""
        try:
            # Mock implementation - would normally load from database
            log.info("Knowledge base initialized")
        except Exception as e:
            log.error(f"Failed to load knowledge base: {e}")

    async def update(
        self,
        patterns: List[Pattern],
        outcome: str,
        context: Dict[str, Any]
    ):
        """Update knowledge base with new patterns"""
        try:
            for pattern in patterns:
                # Store or update pattern
                if pattern.id in self.patterns:
                    # Update existing pattern confidence
                    existing_pattern = self.patterns[pattern.id]
                    existing_pattern.confidence = (
                        existing_pattern.confidence * 0.7 +
                        pattern.confidence * 0.3
                    )
                else:
                    # Add new pattern
                    self.patterns[pattern.id] = pattern

            # Update strategy knowledge
            await self._update_strategy_knowledge(patterns, outcome, context)

            # Update performance metrics
            await self._update_performance_metrics(patterns, outcome, context)

            log.info(f"Knowledge base updated with {len(patterns)} patterns")

        except Exception as e:
            log.error(f"Failed to update knowledge base: {e}")

    async def _update_strategy_knowledge(
        self,
        patterns: List[Pattern],
        outcome: str,
        context: Dict[str, Any]
    ):
        """Update strategy knowledge"""
        try:
            for pattern in patterns:
                if pattern.pattern_type == 'success':
                    strategy_key = f"{pattern.data.get('agent_type')}_{pattern.data.get('target_type')}"
                    if strategy_key not in self.strategy_knowledge:
                        self.strategy_knowledge[strategy_key] = []

                    self.strategy_knowledge[strategy_key].append({
                        'pattern_id': pattern.id,
                        'confidence': pattern.confidence,
                        'timestamp': pattern.timestamp,
                        'context': context
                    })

        except Exception as e:
            log.error(f"Failed to update strategy knowledge: {e}")

    async def _update_performance_metrics(
        self,
        patterns: List[Pattern],
        outcome: str,
        context: Dict[str, Any]
    ):
        """Update performance metrics"""
        try:
            metrics_key = context.get('target_type', 'unknown')
            if metrics_key not in self.performance_metrics:
                self.performance_metrics[metrics_key] = {
                    'total_attempts': 0,
                    'success_count': 0,
                    'failure_count': 0,
                    'average_time': 0.0,
                    'last_updated': datetime.now().isoformat()
                }

            metrics = self.performance_metrics[metrics_key]
            metrics['total_attempts'] += 1

            if outcome == 'success':
                metrics['success_count'] += 1
            else:
                metrics['failure_count'] += 1

            # Update average time if available
            for pattern in patterns:
                if 'execution_time' in pattern.data:
                    old_avg = metrics['average_time']
                    count = metrics['success_count'] + metrics['failure_count']
                    new_time = pattern.data['execution_time']
                    metrics['average_time'] = (old_avg * (count - 1) + new_time) / count

            metrics['last_updated'] = datetime.now().isoformat()

        except Exception as e:
            log.error(f"Failed to update performance metrics: {e}")

    async def get_knowledge_for_target(
        self,
        target_type: str,
        max_results: int = 10
    ) -> Dict[str, Any]:
        """Get knowledge for specific target type"""
        try:
            relevant_patterns = [
                pattern for pattern in self.patterns.values()
                if pattern.data.get('target_type') == target_type
            ]

            strategy_info = self.strategy_knowledge.get(target_type, [])

            return {
                'patterns': relevant_patterns[:max_results],
                'strategies': strategy_info,
                'performance_metrics': self.performance_metrics.get(target_type, {})
            }

        except Exception as e:
            log.error(f"Failed to get knowledge for target: {e}")
            return {}

    async def increment_success_count(self, pattern: Pattern, context: Dict[str, Any]):
        """Increment success count for pattern"""
        try:
            if pattern.id in self.patterns:
                pattern.confidence += 0.1
                pattern.confidence = min(pattern.confidence, 1.0)

                # Update strategy knowledge
                strategy_key = f"{pattern.data.get('agent_type')}_{context.get('target_type', 'unknown')}"
                if strategy_key not in self.strategy_knowledge:
                    self.strategy_knowledge[strategy_key] = []

                self.strategy_knowledge[strategy_key].append({
                    'pattern_id': pattern.id,
                    'type': 'success',
                    'timestamp': datetime.now().isoformat()
                })

        except Exception as e:
            log.error(f"Failed to increment success count: {e}")


class StrategyOptimizer:
    """Optimizer for attack strategies"""

    def __init__(self):
        self.optimization_history = []
        self.performance_trends = {}
        self.learning_rate = 0.1

    async def optimize(
        self,
        current_strategies: List[Dict[str, Any]],
        new_knowledge: List[Pattern],
        performance_data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Optimize strategies based on new knowledge"""
        optimized_strategies = []

        try:
            for strategy in current_strategies:
                optimized_strategy = await self._optimize_single_strategy(
                    strategy=strategy,
                    new_knowledge=new_knowledge,
                    performance_data=performance_data
                )
                optimized_strategies.append(optimized_strategy)

            # Generate new strategies based on patterns
            new_strategies = await self._generate_new_strategies(new_knowledge, performance_data)
            optimized_strategies.extend(new_strategies)

            return optimized_strategies

        except Exception as e:
            log.error(f"Strategy optimization failed: {e}")
            return current_strategies  # Return original strategies on failure

    async def _optimize_single_strategy(
        self,
        strategy: Dict[str, Any],
        new_knowledge: List[Pattern],
        performance_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Optimize a single strategy"""
        try:
            strategy_copy = strategy.copy()

            # Find relevant patterns for this strategy
            relevant_patterns = [
                pattern for pattern in new_knowledge
                if self._pattern_matches_strategy(pattern, strategy_copy)
            ]

            if not relevant_patterns:
                return strategy_copy

            # Apply optimizations based on patterns
            for pattern in relevant_patterns:
                if pattern.pattern_type == 'success':
                    strategy_copy = await self._apply_success_optimization(
                        strategy_copy, pattern, performance_data
                    )
                elif pattern.pattern_type == 'failure':
                    strategy_copy = await self._apply_failure_optimization(
                        strategy_copy, pattern, performance_data
                    )

            return strategy_copy

        except Exception as e:
            log.error(f"Single strategy optimization failed: {e}")
            return strategy

    def _pattern_matches_strategy(self, pattern: Pattern, strategy: Dict[str, Any]) -> bool:
        """Check if pattern matches strategy"""
        try:
            strategy_agent = strategy.get('agent_type')
            pattern_agent = pattern.data.get('agent_type')

            if strategy_agent and pattern_agent:
                return strategy_agent == pattern_agent

            return False

        except Exception as e:
            log.error(f"Pattern matching failed: {e}")
            return False

    async def _apply_success_optimization(
        self,
        strategy: Dict[str, Any],
        pattern: Pattern,
        performance_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Apply optimization based on success patterns"""
        try:
            strategy_copy = strategy.copy()

            # Increase confidence for successful patterns
            if 'confidence' in strategy_copy:
                strategy_copy['confidence'] = min(
                    strategy_copy['confidence'] + 0.1,
                    1.0
                )

            # Optimize parameters based on successful execution
            if 'parameters' in strategy_copy and 'execution_time' in pattern.data:
                # Reduce execution time if possible
                current_time = strategy_copy['parameters'].get('timeout', 300)
                pattern_time = pattern.data['execution_time']
                if pattern_time < current_time:
                    strategy_copy['parameters']['timeout'] = max(pattern_time, 60)

            return strategy_copy

        except Exception as e:
            log.error(f"Success optimization failed: {e}")
            return strategy

    async def _apply_failure_optimization(
        self,
        strategy: Dict[str, Any],
        pattern: Pattern,
        performance_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Apply optimization based on failure patterns"""
        try:
            strategy_copy = strategy.copy()

            # Decrease confidence for failure patterns
            if 'confidence' in strategy_copy:
                strategy_copy['confidence'] = max(
                    strategy_copy['confidence'] - 0.15,
                    0.1
                )

            # Adjust parameters to avoid failure
            if 'parameters' in strategy_copy and 'failure_reason' in pattern.data:
                failure_reason = pattern.data['failure_reason']

                if failure_reason == 'timeout':
                    strategy_copy['parameters']['timeout'] = min(
                        strategy_copy['parameters'].get('timeout', 300) + 120,
                        600
                    )
                elif failure_reason == 'resource_exhaustion':
                    strategy_copy['parameters']['max_memory'] = min(
                        strategy_copy['parameters'].get('max_memory', 1024) + 512,
                        4096
                    )

            return strategy_copy

        except Exception as e:
            log.error(f"Failure optimization failed: {e}")
            return strategy

    async def _generate_new_strategies(
        self,
        new_knowledge: List[Pattern],
        performance_data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate new strategies based on learned patterns"""
        new_strategies = []

        try:
            # Generate strategies from high-confidence success patterns
            success_patterns = [
                pattern for pattern in new_knowledge
                if pattern.pattern_type == 'success' and pattern.confidence > 0.8
            ]

            for pattern in success_patterns:
                strategy = await self._create_strategy_from_pattern(pattern, performance_data)
                if strategy:
                    new_strategies.append(strategy)

            return new_strategies

        except Exception as e:
            log.error(f"New strategy generation failed: {e}")
            return []

    async def _create_strategy_from_pattern(
        self,
        pattern: Pattern,
        performance_data: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Create strategy from learned pattern"""
        try:
            agent_type = pattern.data.get('agent_type')
            if not agent_type:
                return None

            strategy = {
                'agent_type': agent_type,
                'confidence': pattern.confidence,
                'parameters': {
                    'timeout': pattern.data.get('execution_time', 180),
                    'max_memory': pattern.data.get('resource_usage', {}).get('memory', 1024),
                    'parallel_execution': True
                },
                'optimization_score': pattern.confidence,
                'source_pattern': pattern.id
            }

            return strategy

        except Exception as e:
            log.error(f"Strategy creation failed: {e}")
            return None

    async def add_strategy(self, strategy: Dict[str, Any]):
        """Add new strategy to optimizer"""
        try:
            self.optimization_history.append({
                'strategy': strategy,
                'timestamp': datetime.now().isoformat()
            })

            log.info(f"Added new strategy: {strategy.get('agent_type', 'unknown')}")

        except Exception as e:
            log.error(f"Failed to add strategy: {e}")


class PerformanceTracker:
    """Track performance improvements over time"""

    def __init__(self):
        self.performance_history = []
        self.improvement_trends = {}

    def calculate_improvement(self) -> float:
        """Calculate performance improvement percentage"""
        try:
            if len(self.performance_history) < 2:
                return 0.0

            # Calculate improvement based on recent performance
            recent_count = min(10, len(self.performance_history))
            recent_performance = self.performance_history[-recent_count:]
            older_performance = self.performance_history[-recent_count*2:-recent_count]

            if not older_performance:
                return 0.0

            recent_avg = np.mean([p['score'] for p in recent_performance])
            older_avg = np.mean([p['score'] for p in older_performance])

            if older_avg == 0:
                return 0.0

            improvement = ((recent_avg - older_avg) / older_avg) * 100
            return improvement

        except Exception as e:
            log.error(f"Failed to calculate improvement: {e}")
            return 0.0

    def record_performance(
        self,
        strategy_name: str,
        score: float,
        execution_time: float,
        success: bool
    ):
        """Record performance data"""
        try:
            performance_record = {
                'strategy': strategy_name,
                'score': score,
                'execution_time': execution_time,
                'success': success,
                'timestamp': datetime.now().isoformat()
            }

            self.performance_history.append(performance_record)

            # Keep only last 100 records
            if len(self.performance_history) > 100:
                self.performance_history.pop(0)

        except Exception as e:
            log.error(f"Failed to record performance: {e}")

    def get_trend_data(self) -> Dict[str, Any]:
        """Get trend data for analysis"""
        try:
            return {
                'improvement_percentage': self.calculate_improvement(),
                'total_records': len(self.performance_history),
                'success_rate': np.mean([p['success'] for p in self.performance_history]) if self.performance_history else 0.0,
                'average_execution_time': np.mean([p['execution_time'] for p in self.performance_history]) if self.performance_history else 0.0
            }

        except Exception as e:
            log.error(f"Failed to get trend data: {e}")
            return {}


class EnhancedAdaptiveLearner:
    """Enhanced adaptive learner with online learning"""

    def __init__(self):
        self.pattern_learner = PatternLearner()
        self.knowledge_base = KnowledgeBase()
        self.strategy_optimizer = StrategyOptimizer()
        self.performance_tracker = PerformanceTracker()

    async def learn_from_attack(
        self,
        attack_result: Dict[str, Any],
        context: Dict[str, Any]
    ) -> LearningResult:
        """
        Learn from attack results and update knowledge
        """
        start_time = datetime.now()

        log.info(f"Learning from attack result: {attack_result.get('id', 'unknown')}")

        try:
            # Extract patterns
            patterns = self.pattern_learner.extract_patterns(attack_result, context)

            # Classify outcome
            outcome = attack_result.get('outcome', 'unknown')

            if outcome == 'success':
                # Learn from success
                await self._learn_from_success(
                    patterns=patterns,
                    attack_result=attack_result,
                    context=context
                )
            elif outcome == 'failure':
                # Learn from failure
                await self._learn_from_failure(
                    patterns=patterns,
                    attack_result=attack_result,
                    context=context
                )

            # Update knowledge base
            await self.knowledge_base.update(
                patterns=patterns,
                outcome=outcome,
                context=context
            )

            # Optimize strategies
            current_strategies = self._get_current_strategies()
            optimized_strategies = await self.strategy_optimizer.optimize(
                current_strategies=current_strategies,
                new_knowledge=patterns,
                performance_data=self.performance_tracker.get_trend_data()
            )

            # Update strategies
            await self._update_strategies(optimized_strategies)

            # Track performance improvement
            improvement = self.performance_tracker.calculate_improvement()

            execution_time = int((datetime.now() - start_time).total_seconds() * 1000)

            return LearningResult(
                patterns_learned=len(patterns),
                knowledge_updated=True,
                strategies_optimized=len(optimized_strategies),
                performance_improvement=improvement,
                execution_time_ms=execution_time
            )

        except Exception as e:
            log.error(f"Learning from attack failed: {e}")
            return LearningResult(
                patterns_learned=0,
                knowledge_updated=False,
                strategies_optimized=0,
                performance_improvement=0.0,
                execution_time_ms=int((datetime.now() - start_time).total_seconds() * 1000)
            )

    async def _learn_from_success(
        self,
        patterns: List[Pattern],
        attack_result: Dict[str, Any],
        context: Dict[str, Any]
    ):
        """Learn from successful attacks"""
        try:
            # Identify key success factors
            success_factors = self._identify_success_factors(
                patterns=patterns,
                attack_result=attack_result
            )

            # Update success patterns
            for factor in success_factors:
                pattern_id = factor.get('pattern_id')
                if pattern_id and pattern_id in self.pattern_learner.pattern_database:
                    pattern = self.pattern_learner.pattern_database[pattern_id]
                    await self.knowledge_base.increment_success_count(
                        pattern=pattern,
                        context=context
                    )

            # Generate new strategies based on success
            new_strategies = self._generate_strategies_from_success(
                success_factors=success_factors,
                context=context
            )

            # Add to strategy pool
            for strategy in new_strategies:
                await self.strategy_optimizer.add_strategy(strategy)

        except Exception as e:
            log.error(f"Learning from success failed: {e}")

    def _identify_success_factors(
        self,
        patterns: List[Pattern],
        attack_result: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Identify key success factors from patterns"""
        success_factors = []

        try:
            success_patterns = [p for p in patterns if p.pattern_type == 'success']

            for pattern in success_patterns:
                factor = {
                    'pattern_id': pattern.id,
                    'agent_type': pattern.data.get('agent_type'),
                    'confidence': pattern.confidence,
                    'execution_time': pattern.data.get('execution_time'),
                    'key_factors': list(pattern.data.keys())
                }
                success_factors.append(factor)

        except Exception as e:
            log.error(f"Success factor identification failed: {e}")

        return success_factors

    def _generate_strategies_from_success(
        self,
        success_factors: List[Dict[str, Any]],
        context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate new strategies based on success factors"""
        strategies = []

        try:
            for factor in success_factors:
                strategy = {
                    'name': f"{factor['agent_type']}_optimized",
                    'agent_type': factor['agent_type'],
                    'confidence': factor['confidence'],
                    'parameters': {
                        'timeout': factor.get('execution_time', 180),
                        'optimization_level': 'high'
                    },
                    'context_requirements': context.get('target_type', 'general')
                }
                strategies.append(strategy)

        except Exception as e:
            log.error(f"Strategy generation from success failed: {e}")

        return strategies

    async def _learn_from_failure(
        self,
        patterns: List[Pattern],
        attack_result: Dict[str, Any],
        context: Dict[str, Any]
    ):
        """Learn from failed attacks"""
        try:
            # Analyze failure patterns
            failure_patterns = [p for p in patterns if p.pattern_type == 'failure']

            for pattern in failure_patterns:
                # Store failure analysis
                failure_analysis = {
                    'pattern_id': pattern.id,
                    'failure_type': pattern.data.get('failure_reason', 'unknown'),
                    'agent_type': pattern.data.get('agent_type'),
                    'context': context,
                    'timestamp': datetime.now().isoformat()
                }

                # This would normally be stored for future analysis
                log.debug(f"Failure analysis stored: {failure_analysis}")

        except Exception as e:
            log.error(f"Learning from failure failed: {e}")

    def _get_current_strategies(self) -> List[Dict[str, Any]]:
        """Get current strategies from system"""
        # Mock implementation
        return [
            {
                'agent_type': 'reconnaissance',
                'confidence': 0.8,
                'parameters': {'timeout': 120}
            },
            {
                'agent_type': 'exploitation',
                'confidence': 0.6,
                'parameters': {'timeout': 300}
            }
        ]

    async def _update_strategies(self, strategies: List[Dict[str, Any]]):
        """Update system strategies"""
        try:
            # This would normally update the actual strategy system
            log.info(f"Updated {len(strategies)} strategies")
        except Exception as e:
            log.error(f"Strategy update failed: {e}")

    async def get_learning_status(self) -> Dict[str, Any]:
        """Get current learning status"""
        try:
            return {
                'patterns_count': len(self.pattern_learner.pattern_database),
                'knowledge_base_status': 'ready',
                'optimization_count': len(self.strategy_optimizer.optimization_history),
                'performance_improvement': self.performance_tracker.calculate_improvement(),
                'last_learning': datetime.now().isoformat()
            }

        except Exception as e:
            log.error(f"Failed to get learning status: {e}")
            return {}