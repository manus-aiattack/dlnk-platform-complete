"""
Enhanced Error Detector with Predictive Capabilities
ตามแผนการพัฒนา Manus AI Attack Platform Phase 1
"""

import asyncio
import json
import numpy as np
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
import statistics

from .logger import log


@dataclass
class Anomaly:
    """Detected anomaly"""
    metric_name: str
    value: float
    threshold: float
    severity: str  # low, medium, high, critical
    timestamp: str
    description: str


@dataclass
class RecoveryStrategy:
    """Recovery strategy for component"""
    name: str
    component: str
    action: str
    parameters: Dict[str, Any]
    success_rate: float
    estimated_time: int  # seconds


@dataclass
class RecoveryResult:
    """Result of recovery action"""
    success: bool
    component: str
    strategy: str
    execution_time: int
    errors: List[str]
    health_status: str


class AnomalyDetector:
    """Advanced anomaly detection system"""

    def __init__(self):
        self.baseline_data = {}
        self.anomaly_thresholds = {}
        self.severity_levels = {
            'low': 1.5,     # 1.5x baseline
            'medium': 2.0,  # 2x baseline
            'high': 3.0,    # 3x baseline
            'critical': 5.0 # 5x baseline
        }

    def detect(self, metrics: Dict[str, Any]) -> List[Anomaly]:
        """Detect anomalies in metrics"""
        anomalies = []

        for metric_name, value in metrics.items():
            if isinstance(value, (int, float)):
                baseline = self.baseline_data.get(metric_name, {'mean': 0, 'std': 1})
                threshold_multiplier = self._get_threshold_multiplier(metric_name)

                # Calculate anomaly score
                if baseline['std'] > 0:
                    z_score = abs(value - baseline['mean']) / baseline['std']
                else:
                    z_score = abs(value - baseline['mean']) if baseline['mean'] != 0 else 0

                # Check if it's an anomaly
                if z_score > threshold_multiplier:
                    severity = self._determine_severity(z_score)
                    anomaly = Anomaly(
                        metric_name=metric_name,
                        value=value,
                        threshold=baseline['mean'] + (baseline['std'] * threshold_multiplier),
                        severity=severity,
                        timestamp=datetime.now().isoformat(),
                        description=f"{metric_name} is {severity} (z-score: {z_score:.2f})"
                    )
                    anomalies.append(anomaly)

        return anomalies

    def _get_threshold_multiplier(self, metric_name: str) -> float:
        """Get threshold multiplier for metric"""
        # Different metrics may have different thresholds
        thresholds = {
            'memory_usage': 2.5,
            'cpu_usage': 3.0,
            'error_rate': 4.0,
            'response_time': 3.5,
            'disk_usage': 2.0,
        }
        return thresholds.get(metric_name, 3.0)

    def _determine_severity(self, z_score: float) -> str:
        """Determine anomaly severity based on z-score"""
        for severity, multiplier in self.severity_levels.items():
            if z_score <= multiplier:
                return severity
        return 'critical'

    def update_baseline(self, metrics: Dict[str, Any]):
        """Update baseline data with new metrics"""
        for metric_name, value in metrics.items():
            if isinstance(value, (int, float)):
                if metric_name not in self.baseline_data:
                    self.baseline_data[metric_name] = {'values': []}

                # Keep rolling window of values
                values = self.baseline_data[metric_name]['values']
                values.append(value)

                # Keep only last 100 values
                if len(values) > 100:
                    values.pop(0)

                # Update baseline statistics
                if len(values) >= 10:  # Need minimum data points
                    mean = statistics.mean(values)
                    std = statistics.stdev(values) if len(values) > 1 else 0

                    self.baseline_data[metric_name] = {
                        'mean': mean,
                        'std': std,
                        'min': min(values),
                        'max': max(values)
                    }


class PatternMatcher:
    """Pattern matching for error detection"""

    def __init__(self):
        self.error_patterns = self._load_error_patterns()

    def _load_error_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Load known error patterns"""
        return {
            'memory_leak': {
                'pattern': ['increasing memory usage', 'gc pressure', 'out of memory'],
                'confidence': 0.9,
                'description': 'Potential memory leak detected'
            },
            'connection_pool_exhaustion': {
                'pattern': ['high connection count', 'connection timeouts', 'pool full'],
                'confidence': 0.85,
                'description': 'Connection pool exhaustion'
            },
            'cpu_overload': {
                'pattern': ['high cpu usage', 'thread pool saturation', 'slow response'],
                'confidence': 0.95,
                'description': 'CPU overload detected'
            },
            'disk_space_low': {
                'pattern': ['high disk usage', 'slow writes', 'storage warnings'],
                'confidence': 0.8,
                'description': 'Low disk space warning'
            }
        }

    def match_patterns(self, metrics: Dict[str, Any], logs: List[str]) -> List[Dict[str, Any]]:
        """Match error patterns in current data"""
        matches = []

        for pattern_name, pattern_data in self.error_patterns.items():
            # Check if pattern matches current metrics/logs
            match_score = self._calculate_pattern_match(pattern_data, metrics, logs)

            if match_score > 0.7:  # Threshold for match
                matches.append({
                    'pattern': pattern_name,
                    'confidence': match_score,
                    'description': pattern_data['description'],
                    'recommended_actions': self._get_recommended_actions(pattern_name)
                })

        return matches

    def _calculate_pattern_match(
        self,
        pattern_data: Dict[str, Any],
        metrics: Dict[str, Any],
        logs: List[str]
    ) -> float:
        """Calculate how well pattern matches current data"""
        # Mock pattern matching logic
        # In real implementation, this would use more sophisticated matching

        pattern_keywords = pattern_data['pattern']
        log_text = ' '.join(logs).lower()

        # Count keyword matches in logs
        keyword_matches = sum(1 for keyword in pattern_keywords if keyword.lower() in log_text)

        # Calculate match score
        match_score = keyword_matches / len(pattern_keywords)

        return match_score

    def _get_recommended_actions(self, pattern_name: str) -> List[str]:
        """Get recommended actions for error pattern"""
        actions = {
            'memory_leak': [
                'Restart service',
                'Increase memory allocation',
                'Analyze memory usage patterns'
            ],
            'connection_pool_exhaustion': [
                'Increase pool size',
                'Optimize connection usage',
                'Restart connection pool'
            ],
            'cpu_overload': [
                'Scale horizontally',
                'Optimize CPU-intensive operations',
                'Restart underperforming instances'
            ],
            'disk_space_low': [
                'Clean up logs',
                'Increase disk space',
                'Move data to external storage'
            ]
        }
        return actions.get(pattern_name, [])


class RecoveryStrategyManager:
    """Manager for recovery strategies"""

    def __init__(self):
        self.strategies = self._load_recovery_strategies()

    def _load_recovery_strategies(self) -> Dict[str, List[RecoveryStrategy]]:
        """Load recovery strategies by component type"""
        strategies = {}

        # API strategies
        strategies['api'] = [
            RecoveryStrategy('restart_service', 'api', 'restart', {}, 0.95, 30),
            RecoveryStrategy('scale_up', 'api', 'scale', {'replicas': 2}, 0.85, 60),
            RecoveryStrategy('clear_cache', 'api', 'clear_cache', {}, 0.75, 10),
        ]

        # Database strategies
        strategies['database'] = [
            RecoveryStrategy('restart_service', 'database', 'restart', {}, 0.90, 120),
            RecoveryStrategy('clear_connections', 'database', 'clear_connections', {}, 0.80, 30),
            RecoveryStrategy('optimize_queries', 'database', 'optimize', {}, 0.70, 300),
        ]

        # Agent strategies
        strategies['agent'] = [
            RecoveryStrategy('restart_agent', 'agent', 'restart', {}, 0.95, 20),
            RecoveryStrategy('reset_context', 'agent', 'reset_context', {}, 0.85, 10),
            RecoveryStrategy('replace_agent', 'agent', 'replace', {}, 0.75, 60),
        ]

        return strategies

    async def select_strategy(
        self,
        component: str,
        anomalies: List[Anomaly],
        severity: str
    ) -> RecoveryStrategy:
        """Select best recovery strategy"""
        component_type = self._get_component_type(component)
        available_strategies = self.strategies.get(component_type, [])

        if not available_strategies:
            # Default strategy
            return RecoveryStrategy('restart_service', component, 'restart', {}, 0.8, 60)

        # Select strategy based on severity and anomalies
        if severity == 'critical':
            # Use most aggressive strategy
            return max(available_strategies, key=lambda x: x.success_rate)
        elif severity == 'high':
            # Use medium aggression
            return sorted(available_strategies, key=lambda x: x.success_rate)[len(available_strategies)//2]
        else:
            # Use least aggressive
            return min(available_strategies, key=lambda x: x.success_rate)

    def _get_component_type(self, component: str) -> str:
        """Get component type from component name"""
        if 'api' in component or 'service' in component:
            return 'api'
        elif 'db' in component or 'database' in component:
            return 'database'
        elif 'agent' in component or 'worker' in component:
            return 'agent'
        else:
            return 'general'

    async def execute_strategy(
        self,
        strategy: RecoveryStrategy,
        component: str
    ) -> RecoveryResult:
        """Execute recovery strategy"""
        try:
            start_time = datetime.now()

            # Mock execution - would normally call actual recovery actions
            if strategy.action == 'restart':
                result = await self._execute_restart(component)
            elif strategy.action == 'scale':
                result = await self._execute_scale(component, strategy.parameters)
            elif strategy.action == 'clear_cache':
                result = await self._execute_clear_cache(component)
            elif strategy.action == 'restart_agent':
                result = await self._execute_restart_agent(component)
            else:
                result = await self._execute_generic_recovery(strategy, component)

            execution_time = int((datetime.now() - start_time).total_seconds())

            return RecoveryResult(
                success=result['success'],
                component=component,
                strategy=strategy.name,
                execution_time=execution_time,
                errors=result.get('errors', []),
                health_status=result.get('health_status', 'unknown')
            )

        except Exception as e:
            log.error(f"Recovery strategy execution failed: {e}")
            return RecoveryResult(
                success=False,
                component=component,
                strategy=strategy.name,
                execution_time=0,
                errors=[str(e)],
                health_status='error'
            )

    async def _execute_restart(self, component: str) -> Dict[str, Any]:
        """Execute service restart"""
        # Mock implementation
        log.info(f"Restarting component: {component}")
        await asyncio.sleep(5)  # Simulate restart time
        return {'success': True, 'health_status': 'healthy'}

    async def _execute_scale(self, component: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute scaling operation"""
        # Mock implementation
        replicas = parameters.get('replicas', 1)
        log.info(f"Scaling {component} to {replicas} replicas")
        await asyncio.sleep(10)  # Simulate scaling time
        return {'success': True, 'health_status': 'healthy'}

    async def _execute_clear_cache(self, component: str) -> Dict[str, Any]:
        """Execute cache clearing"""
        # Mock implementation
        log.info(f"Clearing cache for {component}")
        await asyncio.sleep(2)  # Simulate cache clearing
        return {'success': True, 'health_status': 'healthy'}

    async def _execute_restart_agent(self, component: str) -> Dict[str, Any]:
        """Execute agent restart"""
        # Mock implementation
        log.info(f"Restarting agent: {component}")
        await asyncio.sleep(3)  # Simulate agent restart
        return {'success': True, 'health_status': 'healthy'}

    async def _execute_generic_recovery(self, strategy: RecoveryStrategy, component: str) -> Dict[str, Any]:
        """Execute generic recovery action"""
        # Mock implementation
        log.info(f"Executing {strategy.action} for {component}")
        await asyncio.sleep(5)
        return {'success': True, 'health_status': 'healthy'}


class EnhancedErrorDetector:
    """Enhanced error detector with predictive capabilities"""

    def __init__(self):
        self.anomaly_detector = AnomalyDetector()
        self.pattern_matcher = PatternMatcher()
        self.recovery_strategies = RecoveryStrategyManager()

        # Failure prediction model
        self.failure_prediction_model = self._load_failure_prediction_model()

    def _load_failure_prediction_model(self):
        """Load failure prediction model"""
        # Mock model loading
        log.info("Failure prediction model loaded")
        return None  # Placeholder

    async def detect_and_recover(
        self,
        component: str,
        metrics: Dict[str, Any],
        logs: Optional[List[str]] = None
    ) -> RecoveryResult:
        """
        Detect errors and automatically recover
        """
        logs = logs or []

        log.info(f"Detecting and recovering component: {component}")

        try:
            # Detect anomalies
            anomalies = self.anomaly_detector.detect(metrics)

            if not anomalies:
                return RecoveryResult(
                    success=True,
                    component=component,
                    strategy="no_action",
                    execution_time=0,
                    errors=[],
                    health_status="healthy"
                )

            # Classify error severity
            severity = self._classify_severity(anomalies)

            # Predict if this will lead to failure
            failure_probability = self.predict_failure(
                component=component,
                anomalies=anomalies,
                metrics=metrics,
                logs=logs
            )

            log.info(f"Failure probability for {component}: {failure_probability:.2%}")

            if failure_probability > 0.7:
                # High risk - take immediate action
                log.warning(f"High failure risk detected for {component}: {failure_probability:.2%}")

                # Select recovery strategy
                strategy = await self.recovery_strategies.select_strategy(
                    component=component,
                    anomalies=anomalies,
                    severity=severity
                )

                # Execute recovery
                recovery_result = await self.recovery_strategies.execute_strategy(
                    strategy=strategy,
                    component=component
                )

                # Verify recovery
                if recovery_result.success:
                    log.info(f"Successfully recovered {component}")
                    # Learn from this recovery
                    await self._learn_from_recovery(
                        component=component,
                        anomalies=anomalies,
                        strategy=strategy,
                        result=recovery_result
                    )
                else:
                    # Escalate to next level
                    await self._escalate_recovery(
                        component=component,
                        failed_strategy=strategy
                    )

                return recovery_result
            else:
                # Low risk - monitor
                return RecoveryResult(
                    success=True,
                    component=component,
                    strategy="monitoring",
                    execution_time=0,
                    errors=[],
                    health_status="monitoring",
                    failure_probability=failure_probability
                )

        except Exception as e:
            log.error(f"Error detection and recovery failed: {e}")
            return RecoveryResult(
                success=False,
                component=component,
                strategy="error",
                execution_time=0,
                errors=[str(e)],
                health_status="error"
            )

    def _classify_severity(self, anomalies: List[Anomaly]) -> str:
        """Classify overall severity of anomalies"""
        if not anomalies:
            return 'low'

        # Get highest severity
        severities = [anomaly.severity for anomaly in anomalies]
        severity_weights = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}

        max_weight = max(severity_weights[sev] for sev in severities)
        max_severity = [sev for sev, weight in severity_weights.items() if weight == max_weight][0]

        return max_severity

    def predict_failure(
        self,
        component: str,
        anomalies: List[Anomaly],
        metrics: Dict[str, Any],
        logs: List[str]
    ) -> float:
        """Predict probability of failure"""
        try:
            # Extract features for prediction
            features = self._extract_failure_features(
                component=component,
                anomalies=anomalies,
                metrics=metrics,
                logs=logs
            )

            # Use simple heuristic for failure prediction
            # In real implementation, this would use ML model
            base_risk = 0.1  # Base failure probability

            # Add risk from anomalies
            for anomaly in anomalies:
                severity_weights = {'low': 0.1, 'medium': 0.3, 'high': 0.6, 'critical': 0.9}
                base_risk += severity_weights.get(anomaly.severity, 0.5) * 0.2

            # Add risk from patterns
            patterns = self.pattern_matcher.match_patterns(metrics, logs)
            for pattern in patterns:
                base_risk += pattern['confidence'] * 0.3

            # Add component-specific risk
            component_risk = self._get_component_risk(component)
            base_risk += component_risk

            # Cap at 99%
            return min(base_risk, 0.99)

        except Exception as e:
            log.error(f"Failed to predict failure: {e}")
            return 0.5  # Default probability

    def _extract_failure_features(
        self,
        component: str,
        anomalies: List[Anomaly],
        metrics: Dict[str, Any],
        logs: List[str]
    ) -> np.ndarray:
        """Extract features for failure prediction"""
        # Mock feature extraction
        features = []

        # Component type features
        component_types = ['api', 'database', 'agent', 'worker', 'scheduler']
        for comp_type in component_types:
            features.append(1.0 if comp_type in component.lower() else 0.0)

        # Anomaly features
        severity_counts = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        for anomaly in anomalies:
            severity_counts[anomaly.severity] += 1

        features.extend([severity_counts[sev] for sev in ['low', 'medium', 'high', 'critical']])

        # Metric features
        for metric_name in ['cpu_usage', 'memory_usage', 'error_rate', 'response_time']:
            features.append(metrics.get(metric_name, 0.0))

        return np.array(features)

    def _get_component_risk(self, component: str) -> float:
        """Get base risk for component type"""
        risk_mapping = {
            'database': 0.3,
            'api': 0.2,
            'agent': 0.1,
            'worker': 0.15,
            'scheduler': 0.25,
        }

        for comp_type, risk in risk_mapping.items():
            if comp_type in component.lower():
                return risk

        return 0.1  # Default risk

    async def _learn_from_recovery(
        self,
        component: str,
        anomalies: List[Anomaly],
        strategy: RecoveryStrategy,
        result: RecoveryResult
    ):
        """Learn from recovery action"""
        try:
            learning_data = {
                'timestamp': datetime.now().isoformat(),
                'component': component,
                'anomalies': [{'name': a.metric_name, 'severity': a.severity} for a in anomalies],
                'strategy': strategy.name,
                'success': result.success,
                'execution_time': result.execution_time,
                'failure_probability': getattr(result, 'failure_probability', 0)
            }

            # This would normally be stored in a learning database
            log.debug(f"Learned from recovery of {component}")

        except Exception as e:
            log.error(f"Failed to learn from recovery: {e}")

    async def _escalate_recovery(
        self,
        component: str,
        failed_strategy: RecoveryStrategy
    ):
        """Escalate recovery to higher level"""
        try:
            log.warning(f"Escalating recovery for {component} after failed {failed_strategy.name}")

            # This would normally trigger alerts to operators
            # or try more aggressive recovery strategies

        except Exception as e:
            log.error(f"Failed to escalate recovery: {e}")

    def update_baseline(self, metrics: Dict[str, Any]):
        """Update baseline data for anomaly detection"""
        self.anomaly_detector.update_baseline(metrics)

    async def get_health_metrics(self) -> Dict[str, Any]:
        """Get health metrics for monitoring"""
        return {
            'anomaly_detector_status': 'healthy',
            'pattern_matcher_status': 'ready',
            'recovery_strategies_count': len(self.recovery_strategies.strategies),
            'last_updated': datetime.now().isoformat(),
            'baseline_metrics_count': len(self.anomaly_detector.baseline_data)
        }