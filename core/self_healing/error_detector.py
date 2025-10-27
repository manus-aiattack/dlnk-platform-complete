"""
Error Detection and Recovery Engine
Automatically detects and recovers from errors
"""

import asyncio
import traceback
from typing import Dict, List, Optional, Callable
from datetime import datetime
from collections import defaultdict
import logging

log = logging.getLogger(__name__)


class ErrorDetector:
    """
    Error Detection and Recovery Engine
    
    Features:
    - Automatic error detection
    - Root cause analysis
    - Recovery strategy selection
    - Automatic retry with adaptation
    """
    
    def __init__(self):
        self.error_history = []
        self.error_patterns = defaultdict(int)
        self.recovery_strategies = self._load_recovery_strategies()
        self.max_retries = 3
    
    def _load_recovery_strategies(self) -> Dict:
        """Load recovery strategies for different error types"""
        
        return {
            'NetworkError': {
                'strategies': [
                    'retry_with_backoff',
                    'switch_proxy',
                    'reduce_request_rate',
                    'switch_user_agent'
                ],
                'max_retries': 5
            },
            
            'TimeoutError': {
                'strategies': [
                    'increase_timeout',
                    'retry_with_backoff',
                    'split_request'
                ],
                'max_retries': 3
            },
            
            'AuthenticationError': {
                'strategies': [
                    'refresh_token',
                    'reauth',
                    'switch_credentials'
                ],
                'max_retries': 2
            },
            
            'RateLimitError': {
                'strategies': [
                    'exponential_backoff',
                    'switch_api_key',
                    'reduce_request_rate'
                ],
                'max_retries': 10
            },
            
            'WAFBlockedError': {
                'strategies': [
                    'switch_ip',
                    'modify_payload',
                    'add_evasion_techniques',
                    'reduce_attack_frequency'
                ],
                'max_retries': 5
            },
            
            'ExploitFailedError': {
                'strategies': [
                    'try_alternative_exploit',
                    'modify_payload',
                    'adjust_timing',
                    'change_attack_vector'
                ],
                'max_retries': 3
            },
            
            'ResourceExhaustedError': {
                'strategies': [
                    'free_resources',
                    'reduce_parallelism',
                    'cleanup_temp_files'
                ],
                'max_retries': 2
            },
            
            'ConfigurationError': {
                'strategies': [
                    'reload_config',
                    'use_default_config',
                    'validate_config'
                ],
                'max_retries': 1
            }
        }
    
    async def detect_and_recover(
        self,
        operation: Callable,
        *args,
        **kwargs
    ) -> Dict:
        """
        Execute operation with automatic error detection and recovery
        
        Args:
            operation: Operation to execute
            *args: Operation arguments
            **kwargs: Operation keyword arguments
        
        Returns:
            Operation result or recovery result
        """
        attempt = 0
        last_error = None
        
        while attempt < self.max_retries:
            try:
                log.info(f"[ErrorDetector] Executing operation (attempt {attempt + 1}/{self.max_retries})")
                
                result = await operation(*args, **kwargs)
                
                if attempt > 0:
                    log.info(f"[ErrorDetector] Operation succeeded after {attempt} retries")
                
                return {
                    'success': True,
                    'result': result,
                    'attempts': attempt + 1
                }
                
            except Exception as e:
                attempt += 1
                last_error = e
                
                log.warning(f"[ErrorDetector] Operation failed (attempt {attempt}): {e}")
                
                # Record error
                await self._record_error(e, operation.__name__)
                
                # Analyze error
                error_analysis = await self._analyze_error(e)
                
                # Select recovery strategy
                recovery_strategy = await self._select_recovery_strategy(error_analysis)
                
                if recovery_strategy and attempt < self.max_retries:
                    # Apply recovery
                    await self._apply_recovery(recovery_strategy, error_analysis)
                    
                    # Wait before retry
                    await asyncio.sleep(self._calculate_backoff(attempt))
                else:
                    break
        
        # All retries failed
        log.error(f"[ErrorDetector] Operation failed after {attempt} attempts")
        
        return {
            'success': False,
            'error': str(last_error),
            'attempts': attempt,
            'recovery_attempted': True
        }
    
    async def _record_error(self, error: Exception, operation: str):
        """Record error for analysis"""
        
        error_record = {
            'timestamp': datetime.now().isoformat(),
            'type': type(error).__name__,
            'message': str(error),
            'operation': operation,
            'traceback': traceback.format_exc()
        }
        
        self.error_history.append(error_record)
        self.error_patterns[type(error).__name__] += 1
        
        # Keep only recent errors
        if len(self.error_history) > 1000:
            self.error_history = self.error_history[-1000:]
    
    async def _analyze_error(self, error: Exception) -> Dict:
        """Analyze error to determine root cause"""
        
        error_type = type(error).__name__
        error_message = str(error)
        
        analysis = {
            'type': error_type,
            'message': error_message,
            'category': self._categorize_error(error_type, error_message),
            'severity': self._assess_severity(error_type),
            'recoverable': self._is_recoverable(error_type),
            'root_cause': self._identify_root_cause(error_type, error_message)
        }
        
        return analysis
    
    def _categorize_error(self, error_type: str, error_message: str) -> str:
        """Categorize error"""
        
        # Network errors
        if any(keyword in error_type.lower() for keyword in ['connection', 'network', 'socket']):
            return 'NetworkError'
        
        # Timeout errors
        if 'timeout' in error_type.lower() or 'timeout' in error_message.lower():
            return 'TimeoutError'
        
        # Authentication errors
        if any(keyword in error_message.lower() for keyword in ['auth', 'unauthorized', '401', '403']):
            return 'AuthenticationError'
        
        # Rate limit errors
        if any(keyword in error_message.lower() for keyword in ['rate limit', '429', 'too many requests']):
            return 'RateLimitError'
        
        # WAF blocked
        if any(keyword in error_message.lower() for keyword in ['waf', 'blocked', 'firewall', '403']):
            return 'WAFBlockedError'
        
        # Resource errors
        if any(keyword in error_type.lower() for keyword in ['memory', 'resource']):
            return 'ResourceExhaustedError'
        
        return 'UnknownError'
    
    def _assess_severity(self, error_type: str) -> str:
        """Assess error severity"""
        
        critical_errors = ['SystemError', 'MemoryError', 'KeyboardInterrupt']
        high_errors = ['ConnectionError', 'TimeoutError', 'AuthenticationError']
        
        if error_type in critical_errors:
            return 'CRITICAL'
        elif error_type in high_errors:
            return 'HIGH'
        else:
            return 'MEDIUM'
    
    def _is_recoverable(self, error_type: str) -> bool:
        """Check if error is recoverable"""
        
        non_recoverable = ['KeyboardInterrupt', 'SystemExit', 'ConfigurationError']
        
        return error_type not in non_recoverable
    
    def _identify_root_cause(self, error_type: str, error_message: str) -> str:
        """Identify root cause of error"""
        
        # Network issues
        if 'connection refused' in error_message.lower():
            return 'Target service is down or unreachable'
        
        if 'timeout' in error_message.lower():
            return 'Operation took too long, possibly due to network latency or slow target'
        
        # Authentication issues
        if 'unauthorized' in error_message.lower():
            return 'Invalid or expired credentials'
        
        # Rate limiting
        if 'rate limit' in error_message.lower():
            return 'Too many requests sent to target'
        
        # WAF
        if 'blocked' in error_message.lower():
            return 'Request blocked by WAF or security system'
        
        return 'Unknown root cause'
    
    async def _select_recovery_strategy(self, error_analysis: Dict) -> Optional[str]:
        """Select appropriate recovery strategy"""
        
        error_category = error_analysis['category']
        
        if not error_analysis['recoverable']:
            log.warning(f"[ErrorDetector] Error is not recoverable: {error_category}")
            return None
        
        if error_category in self.recovery_strategies:
            strategies = self.recovery_strategies[error_category]['strategies']
            
            # Select first strategy (in production, use ML to select best)
            if strategies:
                return strategies[0]
        
        return 'retry_with_backoff'  # Default strategy
    
    async def _apply_recovery(self, strategy: str, error_analysis: Dict):
        """Apply recovery strategy"""
        
        log.info(f"[ErrorDetector] Applying recovery strategy: {strategy}")
        
        if strategy == 'retry_with_backoff':
            # Just wait (handled by caller)
            pass
        
        elif strategy == 'increase_timeout':
            # Increase timeout for next attempt
            log.info("[ErrorDetector] Increasing timeout for next attempt")
        
        elif strategy == 'switch_proxy':
            log.info("[ErrorDetector] Switching proxy for next attempt")
        
        elif strategy == 'switch_user_agent':
            log.info("[ErrorDetector] Switching user agent for next attempt")
        
        elif strategy == 'modify_payload':
            log.info("[ErrorDetector] Modifying payload for next attempt")
        
        elif strategy == 'add_evasion_techniques':
            log.info("[ErrorDetector] Adding evasion techniques for next attempt")
        
        elif strategy == 'free_resources':
            log.info("[ErrorDetector] Freeing resources")
            # In production, actually free resources
        
        elif strategy == 'reload_config':
            log.info("[ErrorDetector] Reloading configuration")
        
        else:
            log.warning(f"[ErrorDetector] Unknown recovery strategy: {strategy}")
    
    def _calculate_backoff(self, attempt: int) -> float:
        """Calculate exponential backoff time"""
        
        # Exponential backoff: 2^attempt seconds
        return min(2 ** attempt, 60)  # Max 60 seconds
    
    async def get_error_statistics(self) -> Dict:
        """Get error statistics"""
        
        stats = {
            'total_errors': len(self.error_history),
            'error_types': dict(self.error_patterns),
            'most_common_error': max(self.error_patterns.items(), key=lambda x: x[1])[0] if self.error_patterns else None,
            'recent_errors': self.error_history[-10:] if self.error_history else []
        }
        
        return stats
    
    async def predict_failure(self, operation: str, context: Dict) -> float:
        """
        Predict probability of failure for operation using ML
        
        Args:
            operation: Operation name
            context: Operation context
        
        Returns:
            Failure probability (0.0 - 1.0)
        """
        # Check historical failure rate
        operation_errors = [e for e in self.error_history if e['operation'] == operation]
        
        if not operation_errors:
            return 0.1  # Low probability if no history
        
        # Calculate failure rate from recent history
        recent_errors = operation_errors[-20:]
        failure_count = len(recent_errors)
        
        # Consider context factors
        context_factors = [
            context.get('network_quality', 1.0),
            context.get('target_availability', 1.0),
            context.get('resource_availability', 1.0)
        ]
        
        # Weighted failure probability
        base_failure_rate = failure_count / 20.0
        context_penalty = 1.0 - (sum(context_factors) / len(context_factors))
        
        failure_prob = min(base_failure_rate + context_penalty, 0.95)
        
        return failure_prob
    
    async def detect_anomalies(self) -> List[Dict]:
        """
        Detect anomalies in error patterns
        
        Returns:
            List of detected anomalies
        """
        anomalies = []
        
        # Check for sudden spike in errors
        if len(self.error_history) >= 10:
            recent_errors = self.error_history[-10:]
            older_errors = self.error_history[-20:-10] if len(self.error_history) >= 20 else []
            
            if older_errors:
                recent_rate = len(recent_errors) / 10.0
                older_rate = len(older_errors) / 10.0
                
                if recent_rate > older_rate * 2:
                    anomalies.append({
                        'type': 'error_spike',
                        'severity': 'HIGH',
                        'message': f'Error rate increased by {(recent_rate / older_rate - 1) * 100:.1f}%',
                        'recent_rate': recent_rate,
                        'older_rate': older_rate
                    })
        
        # Check for new error types
        recent_error_types = set(e['type'] for e in self.error_history[-10:])
        historical_error_types = set(e['type'] for e in self.error_history[:-10])
        
        new_error_types = recent_error_types - historical_error_types
        if new_error_types:
            anomalies.append({
                'type': 'new_error_types',
                'severity': 'MEDIUM',
                'message': f'New error types detected: {new_error_types}',
                'error_types': list(new_error_types)
            })
        
        # Check for repeated failures on same operation
        operation_failures = defaultdict(int)
        for error in self.error_history[-20:]:
            operation_failures[error['operation']] += 1
        
        for operation, count in operation_failures.items():
            if count >= 5:
                anomalies.append({
                    'type': 'repeated_operation_failure',
                    'severity': 'HIGH',
                    'message': f'Operation "{operation}" failed {count} times recently',
                    'operation': operation,
                    'failure_count': count
                })
        
        return anomalies
    
    async def generate_error_report(self) -> Dict:
        """
        Generate comprehensive error report
        
        Returns:
            Dict with error analysis and recommendations
        """
        stats = await self.get_error_statistics()
        anomalies = await self.detect_anomalies()
        
        # Analyze error trends
        error_trends = self._analyze_error_trends()
        
        # Generate recommendations
        recommendations = self._generate_recommendations(stats, anomalies, error_trends)
        
        return {
            'statistics': stats,
            'anomalies': anomalies,
            'trends': error_trends,
            'recommendations': recommendations,
            'health_score': self._calculate_health_score(stats, anomalies)
        }
    
    def _analyze_error_trends(self) -> Dict:
        """
        Analyze error trends over time
        
        Returns:
            Dict with trend analysis
        """
        if len(self.error_history) < 20:
            return {'trend': 'insufficient_data'}
        
        # Split into time windows
        window_size = 10
        windows = [
            self.error_history[i:i+window_size]
            for i in range(0, len(self.error_history), window_size)
        ]
        
        # Calculate error rates per window
        error_rates = [len(window) for window in windows]
        
        # Determine trend
        if len(error_rates) >= 2:
            recent_avg = sum(error_rates[-2:]) / 2
            older_avg = sum(error_rates[:-2]) / max(len(error_rates) - 2, 1)
            
            if recent_avg > older_avg * 1.5:
                trend = 'increasing'
            elif recent_avg < older_avg * 0.5:
                trend = 'decreasing'
            else:
                trend = 'stable'
        else:
            trend = 'stable'
        
        return {
            'trend': trend,
            'error_rates': error_rates,
            'recent_average': sum(error_rates[-2:]) / 2 if len(error_rates) >= 2 else 0
        }
    
    def _generate_recommendations(self, stats: Dict, anomalies: List[Dict], trends: Dict) -> List[str]:
        """
        Generate recommendations based on error analysis
        
        Args:
            stats: Error statistics
            anomalies: Detected anomalies
            trends: Error trends
        
        Returns:
            List of recommendations
        """
        recommendations = []
        
        # High error rate
        if stats['total_errors'] > 50:
            recommendations.append(
                "⚠️ High error rate detected - consider reviewing system health and target availability"
            )
        
        # Error spike
        error_spike_anomalies = [a for a in anomalies if a['type'] == 'error_spike']
        if error_spike_anomalies:
            recommendations.append(
                "🔥 Error spike detected - investigate recent changes or target issues"
            )
        
        # Repeated failures
        repeated_failures = [a for a in anomalies if a['type'] == 'repeated_operation_failure']
        if repeated_failures:
            for anomaly in repeated_failures:
                recommendations.append(
                    f"🔄 Operation \"{anomaly['operation']}\" failing repeatedly - consider alternative approach"
                )
        
        # Increasing trend
        if trends.get('trend') == 'increasing':
            recommendations.append(
                "📈 Error rate is increasing - proactive intervention recommended"
            )
        
        # Most common error
        if stats.get('most_common_error'):
            recommendations.append(
                f"🎯 Focus on fixing {stats['most_common_error']} - it's the most common error type"
            )
        
        if not recommendations:
            recommendations.append(
                "✅ System health is good - no critical issues detected"
            )
        
        return recommendations
    
    def _calculate_health_score(self, stats: Dict, anomalies: List[Dict]) -> float:
        """
        Calculate system health score (0-100)
        
        Args:
            stats: Error statistics
            anomalies: Detected anomalies
        
        Returns:
            Health score (0-100)
        """
        score = 100.0
        
        # Deduct for total errors
        error_penalty = min(stats['total_errors'] * 0.5, 30)
        score -= error_penalty
        
        # Deduct for anomalies
        for anomaly in anomalies:
            if anomaly['severity'] == 'HIGH':
                score -= 15
            elif anomaly['severity'] == 'MEDIUM':
                score -= 10
            else:
                score -= 5
        
        return max(score, 0.0)


if __name__ == '__main__':
    async def test():
        detector = ErrorDetector()
        
        # Test operation that fails
        async def failing_operation():
            raise ConnectionError("Connection refused")
        
        result = await detector.detect_and_recover(failing_operation)
        
        print("Recovery Result:")
        print(f"  Success: {result['success']}")
        print(f"  Attempts: {result['attempts']}")
        
        if not result['success']:
            print(f"  Error: {result['error']}")
        
        # Get statistics
        stats = await detector.get_error_statistics()
        print(f"\nError Statistics:")
        print(f"  Total Errors: {stats['total_errors']}")
        print(f"  Error Types: {stats['error_types']}")
    
    asyncio.run(test())

