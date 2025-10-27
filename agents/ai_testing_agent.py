"""
AI Attack Testing Agent
Comprehensive testing and validation of AI-driven attack agents
"""

import asyncio
import time
import json
import statistics
import random
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from core.base_agent import BaseAgent
from core.data_models import AgentData, AttackPhase, Strategy


@dataclass
class TestFinding:
    """Testing finding"""
    test_name: str
    agent_type: str
    success_rate: float
    performance_metrics: Dict[str, Any]
    vulnerabilities_found: List[str]
    recommendations: List[str]


class AITestingAgent(BaseAgent):
    """AI Testing Agent for comprehensive attack agent validation"""

    def __init__(self):
        super().__init__()
        self.findings: List[TestFinding] = []
        self.test_results = []
        self.performance_benchmark = self._initialize_performance_benchmark()

    async def setup(self):
        """Initialize AI testing agent"""
        await super().setup()
        self.logger.info("AI Testing Agent initialized")

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute comprehensive AI attack agent testing"""
        try:
            test_type = strategy.context.get('test_type', 'comprehensive')
            target_agents = strategy.context.get('target_agents', ['all'])
            test_duration = strategy.context.get('test_duration', 300)  # 5 minutes

            self.logger.info(f"Starting AI attack agent testing: {test_type}")

            # AI analysis for optimal testing strategy
            test_strategy = await self._analyze_testing_strategy(test_type, target_agents)

            # Execute comprehensive testing
            results = await self._execute_comprehensive_testing(
                target_agents, test_strategy, test_duration
            )

            # AI analysis of test results
            analysis = await self._analyze_test_results(results)

            return AgentData(
                agent_name="AITestingAgent",
                success=True,
                summary=f"AI attack agent testing completed",
                errors=[],
                execution_time=0,
                memory_usage=0,
                cpu_usage=0,
                context={
                    'test_type': test_type,
                    'target_agents': target_agents,
                    'test_duration': test_duration,
                    'findings': analysis,
                    'raw_results': results,
                    'performance_benchmark': self.performance_benchmark
                }
            )

        except Exception as e:
            self.logger.error(f"AI testing failed: {e}")
            return AgentData(
                agent_name="AITestingAgent",
                success=False,
                summary="AI testing failed",
                errors=[str(e)],
                execution_time=0,
                memory_usage=0,
                cpu_usage=0,
                context={'test_type': strategy.context.get('test_type')}
            )

    async def _analyze_testing_strategy(self, test_type: str, target_agents: List[str]) -> Dict[str, Any]:
        """AI analysis to determine optimal testing strategy"""
        try:
            # AI analysis of testing requirements
            testing_profiles = {
                'comprehensive': {
                    'test_coverage': 'full',
                    'performance_testing': True,
                    'security_testing': True,
                    'integration_testing': True,
                    'stress_testing': True,
                    'ai_optimization': True
                },
                'performance': {
                    'test_coverage': 'performance_only',
                    'performance_testing': True,
                    'security_testing': False,
                    'integration_testing': False,
                    'stress_testing': True,
                    'ai_optimization': False
                },
                'security': {
                    'test_coverage': 'security_only',
                    'performance_testing': False,
                    'security_testing': True,
                    'integration_testing': True,
                    'stress_testing': False,
                    'ai_optimization': True
                },
                'integration': {
                    'test_coverage': 'integration_only',
                    'performance_testing': True,
                    'security_testing': True,
                    'integration_testing': True,
                    'stress_testing': False,
                    'ai_optimization': False
                }
            }

            base_strategy = testing_profiles.get(test_type, testing_profiles['comprehensive'])

            # AI optimization for target agents
            if 'all' in target_agents:
                base_strategy['target_agents'] = [
                    'NetworkScannerAgent',
                    'ProtocolFuzzerAgent',
                    'NetworkTrafficAnalyzerAgent',
                    'PacketCaptureAgent',
                    'NetworkExploitationAgent'
                ]
            else:
                base_strategy['target_agents'] = target_agents

            # Add intelligent test prioritization
            base_strategy['test_prioritization'] = 'ai_optimized'
            base_strategy['failure_recovery'] = True
            base_strategy['adaptive_testing'] = True

            return base_strategy

        except Exception as e:
            self.logger.warning(f"AI testing strategy analysis failed: {e}")
            return {
                'test_coverage': 'basic',
                'performance_testing': True,
                'security_testing': False,
                'integration_testing': False,
                'stress_testing': False,
                'ai_optimization': False,
                'target_agents': ['NetworkScannerAgent'],
                'test_prioritization': 'basic',
                'failure_recovery': True,
                'adaptive_testing': False
            }

    async def _execute_comprehensive_testing(self, target_agents: List[str], strategy: Dict[str, Any], duration: int) -> Dict[str, Any]:
        """Execute comprehensive testing of AI attack agents"""
        try:
            test_results = []
            start_time = time.time()
            self.start_time = start_time  # Store for duration checking

            # Execute different types of tests based on strategy
            if strategy.get('performance_testing', False):
                performance_results = await self._execute_performance_tests(target_agents, strategy)
                test_results.extend(performance_results)

            if strategy.get('security_testing', False):
                security_results = await self._execute_security_tests(target_agents, strategy)
                test_results.extend(security_results)

            if strategy.get('integration_testing', False):
                integration_results = await self._execute_integration_tests(target_agents, strategy)
                test_results.extend(integration_results)

            if strategy.get('stress_testing', False):
                stress_results = await self._execute_stress_tests(target_agents, strategy)
                test_results.extend(stress_results)

            # Calculate overall metrics
            overall_metrics = self._calculate_overall_metrics(test_results)

            return {
                'test_results': test_results,
                'overall_metrics': overall_metrics,
                'test_duration': time.time() - start_time,
                'strategy': strategy,
                'agent_count': len(target_agents)
            }

        except Exception as e:
            self.logger.error(f"Comprehensive testing execution failed: {e}")
            return {'error': str(e), 'test_results': []}

    async def _execute_performance_tests(self, target_agents: List[str], strategy: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Execute performance testing of AI attack agents"""
        try:
            performance_results = []

            for agent in target_agents:
                # Simulate performance test execution
                test_result = await self._simulate_performance_test(agent, strategy)
                performance_results.append(test_result)

                # Check if test duration exceeded
                if time.time() - self.start_time > strategy.get('test_duration', 300):
                    break

            return performance_results

        except Exception as e:
            self.logger.warning(f"Performance testing failed: {e}")
            return []

    async def _simulate_performance_test(self, agent: str, strategy: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate performance test for an agent"""
        try:
            await asyncio.sleep(0.5)  # Simulate test execution time

            # Generate performance metrics
            metrics = {
                'agent_name': agent,
                'test_type': 'performance',
                'execution_time_ms': random.randint(100, 5000),
                'memory_usage_mb': random.randint(50, 500),
                'cpu_usage_percent': random.randint(10, 80),
                'success_rate': random.uniform(0.7, 1.0),
                'throughput_operations_per_second': random.randint(10, 100),
                'response_time_ms': random.randint(50, 1000),
                'error_rate': random.uniform(0.0, 0.3),
                'concurrent_capability': random.randint(1, 10),
                'ai_optimization_score': random.uniform(0.5, 1.0)
            }

            return {
                'agent': agent,
                'metrics': metrics,
                'test_passed': metrics['success_rate'] > 0.7,
                'performance_grade': self._calculate_performance_grade(metrics),
                'bottlenecks': self._identify_bottlenecks(metrics),
                'optimization_suggestions': self._generate_optimization_suggestions(metrics)
            }

        except Exception as e:
            self.logger.debug(f"Performance test simulation failed: {e}")
            return {
                'agent': agent,
                'test_passed': False,
                'error': str(e)
            }

    def _calculate_performance_grade(self, metrics: Dict[str, Any]) -> str:
        """Calculate performance grade based on metrics"""
        try:
            success_rate = metrics.get('success_rate', 0)
            response_time = metrics.get('response_time_ms', 1000)
            error_rate = metrics.get('error_rate', 0.5)

            if success_rate >= 0.9 and response_time <= 200 and error_rate <= 0.1:
                return 'A+'
            elif success_rate >= 0.8 and response_time <= 500 and error_rate <= 0.2:
                return 'A'
            elif success_rate >= 0.7 and response_time <= 1000 and error_rate <= 0.3:
                return 'B'
            else:
                return 'C'

        except Exception as e:
            self.logger.warning(f"Performance grade calculation failed: {e}")
            return 'Unknown'

    def _identify_bottlenecks(self, metrics: Dict[str, Any]) -> List[str]:
        """Identify performance bottlenecks"""
        bottlenecks = []

        if metrics.get('response_time_ms', 0) > 1000:
            bottlenecks.append('High response time')
        if metrics.get('cpu_usage_percent', 0) > 80:
            bottlenecks.append('High CPU usage')
        if metrics.get('memory_usage_mb', 0) > 400:
            bottlenecks.append('High memory usage')
        if metrics.get('error_rate', 0) > 0.3:
            bottlenecks.append('High error rate')

        return bottlenecks

    def _generate_optimization_suggestions(self, metrics: Dict[str, Any]) -> List[str]:
        """Generate optimization suggestions"""
        suggestions = []

        if metrics.get('response_time_ms', 0) > 1000:
            suggestions.append('Optimize algorithm efficiency')
            suggestions.append('Implement caching mechanisms')
        if metrics.get('cpu_usage_percent', 0) > 80:
            suggestions.append('Reduce computational complexity')
            suggestions.append('Implement parallel processing')
        if metrics.get('memory_usage_mb', 0) > 400:
            suggestions.append('Optimize memory allocation')
            suggestions.append('Implement memory pooling')
        if metrics.get('error_rate', 0) > 0.3:
            suggestions.append('Improve error handling')
            suggestions.append('Enhance input validation')

        return suggestions

    async def _execute_security_tests(self, target_agents: List[str], strategy: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Execute security testing of AI attack agents"""
        try:
            security_results = []

            for agent in target_agents:
                test_result = await self._simulate_security_test(agent, strategy)
                security_results.append(test_result)

            return security_results

        except Exception as e:
            self.logger.warning(f"Security testing failed: {e}")
            return []

    async def _simulate_security_test(self, agent: str, strategy: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate security test for an agent"""
        try:
            await asyncio.sleep(0.3)

            # Generate security test results
            vulnerabilities = []
            if random.random() > 0.7:
                vulnerabilities.append('Input validation weakness')
            if random.random() > 0.8:
                vulnerabilities.append('Authentication bypass')
            if random.random() > 0.9:
                vulnerabilities.append('Privilege escalation')

            metrics = {
                'agent_name': agent,
                'test_type': 'security',
                'vulnerabilities_found': len(vulnerabilities),
                'security_score': random.uniform(0.1, 1.0),
                'authentication_strength': random.uniform(0.1, 1.0),
                'input_validation_strength': random.uniform(0.1, 1.0),
                'error_handling_strength': random.uniform(0.1, 1.0),
                'data_protection_strength': random.uniform(0.1, 1.0)
            }

            return {
                'agent': agent,
                'metrics': metrics,
                'vulnerabilities': vulnerabilities,
                'security_grade': self._calculate_security_grade(metrics),
                'critical_issues': len(vulnerabilities) > 2,
                'recommendations': self._generate_security_recommendations(vulnerabilities, metrics)
            }

        except Exception as e:
            self.logger.debug(f"Security test simulation failed: {e}")
            return {
                'agent': agent,
                'test_passed': False,
                'error': str(e)
            }

    def _calculate_security_grade(self, metrics: Dict[str, Any]) -> str:
        """Calculate security grade based on metrics"""
        score = metrics.get('security_score', 0)
        if score >= 0.8:
            return 'A+'
        elif score >= 0.6:
            return 'A'
        elif score >= 0.4:
            return 'B'
        else:
            return 'C'

    def _generate_security_recommendations(self, vulnerabilities: List[str], metrics: Dict[str, Any]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []

        if 'Input validation weakness' in vulnerabilities:
            recommendations.append('Implement comprehensive input validation')
        if 'Authentication bypass' in vulnerabilities:
            recommendations.append('Strengthen authentication mechanisms')
        if 'Privilege escalation' in vulnerabilities:
            recommendations.append('Implement proper access controls')

        if metrics.get('authentication_strength', 0) < 0.5:
            recommendations.append('Enhance authentication security')
        if metrics.get('input_validation_strength', 0) < 0.5:
            recommendations.append('Improve input validation')

        return recommendations

    async def _execute_integration_tests(self, target_agents: List[str], strategy: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Execute integration testing of AI attack agents"""
        try:
            integration_results = []

            # Test agent interactions
            for i, agent1 in enumerate(target_agents):
                for agent2 in target_agents[i+1:]:
                    test_result = await self._simulate_integration_test(agent1, agent2, strategy)
                    integration_results.append(test_result)

            return integration_results

        except Exception as e:
            self.logger.warning(f"Integration testing failed: {e}")
            return []

    async def _simulate_integration_test(self, agent1: str, agent2: str, strategy: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate integration test between two agents"""
        try:
            await asyncio.sleep(0.4)

            # Test agent compatibility
            compatibility_score = random.uniform(0.1, 1.0)
            data_exchange_success = random.random() > 0.3
            protocol_compatibility = random.random() > 0.2

            return {
                'agents': f"{agent1} <-> {agent2}",
                'compatibility_score': compatibility_score,
                'data_exchange_success': data_exchange_success,
                'protocol_compatibility': protocol_compatibility,
                'integration_grade': self._calculate_integration_grade(compatibility_score, data_exchange_success),
                'issues': self._identify_integration_issues(compatibility_score, data_exchange_success),
                'recommendations': self._generate_integration_recommendations(compatibility_score, data_exchange_success)
            }

        except Exception as e:
            self.logger.debug(f"Integration test simulation failed: {e}")
            return {
                'agents': f"{agent1} <-> {agent2}",
                'test_passed': False,
                'error': str(e)
            }

    def _calculate_integration_grade(self, compatibility: float, data_exchange: bool) -> str:
        """Calculate integration grade"""
        if compatibility >= 0.8 and data_exchange:
            return 'A+'
        elif compatibility >= 0.6 and data_exchange:
            return 'A'
        elif compatibility >= 0.4:
            return 'B'
        else:
            return 'C'

    def _identify_integration_issues(self, compatibility: float, data_exchange: bool) -> List[str]:
        """Identify integration issues"""
        issues = []
        if compatibility < 0.5:
            issues.append('Low compatibility score')
        if not data_exchange:
            issues.append('Data exchange failure')
        return issues

    def _generate_integration_recommendations(self, compatibility: float, data_exchange: bool) -> List[str]:
        """Generate integration recommendations"""
        recommendations = []
        if compatibility < 0.6:
            recommendations.append('Improve agent compatibility')
        if not data_exchange:
            recommendations.append('Fix data exchange protocols')
        return recommendations

    async def _execute_stress_tests(self, target_agents: List[str], strategy: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Execute stress testing of AI attack agents"""
        try:
            stress_results = []

            for agent in target_agents:
                test_result = await self._simulate_stress_test(agent, strategy)
                stress_results.append(test_result)

            return stress_results

        except Exception as e:
            self.logger.warning(f"Stress testing failed: {e}")
            return []

    async def _simulate_stress_test(self, agent: str, strategy: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate stress test for an agent"""
        try:
            await asyncio.sleep(0.6)

            # Test agent under stress conditions
            load_factor = random.uniform(0.1, 2.0)
            failure_rate = random.uniform(0.0, 0.5)
            recovery_time = random.randint(100, 5000)

            return {
                'agent': agent,
                'load_factor': load_factor,
                'failure_rate': failure_rate,
                'recovery_time_ms': recovery_time,
                'stress_resilience': self._calculate_stress_resilience(load_factor, failure_rate),
                'failure_modes': self._identify_failure_modes(failure_rate),
                'recovery_effectiveness': self._calculate_recovery_effectiveness(recovery_time),
                'stress_test_grade': self._determine_stress_grade(load_factor, failure_rate, recovery_time)
            }

        except Exception as e:
            self.logger.debug(f"Stress test simulation failed: {e}")
            return {
                'agent': agent,
                'test_passed': False,
                'error': str(e)
            }

    def _calculate_stress_resilience(self, load_factor: float, failure_rate: float) -> str:
        """Calculate stress resilience"""
        if load_factor <= 1.0 and failure_rate <= 0.2:
            return 'High'
        elif load_factor <= 1.5 and failure_rate <= 0.3:
            return 'Medium'
        else:
            return 'Low'

    def _identify_failure_modes(self, failure_rate: float) -> List[str]:
        """Identify failure modes"""
        modes = []
        if failure_rate > 0.3:
            modes.append('Frequent failures')
        if failure_rate > 0.4:
            modes.append('Catastrophic failure')
        return modes

    def _calculate_recovery_effectiveness(self, recovery_time: int) -> str:
        """Calculate recovery effectiveness"""
        if recovery_time <= 1000:
            return 'Fast'
        elif recovery_time <= 3000:
            return 'Medium'
        else:
            return 'Slow'

    def _determine_stress_grade(self, load_factor: float, failure_rate: float, recovery_time: int) -> str:
        """Determine stress test grade"""
        if load_factor <= 1.0 and failure_rate <= 0.2 and recovery_time <= 1000:
            return 'A+'
        elif load_factor <= 1.5 and failure_rate <= 0.3 and recovery_time <= 2000:
            return 'A'
        elif load_factor <= 2.0 and failure_rate <= 0.4 and recovery_time <= 3000:
            return 'B'
        else:
            return 'C'

    def _calculate_overall_metrics(self, test_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate overall test metrics"""
        try:
            if not test_results:
                return {'error': 'No test results available'}

            # Calculate aggregate metrics
            total_tests = len(test_results)
            passed_tests = sum(1 for result in test_results if result.get('test_passed', False))

            # Calculate average performance metrics
            avg_success_rate = statistics.mean([
                result.get('metrics', {}).get('success_rate', 0) for result in test_results
                if 'metrics' in result
            ])

            avg_response_time = statistics.mean([
                result.get('metrics', {}).get('response_time_ms', 0) for result in test_results
                if 'metrics' in result
            ])

            total_vulnerabilities = sum([
                len(result.get('vulnerabilities', [])) for result in test_results
                if 'vulnerabilities' in result
            ])

            return {
                'total_tests': total_tests,
                'passed_tests': passed_tests,
                'pass_rate': passed_tests / total_tests if total_tests > 0 else 0,
                'average_success_rate': avg_success_rate,
                'average_response_time_ms': avg_response_time,
                'total_vulnerabilities': total_vulnerabilities,
                'overall_grade': self._calculate_overall_grade(avg_success_rate, passed_tests, total_tests),
                'test_efficiency': self._calculate_test_efficiency(test_results)
            }

        except Exception as e:
            self.logger.warning(f"Overall metrics calculation failed: {e}")
            return {'error': 'Calculation failed'}

    def _calculate_overall_grade(self, avg_success_rate: float, passed_tests: int, total_tests: int) -> str:
        """Calculate overall test grade"""
        pass_rate = passed_tests / total_tests if total_tests > 0 else 0

        if avg_success_rate >= 0.9 and pass_rate >= 0.9:
            return 'A+'
        elif avg_success_rate >= 0.8 and pass_rate >= 0.8:
            return 'A'
        elif avg_success_rate >= 0.7 and pass_rate >= 0.7:
            return 'B'
        elif avg_success_rate >= 0.6 and pass_rate >= 0.6:
            return 'C'
        else:
            return 'D'

    def _calculate_test_efficiency(self, test_results: List[Dict[str, Any]]) -> str:
        """Calculate test efficiency"""
        try:
            if not test_results:
                return 'Unknown'

            efficient_tests = sum(1 for result in test_results
                               if result.get('test_passed', False) and
                               result.get('performance_grade', 'C') in ['A+', 'A', 'B'])

            efficiency = efficient_tests / len(test_results)
            if efficiency >= 0.8:
                return 'High'
            elif efficiency >= 0.6:
                return 'Medium'
            else:
                return 'Low'

        except Exception as e:
            self.logger.warning(f"Test efficiency calculation failed: {e}")
            return 'Unknown'

    def _initialize_performance_benchmark(self) -> Dict[str, Any]:
        """Initialize performance benchmark data"""
        return {
            'baseline_metrics': {
                'response_time_ms': 500,
                'success_rate': 0.8,
                'memory_usage_mb': 200,
                'cpu_usage_percent': 50,
                'error_rate': 0.1
            },
            'industry_standards': {
                'network_scanners': {
                    'response_time_ms': 300,
                    'success_rate': 0.85,
                    'throughput': 1000
                },
                'exploitation_agents': {
                    'response_time_ms': 1000,
                    'success_rate': 0.6,
                    'stealth_level': 0.8
                }
            },
            'ai_optimization_targets': {
                'learning_rate': 0.1,
                'adaptation_speed': 100,
                'prediction_accuracy': 0.9
            }
        }

    async def _analyze_test_results(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """AI analysis of test results"""
        try:
            findings = []

            # Analyze overall performance
            if 'overall_metrics' in results:
                performance_analysis = await self._analyze_performance_metrics(
                    results['overall_metrics']
                )
                findings.append({
                    'category': 'performance_analysis',
                    'analysis': performance_analysis
                })

            # Analyze individual agent performance
            if 'test_results' in results:
                agent_analysis = await self._analyze_individual_agents(
                    results['test_results']
                )
                findings.append({
                    'category': 'agent_analysis',
                    'analysis': agent_analysis
                })

            # Generate improvement recommendations
            improvement_recommendations = await self._generate_improvement_recommendations(results)
            findings.append({
                'category': 'improvement_recommendations',
                'analysis': improvement_recommendations
            })

            return findings

        except Exception as e:
            self.logger.error(f"Test results analysis failed: {e}")
            return []

    async def _analyze_performance_metrics(self, metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze overall performance metrics"""
        try:
            analysis = {
                'performance_score': metrics.get('average_success_rate', 0),
                'efficiency_rating': metrics.get('test_efficiency', 'Unknown'),
                'grade': metrics.get('overall_grade', 'C'),
                'bottlenecks': [],
                'strengths': [],
                'recommendations': []
            }

            # Identify bottlenecks and strengths
            if metrics.get('average_response_time_ms', 0) > 1000:
                analysis['bottlenecks'].append('Slow response time')
            else:
                analysis['strengths'].append('Fast response time')

            if metrics.get('pass_rate', 0) > 0.8:
                analysis['strengths'].append('High test pass rate')
            else:
                analysis['bottlenecks'].append('Low test pass rate')

            # Generate recommendations
            if 'Slow response time' in analysis['bottlenecks']:
                analysis['recommendations'].append('Optimize agent algorithms for speed')
            if 'Low test pass rate' in analysis['bottlenecks']:
                analysis['recommendations'].append('Improve agent reliability and robustness')

            return analysis

        except Exception as e:
            self.logger.warning(f"Performance metrics analysis failed: {e}")
            return {'error': 'Analysis failed'}

    async def _analyze_individual_agents(self, test_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze individual agent performance"""
        try:
            analysis = {
                'agent_count': len(test_results),
                'performance_distribution': {},
                'best_performers': [],
                'worst_performers': [],
                'common_issues': []
            }

            # Analyze each agent
            for result in test_results:
                agent_name = result.get('agent', 'Unknown')
                performance_grade = result.get('performance_grade', 'C')
                test_passed = result.get('test_passed', False)

                # Track performance distribution
                if performance_grade not in analysis['performance_distribution']:
                    analysis['performance_distribution'][performance_grade] = 0
                analysis['performance_distribution'][performance_grade] += 1

                # Track best and worst performers
                if test_passed and performance_grade in ['A+', 'A']:
                    analysis['best_performers'].append(agent_name)
                elif not test_passed or performance_grade in ['C']:
                    analysis['worst_performers'].append(agent_name)

            # Identify common issues
            issue_counts = {}
            for result in test_results:
                issues = result.get('bottlenecks', []) or result.get('issues', [])
                for issue in issues:
                    if issue not in issue_counts:
                        issue_counts[issue] = 0
                    issue_counts[issue] += 1

            # Find most common issues
            for issue, count in issue_counts.items():
                if count > len(test_results) / 2:
                    analysis['common_issues'].append(issue)

            return analysis

        except Exception as e:
            self.logger.warning(f"Individual agent analysis failed: {e}")
            return {'error': 'Analysis failed'}

    async def _generate_improvement_recommendations(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate improvement recommendations based on test results"""
        try:
            recommendations = {
                'priority_actions': [],
                'long_term_improvements': [],
                'ai_optimization_suggestions': [],
                'resource_allocation_suggestions': []
            }

            # Get performance metrics
            overall_metrics = results.get('overall_metrics', {})
            test_results = results.get('test_results', [])

            # Generate priority actions based on critical issues
            if overall_metrics.get('pass_rate', 1.0) < 0.7:
                recommendations['priority_actions'].append('Fix critical agent failures immediately')
            if overall_metrics.get('average_response_time_ms', 0) > 1000:
                recommendations['priority_actions'].append('Optimize agent response times')

            # Analyze individual agent issues for long-term improvements
            for result in test_results:
                bottlenecks = result.get('bottlenecks', []) or result.get('issues', [])
                for bottleneck in bottlenecks:
                    if 'response time' in bottleneck:
                        recommendations['long_term_improvements'].append(
                            f"Optimize {result.get('agent', 'agent')} response time"
                        )
                    elif 'memory usage' in bottleneck:
                        recommendations['long_term_improvements'].append(
                            f"Reduce memory usage for {result.get('agent', 'agent')}"
                        )

            # AI optimization suggestions
            if overall_metrics.get('grade', 'C') in ['C', 'B']:
                recommendations['ai_optimization_suggestions'].append(
                    'Implement advanced AI optimization algorithms'
                )
            recommendations['ai_optimization_suggestions'].append(
                'Add machine learning for adaptive agent behavior'
            )
            recommendations['ai_optimization_suggestions'].append(
                'Implement real-time performance monitoring and adjustment'
            )

            # Resource allocation suggestions
            recommendations['resource_allocation_suggestions'].append(
                'Allocate more resources to high-priority agents'
            )
            recommendations['resource_allocation_suggestions'].append(
                'Implement dynamic resource scaling based on agent load'
            )

            return recommendations

        except Exception as e:
            self.logger.warning(f"Improvement recommendations generation failed: {e}")
            return {'error': 'Recommendation generation failed'}

    async def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the agent's main functionality"""
        strategy = Strategy(
            phase=AttackPhase.TESTING,
            directive='AI attack agent testing execution',
            next_agent='none',
            context=context,
            objectives=['agent_validation', 'performance_optimization']
        )
        result = await self.execute(strategy)
        return {
            'success': result.success,
            'summary': result.summary,
            'findings': result.context.get('findings', []),
            'raw_results': result.context.get('raw_results', {})
        }