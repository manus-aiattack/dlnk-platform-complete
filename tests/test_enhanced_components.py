"""
Unit Tests for Enhanced AI Components
Phase 2: Testing & Quality Assurance - Unit Testing
"""

import pytest
import asyncio
import json
from unittest.mock import Mock, patch, MagicMock
import sys
import os

# Add the project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from core.enhanced_orchestrator import EnhancedOrchestrator, AgentScore, ResourceAllocation
from core.ai_models.enhanced_ai_decision_engine import EnhancedAIDecisionEngine, DecisionResult
from core.self_healing.enhanced_error_detector import EnhancedErrorDetector, Anomaly, RecoveryStrategy
from core.self_learning.enhanced_adaptive_learner import EnhancedAdaptiveLearner, Pattern
from core.data_models import AttackPhase
from tests.test_framework import TestHelper, TestDataGenerator


@pytest.mark.unit
class TestEnhancedOrchestrator:
    """Unit tests for EnhancedOrchestrator"""

    @pytest.fixture
    def orchestrator(self):
        """Create test orchestrator"""
        return EnhancedOrchestrator()

    @pytest.fixture
    def test_context(self):
        """Create test context"""
        return {
            'target_info': {'type': 'web', 'security_level': 'medium'},
            'phase': 'reconnaissance',
            'constraints': {
                'max_cpu': 8,
                'max_memory': 4096,
                'max_agents': 5
            }
        }

    @pytest.mark.asyncio
    async def test_select_optimal_agents(self, orchestrator, test_context):
        """Test agent selection algorithm"""
        # Mock agent registry
        orchestrator.agent_registry = Mock()
        orchestrator.agent_registry.agents = {'TestAgent1': Mock(), 'TestAgent2': Mock()}

        # Test agent selection
        phase = AttackPhase.RECONNAISSANCE
        constraints = {'max_agents': 3, 'min_score': 0.5}

        selected_agents = await orchestrator.select_optimal_agents(
            phase=phase,
            context=test_context,
            constraints=constraints
        )

        assert isinstance(selected_agents, list)
        assert len(selected_agents) <= constraints['max_agents']
        assert len(orchestrator.agent_selection_history) == 1

    @pytest.mark.asyncio
    async def test_score_agent(self, orchestrator, test_context):
        """Test agent scoring"""
        score = await orchestrator._score_agent(
            agent_name='TestAgent',
            phase=AttackPhase.RECONNAISSANCE,
            context=test_context,
            constraints={'max_cpu': 8, 'max_memory': 4096}
        )

        assert isinstance(score, AgentScore)
        assert 0.0 <= score.score <= 1.0
        assert 0.0 <= score.confidence <= 1.0
        assert isinstance(score.reasoning, str)

    def test_get_agents_for_phase(self, orchestrator):
        """Test getting agents for phase"""
        agents = orchestrator._get_agents_for_phase(AttackPhase.RECONNAISSANCE)
        assert isinstance(agents, list)
        assert len(agents) > 0

    def test_get_agent_success_rate(self, orchestrator):
        """Test getting agent success rate"""
        rate = orchestrator._get_agent_success_rate('NmapAgent')
        assert 0.0 <= rate <= 1.0

    @pytest.mark.asyncio
    async def test_coordinate_parallel_execution(self, orchestrator, test_context):
        """Test parallel execution coordination"""
        # Mock agent execution
        with patch.object(orchestrator, 'execute_agent_directly') as mock_execute:
            mock_execute.return_value = Mock()
            mock_execute.return_value.success = True

            results = await orchestrator.coordinate_parallel_execution(
                agent_names=['TestAgent1', 'TestAgent2'],
                context=test_context,
                phase=AttackPhase.RECONNAISSANCE
            )

            assert isinstance(results, list)
            assert mock_execute.called

    def test_allocate_resources(self, orchestrator):
        """Test resource allocation"""
        allocations = orchestrator._allocate_resources(
            ['NmapAgent', 'SQLMapAgent'],
            AttackPhase.RECONNAISSANCE
        )

        assert isinstance(allocations, dict)
        assert 'NmapAgent' in allocations
        assert isinstance(allocations['NmapAgent'], ResourceAllocation)


@pytest.mark.unit
class TestEnhancedAIDecisionEngine:
    """Unit tests for EnhancedAIDecisionEngine"""

    @pytest.fixture
    def decision_engine(self):
        """Create test decision engine"""
        return EnhancedAIDecisionEngine()

    @pytest.fixture
    def test_situation(self):
        """Create test situation"""
        return {
            'type': 'web_attack',
            'complexity': 'medium',
            'target_security': 'high'
        }

    @pytest.fixture
    def test_options(self):
        """Create test options"""
        return [
            {'type': 'reconnaissance', 'method': 'port_scan', 'complexity': 'low'},
            {'type': 'exploitation', 'method': 'sql_injection', 'complexity': 'medium'}
        ]

    @pytest.fixture
    def test_context(self):
        """Create test context"""
        return {
            'target_type': 'web',
            'security_level': 'medium',
            'target_complexity': 'medium'
        }

    @pytest.mark.asyncio
    async def test_make_decision(self, decision_engine, test_situation, test_options, test_context):
        """Test decision making"""
        result = await decision_engine.make_decision(
            situation=test_situation,
            options=test_options,
            context=test_context
        )

        assert isinstance(result, DecisionResult)
        assert isinstance(result.decision, dict)
        assert 0.0 <= result.confidence <= 1.0
        assert 0.0 <= result.success_probability <= 1.0
        assert 0.0 <= result.risk_score <= 1.0
        assert isinstance(result.reasoning, str)

    def test_calculate_success_probability(self, decision_engine, test_options, test_context):
        """Test success probability calculation"""
        features = decision_engine._extract_features(test_options[0], test_context)
        similar_cases = []
        probability = decision_engine._calculate_success_probability(
            option=test_options[0],
            features=features,
            similar_cases=similar_cases
        )

        assert 0.0 <= probability <= 1.0

    def test_calculate_risk(self, decision_engine, test_options, test_context):
        """Test risk calculation"""
        risk = decision_engine._calculate_risk(
            option=test_options[0],
            context=test_context,
            similar_cases=[]
        )

        assert 0.0 <= risk <= 1.0

    def test_extract_features(self, decision_engine, test_situation, test_context):
        """Test feature extraction"""
        features = decision_engine._extract_features(test_situation, test_context)
        assert isinstance(features, list)
        assert len(features) > 0

    @pytest.mark.asyncio
    async def test_generate_alternatives(self, decision_engine, test_situation, test_options, test_context):
        """Test alternative generation"""
        alternatives = await decision_engine._generate_alternatives(
            situation=test_situation,
            failed_option={'option': test_options[0], 'confidence': 0.3},
            context=test_context
        )

        assert isinstance(alternatives, list)


@pytest.mark.unit
class TestEnhancedErrorDetector:
    """Unit tests for EnhancedErrorDetector"""

    @pytest.fixture
    def error_detector(self):
        """Create test error detector"""
        return EnhancedErrorDetector()

    @pytest.fixture
    def test_metrics(self):
        """Create test metrics"""
        return {
            'cpu_usage': 85.0,
            'memory_usage': 90.0,
            'error_rate': 5.0,
            'response_time': 2000.0
        }

    @pytest.fixture
    def test_logs(self):
        """Create test logs"""
        return [
            "Error: Connection timeout",
            "Warning: High memory usage",
            "Info: Processing request"
        ]

    def test_detect_anomalies(self, error_detector, test_metrics):
        """Test anomaly detection"""
        anomalies = error_detector.anomaly_detector.detect(test_metrics)
        assert isinstance(anomalies, list)

    def test_update_baseline(self, error_detector, test_metrics):
        """Test baseline update"""
        error_detector.update_baseline(test_metrics)
        assert len(error_detector.anomaly_detector.baseline_data) > 0

    @pytest.mark.asyncio
    async def test_predict_failure(self, error_detector, test_metrics, test_logs):
        """Test failure prediction"""
        # Mock anomalies
        from core.self_healing.enhanced_error_detector import Anomaly
        anomalies = [
            Anomaly('cpu_usage', 95.0, 80.0, 'high', '2024-01-01T00:00:00', 'High CPU usage')
        ]

        probability = error_detector.predict_failure(
            component='test_component',
            anomalies=anomalies,
            metrics=test_metrics,
            logs=test_logs
        )

        assert 0.0 <= probability <= 1.0

    @pytest.mark.asyncio
    async def test_select_strategy(self, error_detector):
        """Test recovery strategy selection"""
        from core.self_healing.enhanced_error_detector import Anomaly
        anomalies = [Anomaly('cpu_usage', 95.0, 80.0, 'critical', '2024-01-01T00:00:00', 'High CPU')]

        strategy = await error_detector.recovery_strategies.select_strategy(
            component='test_api',
            anomalies=anomalies,
            severity='critical'
        )

        assert isinstance(strategy, RecoveryStrategy)
        assert isinstance(strategy.name, str)
        assert isinstance(strategy.success_rate, float)

    @pytest.mark.asyncio
    async def test_detect_and_recover(self, error_detector, test_metrics, test_logs):
        """Test end-to-end detection and recovery"""
        result = await error_detector.detect_and_recover(
            component='test_component',
            metrics=test_metrics,
            logs=test_logs
        )

        assert hasattr(result, 'success')
        assert hasattr(result, 'component')
        assert hasattr(result, 'strategy')


@pytest.mark.unit
class TestEnhancedAdaptiveLearner:
    """Unit tests for EnhancedAdaptiveLearner"""

    @pytest.fixture
    def adaptive_learner(self):
        """Create test adaptive learner"""
        return EnhancedAdaptiveLearner()

    @pytest.fixture
    def test_attack_result(self):
        """Create test attack result"""
        return {
            'id': 'test_attack_001',
            'outcome': 'success',
            'successful_agents': [
                {'type': 'NmapAgent', 'execution_time': 120, 'resource_usage': {'cpu': 1, 'memory': 512}}
            ],
            'failed_agents': [],
            'timing_data': {
                'original_duration': 300,
                'actual_duration': 240,
                'improvement_percentage': 20
            },
            'coordination_data': {
                'agent_count': 3,
                'parallel_execution_rate': 0.8,
                'success_rate': 0.9
            }
        }

    @pytest.fixture
    def test_context(self):
        """Create test context"""
        return {
            'target_type': 'web',
            'target_complexity': 'medium',
            'phase': 'reconnaissance'
        }

    def test_extract_patterns(self, adaptive_learner, test_attack_result, test_context):
        """Test pattern extraction"""
        patterns = adaptive_learner.pattern_learner.extract_patterns(
            test_attack_result,
            test_context
        )

        assert isinstance(patterns, list)

    @pytest.mark.asyncio
    async def test_learn_from_attack(self, adaptive_learner, test_attack_result, test_context):
        """Test learning from attack"""
        result = await adaptive_learner.learn_from_attack(
            attack_result=test_attack_result,
            context=test_context
        )

        assert hasattr(result, 'patterns_learned')
        assert hasattr(result, 'knowledge_updated')
        assert hasattr(result, 'strategies_optimized')
        assert hasattr(result, 'performance_improvement')
        assert isinstance(result.patterns_learned, int)
        assert isinstance(result.knowledge_updated, bool)
        assert isinstance(result.performance_improvement, float)

    def test_identify_success_factors(self, adaptive_learner, test_attack_result, test_context):
        """Test success factor identification"""
        patterns = adaptive_learner.pattern_learner.extract_patterns(
            test_attack_result,
            test_context
        )

        success_factors = adaptive_learner._identify_success_factors(
            patterns=patterns,
            attack_result=test_attack_result
        )

        assert isinstance(success_factors, list)

    @pytest.mark.asyncio
    async def test_get_learning_status(self, adaptive_learner):
        """Test learning status retrieval"""
        status = await adaptive_learner.get_learning_status()
        assert isinstance(status, dict)
        assert 'patterns_count' in status
        assert 'performance_improvement' in status


@pytest.mark.unit
class TestDataModels:
    """Unit tests for data models"""

    def test_agent_score_creation(self):
        """Test AgentScore creation"""
        score = AgentScore(
            agent_name='TestAgent',
            score=0.85,
            confidence=0.9,
            reasoning='Test reasoning',
            historical_success_rate=0.8,
            risk_score=0.2
        )

        assert score.agent_name == 'TestAgent'
        assert score.score == 0.85
        assert score.confidence == 0.9
        assert score.reasoning == 'Test reasoning'

    def test_decision_result_creation(self):
        """Test DecisionResult creation"""
        result = DecisionResult(
            decision={'type': 'test'},
            confidence=0.8,
            success_probability=0.7,
            risk_score=0.3,
            reasoning='Test reasoning',
            alternatives=[],
            execution_time_ms=100
        )

        assert result.confidence == 0.8
        assert result.success_probability == 0.7
        assert result.risk_score == 0.3
        assert result.execution_time_ms == 100

    def test_anomaly_creation(self):
        """Test Anomaly creation"""
        anomaly = Anomaly(
            metric_name='cpu_usage',
            value=95.0,
            threshold=80.0,
            severity='high',
            timestamp='2024-01-01T00:00:00',
            description='High CPU usage'
        )

        assert anomaly.metric_name == 'cpu_usage'
        assert anomaly.value == 95.0
        assert anomaly.severity == 'high'

    def test_pattern_creation(self):
        """Test Pattern creation"""
        pattern = Pattern(
            id='test_pattern_123',
            pattern_type='success',
            data={'agent_type': 'test', 'execution_time': 100},
            confidence=0.8,
            timestamp='2024-01-01T00:00:00',
            context={'target_type': 'web'}
        )

        assert pattern.id == 'test_pattern_123'
        assert pattern.pattern_type == 'success'
        assert pattern.confidence == 0.8


@pytest.mark.unit
class TestIntegrationHelpers:
    """Unit tests for integration helpers"""

    def test_test_helper_load_save_data(self):
        """Test test helper data loading/saving"""
        helper = TestHelper()
        test_data = {'test_key': 'test_value'}

        # Save data
        helper.save_test_data('test_file.json', test_data)

        # Load data
        loaded_data = helper.load_test_data('test_file.json')

        assert loaded_data == test_data

    def test_test_data_generator(self):
        """Test test data generator"""
        generator = TestDataGenerator()

        agent_data = generator.generate_agent_test_data()
        assert isinstance(agent_data, list)
        assert len(agent_data) > 0

        api_data = generator.generate_api_test_data()
        assert isinstance(api_data, dict)
        assert 'base_url' in api_data

    @pytest.mark.asyncio
    async def test_performance_test_helper(self):
        """Test performance test helper"""
        helper = PerformanceTestHelper()

        async def mock_function():
            await asyncio.sleep(0.1)
            return "result"

        result, execution_time = await helper.measure_execution_time(mock_function)

        assert result == "result"
        assert execution_time >= 100  # Should be around 100ms


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])