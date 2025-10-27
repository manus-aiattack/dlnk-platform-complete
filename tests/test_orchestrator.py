'''
Tests for the Orchestrator
'''
import pytest
import pytest_asyncio
import yaml
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock, patch, ANY

from core.orchestrator import Orchestrator
from core.data_models import AgentData, Strategy, AttackPhase

# Mock Agent class for testing purposes
class MockAgent:
    def __init__(self, agent_name):
        self.name = agent_name
        self.execute_with_error_handling = AsyncMock()

@pytest_asyncio.fixture
async def mock_orchestrator(tmp_path):
    '''Fixture for a mocked Orchestrator instance with mocked dependencies.'''
    with patch('core.orchestrator.AgentRegistry', autospec=True) as MockAgentRegistryClass, \
         patch('core.orchestrator.ContextManager', autospec=True) as MockContextManagerClass, \
         patch('core.orchestrator.PubSubManager', autospec=True) as MockPubSubManagerClass:

        orchestrator = Orchestrator(workspace_dir=str(tmp_path))

        # Configure the mock instances
        orchestrator.agent_registry.agents = {} # Fix for AttributeError: 'agents'
        orchestrator.context_manager.redis = AsyncMock() # Mock redis for logger
        orchestrator.pubsub_manager.redis = AsyncMock() # Mock redis for websocket

        # Mock the cleanup methods on the instances themselves
        orchestrator.context_manager.cleanup = AsyncMock()
        orchestrator.pubsub_manager.close = AsyncMock()

        await orchestrator.initialize()

        yield orchestrator

        # No need to call cleanup here, it's tested separately and handled by the test itself

@pytest.mark.asyncio
async def test_orchestrator_initialization(mock_orchestrator):
    '''Test that the orchestrator and its components are initialized correctly.'''
    assert mock_orchestrator is not None
    mock_orchestrator.agent_registry.auto_discover_agents.assert_called_once()
    mock_orchestrator.context_manager.setup.assert_called_once()
    mock_orchestrator.pubsub_manager.setup.assert_called_once()

@pytest.mark.asyncio
async def test_orchestrator_agent_execution(mock_orchestrator):
    '''Test direct execution of a single agent.'''
    agent_instance = MockAgent(agent_name="TestAgent")
    agent_instance.execute_with_error_handling.return_value = AgentData(
        agent_name="TestAgent", success=True, summary="Agent executed successfully."
    )
    mock_orchestrator.agent_registry.get_agent = AsyncMock(return_value=agent_instance)

    strategy = Strategy(
        phase=AttackPhase.RECONNAISSANCE,
        next_agent="TestAgent",
        directive="Perform a test scan",
    )

    result = await mock_orchestrator.execute_agent_directly("TestAgent", strategy)

    assert result.success is True
    agent_instance.execute_with_error_handling.assert_called_once_with(strategy, extra=ANY)

@pytest.mark.asyncio
async def test_orchestrator_workflow_execution(mock_orchestrator, tmp_path):
    '''Test a full workflow execution with multiple phases and agents.'''
    workflow_data = {
        'workflow_name': 'Test Workflow',
        'phases': [
            {
                'name': 'Reconnaissance',
                'agents': [{'name': 'TestAgent1'}, {'name': 'TestAgent2'}]
            },
            {
                'name': 'Exploitation',
                'agents': [{'name': 'TestAgent3'}]
            }
        ]
    }
    workflow_file = tmp_path / "test_workflow.yaml"
    with open(workflow_file, 'w') as f:
        yaml.dump(workflow_data, f)

    agent1 = MockAgent("TestAgent1")
    agent1.execute_with_error_handling.return_value = AgentData(agent_name="TestAgent1", success=True)
    agent2 = MockAgent("TestAgent2")
    agent2.execute_with_error_handling.return_value = AgentData(agent_name="TestAgent2", success=True)
    agent3 = MockAgent("TestAgent3")
    agent3.execute_with_error_handling.return_value = AgentData(agent_name="TestAgent3", success=True)

    async def get_agent_side_effect(agent_name, **kwargs):
        if agent_name == "TestAgent1": return agent1
        if agent_name == "TestAgent2": return agent2
        if agent_name == "TestAgent3": return agent3
        return None
    mock_orchestrator.agent_registry.get_agent.side_effect = get_agent_side_effect

    target = {'name': 'TestTarget', 'url': 'http://test.com'}
    results = await mock_orchestrator.execute_workflow(str(workflow_file), target)

    assert len(results) == 3, f"Expected 3 results, but got {len(results)}"
    assert all(r.success for r in results)
    assert agent1.execute_with_error_handling.call_count == 1
    assert agent2.execute_with_error_handling.call_count == 1
    assert agent3.execute_with_error_handling.call_count == 1

@pytest.mark.asyncio
async def test_orchestrator_cleanup(mock_orchestrator):
    '''Test that cleanup is called correctly.'''
    await mock_orchestrator.cleanup()
    mock_orchestrator.context_manager.cleanup.assert_called_once()
    mock_orchestrator.pubsub_manager.close.assert_called_once()

