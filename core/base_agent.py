
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from core.data_models import AgentData, Strategy, ErrorType # Import ErrorType
from core.logger import log
from core.context_manager import ContextManager # Import ContextManager
import asyncio
import time


class BaseAgent(ABC):
    """Base class for all agents in the dLNk dLNk system"""

    def __init__(self, context_manager: ContextManager = None, orchestrator=None, **kwargs): # Changed shared_data to context_manager
        self.context_manager = context_manager # Changed shared_data to context_manager
        self.orchestrator = orchestrator
        self.agent_name = self.__class__.__name__
        self.config = kwargs
        self.start_time = None
        self.end_time = None
        self.report_class = AgentData  # Default report class

    async def setup(self):
        """Asynchronous setup method for agent-specific initialization."""
        pass

    @abstractmethod
    async def run(self, strategy: Strategy = None, **kwargs) -> AgentData:
        """
        Main execution method for the agent

        Args:
            strategy: Strategy object containing execution parameters
            **kwargs: Additional parameters specific to the agent

        Returns:
            AgentData: Report containing results and status
        """
        pass

    def validate_strategy(self, strategy: Strategy) -> bool:
        """Validate if the strategy is suitable for this agent"""
        if not strategy:
            return False

        # Check if agent supports the required phase
        if hasattr(self, 'supported_phases'):
            return strategy.phase in self.supported_phases

        return True

    def create_report(self, summary: Optional[str] = None, errors: Optional[List[str]] = None, error_type: Optional[ErrorType] = None, start_time: Optional[float] = None, end_time: Optional[float] = None, **data) -> AgentData:
        report_end_time = end_time if end_time is not None else time.time()
        report_start_time = start_time if start_time is not None else (self.start_time or time.time())

        report_data = {
            "agent_name": self.agent_name,
            "start_time": report_start_time,
            "end_time": report_end_time,
            "success": not bool(errors), # Infer success from errors
            "errors": errors or [],
            "summary": summary,
            "error_type": error_type or (ErrorType.AGENT_REPORTED_FAILURE if errors else ErrorType.UNKNOWN),
            **data
        }
        # Use the specified report class for instantiation
        report_object = self.report_class(**report_data)
        return report_object

    async def execute_with_error_handling(self, strategy: Strategy = None, max_retries: int = 3, initial_backoff: float = 1.0, extra: Optional[Dict[str, Any]] = None, **kwargs) -> AgentData:
        """Execute agent with standardized error handling and exponential backoff retry."""
        self.start_time = time.time()
        
        for attempt in range(max_retries):
            try:
                if not self.validate_strategy(strategy):
                    return self.create_report(
                        errors=[f"Invalid strategy for {self.agent_name}"],
                        error_type=ErrorType.CONFIGURATION,
                        summary=f"Agent {self.agent_name} failed due to invalid strategy."
                    )

                log.info(f"Starting {self.agent_name} (Attempt {attempt + 1}/{max_retries})", extra={**(extra or {}), "agent_name": self.agent_name})
                result = await self.run(strategy, **kwargs)

                if result and hasattr(result, 'success'):
                    log.info(
                        f"Completed {self.agent_name}: {'Success' if result.success else 'Failed'}", extra={**(extra or {}), "agent_name": self.agent_name})
                    return result # Return on success
                else:
                    log.warning(f"{self.agent_name} returned invalid result on attempt {attempt + 1}", extra={**(extra or {}), "agent_name": self.agent_name})
                    # If result is invalid but not an exception, retry
                    if attempt < max_retries - 1:
                        backoff_time = initial_backoff * (2 ** attempt)
                        log.info(f"Retrying {self.agent_name} in {backoff_time:.2f} seconds...", extra={**(extra or {}), "agent_name": self.agent_name})
                        await asyncio.sleep(backoff_time)
                    else:
                        return self.create_report(
                            errors=["Invalid result format after multiple retries."],
                            error_type=ErrorType.LOGIC,
                            summary=f"Agent {self.agent_name} returned invalid result after multiple retries."
                        )

            except Exception as e:
                log.error(f"{self.agent_name} failed with exception on attempt {attempt + 1}: {e}", extra={**(extra or {}), "agent_name": self.agent_name})
                if attempt < max_retries - 1:
                    backoff_time = initial_backoff * (2 ** attempt)
                    log.info(f"Retrying {self.agent_name} in {backoff_time:.2f} seconds...", extra={**(extra or {}), "agent_name": self.agent_name})
                    await asyncio.sleep(backoff_time)
                else:
                    return self.create_report(
                        errors=[f"Exception: {str(e)} after multiple retries."],
                        error_type=ErrorType.LOGIC,
                        summary=f"Agent {self.agent_name} failed with an exception after multiple retries: {e}"
                    )
        
        # Should not be reached if max_retries > 0
        return self.create_report(
            errors=["Agent execution failed unexpectedly."],
            error_type=ErrorType.UNKNOWN,
            summary=f"Agent {self.agent_name} execution failed unexpectedly."
        )

    def get_required_dependencies(self) -> List[str]:
        """Return list of required external tools/dependencies"""
        return getattr(self, 'required_tools', [])

    def get_supported_phases(self) -> List[str]:
        """Return list of supported attack phases"""
        return getattr(self, 'supported_phases', [])

    async def _get_target_info(self, target_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves information about a specific target from the context manager.

        Args:
            target_id: The unique identifier for the target.

        Returns:
            A dictionary containing the target's information, or None if not found.
        """
        if not self.context_manager:
            log.warning(f"{self.agent_name} has no context_manager to get target info.")
            return None
        try:
            # Assuming 'targets' is a dictionary of target models keyed by target_id
            targets = await self.context_manager.get_context('targets')
            return targets.get(target_id)
        except Exception as e:
            log.error(f"Error retrieving target info for '{target_id}': {e}")
            return None

    async def _log_finding(self, finding_data: Dict[str, Any]):
        """
        Logs a new finding by publishing it to the 'agent_findings' channel.

        Args:
            finding_data: A dictionary containing the details of the finding.
        """
        if not self.context_manager:
            log.warning(f"{self.agent_name} has no context_manager to log finding.")
            return
        try:
            # Add agent name to the finding data for traceability
            finding_data['reporting_agent'] = self.agent_name
            await self.context_manager.publish_event('agent_findings', finding_data)
            log.info(f"{self.agent_name} logged a new finding.")
        except Exception as e:
            log.error(f"Error logging finding: {e}")
