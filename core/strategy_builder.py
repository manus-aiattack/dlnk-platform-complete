import json
import time
from core.data_models import Strategy, AttackPhase, AgentData, StrategyBuilderReport, ErrorType
from core.logger import log
from core.ai_planner import AdvancedAIPlanner, PlanningContext
from core.risk_analyzer import RiskAnalyzer
from core.learning_engine import LearningEngine
from core.context_manager import ContextManager # Import ContextManager

from core.base_agent import BaseAgent
from typing import Optional
from core.base_agent import BaseAgent
from core.agent_schema import AGENT_SCHEMA

class StrategyBuilder(BaseAgent):
    supported_phases = [AttackPhase.RECONNAISSANCE]
    required_tools = []
    """
    The Meta-Planner responsible for high-level campaign strategy.
    Now enhanced with AI Planning capabilities for intelligent strategy generation.
    """

    def __init__(self, context_manager: ContextManager = None, orchestrator=None, **kwargs): # Changed shared_data to context_manager
        super().__init__(context_manager, orchestrator, **kwargs) # Pass context_manager to super
        self.master_prompt_modifications = []
        self.ai_planner = AdvancedAIPlanner(context_manager, orchestrator) # Pass context_manager
        self.risk_analyzer = RiskAnalyzer(context_manager) # Pass context_manager
        self.learning_engine = LearningEngine(context_manager) # Pass context_manager
        self.report_class = StrategyBuilderReport

    def _validate_strategy(self, strategy: dict) -> bool:
        agent_name = strategy.get("next_agent")
        if agent_name not in AGENT_SCHEMA:
            log.error(f"Invalid agent name in strategy: {agent_name}")
            return False
        
        required_context = AGENT_SCHEMA[agent_name].get("context_requirements", [])
        for req in required_context:
            if req not in strategy.get("context", {}):
                log.error(f"Missing required context '{req}' for agent '{agent_name}' in strategy: {strategy}")
                return False
        return True

    async def run(self, strategy: Strategy = None, **kwargs) -> StrategyBuilderReport:
        start_time = time.time()
        campaign_goal = kwargs.get(
            "campaign_goal", "Achieve root/administrator access on the target system.")
        log.phase(
            f"StrategyBuilder: Using primary LLM planner to create strategies for: '{campaign_goal}'")

        try:
            # Generate strategies directly from the LLM.
            strategies = await self._create_strategies_from_llm(campaign_goal)

            if not strategies:
                summary = "LLM Planner failed to create any strategies. The campaign may be stalled."
                log.error(summary)
                end_time = time.time()
                return StrategyBuilderReport(
                    agent_name=self.__class__.__name__,
                    start_time=start_time,
                    end_time=end_time,
                    errors=["LLM failed to generate strategies."],
                    error_type=ErrorType.LOGIC,
                    summary=summary,
                    generated_strategies=[]
                )

            summary = f"LLM Planner generated {len(strategies)} intelligent strategies."
            log.info(summary)
            for i, s in enumerate(strategies):
                log.info(
                    f"  {i+1}. {s.next_agent} - {s.directive} (Confidence: {s.confidence_score})")
                if s.llm_reasoning:
                    log.debug(f"    Reasoning: {s.llm_reasoning}")

            # Return the generated strategies to the orchestrator for execution
            end_time = time.time()
            return StrategyBuilderReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                summary=summary,
                generated_strategies=strategies
            )

        except Exception as e:
            error_msg = f"A critical error occurred in StrategyBuilder: {e}"
            log.critical(error_msg, exc_info=True)
            end_time = time.time()
            return StrategyBuilderReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                errors=[error_msg],
                error_type=ErrorType.LOGIC,
                summary=error_msg,
                generated_strategies=[]
            )

    def _parse_strategy_data(self, s_data: dict) -> Optional[Strategy]:
        """Recursively parses a dictionary to create a Strategy object."""
        try:
            # Ensure phase is an AttackPhase enum member
            s_data['phase'] = AttackPhase[s_data['phase']]

            # Recursively parse alternative strategies
            if 'alternative_strategies' in s_data and s_data['alternative_strategies']:
                alt_strategies = []
                for alt_s_data in s_data['alternative_strategies']:
                    parsed_alt = self._parse_strategy_data(alt_s_data)
                    if parsed_alt:
                        alt_strategies.append(parsed_alt)
                s_data['alternative_strategies'] = alt_strategies
            else:
                s_data['alternative_strategies'] = []


            return Strategy(**s_data)
        except KeyError as e:
            log.error(f"Invalid AttackPhase or missing key in LLM response: {e}. Skipping strategy: {s_data}")
            return None
        except Exception as e:
            log.error(f"Failed to create Strategy object from LLM response: {e}. Skipping strategy: {s_data}")
            return None

    async def _create_strategies_from_llm(self, campaign_goal: str) -> list[Strategy]:
        """Uses the LLM to break down a high-level goal into a list of smaller, actionable objectives."""
        target_host = await self.context_manager.get_context('target_host') # Get from context_manager
        target_model_dict = await self.context_manager.get_context('target_model') # Get target_model from context
        
        target_state_json = json.dumps(target_model_dict if target_model_dict else {}, indent=2, default=str)

        internal_network_view = "No internal network scan data available."
        # Assuming internal_scan_report is stored in context_manager if available
        internal_scan_report = await self.context_manager.get_context('internal_scan_report')
        if internal_scan_report and internal_scan_report.get('live_hosts'):
            internal_hosts = []
            for host in internal_scan_report['live_hosts']:
                internal_hosts.append({"ip": host['ip'], "ports": host['ports']})
            internal_network_view = json.dumps(internal_hosts, indent=2)

        action_history = []
        # Heuristics manager is now in orchestrator, not context_manager
        heuristics_manager = self.orchestrator.heuristics_manager
        if heuristics_manager:
            # Successes
            successful_heuristics = await heuristics_manager.get_all_heuristics()
            for he_type, heuristics in successful_heuristics.items():
                for key, value in heuristics.items():
                    strategy = value.get('strategy', {})
                    action_history.append({
                        "status": "SUCCESS",
                        "agent": strategy.get('next_agent'),
                        "directive": strategy.get('directive'),
                        "report_summary": value.get('report_summary', 'No summary provided.')
                    })
            
            # Failures
            failed_heuristics = await heuristics_manager.get_all_failed_heuristics()
            for he_type, heuristics in failed_heuristics.items():
                for key, value in heuristics.items():
                    strategy = value.get('strategy', {})
                    action_history.append({
                        "status": "FAILURE",
                        "agent": strategy.get('next_agent'),
                        "directive": strategy.get('directive'),
                        "error": value.get('error_message', 'Unknown Error'),
                        "error_type": value.get('error_type', 'UNKNOWN')
                    })

        # Limit history to last 15 actions
        action_history_json = json.dumps(action_history[-15:], indent=2)

        agent_schema_json = json.dumps(AGENT_SCHEMA, indent=2)

        prompt = self.orchestrator.prompt_manager.get_prompt(
            'strategy_builder',
            target_state_json=target_state_json,
            internal_network_view=internal_network_view,
            action_history_json=action_history_json,
            campaign_goal=campaign_goal,
            agent_schema=agent_schema_json
        )

        if not prompt:
            log.error(
                "Failed to get prompt from PromptManager for StrategyBuilder.")
            return []

        llm_response = await self.orchestrator.call_llm_func(prompt, context="MetaPlannerGoalDecomposition")

        if llm_response and not llm_response.get("error"):
            try:
                # Expecting the LLM to return a JSON list of Strategy objects (or dicts)
                strategies_data = llm_response.get('strategies', [])
                if isinstance(strategies_data, list) and all(isinstance(s, dict) for s in strategies_data):
                    strategies = []
                    for s_data in strategies_data:
                        if self._validate_strategy(s_data):
                            parsed_strategy = self._parse_strategy_data(s_data)
                            if parsed_strategy:
                                strategies.append(parsed_strategy)
                    return strategies
                else:
                    log.error(
                        f"LLM returned strategies in an invalid format: {strategies_data}")
                    return []
            except Exception as e:
                log.error(f"Failed to parse strategies from LLM response: {e}")
                return []
        return []
