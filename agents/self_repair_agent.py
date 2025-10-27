from core.logger import log
from core.data_models import AgentData, Strategy
from core.data_models import Strategy, SelfRepairReport, ErrorType
import time
from typing import Optional, Dict, Any

from core.base_agent import BaseAgent


class SelfRepairAgent(BaseAgent):
    required_tools = []
    """
    An agent that attempts to repair failed commands by searching for solutions online.
    """

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.report_class = SelfRepairReport

    async def run(self, strategy: Strategy = None, **kwargs) -> SelfRepairReport:
        start_time = time.time()
        failed_command = strategy.context.get("failed_command")
        error_message = strategy.context.get("error_message", "")

        if not failed_command:
            end_time = time.time()
            return self.create_report(
                errors=["'failed_command' not found in context."],
                error_type=ErrorType.CONFIGURATION,
                summary="Self-repair failed: No failed command provided."
            )

        log.info(f"Running self-repair for failed command: {failed_command}")

        # 1. Formulate the search query
        search_query = self._formulate_search_query(
            failed_command, error_message)
        log.info(f"Searching online for solution: {search_query}")

        # 2. Perform the web search via the orchestrator
        search_results_data: Optional[Dict[str, Any]] = None
        try:
            search_results_data = await self.orchestrator.call_tool('google_web_search', query=search_query)
            if not search_results_data or not search_results_data.get("results"):
                log.warning("Web search returned no results.")
                # Ensure it's an empty list for the analyzer
                search_results_data = {"results": []}
        except Exception as e:
            log.error(f"Web search failed: {e}")
            end_time = time.time()
            return self.create_report(
                errors=[f"Web search failed: {e}"],
                error_type=ErrorType.NETWORK,
                summary=f"Self-repair failed: Web search encountered an error: {e}",
                original_command=failed_command
            )

        # 3. Analyze results and propose a fix using the LLM
        suggested_command = await self._analyze_and_propose_fix(failed_command, error_message, search_results_data["results"])

        # 4. Apply the fix
        if suggested_command:
            log.success(
                f"Found potential solution. Suggested command: {suggested_command}")
            fix_result = await self._apply_fix(suggested_command)
            end_time = time.time()
            return self.create_report(
                summary="Potential solution found and applied.",
                original_command=failed_command,
                suggested_command=suggested_command,
                fix_result=fix_result
            )
        else:
            summary = "Could not find a solution online or formulate a fix."
            log.warning(summary)
            end_time = time.time()
            return self.create_report(
                errors=["Failed to find a repair solution."],
                error_type=ErrorType.LOGIC,
                summary=summary,
                original_command=failed_command
            )

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute self repair agent"""
        try:
            target = strategy.context.get('target_url', '')
            
            # Call existing method
            if asyncio.iscoroutinefunction(self.run):
                results = await self.run(target)
            else:
                results = self.run(target)
            
            return AgentData(
                agent_name=self.__class__.__name__,
                success=True,
                summary=f"{self.__class__.__name__} completed successfully",
                errors=[],
                execution_time=0,
                memory_usage=0,
                cpu_usage=0,
                context={'results': results}
            )
        except Exception as e:
            return AgentData(
                agent_name=self.__class__.__name__,
                success=False,
                summary=f"{self.__class__.__name__} failed",
                errors=[str(e)],
                execution_time=0,
                memory_usage=0,
                cpu_usage=0,
                context={}
            )

    def _formulate_search_query(self, failed_command: str, error_message: str) -> str:
        """Formulates a search query based on the failed command and error message."""
        # This can be improved with more sophisticated logic.
        return f"how to fix error in command: {failed_command} error: {error_message}"

    async def _analyze_and_propose_fix(self, failed_command: str, error_message: str, search_results: list) -> str:
        """Analyzes search results and proposes a fix using an LLM call."""
        prompt = self._build_fix_proposal_prompt(
            failed_command, error_message, search_results)

        llm_response = await self.orchestrator.call_llm_func(prompt, context="SelfRepairFixProposal")

        if llm_response and not llm_response.get("error"):
            try:
                # Expecting the LLM to return a JSON object with a "fixed_command" key.
                fixed_command = llm_response.get('fixed_command')
                if isinstance(fixed_command, str):
                    return fixed_command
                else:
                    log.error(
                        f"LLM returned a fix in an invalid format: {fixed_command}")
                    return None
            except Exception as e:
                log.error(f"Failed to parse fix from LLM response: {e}")
                return None
        return None

    def _build_fix_proposal_prompt(self, failed_command: str, error_message: str, search_results: list) -> str:
        """Builds the prompt to instruct the LLM on how to propose a fix."""
        search_results_str = "\n".join(
            [f"- {result['title']}: {result['snippet']}" for result in search_results])

        prompt = f"""
        You are an expert system administrator and software developer. Your task is to analyze a failed shell command, the resulting error message, and a list of web search results to propose a corrected version of the command.

        **Failed Command:**
        `{failed_command}`

        **Error Message:**
        `{error_message}`

        **Web Search Results:**
        {search_results_str}

        **Instructions:**
        1.  Analyze the failed command and the error message.
        2.  Review the web search results for potential solutions.
        3.  Propose a single, corrected command that is likely to succeed.
        4.  Your output MUST be a JSON object with a single key "fixed_command" which contains the corrected command as a string.

        **Example Output:**
        {
            "fixed_command": "nmap -sV -p 1-1000 127.0.0.1"}

        Now, provide the corrected command for the given failure.
        **Output:**
        """
        return prompt

    async def _apply_fix(self, suggested_command: str) -> dict:
        """Applies the suggested fix by executing the command."""
        log.info(f"Applying suggested fix: {suggested_command}")
        try:
            result = await self.orchestrator.run_shell_command(suggested_command)
            # The result from run_shell_command is already a dict with 'success', 'stdout', 'stderr', etc.
            return result
        except Exception as e:
            log.error(f"Failed to apply fix: {e}")
            return {"success": False, "error": str(e)}
