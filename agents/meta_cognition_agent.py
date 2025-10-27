import json
from core.logger import log
from typing import List
from core.data_models import AgentData, AttackPhase, Strategy, ErrorType

from core.base_agent import BaseAgent


class MetaCognitionAgent(BaseAgent):
    # This is a meta-agent, can run in many phases
    supported_phases = [AttackPhase.RECONNAISSANCE]
    required_tools = []
    """
    An agent that analyzes the system's own performance, failures, and successes
    to provide high-level strategic guidance to the SubPlanner.
    It acts as an "inner monologue" to prevent the AI from repeating obvious mistakes
    or getting stuck in non-productive loops.
    """

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.report_class = AgentData # Default report class

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute meta cognition agent"""
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

    def _build_prompt(self, master_context: str) -> str:
        """Builds the prompt for the LLM to analyze the system's state."""
        return f"""
Analyze the provided context, including the overall objective, system state, and recent action history.
Your goal is to provide specific, actionable guidance to the SubPlanner to help it recover from failures or optimize its strategy.

Based on your analysis, you MUST return a JSON object containing a list of guidance strings.

**Guidance List Structure:**
`{{"guidance": ["<guidance_string_1>", "<guidance_string_2>"]}}`

If you identify a flawed prompt in an agent that needs modification, you can suggest a change.
To suggest a prompt modification, you MUST return a JSON object with a `prompt_modification` key.

**Prompt Modification Object Structure:**
`{{"target_agent": "<agent_name>", "instruction": "<reason_for_change>", "new_prompt_segment": "<text_to_add_to_prompt>"}}`

Example Response:
```json
{{
  "guidance": ["The recent SQL injection attempts failed. Pivot to command injection vectors.", "Increase scan intensity for the next reconnaissance phase."]
}}
```

If you have no modifications, return an empty list.

**Current System & Target Context:**
{master_context}
"""

    async def run(self, strategy: Strategy = None, **kwargs) -> AgentData:
        """
        Analyzes the master context and returns a list of strategic guidance strings.
        """
        master_context = kwargs.get("master_context", "")
        log.info(
            "MetaCognitionAgent: Analyzing system performance for strategic guidance...")
        prompt = self._build_prompt(master_context)

        try:
            llm_response = await self.orchestrator.call_llm_func(prompt, context="MetaCognitionAgent")

            if "error" in llm_response:
                log.error(
                    f"MetaCognitionAgent: LLM call failed: {llm_response.get('error')}")
                return self.create_report(
                    errors=[llm_response.get('error')],
                    error_type=ErrorType.LOGIC,
                    summary="MetaCognitionAgent: LLM call failed."
                )

            guidance = llm_response.get("guidance", [])
            if guidance:
                log.success(
                    f"MetaCognitionAgent: Generated {len(guidance)} new guidance directives.")
                for g in guidance:
                    log.info(f"  - Guidance: {g}")
            else:
                log.info("MetaCognitionAgent: No new guidance generated.")

            # --- Apply Prompt Modifications ---
            modifications = llm_response.get("prompt_modifications", [])
            if modifications:
                log.warning(
                    f"MetaCognitionAgent: Found {len(modifications)} prompt modifications to apply.")
                for mod in modifications:
                    target_agent = mod.get("target_agent")
                    instruction = mod.get("instruction")
                    new_segment = mod.get("new_prompt_segment")
                    if all([target_agent, instruction, new_segment]):
                        self.orchestrator.prompt_manager.apply_modification(
                            target_agent, new_segment, instruction)
                    else:
                        log.error(
                            f"Invalid prompt modification object received: {mod}")

            return self.create_report(guidance=guidance, modifications_applied=modifications, summary="MetaCognitionAgent: Guidance generated and modifications applied.")

        except Exception as e:
            log.error(
                f"MetaCognitionAgent: Failed to generate guidance: {e}", exc_info=True)
            return self.create_report(
                errors=[str(e)],
                error_type=ErrorType.LOGIC,
                summary=f"MetaCognitionAgent: Failed to generate guidance due to an unexpected error: {e}"
            )
