from enum import Enum, auto
from core.data_models import Strategy, AttackPhase, AgentData, ScanIntensity, Vulnerability, NetworkGraph, SubPlannerReport, ErrorType
from core.logger import log
import json
import random
import re
from typing import List
from config import settings
import asyncio
import time

from core.base_agent import BaseAgent


class SubPlanner(BaseAgent):
    supported_phases = [AttackPhase.RECONNAISSANCE, AttackPhase.INITIAL_FOOTHOLD, AttackPhase.ESCALATION,
                        AttackPhase.PERSISTENCE, AttackPhase.DEFENSE_EVASION, AttackPhase.DISRUPTION, AttackPhase.REPORTING]
    required_tools = []

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.network_graph = NetworkGraph()
        self.report_class = SubPlannerReport
        self.agent_map = {
            AttackPhase.RECONNAISSANCE: [
                "ReconnaissanceMaster", "TriageAgent", "WafDetectorAgent",
                "SearchCollector", "TelemetryHunter", "ProxyAgent", "WpscanAgent",
                "TechnologyProfilerAgent"
            ],
            AttackPhase.INITIAL_FOOTHOLD: [
                "VulnerabilityResearcher", "VulnerabilityMappingAgent", "NucleiAgent", "SkipfishAgent",
                "FuzzingAgent", "ExploitAgent", "MetasploitAgent",
                "CommandInjectionExploiter", "SQLInjectionExploiter", "XSS_Agent",
                "SSRFAgent", "BOLA_Agent", "RateLimitAgent", "Auth_Agent",
                "ZeroDayHunterAgent", "SqlmapAgent", "IntelligentCredentialAttackAgent",
                "APIFuzzerAgent", "DeserializationExploiterAgent",
                "AFLAgent", # Added AFLAgent
                "CrashAnalyzerAgent", # Added CrashAnalyzerAgent
                "SymbolicExecutorAgent" # Added SymbolicExecutorAgent
            ],
            AttackPhase.ESCALATION: [
                "PostExAgent", "PrivilegeEscalationAgent", "PrivilegeEscalationExploiter",
                "DataDumperAgent", "LateralMovementAgent", "ShellAgent",
                "WafBypassExpert", "WafBypassPayloadGenerator", "ShellUpgraderAgent", "LivingOffTheLandAgent",
                "DataHarvesterAgent", "DataExfiltrationAgent",
                "CrashAnalyzerAgent", # Crash analysis can also be part of escalation
                "SymbolicExecutorAgent" # Symbolic execution can also be part of escalation
            ],
            AttackPhase.PERSISTENCE: [
                "PersistenceAgent", "BotDeploymentAgent"
            ],
            AttackPhase.DEFENSE_EVASION: [
                "WafBypassExpert", "WafBypassPayloadGenerator", "ProxyAgent", "LivingOffTheLandAgent", "DefensiveCountermeasuresAgent"
            ],
            AttackPhase.DISRUPTION: [
                "DDoSAgent"
            ],
            AttackPhase.REPORTING: [
                "ReportingAgent"
            ]
        }

    async def _build_master_prompt(self, objective: str, guidance: List[str] = None) -> str:
        """Builds the complete context and prompt for the master planner LLM."""

        # Fetch dynamic context from ContextManager
        target_model_dict = await self.context_manager.get_context('target_model')
        target_state_json = json.dumps(target_model_dict if target_model_dict else {}, indent=2, default=str)

        # Fetch action history from heuristics manager (now in context)
        action_history = []
        heuristics_manager = await self.context_manager.get_context('heuristics_manager')
        if heuristics_manager:
            # Assuming heuristics_manager in context is the actual object, not just a dict
            # This part might need further refinement if heuristics_manager is stored as JSON
            # For now, assuming it's the object and its methods are callable
            all_heuristics = heuristics_manager.get_all_heuristics()
            for h_type, heuristics in all_heuristics.items():
                for key, value in heuristics.items():
                    strategy = value.get('strategy', {})
                    action_history.append({
                        "status": "SUCCESS",
                        "agent": strategy.get('next_agent'),
                        "directive": strategy.get('directive')
                    })
            failed_heuristics = heuristics_manager.get_all_failed_heuristics()
            for h_type, heuristics in failed_heuristics.items():
                for key, value in heuristics.items():
                    strategy = value.get('strategy', {})
                    action_history.append({
                        "status": "FAILURE",
                        "agent": strategy.get('next_agent'),
                        "directive": strategy.get('directive'),
                        "error": value.get('report', {}).get('errors', ['Unknown Error'])[0]
                    })
        action_history_json = json.dumps(action_history[-15:], indent=2)

        strategic_guidance_json = json.dumps(
            guidance if guidance else [], indent=2)

        # Fetch all known targets from TargetModelManager via ContextManager
        target_model_manager = self.orchestrator.target_model_manager # Assuming orchestrator has target_model_manager
        all_targets = [target.to_dict() for target in target_model_manager.get_all_targets()] # Assuming get_all_targets method
        all_targets_json = json.dumps(all_targets, indent=2, default=str)

        prompt_template = """**CRITICAL RULE: YOUR RESPONSE MUST BE A JSON OBJECT CONTAINING ONLY A "strategies" LIST. YOU MUST FOLLOW THE PROVIDED FORMAT EXACTLY. DO NOT USE "steps", "@class", OR "depends_on". ANY OTHER FORMAT WILL BE REJECTED.**

You are an expert autonomous penetration testing agent. Your role is to select the next single, most logical step in an attack plan. Analyze the provided context, which includes reconnaissance data, past actions (successes and failures), and strategic guidance. Your goal is to achieve root/administrator access on the target system.

**OUTPUT FORMAT:**
You MUST respond with a valid JSON object containing a list of one or more "strategies". Follow this structure precisely.

{{
  "strategies": [
    {{
      "phase": "<ATTACK_PHASE>",
      "reasoning": "<Your detailed reasoning for choosing this agent and phase>",
      "goal": "<A clear, concise goal for this specific action>",
      "next_agent": "<AGENT_NAME>",
      "directive": "<A clear and actionable instruction for the agent>",
      "context": {{
        "<key>": "<value>"
      }}
    }}
  ]
}}

---

**1. ATTACK PHASES:**
You can only choose one of the following phases for the "phase" field:
- **RECONNAISSANCE:** Gathering information (e.g., scanning, enumeration).
- **INITIAL_FOOTHOLD:** Exploiting a vulnerability to gain initial access.
- **ESCALATION:** Elevating privileges on a compromised system.
- **PERSISTENCE:** Establishing long-term access.
- **DEFENSE_EVASION:** Bypassing security measures.
- **LATERAL_MOVEMENT:** Moving to other systems on the network.

---

**2. AVAILABLE AGENTS AND REQUIRED CONTEXT:**
You MUST use ONLY the agents from this list. You MUST provide ALL required context for the chosen agent. Failure to do so will result in mission failure.

*   **`ReconnaissanceMaster`**:
    *   **Description**: Performs broad reconnaissance scans (whatweb, nmap, feroxbuster).
    *   **Phase**: `RECONNAISSANCE`
    *   **Required Context**: {{}}

*   **`APIFuzzerAgent`**:
    *   **Description**: Discovers and fuzzes API endpoints (OpenAPI, GraphQL). Useful when an API is identified.
    *   **Phase**: `INITIAL_FOOTHOLD`
    *   **Required Context**: {{}}

*   **`DeserializationExploiterAgent`**:
    *   **Description**: Finds and exploits insecure deserialization vulnerabilities (Java, .NET, Python). Use if the target technology is known.
    *   **Phase**: `INITIAL_FOOTHOLD`
    *   **Required Context**: {{}}

*   **`VulnerabilityResearcher`**:
    *   **Description**: Searches public sources (like GitHub) for known exploits based on specific queries.
    *   **Phase**: `INITIAL_FOOTHOLD`
    *   **Required Context**: {{"search_queries": ["<technology> exploit", "<CVE-ID> PoC"]}}
    *   **IMPORTANT**: `search_queries` MUST be specific. Do NOT use generic terms like "common vulnerabilities".

*   **`SqlmapAgent`**:
    *   **Description**: Exploits SQL injection vulnerabilities.
    *   **Phase**: `INITIAL_FOOTHOLD`
    *   **Required Context**: {{"target_url": "<URL of the page with potential SQLi>"}}
    *   **Example**: {{"target_url": "https://[target_ip]/login.php?id=1"}}

*   **`MetasploitAgent`**:
    *   **Description**: Uses a specific Metasploit module to exploit a vulnerability. The most reliable way to get a shell.
    *   **Phase**: `INITIAL_FOOTHOLD`
    *   **Required Context**: {{"metasploit_module": "<full_path/to/module>", "target_host": "[target_ip]", "target_port": "<port>"}}
    *   **Usage**: ONLY use this if a previous agent has confirmed a valid Metasploit module exists for a vulnerability.

*   **`PostExAgent`**:
    *   **Description**: Enumerates a system *after* a shell has been obtained.
    *   **Phase**: `ESCALATION`
    *   **Required Context**: {{"shell_id": "<ID of an ACTIVE shell>"}}
    *   **CRITICAL**: DO NOT use this agent if `TARGET_STATE.has_shell` is `False`.

*   **`PrivilegeEscalationAgent`**:
    *   **Description**: Attempts to elevate privileges *after* a shell has been obtained.
    *   **Phase**: `ESCALATION`
    *   **Required Context**: {{"shell_id": "<ID of an ACTIVE shell>"}}
    *   **CRITICAL**: DO NOT use this agent if `TARGET_STATE.has_shell` is `False`.

**CRITICAL RULE:** Do NOT use agents that require specific findings (like `SqlmapAgent`, `ExploitAgent`, `MetasploitAgent`) unless a relevant vulnerability or URL is explicitly listed in the `TARGET_STATE.confirmed_vulnerabilities`. If there are no actionable findings, your ONLY option is to run more `RECONNAISSANCE` agents to find them.

---

**3. CURRENT MISSION DATA:**

**CAMPAIGN GOAL:** {campaign_goal}

**TARGET_STATE:**
```json
{target_state_json}
```

**ACTION HISTORY (Do not repeat failures):**
```json
{action_history_json}
```

**STRATEGIC GUIDANCE (Follow these rules):**
```json
{strategic_guidance_json}
```

**ALL KNOWN TARGETS:**
```json
{all_targets_json}
```

---

**YOUR TASK:**
Based on all the information above, provide the next logical strategy in the specified JSON format. Prioritize actions that are supported by the current findings and state. If you see a confirmed vulnerability, exploit it. If you need more information, perform reconnaissance.
"""

        return prompt_template.format(
            campaign_goal=objective,
            target_state_json=target_state_json,
            action_history_json=action_history_json,
            strategic_guidance_json=strategic_guidance_json,
            all_targets_json=all_targets_json
        )
    def _build_recovery_prompt(self, master_context: str, failure_context: dict, available_agents: list) -> str:
        prompt = f"""
        You are an AI Attack Planner. A previous action has FAILED. Your current goal is to **ANALYZE THE FAILURE AND RECOVER**.

        **MISSION:** Analyze the error message from the failed action and devise a new plan. Do NOT recommend the same agent that just failed.

        --- MASTER CONTEXT ---
        {master_context}

        **--- FAILURE ANALYSIS ---**
        - **Failed Agent:** {failure_context.get('failed_agent')}
        - **Error Message:** {failure_context.get('error_message')}

        --- AVAILABLE AGENTS ---
        {json.dumps(available_agents, indent=2)}

        **CRITICAL: Your response MUST be ONLY a raw JSON object with the following structure:**
        {{
            "strategies": [
                {{
                    "phase": "<The determined attack phase, e.g., INITIAL_FOOTHOLD>",
                    "reasoning": "<Analyze the error and explain your new approach. e.g., 'The exploit failed, suggesting the vulnerability is not exploitable this way. I will try a different approach by researching other vulnerabilities.'>",
                    "goal": "<Define a new short-term goal, e.g., 'Find an alternative exploit vector'>",
                    "next_agent": "<A NEW agent to run. DO NOT use the failed agent again.>",
                    "directive": "<A clear, actionable directive for the new agent>",
                    "finding_to_exploit": "<The specific finding ID, e.g., CVE-2023-1234 or NUCLEI-HIGH-01>"
                }}
            ]
        }}
        """
        return prompt

    def _extract_context(self, llm_data: dict, reports: dict) -> dict:
        """Extracts context and dynamic parameters from the LLM response."""
        context = llm_data.get("context", {})

        if "target_url" not in context:
            directive = llm_data.get("directive", "")
            url_match = re.search(r"https?://[\w\d\.:-]+(?:/\S*)?", directive)
            if url_match:
                context["target_url"] = url_match.group(0)
            else:
                context["target_url"] = self.orchestrator.state.target_url

        if context.get("hostname") in ["localhost:8000", "<target_hostname>"]:
            context["hostname"] = self.orchestrator.state.target_host
            log.info(
                f"Replaced placeholder hostname with actual target: {context['hostname']}")

        if llm_data.get("next_agent") in ["PostExAgent", "PrivilegeEscalationAgent", "DataDumperAgent", "PersistenceAgent", "LateralMovementAgent", "ShellAgent", "DataHarvesterAgent", "DataExfiltrationAgent", "PrivilegeEscalationExploiter"]: # Added PrivilegeEscalationExploiter
            # Check for shell_id in top-level llm_data or within its context
            shell_id = llm_data.get("shell_id") or context.get("shell_id")
            if shell_id:
                context["shell_id"] = shell_id # Ensure it's in the context dict
                log.info(
                    f"Extracted shell_id {shell_id} for {llm_data.get('next_agent')}.")
            else:
                log.warning(
                    f"LLM chose {llm_data.get('next_agent')} but did not specify a shell_id.")

        return context

    async def run_objective(self, objective: str):
        log.phase(f"SubPlanner: Starting to execute objective: '{objective}'")
        for _ in range(settings.MAX_CYCLES_PER_OBJECTIVE):
            strategies_report = await self.run(objective=objective)
            if not strategies_report.success or not strategies_report.generated_strategies:
                log.phase(
                    f"SubPlanner: Objective '{objective}' completed or failed to produce a strategy.")
                break

            tasks = [self.orchestrator._execute_agent(
                strategy) for strategy in strategies_report.generated_strategies]
            await asyncio.gather(*tasks)

    async def run(self, strategy: Strategy = None, **kwargs) -> SubPlannerReport:
        start_time = time.time()
        objective = kwargs.get(
            "objective", "Achieve root/administrator access on the target system.")
        failure_context = kwargs.get("failure_context")
        reports = kwargs.get("reports", {})

        log.info(
            "SubPlanner: Analyzing all available data to build attack strategy...")

        target_model = self.orchestrator.target_model_manager.get_target(
            self.orchestrator.state.target_host)
        if target_model and target_model.confirmed_vulnerabilities:
            priority_vuln = None
            for v in target_model.confirmed_vulnerabilities:
                if v.severity in ["HIGH", "CRITICAL"]:
                    priority_vuln = v
                    break

            if priority_vuln:
                log.success(
                    f"Fast-tracking exploit for high-severity vulnerability: {priority_vuln.vulnerability_id}")
                strategy = Strategy(
                    phase=AttackPhase.INITIAL_FOOTHOLD,
                    next_agent="ExploitAgent",
                    directive=f"Exploit high-severity vulnerability {priority_vuln.vulnerability_id} on {target_model.hostname}",
                    context={"vulnerability_id": priority_vuln.vulnerability_id,
                             "hostname": target_model.hostname}
                )
                end_time = time.time()
                return self.create_report(
                    summary=f"Fast-tracking exploit for high-severity vulnerability: {priority_vuln.vulnerability_id}",
                    generated_strategies=[strategy]
                )

        guidance = []
        meta_cognition_class = self.orchestrator.agent_registry.get_agent_class(
            "MetaCognitionAgent")
        if meta_cognition_class:
            meta_cognition_agent = meta_cognition_class(
                context_manager=self.context_manager, orchestrator=self.orchestrator)
            guidance_report = await meta_cognition_agent.run(master_context="")
            if guidance_report.success:
                guidance = guidance_report.context.get('guidance', [])

        all_agents = [agent for phase_agents in self.agent_map.values()
                      for agent in phase_agents]
        available_agents = sorted(list(set(all_agents)))

        if failure_context:
            log.warning(
                "A previous action failed. Building a recovery strategy.")
            prompt = self._build_recovery_prompt(
                "", failure_context, available_agents)
        else:
            prompt = await self._build_master_prompt(objective=objective, guidance=guidance)

        try:
            log.info(f"SubPlanner: Calling LLM for strategy...")
            llm_response = await self.orchestrator.call_llm_func(prompt, context=f"SubPlanner")

            if "error" in llm_response:
                error_msg = f"LLM call failed: {llm_response.get('error')}"
                log.error(error_msg)
                end_time = time.time()
                return self.create_report(
                    errors=[error_msg],
                    error_type=ErrorType.LOGIC,
                    summary="LLM failed to generate strategies."
                )

            strategies_data = llm_response.get("strategies", [])
            strategies = []

            for llm_data in strategies_data:
                strategy = Strategy(**llm_data)
                strategies.append(strategy)

            if not strategies:
                summary = "LLM did not return any valid strategies. Defaulting to Stop."
                log.warning(summary)
                end_time = time.time()
                return self.create_report(
                    errors=["No valid strategies returned by LLM."],
                    error_type=ErrorType.LOGIC,
                    summary=summary
                )

            end_time = time.time()
            return self.create_report(
                summary=f"Generated {len(strategies)} strategies.",
                generated_strategies=strategies
            )

        except Exception as e:
            error_msg = f"SubPlanner: Failed to generate a valid strategy: {e}"
            log.error(error_msg, exc_info=True)
            end_time = time.time()
            return self.create_report(
                errors=[error_msg],
                error_type=ErrorType.LOGIC,
                summary=f"Failed to create a valid strategy: {e}"
            )
