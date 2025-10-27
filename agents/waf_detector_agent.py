import json
from core.data_models import AgentData, Strategy
from core.data_models import WafReport, AttackPhase, Strategy
from core.logger import log


from core.base_agent import BaseAgent


class WafDetectorAgent(BaseAgent):
    # Assuming AttackPhase enum is not available
    supported_phases = [AttackPhase.RECONNAISSANCE]
    required_tools = ["wafw00f", "curl"]

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)

    async def run(self, strategy: Strategy, **kwargs) -> WafReport:
        target_url = strategy.context.get(
            "target_url")
        if not target_url:
            target_url = await self.context_manager.get_context('target_url')
        log.info(f"WAF Detector: Running wafw00f against {target_url}...")
        command = f"wafw00f -f json -o - {target_url}"

        result = await self.orchestrator.run_shell_command(
            command, "Run wafw00f to detect WAF.")
        log.debug(f"wafw00f result: {result}")

        if not result or not result.get('stdout'):
            error_message = "wafw00f command returned no output. It might not be installed, or the target may be down."
            log.warning(error_message)
            return WafReport(errors=[error_message])

        try:
            waf_data = json.loads(result.get('stdout'))
            if not (waf_data and isinstance(waf_data, list)):
                log.warning("wafw00f output was not a valid list as expected.")
                return WafReport(raw_output=result.get('stdout'))

            waf_info = waf_data[0]
            detected = waf_info.get("detected", False)
            waf_name = waf_info.get("firewall", "Generic")

            if detected:
                log.success(f"WAF detected: {waf_name}")
                return WafReport(detected_waf=waf_name,
                                 raw_output=result.get('stdout'))
            else:
                log.info("No WAF detected by wafw00f. Performing manual checks...")
                headers_response = await self.orchestrator.run_shell_command(
                    f"curl -s -I {target_url}", "Get headers for manual WAF detection.")
                headers = headers_response.get("stdout", "").lower()
                if "cloudflare" in headers:
                    log.success("WAF detected: Cloudflare (manual check)")
                    return WafReport(detected_waf="Cloudflare",
                                     raw_output=headers)
                elif "sucuri" in headers:
                    log.success("WAF detected: Sucuri (manual check)")
                    return WafReport(detected_waf="Sucuri", raw_output=headers)
                elif "incapsula" in headers:
                    log.success("WAF detected: Incapsula (manual check)")
                    return WafReport(detected_waf="Incapsula",
                                     raw_output=headers)
                elif "imperva" in headers:
                    log.success("WAF detected: Imperva (manual check)")
                    return WafReport(detected_waf="Imperva",
                                     raw_output=headers)
                else:
                    log.info("No WAF detected by manual checks.")
                    return WafReport(raw_output=result.get('stdout'))

        except json.JSONDecodeError as e:
            error_message = f"Could not parse wafw00f JSON output. Error: {e}. Raw output was:\n{result.get('stdout')}"
            log.error(error_message)
            return WafReport(errors=[error_message],
                             raw_output=result.get('stdout'))
        except Exception as e:
            error_message = f"An unexpected error occurred in WafDetectorAgent: {e}"
            log.error(error_message, exc_info=True)
            return WafReport(errors=[str(e)])

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute waf detector agent"""
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
