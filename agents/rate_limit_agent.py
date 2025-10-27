from core.data_models import Strategy, RateLimitReport, RateLimitFinding, AttackPhase, ErrorType
from core.data_models import AgentData, Strategy
from core.logger import log
import asyncio
import time

from core.base_agent import BaseAgent


class RateLimitAgent(BaseAgent):
    supported_phases = [AttackPhase.TriageAndResearch]
    required_tools = ["curl"]

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.report_class = RateLimitReport

    async def _check_url(self, url: str) -> RateLimitFinding:
        # Test 1: Burst Test
        log.info(
            f"Testing rate limiting on: {url} with a burst of 20 requests...")
        command = f"curl -s -o /dev/null -w '%{{http_code}}' {url}"
        tasks = [self.orchestrator.run_shell_command(
            command, f"Rate limit burst test request {i+1}/20 to {url}", use_proxy=True) for i in range(20)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                log.error(
                    f"A request failed during burst test for {url}: {result}")
                return RateLimitFinding(endpoint=url, message=f"An error occurred during burst testing: {result}", vulnerable=False)

            if result and result.get('exit_code') == 0 and result.get('stdout', '').strip() == '429':
                log.success(
                    f"Rate limiting (burst) detected on {url} (429 Too Many Requests).")
                return RateLimitFinding(endpoint=url, message="Rate limiting is properly implemented (burst detected).", vulnerable=False)

        log.warning(f"No rate limiting detected on {url} during burst test.")

        # Test 2: Sustained Test
        log.info(
            f"Testing rate limiting on: {url} with a sustained test (1 req/sec for 30s)...")
        sustained_tasks = []
        for i in range(30):
            sustained_tasks.append(self.orchestrator.run_shell_command(
                command, f"Rate limit sustained test request {i+1}/30 to {url}", use_proxy=True))
            await asyncio.sleep(1)  # 1 request per second

        sustained_results = await asyncio.gather(*sustained_tasks, return_exceptions=True)

        for result in sustained_results:
            if isinstance(result, Exception):
                log.error(
                    f"A request failed during sustained test for {url}: {result}")
                # Don't return immediately, as other requests might still reveal the limit
                continue

            if result and result.get('exit_code') == 0 and result.get('stdout', '').strip() == '429':
                log.success(
                    f"Rate limiting (sustained) detected on {url} (429 Too Many Requests).")
                return RateLimitFinding(endpoint=url, message="Rate limiting is properly implemented (sustained test detected).", vulnerable=False)

        log.warning(
            f"No rate limiting detected on {url} after both burst and sustained tests.")
        return RateLimitFinding(
            endpoint=url,
            message="No 429 response received after burst and sustained tests. Endpoint may be vulnerable.",
            vulnerable=True
        )

    async def run(self, strategy: Strategy, **kwargs) -> RateLimitReport:
        start_time = time.time()
        log.phase("RateLimit Agent: Starting API Rate Limit scan...")

        recon_data = await self.context_manager.get_context('recon_data')
        if not recon_data or not recon_data.http_servers:
            summary = "No HTTP servers found in reconnaissance data to test for rate limiting."
            log.warning(summary)
            end_time = time.time()
            return RateLimitReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                summary=summary,
                errors=["Reconnaissance data missing or no HTTP servers found."],
                error_type=ErrorType.CONFIGURATION
            )

        targets = recon_data.http_servers[:5]

        tasks = [self._check_url(url) for url in targets]
        findings = await asyncio.gather(*tasks)

        vulnerable_count = sum(1 for f in findings if f.vulnerable)
        summary = f"Tested {len(targets)} endpoints. Found {vulnerable_count} potentially vulnerable to missing rate limits."
        log.success(summary)
        end_time = time.time()

        return RateLimitReport(
            agent_name=self.__class__.__name__,
            start_time=start_time,
            end_time=end_time,
            findings=findings,
            summary=summary
        )

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute rate limit agent"""
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
