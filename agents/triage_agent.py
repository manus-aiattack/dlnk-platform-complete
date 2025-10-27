import socket
from core.data_models import AgentData, Strategy
import asyncio
import time
from core.base_agent import BaseAgent
from core.data_models import ReconData, TriageReport, Strategy, AttackPhase, ErrorType
from core.logger import log
from agents.triage.vulnerability_prioritizer import VulnerabilityPrioritizer


class TriageAgent(BaseAgent):
    """Analyzes reconnaissance data to identify and prioritize potential vulnerabilities."""
    supported_phases = [AttackPhase.RECONNAISSANCE]
    required_tools = []

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.prioritizer = VulnerabilityPrioritizer(
            rules_file='scoring_rules.yaml')
        self.pubsub_manager = orchestrator.pubsub_manager # Add this line

    async def _filter_subdomains(self, subdomains: list) -> list:
        """Filters out unresolvable subdomains concurrently."""
        if not subdomains:
            return []

        log.info(
            f"Triage Agent: Filtering {len(subdomains)} subdomains concurrently...")

        async def resolve(subdomain):
            try:
                loop = asyncio.get_running_loop()
                await loop.getaddrinfo(subdomain, None)
                return subdomain
            except socket.gaierror:
                log.info(
                    f"  -> Filtering out unresolvable subdomain: {subdomain}")
                return None

        tasks = [resolve(sub) for sub in subdomains]
        results = await asyncio.gather(*tasks)

        resolvable_subdomains = [res for res in results if res is not None]

        filtered_count = len(subdomains) - len(resolvable_subdomains)
        log.info(
            f"Triage Agent: Filtered out {filtered_count} unresolvable subdomains.")
        return resolvable_subdomains

    async def run(self, strategy: Strategy = None, **kwargs) -> TriageReport:
        start_time = time.time()
        log.info("Triage Agent: Analyzing and prioritizing reconnaissance data...")

        recon_data = await self.context_manager.get_context('recon_data')
        if not recon_data:
            end_time = time.time()
            return TriageReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                errors=["Reconnaissance data not found in shared data."],
                error_type=ErrorType.CONFIGURATION,
                summary="Triage failed: Reconnaissance data missing."
            )

        try:
            # --- Filtering Stage ---
            recon_data.subdomains = await self._filter_subdomains(recon_data.subdomains)

            # --- Triage Stage ---
            interesting_findings = self.prioritizer.prioritize(recon_data)

            is_interesting = bool(interesting_findings)

            if not is_interesting:
                assessment = "Target does not seem to have any immediate points of interest after filtering."
                summary = "Triage completed: No immediate points of interest found."
            else:
                assessment = "Target has potential points of interest after filtering."
                summary = f"Triage completed: Found {len(interesting_findings)} interesting findings."

            log.info(f"Triage assessment: {assessment}")
            
            # --- Publish vulnerability_found event ---
            if is_interesting:
                await self.pubsub_manager.publish(
                    "vulnerability_found",
                    {
                        "agent": self.__class__.__name__,
                        "target_url": recon_data.target_url,
                        "findings": [f.to_dict() for f in interesting_findings]
                    }
                )
                log.info(f"Published {len(interesting_findings)} interesting findings to 'vulnerability_found' channel.")
            
            # --- Recommendation Stage ---
            recommendations = self._generate_recommendations(interesting_findings)
            
            end_time = time.time()
            triage_report = TriageReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                is_interesting=is_interesting,
                assessment=assessment,
                interesting_findings=interesting_findings,
                recommendations=recommendations,
                summary=summary
            )
            return triage_report
        except Exception as e:
            end_time = time.time()
            log.error(f"TriageAgent failed: {e}", exc_info=True)
            return TriageReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                errors=[str(e)],
                error_type=ErrorType.LOGIC,
                summary=f"Triage failed due to an unexpected error: {e}"
            )

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute triage agent"""
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

    def _generate_recommendations(self, interesting_findings: list) -> list:
        """Generates a list of recommended actions based on the triage results."""
        recommendations = []
        for finding in interesting_findings:
            if finding.finding.startswith("Open port found:"):
                try:
                    port = finding.finding.split(":")[1].split("/")[0]
                    recommendations.append(f"Run a vulnerability scan on port {port}.")
                except IndexError:
                    print("Error occurred")
            elif "server found:" in finding.finding:
                recommendations.append(f"Fingerprint the web server.")
            elif finding.finding.startswith("Found") and "resolvable subdomains" in finding.finding:
                recommendations.append(f"Perform a web content scan on the subdomains.")
        return recommendations
