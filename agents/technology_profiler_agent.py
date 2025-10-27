"""
An agent that analyzes initial reconnaissance data to create a detailed
profile of the technologies and their specific versions on a target system.
"""

import re
from core.data_models import AgentData, Strategy
from core.logger import log
from core.data_models import Strategy, TechnologyProfilerReport, ReconData, AttackPhase, ErrorType
from core.target_model_manager import TargetModel
import time
from typing import Optional
from core.target_model_manager import TargetModelManager

from core.base_agent import BaseAgent


class TechnologyProfilerAgent(BaseAgent):
    supported_phases = [AttackPhase.RECONNAISSANCE]
    required_tools = []

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.target_model_manager: Optional[TargetModelManager] = None
        self.report_class = TechnologyProfilerReport

    async def setup(self):
        """Asynchronous setup method for TechnologyProfilerAgent."""
        self.target_model_manager = await self.context_manager.get_context('target_model_manager')

    async def run(self, strategy: Strategy, **kwargs) -> TechnologyProfilerReport:
        start_time = time.time()
        hostname = await self.context_manager.get_context('target_host')
        log.phase(
            f"TechnologyProfilerAgent: Profiling technologies for {hostname}")
        target_model = await self.target_model_manager.get_or_create_target(hostname)

        if not hasattr(target_model, 'recon_data') or not target_model.recon_data:
            end_time = time.time()
            return self.create_report(
                errors=["Reconnaissance data not found in the target model."],
                error_type=ErrorType.CONFIGURATION,
                summary="Technology profiling failed: Reconnaissance data missing.",
                hostname=hostname
            )

        profiled_tech = {}

        recon_data_dict = target_model.recon_data
        if isinstance(target_model.recon_data, ReconData):
            recon_data_dict = target_model.recon_data.to_dict()

        network_services = recon_data_dict.get('network_services', [])
        if network_services:
            log.info(
                f"Found {len(network_services)} network services to profile.")
            for service in network_services:
                product = service.get('product', '').strip()
                version = service.get('version', '').strip()
                if product and version:
                    tech_key = product.lower()
                    full_tech_string = f"{product} {version}"
                    profiled_tech[tech_key] = full_tech_string
                    log.info(f"Profiled: {full_tech_string}")

        if not profiled_tech:
            summary = "Completed profiling, but found no new versioned technologies."
            log.warning(summary)
            end_time = time.time()
            return self.create_report(
                summary=summary,
                hostname=hostname
            )

        current_technologies = set(target_model.technologies)
        for tech_key, full_tech_string in profiled_tech.items():
            technologies_to_remove = {
                t for t in current_technologies if t.lower() in tech_key}
            for t in technologies_to_remove:
                current_technologies.remove(t)
            current_technologies.add(full_tech_string)

        target_model.technologies = list(current_technologies)
        await self.target_model_manager.save_model(target_model)
        log.success(
            f"Updated target model for {hostname} with {len(profiled_tech)} profiled technologies.")

        summary = f"Successfully profiled {len(profiled_tech)} technologies: {', '.join(profiled_tech.values())}"
        end_time = time.time()
        return TechnologyProfilerReport(
            agent_name=self.__class__.__name__,
            start_time=start_time,
            end_time=end_time,
            hostname=hostname,
            profiled_technologies=profiled_tech,
            summary=summary
        )

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute technology profiler agent"""
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
