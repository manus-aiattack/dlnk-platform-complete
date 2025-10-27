from core.base_agent import BaseAgent
from core.data_models import ReconData, AttackPhase, Strategy, ScanIntensity, ErrorType
from core.logger import log
from core.redis_client import get_redis_client # Changed from redis_client
import json
from config import settings
import os
import asyncio
import re
import redis.asyncio as aioredis # Import aioredis
import time
from core.context_manager import ContextManager # Import ContextManager

from agents.port_scan_agent import PortScanAgent
from agents.vulnerability_scan_agent import VulnerabilityScanAgent
from agents.web_crawler_agent import WebCrawlerAgent


class ReconnaissanceMasterAgent(BaseAgent):
    """Master reconnaissance agent that orchestrates initial target discovery"""

    supported_phases = [AttackPhase.RECONNAISSANCE]
    required_tools = ["nmap", "subfinder", "theharvester",
                      "dirsearch", "whatweb", "feroxbuster"]

    def __init__(self, context_manager: ContextManager = None, orchestrator=None, **kwargs): # Changed shared_data to context_manager
        super().__init__(context_manager, orchestrator, **kwargs) # Pass context_manager to super
        self.scan_intensity = kwargs.get('scan_intensity', 'normal')
        self.redis = None # Initialize redis client to None
        self.report_class = ReconData

    async def setup(self): # Add async setup method
        try:
            self.redis = await get_redis_client()
        except aioredis.ConnectionError as e:
            log.critical(f"ReconnaissanceMaster failed to connect to Redis: {e}")
            raise

    def _sanitize_url_for_filename(self, url: str) -> str:
        sanitized = re.sub(r'^https?://', '', url)
        sanitized = re.sub(r'[/:?=&]', '_', sanitized)
        return sanitized

    async def _run_command(self, command: str, description: str, recon_data: ReconData) -> dict:
        log.info(f"Executing: {description}")
        try:
            result = await self.orchestrator.run_shell_command(command, description)
            if result and result.get('exit_code') == 0:
                log.success(f"{description} completed.")
                return result
            else:
                error_msg = f"{description} failed. Stderr: {result.get('stderr', 'N/A')}"
                log.error(error_msg)
                recon_data.errors.append(error_msg)
                return result
        except Exception as e:
            error_msg = f"An exception occurred during '{description}': {e}"
            log.error(error_msg, exc_info=True)
            recon_data.errors.append(error_msg)
            return {"error": str(e), "exit_code": -1}

    async def run(self, strategy: Strategy = None, **kwargs) -> ReconData:
        """Execute comprehensive reconnaissance scan using specialized agents."""
        start_time = time.time()
        log.phase("Reconnaissance Master: Starting reconnaissance...")
        target_host = await self.context_manager.get_context('target_host') or strategy.context.get('target_host')
        target_url = await self.context_manager.get_context('target_url') or strategy.context.get('target_url')
        
        if not target_host or not target_url:
            end_time = time.time()
            return ReconData(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                errors=["Target host or URL not found in context."],
                error_type=ErrorType.CONFIGURATION,
                summary="Reconnaissance failed: Missing target host or URL."
            )

        recon_data = ReconData(target_url=target_url, target_host=target_host)

        # Collect results from specialized agents via Pub/Sub
        port_scan_results = []
        vulnerability_scan_results = []
        web_crawl_results = []

        async def handle_port_scan_results(message):
            port_scan_results.append(message)
        
        async def handle_vulnerability_scan_results(message):
            vulnerability_scan_results.append(message)

        async def handle_web_crawl_results(message):
            web_crawl_results.append(message)

        # Subscribe to channels
        await self.orchestrator.pubsub_manager.subscribe("port_scan_results", handle_port_scan_results)
        await self.orchestrator.pubsub_manager.subscribe("vulnerability_scan_results", handle_vulnerability_scan_results)
        await self.orchestrator.pubsub_manager.subscribe("web_crawl_results", handle_web_crawl_results)

        try:
            # Create and execute strategies for specialized agents
            tasks = []

            # PortScanAgent
            tasks.append(self.orchestrator._execute_agent(Strategy(
                phase=AttackPhase.RECONNAISSANCE,
                next_agent="PortScanAgent",
                directive=f"Perform port scan on {target_host}",
                context={"target_host": target_host}
            )))

            # VulnerabilityScanAgent (targeting the URL)
            tasks.append(self.orchestrator._execute_agent(Strategy(
                phase=AttackPhase.RECONNAISSANCE,
                next_agent="VulnerabilityScanAgent",
                directive=f"Perform vulnerability scan on {target_url}",
                context={"target": target_url}
            )))

            # WebCrawlerAgent
            tasks.append(self.orchestrator._execute_agent(Strategy(
                phase=AttackPhase.RECONNAISSANCE,
                next_agent="WebCrawlerAgent",
                directive=f"Crawl {target_url}",
                context={"base_url": target_url}
            )))

            # Run all specialized agents concurrently
            await asyncio.gather(*tasks)

            # Give some time for Pub/Sub messages to be processed
            await asyncio.sleep(2) 

            # Aggregate results
            for ps_result in port_scan_results:
                if ps_result.get("results"):
                    for host_info in ps_result["results"]:
                        if host_info["host"] == target_host:
                            recon_data.network_services.extend(host_info["open_ports"])
            
            for vs_result in vulnerability_scan_results:
                if vs_result.get("results"):
                    # Assuming vulnerability_scan_results contain raw Nuclei output
                    recon_data.nikto_results.extend(vs_result["results"]) # Using nikto_results as a generic vuln scan field
            
            for wc_result in web_crawl_results:
                if wc_result.get("crawled_urls"):
                    recon_data.crawled_urls.extend(wc_result["crawled_urls"])
                if wc_result.get("forms"):
                    recon_data.forms.extend(wc_result["forms"])

            summary = f"Reconnaissance completed for {target_host}. Found {len(recon_data.network_services)} services and {len(recon_data.crawled_urls)} crawled URLs."
            log.success(summary)
            end_time = time.time()
            recon_data.agent_name = self.__class__.__name__
            recon_data.start_time = start_time
            recon_data.end_time = end_time
            recon_data.summary = summary
            return recon_data

        except Exception as e:
            log.error(f"ReconnaissanceMaster failed: {e}", exc_info=True)
            end_time = time.time()
            recon_data.agent_name = self.__class__.__name__
            recon_data.start_time = start_time
            recon_data.end_time = end_time
            recon_data.errors.append(str(e))
            recon_data.error_type = ErrorType.LOGIC
            recon_data.summary = f"Reconnaissance failed due to an unexpected error: {e}"
            return recon_data
        finally:
            # Unsubscribe from channels
            await self.orchestrator.pubsub_manager.unsubscribe("port_scan_results", handle_port_scan_results)
            await self.orchestrator.pubsub_manager.unsubscribe("vulnerability_scan_results", handle_vulnerability_scan_results)
            await self.orchestrator.pubsub_manager.unsubscribe("web_crawl_results", handle_web_crawl_results)
