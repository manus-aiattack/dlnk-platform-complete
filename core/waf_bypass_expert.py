import logging
from typing import Dict, Any, Optional
from core.logger import log
from core.data_models import WafBypassReport, Strategy, AttackPhase, ErrorType
from agents.waf_bypass.payload_generator import WafBypassPayloadGenerator
import requests
import asyncio
import time

from core.base_agent import BaseAgent


class WafBypassExpert(BaseAgent):
    supported_phases = [AttackPhase.DEFENSE_EVASION]
    required_tools = []

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.payload_generator: Optional[WafBypassPayloadGenerator] = None
        self.waf_block_codes = {403, 406, 418,
                                429, 503}  # Common WAF block codes
        self.report_class = WafBypassReport

    async def setup(self):
        """Asynchronous setup method for WafBypassExpert."""
        self.payload_generator = await self.context_manager.get_context('payload_generator')

    async def _search_for_origin_ip(self, target_domain: str) -> str | None:
        """
        Performs web searches to find the real IP address of a domain.
        """
        log.info(
            f"[WafBypassExpert] Searching for origin IP of {target_domain} using web search...")

        # List of search queries to try
        queries = [
            f"origin IP of {target_domain}",
            f"real IP of {target_domain}",
            f"bypass cloudflare {target_domain}",
            f"dns history {target_domain}",
            f"crimeflare {target_domain}"
        ]

        for query in queries:
            try:
                search_results = await self.orchestrator.perform_web_search(
                    query)

                if not search_results:
                    continue

                for result in search_results:
                    snippet = result.get('snippet', '')
                    import re
                    ip_match = re.search(
                        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', snippet)

                    if ip_match:
                        origin_ip = ip_match.group(0)
                        log.success(
                            f"[WafBypassExpert] Potential origin IP found from query '{query}': {origin_ip}")
                        return origin_ip

            except Exception as e:
                log.error(
                    f"[WafBypassExpert] Error during web search with query '{query}': {e}",
                    exc_info=True)

        log.warning(
            f"[WafBypassExpert] Could not find origin IP for {target_domain} after trying multiple web searches.")
        return None

    async def find_origin_ip(self, target_domain: str) -> str | None:
        """
        Uses web search to find the real IP address of a domain behind a CDN like Cloudflare.
        """
        return await self._search_for_origin_ip(target_domain)

    async def run(self, strategy: Strategy, **kwargs) -> WafBypassReport:
        start_time = time.time()
        target_url = strategy.context.get(
            "target_url")
        if not target_url:
            target_url = await self.context_manager.get_context('target_url')
        original_payload = strategy.context.get("original_payload")
        from urllib.parse import urlparse
        domain = urlparse(target_url).netloc

        # --- Step 1: Find Origin IP ---
        origin_ip = await self.find_origin_ip(domain)
        if origin_ip:
            # If we find an IP, the primary goal is to use it.
            # We can update the target model for subsequent agents.
            log.info(
                f"Updating target model with newly discovered origin IP: {origin_ip}")

            # Hypothetical update
            end_time = time.time()
            return WafBypassReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                summary=f"Found potential origin IP: {origin_ip}. Subsequent scans should target this IP directly.",
                origin_ip=origin_ip
            )

        # --- Step 2: Payload Generation (if no origin IP found) ---
        if not original_payload:
            end_time = time.time()
            return WafBypassReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                summary="No origin IP found and no payload provided for testing.",
                errors=["Missing original_payload in context for payload generation."],
                error_type=ErrorType.CONFIGURATION
            )

        log.info(
            f"[WafBypassExpert] Origin IP not found. Attempting to bypass WAF for payload: {original_payload}")

        # Generate a set of bypass payloads
        bypass_payloads = await self.payload_generator.generate_payloads(
            original_payload)
        if not bypass_payloads:
            end_time = time.time()
            return WafBypassReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                errors=["Failed to generate bypass payloads."],
                error_type=ErrorType.LOGIC,
                summary="WAF bypass failed: Could not generate bypass payloads."
            )

        log.info(
            f"[WafBypassExpert] Testing {len(bypass_payloads)} generated payloads...")

        tested_payloads = []
        loop = asyncio.get_running_loop()
        for payload in bypass_payloads:
            try:
                response = await loop.run_in_executor(None, lambda: requests.get(
                    target_url, params={"q": payload}, timeout=10))
                tested_payloads.append(
                    {"payload": payload, "status_code": response.status_code}
                )

                if response.status_code not in self.waf_block_codes:
                    summary = f"WAF bypass successful with payload: {payload}"
                    log.success(f"[WafBypassExpert] {summary}")
                    end_time = time.time()
                    return WafBypassReport(
                        agent_name=self.__class__.__name__,
                        start_time=start_time,
                        end_time=end_time,
                        summary=summary,
                        original_payload=original_payload,
                        tested_bypass_payloads=tested_payloads,
                        successful_bypass_payload=payload
                    )
                else:
                    log.info(
                        f"Payload blocked: {payload} (Status: {response.status_code})")

            except requests.exceptions.RequestException as e:
                log.error(
                    f"[WafBypassExpert] Request failed for payload {payload}: {e}")
                tested_payloads.append(
                    {"payload": payload, "status_code": "Error"}
                )

        summary = "Could not find origin IP and all generated bypass payloads were blocked."
        log.warning(f"[WafBypassExpert] {summary}")
        end_time = time.time()
        return WafBypassReport(
            agent_name=self.__class__.__name__,
            start_time=start_time,
            end_time=end_time,
            summary=summary,
            original_payload=original_payload,
            tested_bypass_payloads=tested_payloads,
            errors=["All generated bypass payloads were blocked."],
            error_type=ErrorType.LOGIC
        )
