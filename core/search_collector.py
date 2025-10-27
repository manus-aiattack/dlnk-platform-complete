from typing import List
from core.data_models import SearchCollectorReport, Strategy, AttackPhase, ErrorType
from core.logger import log
import time

from core.base_agent import BaseAgent


class SearchCollector(BaseAgent):
    supported_phases = [AttackPhase.RECONNAISSANCE]
    required_tools = []

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.report_class = SearchCollectorReport

    async def run(self, strategy: Strategy, **kwargs) -> SearchCollectorReport:
        start_time = time.time()
        queries = strategy.context.get("search_queries")
        if not queries:
            end_time = time.time()
            return SearchCollectorReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                query="",
                results=[],
                errors=["Missing search_queries in strategy context."],
                error_type=ErrorType.CONFIGURATION,
                summary="Search collection failed: No queries provided."
            )

        log.info(
            f"Search Collector: Performing web searches for {len(queries)} queries across multiple engines...")
        all_results = []
        search_engines = {
            "google": self.orchestrator.google_web_search,
            # "bing": self.orchestrator.bing_web_search, # Placeholder
            # "duckduckgo": self.orchestrator.ddg_web_search, # Placeholder
        }

        for engine_name, search_func in search_engines.items():
            for query in queries:
                log.info(f"Searching on {engine_name} for: {query}")
                try:
                    search_results = await search_func(query)
                    if search_results:
                        # Add engine name to results for context
                        for res in search_results:
                            res['engine'] = engine_name
                        all_results.extend(search_results)
                except Exception as e:
                    log.error(
                        f"Error during {engine_name} search for query '{query}': {e}")

        summary = f"Found {len(all_results)} total results from all engines for {len(queries)} queries."
        log.success(summary)
        end_time = time.time()
        return SearchCollectorReport(
            agent_name=self.__class__.__name__,
            start_time=start_time,
            end_time=end_time,
            query=", ".join(queries),
            results=all_results,
            summary=summary
        )
