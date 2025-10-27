import asyncio
import httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from core.base_agent import BaseAgent
from core.data_models import AgentData, Strategy, WebCrawlerReport, ErrorType
from core.logger import log
import time
from typing import List, Dict, Any

class WebCrawlerAgent(BaseAgent):
    """
    Crawls a target website to discover URLs and forms.
    """
    required_tools = [] # No external tools needed, uses httpx and BeautifulSoup

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pubsub_manager = self.orchestrator.pubsub_manager
        self.crawled_urls = set()
        self.forms = []
        self.client = httpx.AsyncClient(timeout=10.0, follow_redirects=True)
        self.report_class = WebCrawlerReport

    async def run(self, strategy: Strategy) -> WebCrawlerReport:
        start_time = time.time()
        base_url = strategy.context.get("base_url")
        if not base_url:
            end_time = time.time()
            return self.create_report(
                errors=["Base URL not specified for WebCrawlerAgent."],
                error_type=ErrorType.CONFIGURATION,
                summary="Web crawl failed: Base URL not specified."
            )

        log.info(f"WebCrawlerAgent: Starting crawl on {base_url}...")
        
        try:
            await self._crawl(base_url, base_url)

            summary = f"WebCrawlerAgent: Crawl on {base_url} completed. Found {len(self.crawled_urls)} URLs and {len(self.forms)} forms."
            log.success(summary)
            
            # Publish crawl results
            await self.pubsub_manager.publish(
                "web_crawl_results",
                {
                    "agent": self.__class__.__name__,
                    "base_url": base_url,
                    "crawled_urls": list(self.crawled_urls),
                    "forms": self.forms,
                    "timestamp": time.time()
                }
            )

            end_time = time.time()
            return self.create_report(
                summary=summary,
                base_url=base_url,
                crawled_urls=list(self.crawled_urls),
                forms=self.forms
            )

        except Exception as e:
            log.error(f"WebCrawlerAgent: An unexpected error occurred: {e}", exc_info=True)
            end_time = time.time()
            return self.create_report(
                errors=[f"An unexpected error occurred: {e}"],
                error_type=ErrorType.LOGIC,
                summary=f"Web crawl failed due to an unexpected error: {e}",
                base_url=base_url
            )

    async def _crawl(self, current_url: str, base_url: str, depth: int = 0, max_depth: int = 2):
        if depth > max_depth or current_url in self.crawled_urls:
            return

        self.crawled_urls.add(current_url)
        log.debug(f"WebCrawlerAgent: Crawling: {current_url} (Depth: {depth})")

        try:
            response = await self.client.get(current_url)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.text, 'html.parser')

            # Extract forms
            for form in soup.find_all('form'):
                form_details = {"action": form.get('action'), "method": form.get('method', 'get').lower(), "inputs": []}
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    form_details["inputs"].append({
                        "name": input_tag.get('name'),
                        "type": input_tag.get('type', 'text'),
                        "value": input_tag.get('value')
                    })
                self.forms.append(form_details)

            # Extract links and continue crawling
            for link in soup.find_all('a', href=True):
                href = link.get('href')
                full_url = urljoin(base_url, href)
                
                # Only follow links within the same domain
                if urlparse(full_url).netloc == urlparse(base_url).netloc:
                    await self._crawl(full_url, base_url, depth + 1, max_depth)

        except httpx.RequestError as e:
            log.warning(f"WebCrawlerAgent: Request failed for {current_url}: {e}")
        except Exception as e:
            log.error(f"WebCrawlerAgent: Error processing {current_url}: {e}")

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute web crawler agent"""
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
