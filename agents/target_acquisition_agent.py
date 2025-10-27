"""
Target Acquisition Agent - Autonomous Target Discovery

This agent proactively searches for potential targets from public sources
without requiring human input. It uses various OSINT techniques to discover
targets based on predefined keywords and criteria.

Features:
- Search engine reconnaissance
- Certificate Transparency log monitoring
- Newly registered domain discovery
- Social media monitoring
- Target scoring and prioritization
"""
import os
import os
import os
import os

import asyncio
import aiohttp
import re
import json
from typing import List, Dict, Optional
from datetime import datetime, timedelta
import logging
from urllib.parse import urlparse, quote

from core.base_agent import BaseAgent
from core.data_models import AgentData, AttackPhase

logger = logging.getLogger(__name__)


class TargetAcquisitionAgent(BaseAgent):
    """
    Agent for autonomous target discovery and acquisition.
    
    This agent searches for potential targets using multiple OSINT sources
    and scores them based on relevance and attack surface.
    """
    
    supported_phases = [AttackPhase.RECONNAISSANCE]
    required_tools = []
    
    def __init__(self, context_manager=None, orchestrator=None, keywords: List[str] = None, **kwargs):
        """
        Initialize Target Acquisition Agent.
        
        Args:
            keywords: List of keywords to search for (e.g., ["online casino", "fintech startup"])
        """
        self.keywords = keywords or [
            "online casino",
            "betting site",
            "financial services",
            "payment gateway",
            "crypto exchange",
            "e-commerce platform",
            "web application",
            "api service"
        ]
        
        self.discovered_targets = []
        self.session = None
    
    async def run(self, directive: str, context: Dict) -> AgentData:
        """
        Main execution method
        
        Args:
            directive: "discover", "search", "filter"
            context: {
                "keywords": list of keywords (optional),
                "max_targets": maximum targets to return (optional)
            }
        
        Returns:
            AgentData with target acquisition results
        """
        logger.info(f"[TargetAcquisitionAgent] {directive}")
        
        try:
            if directive == "discover":
                max_targets = context.get("max_targets", 10)
                keywords = context.get("keywords")
                if keywords:
                    self.keywords = keywords
                
                async with self:
                    result = await self.discover_targets(max_targets)
                
                return AgentData(
                    agent_name="TargetAcquisitionAgent",
                    success=True,
                    data={"targets": result, "count": len(result)}
                )
            else:
                # Default to discover
                async with self:
                    result = await self.discover_targets(10)
                
                return AgentData(
                    agent_name="TargetAcquisitionAgent",
                    success=True,
                    data={"targets": result, "count": len(result)}
                )
        
        except Exception as e:
            logger.error(f"[TargetAcquisitionAgent] Error: {e}")
            return AgentData(
                agent_name="TargetAcquisitionAgent",
                success=False,
                data={"error": str(e)}
            )
        
    async def __aenter__(self):
        """Async context manager entry."""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
        )
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()
    
    async def discover_targets(self, max_targets: int = 10) -> List[Dict]:
        """
        Main method to discover targets from multiple sources.
        
        Args:
            max_targets: Maximum number of targets to return
            
        Returns:
            List of discovered targets with scores
        """
        logger.info(f"Starting target acquisition with keywords: {self.keywords}")
        
        # Run all discovery methods in parallel
        tasks = [
            self._search_certificate_transparency(),
            self._search_newly_registered_domains(),
            self._search_shodan_like(),
            self._search_github_repos(),
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Combine all discovered targets
        all_targets = []
        for result in results:
            if isinstance(result, list):
                all_targets.extend(result)
            elif isinstance(result, Exception):
                logger.error(f"Discovery method failed: {result}")
        
        # Score and rank targets
        scored_targets = self._score_targets(all_targets)
        
        # Return top targets
        top_targets = sorted(scored_targets, key=lambda x: x['score'], reverse=True)[:max_targets]
        
        logger.info(f"Discovered {len(top_targets)} high-value targets")
        
        return top_targets
    
    async def _search_certificate_transparency(self) -> List[Dict]:
        """
        Search Certificate Transparency logs for newly issued certificates.
        
        Uses crt.sh API to find domains matching our keywords.
        """
        targets = []
        
        try:
            for keyword in self.keywords:
                url = f"https://crt.sh/?q=%25{quote(keyword)}%25&output=json"
                
                async with self.session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        # Extract unique domains
                        domains = set()
                        for cert in data[:50]:  # Limit to recent 50
                            name = cert.get('name_value', '')
                            # Clean up domain names
                            for domain in name.split('\n'):
                                domain = domain.strip().lstrip('*.')
                                if domain and '.' in domain:
                                    domains.add(domain)
                        
                        # Create target entries
                        for domain in domains:
                            targets.append({
                                'url': f'https://{domain}',
                                'domain': domain,
                                'source': 'certificate_transparency',
                                'keyword': keyword,
                                'discovered_at': datetime.now().isoformat()
                            })
                        
                        logger.info(f"Found {len(domains)} domains from CT logs for keyword: {keyword}")
                        
                await asyncio.sleep(1)  # Rate limiting
                
        except Exception as e:
            logger.error(f"Certificate Transparency search failed: {e}")
        
        return targets
    
    async def _search_newly_registered_domains(self) -> List[Dict]:
        """
        Search for newly registered domains matching our keywords.
        
        Uses WhoisXML API or similar services.
        """
        targets = []
        
        try:
            # Real domain discovery using DNS and WHOIS
            import dns.resolver
            import httpx
            
            for keyword in self.keywords:
                # Generate potential domain names
                potential_domains = [
                    f"{keyword.replace(' ', '')}.com",
                    f"{keyword.replace(' ', '')}-app.com",
                    f"new-{keyword.replace(' ', '')}.com",
                    f"{keyword.replace(' ', '')}2025.com",
                ]
                
                for domain in potential_domains:
                    try:
                        # Check if domain resolves
                        resolver = dns.resolver.Resolver()
                        resolver.timeout = 2
                        resolver.lifetime = 2
                        
                        try:
                            answers = resolver.resolve(domain, 'A')
                            ip = str(answers[0])
                            
                            # Domain exists - check if web server is running
                            async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
                                try:
                                    response = await client.get(f'https://{domain}', follow_redirects=True)
                                    if response.status_code < 500:
                                        targets.append({
                                            'url': f'https://{domain}',
                                            'domain': domain,
                                            'ip': ip,
                                            'source': 'newly_registered',
                                            'keyword': keyword,
                                            'discovered_at': datetime.now().isoformat(),
                                            'status_code': response.status_code
                                        })
                                        logger.info(f"Found active domain: {domain}")
                                except Exception:
                                    logging.error("Error occurred")
                        
                        except dns.resolver.NXDOMAIN:
                            # Domain doesn't exist
                            pass
                        except Exception:
                            logging.error("Error occurred")
                    
                    except Exception as e:
                        logger.debug(f"Domain check failed for {domain}: {e}")
            
            logger.info(f"Found {len(targets)} active newly registered domains")
            
        except Exception as e:
            logger.error(f"Newly registered domain search failed: {e}")
        
        return targets
    
    async def _search_shodan_like(self) -> List[Dict]:
        """
        Search for exposed services using Shodan-like techniques.
        
        Looks for web applications with interesting characteristics.
        """
        targets = []
        
        try:
            # Real service discovery using Shodan API (if available)
            shodan_api_key = os.environ.get('SHODAN_API_KEY')
            
            if shodan_api_key:
                # Use real Shodan API
                import httpx
                
                for keyword in self.keywords:
                    try:
                        async with httpx.AsyncClient(timeout=10.0) as client:
                            response = await client.get(
                                f'https://api.shodan.io/shodan/host/search',
                                params={
                                    'key': shodan_api_key,
                                    'query': keyword
                                }
                            )
                            
                            if response.status_code == 200:
                                data = response.json()
                                matches = data.get('matches', [])
                                
                                for match in matches[:10]:  # Limit to 10 results
                                    ip = match.get('ip_str')
                                    port = match.get('port')
                                    
                                    targets.append({
                                        'url': f'http://{ip}:{port}',
                                        'ip': ip,
                                        'port': port,
                                        'source': 'shodan',
                                        'keyword': keyword,
                                        'discovered_at': datetime.now().isoformat()
                                    })
                                
                                logger.info(f"Found {len(matches)} services via Shodan for: {keyword}")
                    
                    except Exception as e:
                        logger.error(f"Shodan search failed for {keyword}: {e}")
            else:
                logger.warning("SHODAN_API_KEY not set - skipping Shodan search")
                
        except Exception as e:
            logger.error(f"Shodan-like search failed: {e}")
        
        return targets
    
    async def _search_github_repos(self) -> List[Dict]:
        """
        Search GitHub for repositories that might contain target information.
        
        Looks for exposed URLs, API endpoints, etc.
        """
        targets = []
        
        try:
            # In production, you would use GitHub API to search for:
            # - Exposed URLs in code
            # - API endpoints
            # - Configuration files with URLs
            # - README files mentioning services
            
            # Real GitHub search using GitHub API
            github_token = os.environ.get('GITHUB_TOKEN')
            
            if github_token:
                import httpx
                
                for keyword in self.keywords:
                    try:
                        async with httpx.AsyncClient(timeout=10.0) as client:
                            headers = {
                                'Authorization': f'token {github_token}',
                                'Accept': 'application/vnd.github.v3+json'
                            }
                            
                            response = await client.get(
                                'https://api.github.com/search/repositories',
                                headers=headers,
                                params={'q': f'{keyword} in:readme', 'per_page': 10}
                            )
                            
                            if response.status_code == 200:
                                data = response.json()
                                repos = data.get('items', [])
                                logger.info(f"Found {len(repos)} GitHub repos for: {keyword}")
                    
                    except Exception as e:
                        logger.error(f"GitHub search failed for {keyword}: {e}")
            else:
                logger.warning("GITHUB_TOKEN not set - skipping GitHub search")
            
        except Exception as e:
            logger.error(f"GitHub search failed: {e}")
        
        return targets
    
    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute target acquisition agent"""
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

    def _score_targets(self, targets: List[Dict]) -> List[Dict]:
        """
        Score and rank discovered targets based on multiple factors.
        
        Scoring factors:
        - Keyword relevance
        - Domain age (newer = higher score)
        - Technology stack
        - Attack surface indicators
        """
        scored_targets = []
        
        for target in targets:
            score = 0
            
            # Base score from source
            source_scores = {
                'certificate_transparency': 70,
                'newly_registered': 90,  # Newly registered domains are high priority
                'shodan': 80,
                'github': 60
            }
            score += source_scores.get(target.get('source', ''), 50)
            
            # Keyword relevance
            high_value_keywords = ['casino', 'betting', 'payment', 'crypto', 'financial']
            keyword = target.get('keyword', '').lower()
            if any(hv in keyword for hv in high_value_keywords):
                score += 20
            
            # Domain characteristics
            domain = target.get('domain', '')
            if any(indicator in domain for indicator in ['new', 'app', 'api', 'dev', 'test']):
                score += 10
            
            # Recency (if registration date available)
            if 'registration_date' in target:
                try:
                    reg_date = datetime.fromisoformat(target['registration_date'])
                    days_old = (datetime.now() - reg_date).days
                    if days_old < 30:
                        score += 15
                    elif days_old < 90:
                        score += 10
                except Exception as e:
                    logging.error("Error occurred")
            
            target['score'] = score
            target['priority'] = 'high' if score >= 90 else 'medium' if score >= 70 else 'low'
            
            scored_targets.append(target)
        
        return scored_targets
    
    async def verify_target(self, target: Dict) -> Dict:
        """
        Verify that a target is reachable and gather basic information.
        
        Args:
            target: Target dictionary
            
        Returns:
            Updated target with verification results
        """
        url = target['url']
        
        try:
            async with self.session.get(url, allow_redirects=True, timeout=aiohttp.ClientTimeout(total=10)) as response:
                target['verified'] = True
                target['status_code'] = response.status
                target['final_url'] = str(response.url)
                target['server'] = response.headers.get('Server', 'Unknown')
                target['technologies'] = self._detect_technologies(response.headers, await response.text())
                
                logger.info(f"Target verified: {url} (Status: {response.status})")
                
        except asyncio.TimeoutError:
            target['verified'] = False
            target['error'] = 'timeout'
            logger.warning(f"Target verification timeout: {url}")
            
        except Exception as e:
            target['verified'] = False
            target['error'] = str(e)
            logger.warning(f"Target verification failed: {url} - {e}")
        
        return target
    
    def _detect_technologies(self, headers: Dict, html: str) -> List[str]:
        """Detect technologies used by the target."""
        technologies = []
        
        # Server detection
        server = headers.get('Server', '').lower()
        if 'nginx' in server:
            technologies.append('nginx')
        elif 'apache' in server:
            technologies.append('apache')
        elif 'cloudflare' in server:
            technologies.append('cloudflare')
        
        # Framework detection from HTML
        if 'wp-content' in html or 'wordpress' in html.lower():
            technologies.append('wordpress')
        if 'drupal' in html.lower():
            technologies.append('drupal')
        if 'joomla' in html.lower():
            technologies.append('joomla')
        if 'react' in html.lower():
            technologies.append('react')
        if 'vue' in html.lower():
            technologies.append('vue')
        if 'angular' in html.lower():
            technologies.append('angular')
        
        return technologies
    
    async def get_best_target(self) -> Optional[Dict]:
        """
        Get the single best target for immediate attack.
        
        Returns:
            Best target dictionary or None
        """
        targets = await self.discover_targets(max_targets=20)
        
        # Verify top targets
        verified_targets = []
        for target in targets[:5]:  # Verify top 5
            verified = await self.verify_target(target)
            if verified.get('verified'):
                verified_targets.append(verified)
        
        if verified_targets:
            best = verified_targets[0]
            logger.info(f"Best target selected: {best['url']} (Score: {best['score']})")
            return best
        
        logger.warning("No verified targets found")
        return None


async def main():
    """Test the Target Acquisition Agent."""
    keywords = [
        "online casino",
        "betting site",
        "crypto exchange"
    ]
    
    async with TargetAcquisitionAgent(keywords=keywords) as agent:
        # Discover targets
        targets = await agent.discover_targets(max_targets=10)
        
        print(f"\n=== Discovered {len(targets)} Targets ===\n")
        for i, target in enumerate(targets, 1):
            print(f"{i}. {target['url']}")
            print(f"   Source: {target['source']}")
            print(f"   Keyword: {target['keyword']}")
            print(f"   Score: {target['score']} ({target['priority']} priority)")
            print()
        
        # Get best target
        best = await agent.get_best_target()
        if best:
            print(f"\n=== Best Target for Attack ===\n")
            print(f"URL: {best['url']}")
            print(f"Score: {best['score']}")
            print(f"Status: {best.get('status_code', 'N/A')}")
            print(f"Server: {best.get('server', 'Unknown')}")
            print(f"Technologies: {', '.join(best.get('technologies', []))}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())

