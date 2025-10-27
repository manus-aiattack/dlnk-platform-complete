"""
Data Collector from CVE API, NVD API, Exploit-DB
"""

import asyncio
import aiohttp
from typing import List, Dict
import logging

log = logging.getLogger(__name__)


class DataCollector:
    """Collects vulnerability data from free APIs"""
    
    def __init__(self):
        self.sources = {
            'cve_circl': 'https://cve.circl.lu/api',
            'nvd': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
            'exploit_db': 'https://www.exploit-db.com'
        }
    
    async def collect_from_cve_circl(self, limit: int = 100) -> List[Dict]:
        """Collect from CVE Circl API (free)"""
        log.info(f"[DataCollector] Collecting from CVE Circl (limit={limit})")
        
        data = []
        
        try:
            async with aiohttp.ClientSession() as session:
                # Get recent CVEs
                url = f"{self.sources['cve_circl']}/last"
                
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as response:
                    if response.status == 200:
                        cves = await response.json()
                        
                        for cve in cves[:limit]:
                            data.append({
                                'cve_id': cve.get('id'),
                                'description': cve.get('summary', ''),
                                'cvss': cve.get('cvss'),
                                'published': cve.get('Published'),
                                'source': 'cve_circl'
                            })
        
        except Exception as e:
            log.error(f"[DataCollector] CVE Circl error: {e}")
        
        log.info(f"[DataCollector] Collected {len(data)} CVEs from Circl")
        return data
    
    async def collect_from_nvd(self, limit: int = 100) -> List[Dict]:
        """Collect from NVD API (free)"""
        log.info(f"[DataCollector] Collecting from NVD (limit={limit})")
        
        data = []
        
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.sources['nvd']}?resultsPerPage={min(limit, 2000)}"
                
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as response:
                    if response.status == 200:
                        result = await response.json()
                        vulnerabilities = result.get('vulnerabilities', [])
                        
                        for vuln in vulnerabilities[:limit]:
                            cve = vuln.get('cve', {})
                            data.append({
                                'cve_id': cve.get('id'),
                                'description': cve.get('descriptions', [{}])[0].get('value', ''),
                                'cvss': cve.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseScore'),
                                'published': cve.get('published'),
                                'source': 'nvd'
                            })
        
        except Exception as e:
            log.error(f"[DataCollector] NVD error: {e}")
        
        log.info(f"[DataCollector] Collected {len(data)} CVEs from NVD")
        return data
    
    async def collect_all(self, limit_per_source: int = 50) -> List[Dict]:
        """Collect from all sources"""
        log.info("[DataCollector] Collecting from all sources")
        
        tasks = [
            self.collect_from_cve_circl(limit_per_source),
            self.collect_from_nvd(limit_per_source)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        all_data = []
        for result in results:
            if isinstance(result, list):
                all_data.extend(result)
        
        log.info(f"[DataCollector] Total collected: {len(all_data)} vulnerabilities")
        
        return all_data
