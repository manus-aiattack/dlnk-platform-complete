"""
Advanced Threat Intelligence Aggregator
Integrates multiple threat intelligence feeds for comprehensive vulnerability intelligence
"""

import asyncio
import aiohttp
import json
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum

from core.logger import get_logger
from core.redis_client import get_redis_client

log = get_logger(__name__)


class ThreatSeverity(Enum):
    """Threat severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ThreatType(Enum):
    """Types of threats"""
    CVE = "cve"
    EXPLOIT = "exploit"
    MALWARE = "malware"
    IOC = "ioc"
    TECHNIQUE = "technique"
    VULNERABILITY = "vulnerability"
    ZERO_DAY = "zero_day"


@dataclass
class ThreatIntelligence:
    """Threat intelligence data"""
    threat_id: str
    threat_type: ThreatType
    severity: ThreatSeverity
    title: str
    description: str
    affected_products: List[str] = field(default_factory=list)
    affected_versions: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None
    exploit_available: bool = False
    exploit_public: bool = False
    exploit_code: Optional[str] = None
    exploit_url: Optional[str] = None
    mitre_attack_ids: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    published_date: Optional[datetime] = None
    last_modified: Optional[datetime] = None
    source: str = ""
    raw_data: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self):
        return {
            "threat_id": self.threat_id,
            "threat_type": self.threat_type.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "affected_products": self.affected_products,
            "affected_versions": self.affected_versions,
            "cvss_score": self.cvss_score,
            "cve_id": self.cve_id,
            "exploit_available": self.exploit_available,
            "exploit_public": self.exploit_public,
            "exploit_code": self.exploit_code,
            "exploit_url": self.exploit_url,
            "mitre_attack_ids": self.mitre_attack_ids,
            "references": self.references,
            "published_date": self.published_date.isoformat() if self.published_date else None,
            "last_modified": self.last_modified.isoformat() if self.last_modified else None,
            "source": self.source,
            "raw_data": self.raw_data
        }


class ThreatIntelAggregator:
    """
    Advanced Threat Intelligence Aggregator
    
    Integrates with:
    - NVD (National Vulnerability Database)
    - Exploit-DB
    - VulnDB
    - MITRE ATT&CK
    - GitHub Security Advisories
    - CVE Details
    - Packet Storm
    - 0day.today
    - Custom feeds
    """
    
    def __init__(self, api_keys: Optional[Dict[str, str]] = None):
        self.api_keys = api_keys or {}
        self.redis = None
        self.session = None
        self.cache_ttl = 3600  # 1 hour
        
    async def initialize(self):
        """Initialize threat intelligence aggregator"""
        self.redis = await get_redis_client()
        self.session = aiohttp.ClientSession()
        log.info("Threat Intelligence Aggregator initialized")
    
    async def cleanup(self):
        """Cleanup resources"""
        if self.session:
            await self.session.close()
    
    async def search_vulnerabilities(
        self,
        product: str,
        version: Optional[str] = None,
        severity_min: Optional[ThreatSeverity] = None
    ) -> List[ThreatIntelligence]:
        """
        Search for vulnerabilities affecting a product
        
        Args:
            product: Product name
            version: Product version (optional)
            severity_min: Minimum severity level
            
        Returns:
            List of ThreatIntelligence objects
        """
        log.info(f"Searching vulnerabilities for {product} {version or ''}")
        
        # Check cache first
        cache_key = f"vuln_search:{product}:{version or 'any'}"
        cached = await self._get_from_cache(cache_key)
        if cached:
            return [ThreatIntelligence(**item) for item in cached]
        
        # Aggregate from multiple sources
        results = []
        
        # NVD
        nvd_results = await self._search_nvd(product, version)
        results.extend(nvd_results)
        
        # Exploit-DB
        exploitdb_results = await self._search_exploitdb(product, version)
        results.extend(exploitdb_results)
        
        # VulnDB (if API key available)
        if "vulndb" in self.api_keys:
            vulndb_results = await self._search_vulndb(product, version)
            results.extend(vulndb_results)
        
        # GitHub Security Advisories
        github_results = await self._search_github_advisories(product)
        results.extend(github_results)
        
        # Filter by severity if specified
        if severity_min:
            severity_order = {
                ThreatSeverity.INFO: 0,
                ThreatSeverity.LOW: 1,
                ThreatSeverity.MEDIUM: 2,
                ThreatSeverity.HIGH: 3,
                ThreatSeverity.CRITICAL: 4
            }
            min_level = severity_order[severity_min]
            results = [
                r for r in results
                if severity_order[r.severity] >= min_level
            ]
        
        # Sort by severity and CVSS score
        results.sort(
            key=lambda x: (
                -self._severity_to_int(x.severity),
                -(x.cvss_score or 0)
            )
        )
        
        # Cache results
        await self._save_to_cache(
            cache_key,
            [r.to_dict() for r in results]
        )
        
        log.info(f"Found {len(results)} vulnerabilities for {product}")
        
        return results
    
    async def get_exploit_for_cve(self, cve_id: str) -> Optional[ThreatIntelligence]:
        """
        Get exploit information for a CVE
        
        Args:
            cve_id: CVE identifier (e.g., CVE-2024-1234)
            
        Returns:
            ThreatIntelligence with exploit info or None
        """
        log.info(f"Searching exploit for {cve_id}")
        
        # Check cache
        cache_key = f"exploit:{cve_id}"
        cached = await self._get_from_cache(cache_key)
        if cached:
            return ThreatIntelligence(**cached)
        
        # Search Exploit-DB
        exploit = await self._get_exploitdb_by_cve(cve_id)
        
        if not exploit:
            # Search GitHub for PoC
            exploit = await self._search_github_poc(cve_id)
        
        if not exploit:
            # Search Packet Storm
            exploit = await self._search_packet_storm(cve_id)
        
        if exploit:
            await self._save_to_cache(cache_key, exploit.to_dict())
        
        return exploit
    
    async def get_zero_day_intelligence(self) -> List[ThreatIntelligence]:
        """
        Get intelligence on potential zero-day vulnerabilities
        
        Returns:
            List of potential zero-day threats
        """
        log.info("Fetching zero-day intelligence")
        
        # Check cache
        cache_key = "zero_day_intel"
        cached = await self._get_from_cache(cache_key)
        if cached:
            return [ThreatIntelligence(**item) for item in cached]
        
        results = []
        
        # 0day.today (if available)
        if "0day_today" in self.api_keys:
            zero_days = await self._fetch_0day_today()
            results.extend(zero_days)
        
        # Twitter/X monitoring for security researchers
        # (Would implement social media monitoring in production)
        
        # Security mailing lists
        # (Would implement mailing list monitoring in production)
        
        # Cache for shorter time (15 minutes) as this is time-sensitive
        await self._save_to_cache(cache_key, [r.to_dict() for r in results], ttl=900)
        
        return results
    
    async def get_mitre_attack_techniques(
        self,
        tactic: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get MITRE ATT&CK techniques
        
        Args:
            tactic: Filter by tactic (e.g., "initial-access")
            
        Returns:
            List of techniques
        """
        log.info(f"Fetching MITRE ATT&CK techniques for tactic: {tactic or 'all'}")
        
        # This would fetch from MITRE ATT&CK API or database
        # Simplified implementation
        
        techniques = []
        
        # Example techniques (would be fetched from actual API)
        if not tactic or tactic == "initial-access":
            techniques.append({
                "id": "T1190",
                "name": "Exploit Public-Facing Application",
                "description": "Adversaries may attempt to exploit a weakness in an Internet-facing host or system.",
                "tactic": "initial-access"
            })
        
        if not tactic or tactic == "execution":
            techniques.append({
                "id": "T1059",
                "name": "Command and Scripting Interpreter",
                "description": "Adversaries may abuse command and script interpreters to execute commands.",
                "tactic": "execution"
            })
        
        return techniques
    
    async def enrich_vulnerability(
        self,
        vuln_type: str,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Enrich vulnerability information with threat intelligence
        
        Args:
            vuln_type: Type of vulnerability
            context: Context information (technology, version, etc.)
            
        Returns:
            Enriched vulnerability data
        """
        enriched = {
            "vuln_type": vuln_type,
            "context": context,
            "threat_intel": [],
            "exploits": [],
            "mitre_techniques": [],
            "recommendations": []
        }
        
        # Get related CVEs
        if "technology" in context:
            vulns = await self.search_vulnerabilities(
                product=context["technology"],
                version=context.get("version")
            )
            enriched["threat_intel"] = [v.to_dict() for v in vulns[:5]]  # Top 5
            
            # Get exploits for CVEs
            for vuln in vulns[:3]:  # Top 3
                if vuln.cve_id:
                    exploit = await self.get_exploit_for_cve(vuln.cve_id)
                    if exploit and exploit.exploit_available:
                        enriched["exploits"].append(exploit.to_dict())
        
        # Map to MITRE ATT&CK
        mitre_mapping = {
            "sql_injection": ["T1190"],
            "xss": ["T1190", "T1059"],
            "rce": ["T1190", "T1059"],
            "ssrf": ["T1190"],
            "file_upload": ["T1190", "T1105"]
        }
        
        if vuln_type in mitre_mapping:
            for technique_id in mitre_mapping[vuln_type]:
                # Would fetch full technique details
                enriched["mitre_techniques"].append({
                    "id": technique_id,
                    "relevance": "high"
                })
        
        # Generate recommendations
        enriched["recommendations"] = self._generate_recommendations(
            vuln_type,
            enriched["threat_intel"]
        )
        
        return enriched
    
    # Private methods for each threat intel source
    
    async def _search_nvd(
        self,
        product: str,
        version: Optional[str]
    ) -> List[ThreatIntelligence]:
        """Search NVD database"""
        results = []
        
        try:
            # NVD API endpoint
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {
                "keywordSearch": product,
                "resultsPerPage": 20
            }
            
            async with self.session.get(url, params=params, timeout=30) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    for item in data.get("vulnerabilities", []):
                        cve = item.get("cve", {})
                        cve_id = cve.get("id", "")
                        
                        # Extract CVSS score
                        cvss_score = None
                        metrics = cve.get("metrics", {})
                        if "cvssMetricV31" in metrics:
                            cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                        elif "cvssMetricV2" in metrics:
                            cvss_score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
                        
                        # Determine severity
                        severity = self._cvss_to_severity(cvss_score)
                        
                        # Extract description
                        descriptions = cve.get("descriptions", [])
                        description = descriptions[0]["value"] if descriptions else ""
                        
                        threat = ThreatIntelligence(
                            threat_id=cve_id,
                            threat_type=ThreatType.CVE,
                            severity=severity,
                            title=cve_id,
                            description=description,
                            cvss_score=cvss_score,
                            cve_id=cve_id,
                            published_date=datetime.fromisoformat(cve.get("published", "").replace("Z", "+00:00")),
                            source="NVD",
                            raw_data=cve
                        )
                        
                        results.append(threat)
                        
        except Exception as e:
            log.error(f"Error searching NVD: {e}")
        
        return results
    
    async def _search_exploitdb(
        self,
        product: str,
        version: Optional[str]
    ) -> List[ThreatIntelligence]:
        """Search Exploit-DB"""
        results = []
        
        try:
            # Exploit-DB search (would use actual API in production)
            # This is a simplified example
            
            # For now, return empty list
            # In production, would scrape or use Exploit-DB API
            pass
            
        except Exception as e:
            log.error(f"Error searching Exploit-DB: {e}")
        
        return results
    
    async def _search_vulndb(
        self,
        product: str,
        version: Optional[str]
    ) -> List[ThreatIntelligence]:
        """Search VulnDB (commercial)"""
        results = []
        
        try:
            # VulnDB API (requires subscription)
            # Would implement with actual API key
            pass
            
        except Exception as e:
            log.error(f"Error searching VulnDB: {e}")
        
        return results
    
    async def _search_github_advisories(
        self,
        product: str
    ) -> List[ThreatIntelligence]:
        """Search GitHub Security Advisories"""
        results = []
        
        try:
            # GitHub GraphQL API for security advisories
            # Would implement with GitHub API
            pass
            
        except Exception as e:
            log.error(f"Error searching GitHub advisories: {e}")
        
        return results
    
    async def _get_exploitdb_by_cve(
        self,
        cve_id: str
    ) -> Optional[ThreatIntelligence]:
        """Get exploit from Exploit-DB by CVE"""
        try:
            # Would search Exploit-DB for CVE
            # Return exploit if found
            pass
        except Exception as e:
            log.error(f"Error getting exploit from Exploit-DB: {e}")
        
        return None
    
    async def _search_github_poc(
        self,
        cve_id: str
    ) -> Optional[ThreatIntelligence]:
        """Search GitHub for PoC exploits"""
        try:
            # Would search GitHub repositories for PoC code
            # Many security researchers publish PoCs on GitHub
            pass
        except Exception as e:
            log.error(f"Error searching GitHub for PoC: {e}")
        
        return None
    
    async def _search_packet_storm(
        self,
        cve_id: str
    ) -> Optional[ThreatIntelligence]:
        """Search Packet Storm Security"""
        try:
            # Would search Packet Storm
            pass
        except Exception as e:
            log.error(f"Error searching Packet Storm: {e}")
        
        return None
    
    async def _fetch_0day_today(self) -> List[ThreatIntelligence]:
        """Fetch from 0day.today"""
        results = []
        
        try:
            # Would fetch from 0day.today API
            # This is a commercial/restricted feed
            pass
        except Exception as e:
            log.error(f"Error fetching from 0day.today: {e}")
        
        return results
    
    # Helper methods
    
    def _cvss_to_severity(self, cvss_score: Optional[float]) -> ThreatSeverity:
        """Convert CVSS score to severity level"""
        if not cvss_score:
            return ThreatSeverity.INFO
        
        if cvss_score >= 9.0:
            return ThreatSeverity.CRITICAL
        elif cvss_score >= 7.0:
            return ThreatSeverity.HIGH
        elif cvss_score >= 4.0:
            return ThreatSeverity.MEDIUM
        elif cvss_score > 0:
            return ThreatSeverity.LOW
        else:
            return ThreatSeverity.INFO
    
    def _severity_to_int(self, severity: ThreatSeverity) -> int:
        """Convert severity to integer for sorting"""
        return {
            ThreatSeverity.CRITICAL: 4,
            ThreatSeverity.HIGH: 3,
            ThreatSeverity.MEDIUM: 2,
            ThreatSeverity.LOW: 1,
            ThreatSeverity.INFO: 0
        }[severity]
    
    def _generate_recommendations(
        self,
        vuln_type: str,
        threat_intel: List[Dict[str, Any]]
    ) -> List[str]:
        """Generate remediation recommendations"""
        recommendations = []
        
        # Generic recommendations by vulnerability type
        vuln_recommendations = {
            "sql_injection": [
                "Use parameterized queries or prepared statements",
                "Implement input validation and sanitization",
                "Apply principle of least privilege to database accounts",
                "Use WAF with SQL injection protection"
            ],
            "xss": [
                "Implement output encoding/escaping",
                "Use Content Security Policy (CSP)",
                "Validate and sanitize all user input",
                "Use modern frameworks with built-in XSS protection"
            ],
            "rce": [
                "Avoid executing user-supplied input",
                "Implement strict input validation",
                "Use sandboxing and containerization",
                "Apply security patches immediately"
            ]
        }
        
        if vuln_type in vuln_recommendations:
            recommendations.extend(vuln_recommendations[vuln_type])
        
        # Add specific recommendations based on threat intel
        if threat_intel:
            recommendations.append(
                f"Apply patches for {len(threat_intel)} known vulnerabilities"
            )
        
        return recommendations
    
    async def _get_from_cache(self, key: str) -> Optional[Any]:
        """Get data from Redis cache"""
        if not self.redis:
            return None
        
        try:
            data = await self.redis.get(f"threat_intel:{key}")
            if data:
                return json.loads(data)
        except Exception as e:
            log.warning(f"Cache get error: {e}")
        
        return None
    
    async def _save_to_cache(
        self,
        key: str,
        data: Any,
        ttl: Optional[int] = None
    ):
        """Save data to Redis cache"""
        if not self.redis:
            return
        
        try:
            await self.redis.setex(
                f"threat_intel:{key}",
                ttl or self.cache_ttl,
                json.dumps(data)
            )
        except Exception as e:
            log.warning(f"Cache save error: {e}")

