"""
Threat Intelligence Service
Ingests, processes, and provides threat intelligence data
"""

import asyncio
import json
import os
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import httpx
import aiohttp

from core.logger import log
from core.context_manager import ContextManager


class VulnerabilityData(BaseModel):
    cve_id: str
    description: str
    severity: str
    cvss_score: float
    affected_products: List[str]
    exploit_available: bool
    exploit_maturity: Optional[str]
    references: List[str]


class ExploitData(BaseModel):
    exploit_id: str
    title: str
    cve_ids: List[str]
    platform: str
    exploit_type: str
    reliability: str
    source: str
    code_url: Optional[str]


class ThreatIntelService:
    """Threat Intelligence Service"""
    
    def __init__(self):
        self.context_manager = None
        self.vulnerability_cache = {}
        self.exploit_cache = {}
        self.last_update = None
        self.update_interval = 3600  # 1 hour
        
    async def initialize(self):
        """Initialize service"""
        try:
            self.context_manager = ContextManager()
            await self.context_manager.setup()
            
            # Start background update task
            asyncio.create_task(self._periodic_update())
            
            log.success("Threat Intelligence Service initialized")
            
        except Exception as e:
            log.error(f"Failed to initialize Threat Intel Service: {e}")
            raise
    
    async def _periodic_update(self):
        """Periodically update threat intelligence"""
        while True:
            try:
                await self.update_threat_intelligence()
                await asyncio.sleep(self.update_interval)
            except Exception as e:
                log.error(f"Periodic update error: {e}")
                await asyncio.sleep(300)  # Retry after 5 minutes
    
    async def update_threat_intelligence(self):
        """Update threat intelligence from multiple sources"""
        try:
            log.info("Updating threat intelligence...")
            
            # Update from multiple sources concurrently
            await asyncio.gather(
                self._update_from_nvd(),
                self._update_from_exploitdb(),
                self._update_from_cisa_kev(),
                return_exceptions=True
            )
            
            self.last_update = datetime.now()
            log.success(f"Threat intelligence updated. Total CVEs: {len(self.vulnerability_cache)}, Exploits: {len(self.exploit_cache)}")
            
        except Exception as e:
            log.error(f"Failed to update threat intelligence: {e}")
    
    async def _update_from_nvd(self):
        """Update from NVD (National Vulnerability Database)"""
        try:
            # NVD API endpoint
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            
            # Get recent CVEs (last 7 days)
            params = {
                "pubStartDate": (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S.000"),
                "pubEndDate": datetime.now().strftime("%Y-%m-%dT%H:%M:%S.000")
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        for item in data.get("vulnerabilities", []):
                            cve = item.get("cve", {})
                            cve_id = cve.get("id")
                            
                            if cve_id:
                                vuln_data = VulnerabilityData(
                                    cve_id=cve_id,
                                    description=cve.get("descriptions", [{}])[0].get("value", ""),
                                    severity=self._extract_severity(cve),
                                    cvss_score=self._extract_cvss_score(cve),
                                    affected_products=self._extract_affected_products(cve),
                                    exploit_available=False,  # Will be updated from ExploitDB
                                    exploit_maturity=None,
                                    references=[ref.get("url", "") for ref in cve.get("references", [])]
                                )
                                
                                self.vulnerability_cache[cve_id] = vuln_data
                        
                        log.info(f"Updated {len(data.get('vulnerabilities', []))} CVEs from NVD")
                    
        except Exception as e:
            log.error(f"Failed to update from NVD: {e}")
    
    async def _update_from_exploitdb(self):
        """Update from Exploit-DB"""
        try:
            # Exploit-DB CSV endpoint
            url = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        content = await response.text()
                        lines = content.split('\n')[1:]  # Skip header
                        
                        count = 0
                        for line in lines[:1000]:  # Process last 1000 exploits
                            if not line.strip():
                                continue
                            
                            parts = line.split(',')
                            if len(parts) >= 5:
                                exploit_id = parts[0]
                                title = parts[2]
                                platform = parts[4]
                                
                                exploit_data = ExploitData(
                                    exploit_id=f"EDB-{exploit_id}",
                                    title=title,
                                    cve_ids=[],  # Extract from title if present
                                    platform=platform,
                                    exploit_type="unknown",
                                    reliability="unknown",
                                    source="exploitdb",
                                    code_url=f"https://www.exploit-db.com/exploits/{exploit_id}"
                                )
                                
                                self.exploit_cache[exploit_data.exploit_id] = exploit_data
                                count += 1
                        
                        log.info(f"Updated {count} exploits from Exploit-DB")
                        
        except Exception as e:
            log.error(f"Failed to update from Exploit-DB: {e}")
    
    async def _update_from_cisa_kev(self):
        """Update from CISA Known Exploited Vulnerabilities"""
        try:
            url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        for vuln in data.get("vulnerabilities", []):
                            cve_id = vuln.get("cveID")
                            
                            if cve_id:
                                # Update existing CVE or create new one
                                if cve_id in self.vulnerability_cache:
                                    self.vulnerability_cache[cve_id].exploit_available = True
                                    self.vulnerability_cache[cve_id].exploit_maturity = "active"
                                else:
                                    vuln_data = VulnerabilityData(
                                        cve_id=cve_id,
                                        description=vuln.get("vulnerabilityName", ""),
                                        severity="HIGH",
                                        cvss_score=8.0,
                                        affected_products=[vuln.get("product", "")],
                                        exploit_available=True,
                                        exploit_maturity="active",
                                        references=[]
                                    )
                                    self.vulnerability_cache[cve_id] = vuln_data
                        
                        log.info(f"Updated {len(data.get('vulnerabilities', []))} KEVs from CISA")
                        
        except Exception as e:
            log.error(f"Failed to update from CISA KEV: {e}")
    
    def _extract_severity(self, cve: Dict) -> str:
        """Extract severity from CVE data"""
        metrics = cve.get("metrics", {})
        
        if "cvssMetricV31" in metrics:
            return metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")
        elif "cvssMetricV2" in metrics:
            severity_score = metrics["cvssMetricV2"][0].get("cvssData", {}).get("baseScore", 0)
            if severity_score >= 7.0:
                return "HIGH"
            elif severity_score >= 4.0:
                return "MEDIUM"
            else:
                return "LOW"
        
        return "UNKNOWN"
    
    def _extract_cvss_score(self, cve: Dict) -> float:
        """Extract CVSS score from CVE data"""
        metrics = cve.get("metrics", {})
        
        if "cvssMetricV31" in metrics:
            return metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseScore", 0.0)
        elif "cvssMetricV2" in metrics:
            return metrics["cvssMetricV2"][0].get("cvssData", {}).get("baseScore", 0.0)
        
        return 0.0
    
    def _extract_affected_products(self, cve: Dict) -> List[str]:
        """Extract affected products from CVE data"""
        products = []
        
        configurations = cve.get("configurations", [])
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    cpe = cpe_match.get("criteria", "")
                    if cpe:
                        products.append(cpe)
        
        return products[:10]  # Limit to 10 products
    
    async def search_vulnerabilities(
        self,
        product: Optional[str] = None,
        severity: Optional[str] = None,
        exploit_available: Optional[bool] = None
    ) -> List[VulnerabilityData]:
        """Search vulnerabilities"""
        results = []
        
        for vuln in self.vulnerability_cache.values():
            if product and not any(product.lower() in p.lower() for p in vuln.affected_products):
                continue
            
            if severity and vuln.severity != severity:
                continue
            
            if exploit_available is not None and vuln.exploit_available != exploit_available:
                continue
            
            results.append(vuln)
        
        # Sort by CVSS score (highest first)
        results.sort(key=lambda x: x.cvss_score, reverse=True)
        
        return results
    
    async def search_exploits(
        self,
        cve_id: Optional[str] = None,
        platform: Optional[str] = None
    ) -> List[ExploitData]:
        """Search exploits"""
        results = []
        
        for exploit in self.exploit_cache.values():
            if cve_id and cve_id not in exploit.cve_ids and cve_id not in exploit.title:
                continue
            
            if platform and platform.lower() not in exploit.platform.lower():
                continue
            
            results.append(exploit)
        
        return results
    
    async def get_attack_patterns(self, objective: str) -> List[Dict[str, Any]]:
        """Get attack patterns from MITRE ATT&CK"""
        # Simplified MITRE ATT&CK patterns mapping
        patterns = {
            "backdoor": [
                {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
                {"id": "T1505", "name": "Server Software Component", "tactic": "Persistence"},
                {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"}
            ],
            "command_execution": [
                {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
                {"id": "T1203", "name": "Exploitation for Client Execution", "tactic": "Execution"},
                {"id": "T1106", "name": "Native API", "tactic": "Execution"}
            ],
            "privilege_escalation": [
                {"id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
                {"id": "T1078", "name": "Valid Accounts", "tactic": "Privilege Escalation"},
                {"id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation"}
            ],
            "data_exfiltration": [
                {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
                {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
                {"id": "T1567", "name": "Exfiltration Over Web Service", "tactic": "Exfiltration"}
            ]
        }
        
        return patterns.get(objective.lower(), [])


# FastAPI Application
app = FastAPI(title="Threat Intelligence Service")
threat_intel_service: Optional[ThreatIntelService] = None


@app.on_event("startup")
async def startup_event():
    """Initialize service on startup"""
    global threat_intel_service
    
    try:
        threat_intel_service = ThreatIntelService()
        await threat_intel_service.initialize()
        
        # Initial update
        await threat_intel_service.update_threat_intelligence()
        
        log.success("Threat Intelligence Service started")
        
    except Exception as e:
        log.error(f"Failed to start Threat Intelligence Service: {e}")
        raise


@app.post("/update")
async def trigger_update():
    """Manually trigger threat intelligence update"""
    try:
        await threat_intel_service.update_threat_intelligence()
        return {"status": "success", "last_update": threat_intel_service.last_update.isoformat()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/vulnerabilities")
async def search_vulnerabilities(
    product: Optional[str] = None,
    severity: Optional[str] = None,
    exploit_available: Optional[bool] = None
):
    """Search vulnerabilities"""
    try:
        results = await threat_intel_service.search_vulnerabilities(product, severity, exploit_available)
        return {"count": len(results), "vulnerabilities": [v.dict() for v in results[:100]]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/exploits")
async def search_exploits(
    cve_id: Optional[str] = None,
    platform: Optional[str] = None
):
    """Search exploits"""
    try:
        results = await threat_intel_service.search_exploits(cve_id, platform)
        return {"count": len(results), "exploits": [e.dict() for e in results[:100]]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/attack-patterns/{objective}")
async def get_attack_patterns(objective: str):
    """Get MITRE ATT&CK patterns for objective"""
    try:
        patterns = await threat_intel_service.get_attack_patterns(objective)
        return {"objective": objective, "patterns": patterns}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/stats")
async def get_stats():
    """Get threat intelligence statistics"""
    return {
        "vulnerabilities_count": len(threat_intel_service.vulnerability_cache),
        "exploits_count": len(threat_intel_service.exploit_cache),
        "last_update": threat_intel_service.last_update.isoformat() if threat_intel_service.last_update else None
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}


@app.get("/ready")
async def readiness_check():
    """Readiness check endpoint"""
    if threat_intel_service is None:
        raise HTTPException(status_code=503, detail="Service not ready")
    return {"status": "ready"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8006)

