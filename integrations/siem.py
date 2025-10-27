"""
SIEM Integration
ส่งข้อมูลไปยัง SIEM systems (Splunk, ELK, QRadar)
"""

import aiohttp
import json
from typing import Dict, List, Any, Optional
from datetime import datetime
from enum import Enum

from core.logger import log


class SIEMType(Enum):
    """SIEM system types"""
    SPLUNK = "splunk"
    ELK = "elk"
    QRADAR = "qradar"


class SplunkIntegration:
    """Splunk HTTP Event Collector (HEC) integration"""
    
    def __init__(self, hec_url: str, hec_token: str, index: str = "main"):
        """
        Initialize Splunk integration
        
        Args:
            hec_url: Splunk HEC URL
            hec_token: HEC token
            index: Splunk index
        """
        self.hec_url = hec_url
        self.hec_token = hec_token
        self.index = index
    
    async def send_event(
        self,
        event_data: Dict[str, Any],
        source: str = "dlnk_attack_platform",
        sourcetype: str = "security:attack"
    ) -> bool:
        """
        ส่ง event ไปยัง Splunk
        
        Args:
            event_data: Event data
            source: Event source
            sourcetype: Event sourcetype
        
        Returns:
            Success status
        """
        try:
            # Build HEC payload
            payload = {
                "time": int(datetime.now().timestamp()),
                "host": "dlnk-platform",
                "source": source,
                "sourcetype": sourcetype,
                "index": self.index,
                "event": event_data
            }
            
            headers = {
                "Authorization": f"Splunk {self.hec_token}",
                "Content-Type": "application/json"
            }
            
            # Send to Splunk
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.hec_url}/services/collector/event",
                    json=payload,
                    headers=headers,
                    ssl=False  # Set to True in production with valid cert
                ) as response:
                    if response.status == 200:
                        log.info("[SplunkIntegration] Event sent successfully")
                        return True
                    else:
                        log.error(f"[SplunkIntegration] Failed to send event: {response.status}")
                        return False
        
        except Exception as e:
            log.error(f"[SplunkIntegration] Error sending event: {e}")
            return False
    
    async def send_vulnerability(self, vulnerability: Dict[str, Any]) -> bool:
        """
        ส่ง vulnerability event
        
        Args:
            vulnerability: Vulnerability data
        
        Returns:
            Success status
        """
        event_data = {
            "event_type": "vulnerability_found",
            "vulnerability_type": vulnerability.get("type"),
            "severity": vulnerability.get("severity"),
            "cvss_score": vulnerability.get("cvss_score"),
            "target": vulnerability.get("target"),
            "location": vulnerability.get("location"),
            "description": vulnerability.get("description"),
            "timestamp": datetime.now().isoformat()
        }
        
        return await self.send_event(event_data, sourcetype="security:vulnerability")
    
    async def send_attack_log(self, attack_log: Dict[str, Any]) -> bool:
        """
        ส่ง attack log
        
        Args:
            attack_log: Attack log data
        
        Returns:
            Success status
        """
        event_data = {
            "event_type": "attack_log",
            "session_id": attack_log.get("session_id"),
            "target": attack_log.get("target"),
            "attack_type": attack_log.get("attack_type"),
            "status": attack_log.get("status"),
            "timestamp": datetime.now().isoformat()
        }
        
        return await self.send_event(event_data, sourcetype="security:attack_log")


class ELKIntegration:
    """Elasticsearch integration"""
    
    def __init__(self, elasticsearch_url: str, index_prefix: str = "dlnk"):
        """
        Initialize ELK integration
        
        Args:
            elasticsearch_url: Elasticsearch URL
            index_prefix: Index prefix
        """
        self.elasticsearch_url = elasticsearch_url
        self.index_prefix = index_prefix
    
    async def send_document(
        self,
        document: Dict[str, Any],
        index_suffix: str = "attacks"
    ) -> bool:
        """
        ส่ง document ไปยัง Elasticsearch
        
        Args:
            document: Document data
            index_suffix: Index suffix
        
        Returns:
            Success status
        """
        try:
            # Add timestamp
            document["@timestamp"] = datetime.now().isoformat()
            
            # Build index name with date
            index_name = f"{self.index_prefix}-{index_suffix}-{datetime.now().strftime('%Y.%m.%d')}"
            
            # Send to Elasticsearch
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.elasticsearch_url}/{index_name}/_doc",
                    json=document
                ) as response:
                    if response.status in [200, 201]:
                        log.info("[ELKIntegration] Document sent successfully")
                        return True
                    else:
                        log.error(f"[ELKIntegration] Failed to send document: {response.status}")
                        return False
        
        except Exception as e:
            log.error(f"[ELKIntegration] Error sending document: {e}")
            return False
    
    async def send_vulnerability(self, vulnerability: Dict[str, Any]) -> bool:
        """
        ส่ง vulnerability document
        
        Args:
            vulnerability: Vulnerability data
        
        Returns:
            Success status
        """
        document = {
            "event_type": "vulnerability",
            "vulnerability": {
                "type": vulnerability.get("type"),
                "severity": vulnerability.get("severity"),
                "cvss_score": vulnerability.get("cvss_score"),
                "cvss_vector": vulnerability.get("cvss_vector")
            },
            "target": {
                "url": vulnerability.get("target"),
                "location": vulnerability.get("location")
            },
            "description": vulnerability.get("description"),
            "remediation": vulnerability.get("remediation")
        }
        
        return await self.send_document(document, "vulnerabilities")
    
    async def send_attack_metrics(self, metrics: Dict[str, Any]) -> bool:
        """
        ส่ง attack metrics
        
        Args:
            metrics: Metrics data
        
        Returns:
            Success status
        """
        document = {
            "event_type": "metrics",
            "session_id": metrics.get("session_id"),
            "target": metrics.get("target"),
            "metrics": {
                "total_requests": metrics.get("total_requests"),
                "successful_exploits": metrics.get("successful_exploits"),
                "vulnerabilities_found": metrics.get("vulnerabilities_found"),
                "duration_seconds": metrics.get("duration_seconds")
            }
        }
        
        return await self.send_document(document, "metrics")


class SIEMManager:
    """
    SIEM Manager
    
    จัดการการส่งข้อมูลไปยัง SIEM systems
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize SIEM manager
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.integrations = {}
        
        # Initialize Splunk
        if config.get("splunk_hec_url") and config.get("splunk_hec_token"):
            self.integrations[SIEMType.SPLUNK] = SplunkIntegration(
                hec_url=config["splunk_hec_url"],
                hec_token=config["splunk_hec_token"],
                index=config.get("splunk_index", "main")
            )
        
        # Initialize ELK
        if config.get("elasticsearch_url"):
            self.integrations[SIEMType.ELK] = ELKIntegration(
                elasticsearch_url=config["elasticsearch_url"],
                index_prefix=config.get("elk_index_prefix", "dlnk")
            )
    
    async def send_vulnerability(
        self,
        vulnerability: Dict[str, Any],
        siem_types: Optional[List[SIEMType]] = None
    ) -> Dict[SIEMType, bool]:
        """
        ส่ง vulnerability ไปยัง SIEM systems
        
        Args:
            vulnerability: Vulnerability data
            siem_types: List of SIEM types (None = all)
        
        Returns:
            Dictionary of SIEM type -> success status
        """
        results = {}
        
        target_siems = siem_types or list(self.integrations.keys())
        
        for siem_type in target_siems:
            integration = self.integrations.get(siem_type)
            if integration:
                success = await integration.send_vulnerability(vulnerability)
                results[siem_type] = success
        
        return results
    
    async def send_attack_log(
        self,
        attack_log: Dict[str, Any],
        siem_types: Optional[List[SIEMType]] = None
    ) -> Dict[SIEMType, bool]:
        """
        ส่ง attack log ไปยัง SIEM systems
        
        Args:
            attack_log: Attack log data
            siem_types: List of SIEM types (None = all)
        
        Returns:
            Dictionary of SIEM type -> success status
        """
        results = {}
        
        target_siems = siem_types or list(self.integrations.keys())
        
        for siem_type in target_siems:
            integration = self.integrations.get(siem_type)
            if integration:
                if siem_type == SIEMType.SPLUNK:
                    success = await integration.send_attack_log(attack_log)
                elif siem_type == SIEMType.ELK:
                    success = await integration.send_document(attack_log, "attacks")
                else:
                    success = False
                
                results[siem_type] = success
        
        return results
    
    async def send_metrics(
        self,
        metrics: Dict[str, Any],
        siem_types: Optional[List[SIEMType]] = None
    ) -> Dict[SIEMType, bool]:
        """
        ส่ง metrics ไปยัง SIEM systems
        
        Args:
            metrics: Metrics data
            siem_types: List of SIEM types (None = all)
        
        Returns:
            Dictionary of SIEM type -> success status
        """
        results = {}
        
        target_siems = siem_types or list(self.integrations.keys())
        
        for siem_type in target_siems:
            integration = self.integrations.get(siem_type)
            if integration and siem_type == SIEMType.ELK:
                success = await integration.send_attack_metrics(metrics)
                results[siem_type] = success
        
        return results


# Example usage
if __name__ == "__main__":
    import asyncio
    
    async def main():
        # Configuration
        config = {
            "splunk_hec_url": "http://localhost:8088",
            "splunk_hec_token": "YOUR-HEC-TOKEN",
            "splunk_index": "security",
            "elasticsearch_url": "http://localhost:9200",
            "elk_index_prefix": "dlnk"
        }
        
        # Initialize manager
        manager = SIEMManager(config)
        
        # Send vulnerability
        vulnerability = {
            "type": "SQL Injection",
            "severity": "Critical",
            "cvss_score": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "target": "http://localhost:8000",
            "location": "/api/users?id=1",
            "description": "SQL injection in user_id parameter",
            "remediation": "Use prepared statements"
        }
        
        results = await manager.send_vulnerability(vulnerability)
        print(f"Vulnerability sent to SIEM: {results}")
        
        # Send attack log
        attack_log = {
            "session_id": "session_123",
            "target": "http://localhost:8000",
            "attack_type": "web_application",
            "status": "completed",
            "vulnerabilities_found": 5
        }
        
        results = await manager.send_attack_log(attack_log)
        print(f"Attack log sent to SIEM: {results}")
    
    asyncio.run(main())

