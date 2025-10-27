"""
Nmap Agent - Network Scanning และ Service Detection
ครอบคลุมทุก scan mode ของ Nmap
"""

import asyncio
import json
import subprocess
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path
from core.logger import log
from core.base_agent import BaseAgent
from core.data_models import AgentData, AttackPhase


class NmapAgent(BaseAgent):
    """
    
    supported_phases = [AttackPhase.RECONNAISSANCE]
    required_tools = ["nmap"]
    Nmap Agent สำหรับ network scanning
    
    Scan Modes:
    - Quick Scan: เร็ว, ports ที่สำคัญ
    - Full Scan: ครบถ้วน, ทุก ports
    - Stealth Scan: SYN scan, หลบ firewall
    - Service Detection: -sV, version detection
    - OS Detection: -O, ระบุ OS
    - Aggressive Scan: -A, ครบทุกอย่าง
    - UDP Scan: -sU, UDP ports
    - Script Scan: NSE scripts
    """
    
    def __init__(self):
        self.name = "NmapAgent"
        self.scan_history = []
        self.output_dir = Path("scan_results")
        self.output_dir.mkdir(exist_ok=True)
        
        # ตรวจสอบว่ามี nmap หรือไม่
        self.nmap_available = self._check_nmap()
        
    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute nmap agent"""
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

    def _check_nmap(self) -> bool:
        """ตรวจสอบว่ามี nmap installed"""
        try:
            result = subprocess.run(
                ["nmap", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                log.success(f"[{self.name}] Nmap available: {result.stdout.split()[2]}")
                return True
        except Exception as e:
            log.error(f"[{self.name}] Nmap not found: {e}")
        return False
    
    async def run(self, directive: str, context: Dict) -> AgentData:
        """
        Main execution method
        
        Args:
            directive: "quick", "full", "stealth", "service", "os", "aggressive", "udp", "script"
            context: {
                "target": IP or hostname,
                "ports": port range (optional),
                "scripts": NSE scripts (for script scan)
            }
        
        Returns:
            AgentData with scan results
        """
        log.info(f"[NmapAgent] Starting {directive} scan")
        
        target = context.get("target")
        if not target:
            return AgentData(
                agent_name="NmapAgent",
                success=False,
                data={"error": "No target provided"}
            )
        
        ports = context.get("ports", "1-1000")
        scripts = context.get("scripts", "default")
        
        try:
            if directive == "quick":
                result = await self.quick_scan(target, ports)
            elif directive == "full":
                result = await self.full_scan(target, ports)
            elif directive == "stealth":
                result = await self.stealth_scan(target, ports)
            elif directive == "service":
                result = await self.service_detection(target, ports)
            elif directive == "os":
                result = await self.os_detection(target)
            elif directive == "aggressive":
                result = await self.aggressive_scan(target)
            elif directive == "udp":
                result = await self.udp_scan(target, ports)
            elif directive == "script":
                result = await self.script_scan(target, scripts, ports)
            else:
                result = await self.quick_scan(target, ports)
            
            return AgentData(
                agent_name="NmapAgent",
                success=result.get("success", False),
                data=result
            )
        
        except Exception as e:
            log.error(f"[NmapAgent] Error: {e}")
            return AgentData(
                agent_name="NmapAgent",
                success=False,
                data={"error": str(e)}
            )

    
    async def quick_scanuick_scan(
        self,
        target: str,
        ports: str = "1-1000"
    ) -> Dict[str, Any]:
        """
        Quick Scan - เร็ว, ports ที่สำคัญ
        
        Args:
            target: IP หรือ hostname
            ports: port range (default: 1-1000)
        """
        log.info(f"[{self.name}] Quick scan: {target}")
        
        args = [
            "nmap",
            "-T4",  # Aggressive timing
            "-F",   # Fast mode (100 common ports)
            "-p", ports,
            target,
            "-oX", "-"  # XML output to stdout
        ]
        
        return await self._run_scan(target, args, "quick")
    
    async def full_scan(
        self,
        target: str,
        ports: str = "1-65535"
    ) -> Dict[str, Any]:
        """
        Full Scan - ครบถ้วน, ทุก ports
        
        Args:
            target: IP หรือ hostname
            ports: port range (default: 1-65535)
        """
        log.info(f"[{self.name}] Full scan: {target}")
        
        args = [
            "nmap",
            "-p", ports,
            "-T4",
            target,
            "-oX", "-"
        ]
        
        return await self._run_scan(target, args, "full")
    
    async def stealth_scan(
        self,
        target: str,
        ports: str = "1-1000"
    ) -> Dict[str, Any]:
        """
        Stealth Scan - SYN scan, หลบ firewall
        
        Args:
            target: IP หรือ hostname
            ports: port range
        """
        log.info(f"[{self.name}] Stealth scan: {target}")
        
        args = [
            "nmap",
            "-sS",  # SYN scan
            "-T2",  # Polite timing
            "-p", ports,
            target,
            "-oX", "-"
        ]
        
        return await self._run_scan(target, args, "stealth")
    
    async def service_detection(
        self,
        target: str,
        ports: str = "1-1000"
    ) -> Dict[str, Any]:
        """
        Service Detection - version detection
        
        Args:
            target: IP หรือ hostname
            ports: port range
        """
        log.info(f"[{self.name}] Service detection: {target}")
        
        args = [
            "nmap",
            "-sV",  # Version detection
            "-p", ports,
            target,
            "-oX", "-"
        ]
        
        return await self._run_scan(target, args, "service")
    
    async def os_detection(
        self,
        target: str
    ) -> Dict[str, Any]:
        """
        OS Detection - ระบุ operating system
        
        Args:
            target: IP หรือ hostname
        """
        log.info(f"[{self.name}] OS detection: {target}")
        
        args = [
            "nmap",
            "-O",  # OS detection
            "-T4",
            target,
            "-oX", "-"
        ]
        
        return await self._run_scan(target, args, "os")
    
    async def aggressive_scan(
        self,
        target: str,
        ports: str = "1-1000"
    ) -> Dict[str, Any]:
        """
        Aggressive Scan - ครบทุกอย่าง (-A)
        
        Args:
            target: IP หรือ hostname
            ports: port range
        """
        log.info(f"[{self.name}] Aggressive scan: {target}")
        
        args = [
            "nmap",
            "-A",  # Aggressive (OS, version, scripts, traceroute)
            "-p", ports,
            target,
            "-oX", "-"
        ]
        
        return await self._run_scan(target, args, "aggressive")
    
    async def udp_scan(
        self,
        target: str,
        ports: str = "53,67,68,69,123,161,162,500"
    ) -> Dict[str, Any]:
        """
        UDP Scan - scan UDP ports
        
        Args:
            target: IP หรือ hostname
            ports: UDP ports (default: common UDP ports)
        """
        log.info(f"[{self.name}] UDP scan: {target}")
        
        args = [
            "nmap",
            "-sU",  # UDP scan
            "-p", ports,
            target,
            "-oX", "-"
        ]
        
        return await self._run_scan(target, args, "udp")
    
    async def script_scan(
        self,
        target: str,
        scripts: str = "default",
        ports: str = "1-1000"
    ) -> Dict[str, Any]:
        """
        Script Scan - NSE scripts
        
        Args:
            target: IP หรือ hostname
            scripts: NSE scripts (default, vuln, exploit, etc.)
            ports: port range
        """
        log.info(f"[{self.name}] Script scan: {target} with {scripts}")
        
        args = [
            "nmap",
            "--script", scripts,
            "-p", ports,
            target,
            "-oX", "-"
        ]
        
        return await self._run_scan(target, args, "script")
    
    async def vulnerability_scan(
        self,
        target: str,
        ports: str = "1-1000"
    ) -> Dict[str, Any]:
        """
        Vulnerability Scan - ใช้ vuln scripts
        
        Args:
            target: IP หรือ hostname
            ports: port range
        """
        log.info(f"[{self.name}] Vulnerability scan: {target}")
        
        args = [
            "nmap",
            "--script", "vuln",
            "-p", ports,
            target,
            "-oX", "-"
        ]
        
        return await self._run_scan(target, args, "vulnerability")
    
    async def custom_scan(
        self,
        target: str,
        custom_args: List[str]
    ) -> Dict[str, Any]:
        """
        Custom Scan - กำหนด arguments เอง
        
        Args:
            target: IP หรือ hostname
            custom_args: custom nmap arguments
        """
        log.info(f"[{self.name}] Custom scan: {target}")
        
        args = ["nmap"] + custom_args + [target, "-oX", "-"]
        
        return await self._run_scan(target, args, "custom")
    
    async def _run_scan(
        self,
        target: str,
        args: List[str],
        scan_type: str
    ) -> Dict[str, Any]:
        """
        รัน nmap scan
        
        Args:
            target: target host
            args: nmap arguments
            scan_type: ประเภทของ scan
        """
        if not self.nmap_available:
            return {
                "success": False,
                "error": "Nmap not available",
                "target": target,
                "scan_type": scan_type
            }
        
        start_time = datetime.now()
        
        try:
            # รัน nmap
            process = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                log.error(f"[{self.name}] Scan failed: {stderr.decode()}")
                return {
                    "success": False,
                    "error": stderr.decode(),
                    "target": target,
                    "scan_type": scan_type
                }
            
            # Parse XML output
            xml_output = stdout.decode()
            scan_results = self._parse_nmap_xml(xml_output)
            
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            result = {
                "success": True,
                "target": target,
                "scan_type": scan_type,
                "duration": duration,
                "timestamp": start_time.isoformat(),
                "results": scan_results
            }
            
            # บันทึก history
            self.scan_history.append(result)
            
            # บันทึกไฟล์
            self._save_scan_result(result)
            
            log.success(f"[{self.name}] Scan completed in {duration:.2f}s")
            
            return result
            
        except Exception as e:
            log.error(f"[{self.name}] Scan error: {e}")
            return {
                "success": False,
                "error": str(e),
                "target": target,
                "scan_type": scan_type
            }
    
    def _parse_nmap_xml(self, xml_output: str) -> Dict[str, Any]:
        """Parse Nmap XML output"""
        try:
            root = ET.fromstring(xml_output)
            
            results = {
                "hosts": [],
                "summary": {}
            }
            
            # Parse hosts
            for host in root.findall("host"):
                host_info = {
                    "addresses": [],
                    "hostnames": [],
                    "ports": [],
                    "os": None,
                    "status": None
                }
                
                # Status
                status = host.find("status")
                if status is not None:
                    host_info["status"] = status.get("state")
                
                # Addresses
                for addr in host.findall("address"):
                    host_info["addresses"].append({
                        "addr": addr.get("addr"),
                        "type": addr.get("addrtype")
                    })
                
                # Hostnames
                hostnames = host.find("hostnames")
                if hostnames is not None:
                    for hostname in hostnames.findall("hostname"):
                        host_info["hostnames"].append({
                            "name": hostname.get("name"),
                            "type": hostname.get("type")
                        })
                
                # Ports
                ports = host.find("ports")
                if ports is not None:
                    for port in ports.findall("port"):
                        port_info = {
                            "port": port.get("portid"),
                            "protocol": port.get("protocol"),
                            "state": None,
                            "service": None,
                            "version": None
                        }
                        
                        state = port.find("state")
                        if state is not None:
                            port_info["state"] = state.get("state")
                        
                        service = port.find("service")
                        if service is not None:
                            port_info["service"] = service.get("name")
                            port_info["version"] = service.get("version")
                            port_info["product"] = service.get("product")
                        
                        host_info["ports"].append(port_info)
                
                # OS Detection
                os_elem = host.find("os")
                if os_elem is not None:
                    osmatch = os_elem.find("osmatch")
                    if osmatch is not None:
                        host_info["os"] = {
                            "name": osmatch.get("name"),
                            "accuracy": osmatch.get("accuracy")
                        }
                
                results["hosts"].append(host_info)
            
            # Summary
            runstats = root.find("runstats")
            if runstats is not None:
                finished = runstats.find("finished")
                if finished is not None:
                    results["summary"]["elapsed"] = finished.get("elapsed")
                
                hosts_elem = runstats.find("hosts")
                if hosts_elem is not None:
                    results["summary"]["total_hosts"] = hosts_elem.get("total")
                    results["summary"]["up_hosts"] = hosts_elem.get("up")
                    results["summary"]["down_hosts"] = hosts_elem.get("down")
            
            return results
            
        except Exception as e:
            log.error(f"[{self.name}] XML parse error: {e}")
            return {"error": str(e)}
    
    def _save_scan_result(self, result: Dict[str, Any]):
        """บันทึกผล scan ลงไฟล์"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{result['target']}_{result['scan_type']}_{timestamp}.json"
            filepath = self.output_dir / filename
            
            with open(filepath, 'w') as f:
                json.dump(result, f, indent=2)
            
            log.info(f"[{self.name}] Saved to {filepath}")
            
        except Exception as e:
            log.error(f"[{self.name}] Save error: {e}")
    
    def get_scan_history(self) -> List[Dict[str, Any]]:
        """ดึง scan history"""
        return self.scan_history
    
    def get_latest_scan(self) -> Optional[Dict[str, Any]]:
        """ดึง scan ล่าสุด"""
        if self.scan_history:
            return self.scan_history[-1]
        return None


# Singleton instance
nmap_agent = NmapAgent()


# Helper functions
async def quick_scan(target: str, ports: str = "1-1000") -> Dict[str, Any]:
    """Quick scan wrapper"""
    return await nmap_agent.quick_scan(target, ports)


async def full_scan(target: str) -> Dict[str, Any]:
    """Full scan wrapper"""
    return await nmap_agent.full_scan(target)


async def stealth_scan(target: str, ports: str = "1-1000") -> Dict[str, Any]:
    """Stealth scan wrapper"""
    return await nmap_agent.stealth_scan(target, ports)


async def service_detection(target: str, ports: str = "1-1000") -> Dict[str, Any]:
    """Service detection wrapper"""
    return await nmap_agent.service_detection(target, ports)


async def vulnerability_scan(target: str, ports: str = "1-1000") -> Dict[str, Any]:
    """Vulnerability scan wrapper"""
    return await nmap_agent.vulnerability_scan(target, ports)

