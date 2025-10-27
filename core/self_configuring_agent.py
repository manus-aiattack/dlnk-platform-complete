"""
Self-Configuring Agent System
Agents automatically detect environment and configure themselves
"""

import asyncio
import platform
import subprocess
import shutil
from typing import Dict, List, Any, Optional
import logging
import psutil
import socket

log = logging.getLogger(__name__)


class EnvironmentDetector:
    """Detect execution environment"""
    
    @staticmethod
    async def detect_os() -> Dict[str, str]:
        """Detect operating system"""
        return {
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor()
        }
    
    @staticmethod
    async def detect_network() -> Dict[str, Any]:
        """Detect network configuration"""
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            
            # Get network interfaces
            interfaces = psutil.net_if_addrs()
            
            return {
                'hostname': hostname,
                'local_ip': local_ip,
                'interfaces': {
                    name: [addr.address for addr in addrs]
                    for name, addrs in interfaces.items()
                }
            }
        except Exception as e:
            log.error(f"Network detection failed: {e}")
            return {}
    
    @staticmethod
    async def detect_resources() -> Dict[str, Any]:
        """Detect system resources"""
        try:
            cpu_count = psutil.cpu_count()
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            return {
                'cpu_count': cpu_count,
                'cpu_percent': psutil.cpu_percent(interval=0.1),
                'memory_total': memory.total,
                'memory_available': memory.available,
                'memory_percent': memory.percent,
                'disk_total': disk.total,
                'disk_free': disk.free,
                'disk_percent': disk.percent
            }
        except Exception as e:
            log.error(f"Resource detection failed: {e}")
            return {}
    
    @staticmethod
    async def detect_tools() -> Dict[str, bool]:
        """Detect available attack tools"""
        tools = {
            'nmap': 'nmap',
            'sqlmap': 'sqlmap',
            'metasploit': 'msfconsole',
            'burp': 'burpsuite',
            'wireshark': 'wireshark',
            'john': 'john',
            'hashcat': 'hashcat',
            'hydra': 'hydra',
            'nikto': 'nikto',
            'dirb': 'dirb',
            'gobuster': 'gobuster',
            'ffuf': 'ffuf',
            'wfuzz': 'wfuzz',
            'nuclei': 'nuclei',
            'masscan': 'masscan'
        }
        
        available = {}
        for tool_name, command in tools.items():
            available[tool_name] = shutil.which(command) is not None
        
        return available
    
    @staticmethod
    async def detect_python_packages() -> Dict[str, bool]:
        """Detect available Python packages"""
        packages = [
            'requests', 'aiohttp', 'beautifulsoup4', 'lxml',
            'scapy', 'paramiko', 'pycrypto', 'cryptography',
            'sqlalchemy', 'asyncpg', 'redis', 'celery',
            'numpy', 'pandas', 'tensorflow', 'torch'
        ]
        
        available = {}
        for package in packages:
            try:
                __import__(package.replace('-', '_'))
                available[package] = True
            except ImportError:
                available[package] = False
        
        return available
    
    @staticmethod
    async def detect_container() -> Dict[str, Any]:
        """Detect if running in container"""
        is_container = False
        container_type = None
        
        # Check for Docker
        if os.path.exists('/.dockerenv'):
            is_container = True
            container_type = 'docker'
        
        # Check for Kubernetes
        elif os.path.exists('/var/run/secrets/kubernetes.io'):
            is_container = True
            container_type = 'kubernetes'
        
        # Check cgroup
        try:
            with open('/proc/1/cgroup', 'r') as f:
                if 'docker' in f.read():
                    is_container = True
                    container_type = 'docker'
        except:
            pass
        
        return {
            'is_container': is_container,
            'type': container_type
        }


class SelfConfiguringAgent:
    """
    Self-Configuring Agent Base Class
    
    Automatically detects environment and configures parameters
    """
    
    def __init__(self):
        self.environment = {}
        self.config = {}
        self.capabilities = []
    
    async def auto_configure(self):
        """Automatically configure based on environment"""
        log.info(f"[{self.__class__.__name__}] Starting auto-configuration...")
        
        # Detect environment
        await self._detect_environment()
        
        # Adjust parameters
        await self._adjust_parameters()
        
        # Determine capabilities
        await self._determine_capabilities()
        
        log.info(f"[{self.__class__.__name__}] Auto-configuration complete")
        log.info(f"  Capabilities: {', '.join(self.capabilities)}")
    
    async def _detect_environment(self):
        """Detect execution environment"""
        detector = EnvironmentDetector()
        
        self.environment = {
            'os': await detector.detect_os(),
            'network': await detector.detect_network(),
            'resources': await detector.detect_resources(),
            'tools': await detector.detect_tools(),
            'packages': await detector.detect_python_packages(),
            'container': await detector.detect_container()
        }
        
        log.debug(f"Environment detected: {self.environment['os']['system']}")
    
    async def _adjust_parameters(self):
        """Adjust parameters based on environment"""
        resources = self.environment.get('resources', {})
        
        # Adjust concurrency based on CPU
        cpu_count = resources.get('cpu_count', 1)
        self.config['max_concurrent_tasks'] = max(1, cpu_count - 1)
        
        # Adjust memory limits
        memory_available = resources.get('memory_available', 0)
        if memory_available > 0:
            # Use up to 50% of available memory
            self.config['max_memory_mb'] = (memory_available // 1024 // 1024) // 2
        else:
            self.config['max_memory_mb'] = 512
        
        # Adjust timeouts based on network
        network = self.environment.get('network', {})
        if network:
            self.config['network_timeout'] = 30
        else:
            self.config['network_timeout'] = 10
        
        # Adjust based on container
        container = self.environment.get('container', {})
        if container.get('is_container'):
            # More conservative in containers
            self.config['max_concurrent_tasks'] = max(1, self.config['max_concurrent_tasks'] // 2)
        
        log.debug(f"Parameters adjusted: {self.config}")
    
    async def _determine_capabilities(self):
        """Determine agent capabilities"""
        tools = self.environment.get('tools', {})
        packages = self.environment.get('packages', {})
        
        # Network scanning
        if tools.get('nmap') or tools.get('masscan'):
            self.capabilities.append('network_scanning')
        
        # Web scanning
        if tools.get('nikto') or tools.get('nuclei'):
            self.capabilities.append('web_scanning')
        
        # SQL injection
        if tools.get('sqlmap'):
            self.capabilities.append('sql_injection')
        
        # Password cracking
        if tools.get('john') or tools.get('hashcat'):
            self.capabilities.append('password_cracking')
        
        # Fuzzing
        if tools.get('ffuf') or tools.get('wfuzz'):
            self.capabilities.append('fuzzing')
        
        # Exploitation
        if tools.get('metasploit'):
            self.capabilities.append('exploitation')
        
        # Python-based capabilities
        if packages.get('scapy'):
            self.capabilities.append('packet_crafting')
        
        if packages.get('paramiko'):
            self.capabilities.append('ssh_operations')
        
        if packages.get('cryptography'):
            self.capabilities.append('cryptographic_operations')
    
    async def check_tool_availability(self, tool_name: str) -> bool:
        """Check if specific tool is available"""
        return self.environment.get('tools', {}).get(tool_name, False)
    
    async def install_missing_tool(self, tool_name: str) -> bool:
        """Attempt to install missing tool"""
        log.info(f"[{self.__class__.__name__}] Attempting to install {tool_name}...")
        
        os_system = self.environment.get('os', {}).get('system', '')
        
        try:
            if os_system == 'Linux':
                # Try apt-get
                result = subprocess.run(
                    ['sudo', 'apt-get', 'install', '-y', tool_name],
                    capture_output=True,
                    timeout=300
                )
                
                if result.returncode == 0:
                    log.info(f"  ✅ {tool_name} installed successfully")
                    return True
            
            log.warning(f"  ❌ Failed to install {tool_name}")
            return False
            
        except Exception as e:
            log.error(f"  ❌ Error installing {tool_name}: {e}")
            return False
    
    async def get_optimal_concurrency(self) -> int:
        """Get optimal concurrency level"""
        return self.config.get('max_concurrent_tasks', 1)
    
    async def get_memory_limit(self) -> int:
        """Get memory limit in MB"""
        return self.config.get('max_memory_mb', 512)
    
    async def adapt_to_target(self, target_info: Dict[str, Any]):
        """Adapt configuration based on target"""
        # Adjust timeouts based on target response time
        if 'avg_response_time' in target_info:
            response_time = target_info['avg_response_time']
            self.config['request_timeout'] = max(5, response_time * 3)
        
        # Adjust rate limiting based on target
        if target_info.get('has_rate_limiting'):
            self.config['requests_per_second'] = 1
        else:
            self.config['requests_per_second'] = 10
        
        log.debug(f"Adapted to target: {self.config}")


import os


class AgentAutoInstaller:
    """Automatically install missing dependencies"""
    
    @staticmethod
    async def install_python_package(package: str) -> bool:
        """Install Python package"""
        try:
            subprocess.run(
                ['pip3', 'install', package],
                capture_output=True,
                timeout=300,
                check=True
            )
            log.info(f"✅ Installed Python package: {package}")
            return True
        except Exception as e:
            log.error(f"❌ Failed to install {package}: {e}")
            return False
    
    @staticmethod
    async def install_system_tool(tool: str) -> bool:
        """Install system tool"""
        try:
            subprocess.run(
                ['sudo', 'apt-get', 'install', '-y', tool],
                capture_output=True,
                timeout=300,
                check=True
            )
            log.info(f"✅ Installed system tool: {tool}")
            return True
        except Exception as e:
            log.error(f"❌ Failed to install {tool}: {e}")
            return False

