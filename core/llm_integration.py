#!/usr/bin/env python3
"""
LLM Integration - Vanchin AI Only
"""

import os
import json
import requests
from typing import List, Dict, Any, Optional
from loguru import logger


class LLMIntegration:
    def __init__(self):
        self.api_key = os.getenv("VC_API_KEY", "jjMoD5XYaClAwYlfMUzllfWucvd3NPZy67F3Ax4IT-c")
        self.base_url = "https://vanchin.streamlake.ai/api/gateway/v1/endpoints"
        self.model = "ep-rtt0hh-1761571039145129553"
        
        logger.info(f"[LLM] Using Vanchin AI: {self.model}")
    
    def chat(self, messages: List[Dict[str, str]], **kwargs) -> str:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": kwargs.get("temperature", 0.7),
            "max_tokens": kwargs.get("max_tokens", 2000)
        }
        
        response = requests.post(
            f"{self.base_url}/chat/completions",
            headers=headers,
            json=payload,
            timeout=60
        )
        response.raise_for_status()
        
        data = response.json()
        return data["choices"][0]["message"]["content"]
    
    def ask(self, question: str, system_prompt: Optional[str] = None) -> str:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": question})
        return self.chat(messages)


llm = LLMIntegration()
