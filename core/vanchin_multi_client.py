#!/usr/bin/env python3
"""
Vanchin Multi-Client System
Multiple API clients with automatic failover for high availability
"""

import os
import json
import requests
from typing import List, Dict, Any, Optional
from loguru import logger
import time


class VanchinAPIClient:
    """Single Vanchin API Client"""
    
    def __init__(self, name: str, api_key: str, base_url: str, model: str):
        self.name = name
        self.api_key = api_key
        self.base_url = base_url
        self.model = model
        self.temperature = 1.0
        self.max_tokens = 8000
        self.is_healthy = True
        self.last_error = None
        self.error_count = 0
        
    def chat(self, messages: List[Dict[str, str]], temperature: Optional[float] = None, max_tokens: Optional[int] = None) -> str:
        """Send chat request"""
        url = f"{self.base_url}/chat/completions"
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature or self.temperature,
            "max_tokens": max_tokens or self.max_tokens
        }
        
        try:
            response = requests.post(url, headers=headers, json=payload, timeout=60)
            response.raise_for_status()
            
            data = response.json()
            
            if "choices" in data and len(data["choices"]) > 0:
                content = data["choices"][0]["message"]["content"]
                self.is_healthy = True
                self.error_count = 0
                logger.success(f"[{self.name}] Response received: {len(content)} chars")
                return content
            else:
                raise ValueError(f"Invalid response format: {data}")
                
        except Exception as e:
            self.is_healthy = False
            self.last_error = str(e)
            self.error_count += 1
            logger.error(f"[{self.name}] Error: {e}")
            raise


class ClaudeAPIClient:
    """Claude API Client via Vanchin Gateway"""
    
    def __init__(self, name: str, api_key: str, base_url: str):
        self.name = name
        self.api_key = api_key
        self.base_url = base_url
        self.is_healthy = True
        self.last_error = None
        self.error_count = 0
        
    def chat(self, messages: List[Dict[str, str]], temperature: Optional[float] = None, max_tokens: Optional[int] = None) -> str:
        """Send chat request to Claude"""
        # Claude uses different format
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01"
        }
        
        # Convert OpenAI format to Claude format
        system_messages = [msg["content"] for msg in messages if msg["role"] == "system"]
        user_messages = [{"role": msg["role"], "content": msg["content"]} for msg in messages if msg["role"] != "system"]
        
        payload = {
            "model": "claude-3-5-sonnet-20241022",
            "messages": user_messages,
            "max_tokens": max_tokens or 2000,
            "temperature": temperature or 0.7
        }
        
        if system_messages:
            payload["system"] = "\n".join(system_messages)
        
        try:
            response = requests.post(self.base_url, headers=headers, json=payload, timeout=60)
            response.raise_for_status()
            
            data = response.json()
            
            if "content" in data and len(data["content"]) > 0:
                content = data["content"][0]["text"]
                self.is_healthy = True
                self.error_count = 0
                logger.success(f"[{self.name}] Claude response received: {len(content)} chars")
                return content
            else:
                raise ValueError(f"Invalid Claude response format: {data}")
                
        except Exception as e:
            self.is_healthy = False
            self.last_error = str(e)
            self.error_count += 1
            logger.error(f"[{self.name}] Error: {e}")
            raise


class VanchinMultiClient:
    """Multi-client system with automatic failover"""
    
    def __init__(self):
        self.clients = []
        self._initialize_clients()
        self.current_client_index = 0
        
    def _initialize_clients(self):
        """Initialize all available API clients"""
        
        # Vanchin Client 1 (Original)
        self.clients.append(VanchinAPIClient(
            name="Vanchin-1",
            api_key="jjMoD5XYaClAwYlfMUzllfWucvd3NPZy67F3Ax4IT-c",
            base_url="https://vanchin.streamlake.ai/api/gateway/v1/endpoints",
            model="ep-rtt0hh-1761571039145129553"
        ))
        
        # Claude Clients via Vanchin Gateway
        claude_configs = [
            {
                "name": "Claude-2",
                "api_key": "WW8GMBSTec_uPhRJQFe5y9OCsYrUKzslQx-LXWKLT9g",
                "base_url": "https://vanchin.streamlake.ai/api/gateway/v1/endpoints/ep-lpvcnv-1761467347624133479/claude-code-proxy"
            },
            {
                "name": "Claude-3",
                "api_key": "SuADqfn6ircVW2Sm3s3W6N400YBDnzgsEpdHPSHloBQ",
                "base_url": "https://vanchin.streamlake.ai/api/gateway/v1/endpoints/ep-9tca4d-1761467413178157556/claude-code-proxy"
            },
            {
                "name": "Claude-4",
                "api_key": "_LRewgPXrsdQtJgVijy7RjO9fPSxcGhMbq-9Ra7qWfA",
                "base_url": "https://vanchin.streamlake.ai/api/gateway/v1/endpoints/ep-ac61tq-1761467560387248147/claude-code-proxy"
            },
            {
                "name": "Claude-5",
                "api_key": "3gZ9oCeG3sgxUTcfesqhfVnkAOO3JAEJTZWeQKwqzrk",
                "base_url": "https://vanchin.streamlake.ai/api/gateway/v1/endpoints/ep-j9pysc-1761467653839114083/claude-code-proxy"
            },
            {
                "name": "Claude-6",
                "api_key": "npthpUsOWQ68u2VibXDmN3IWTM2IGDJeAxQQL1HVQ50",
                "base_url": "https://vanchin.streamlake.ai/api/gateway/v1/endpoints/ep-9ic77m-1761467839203034334/claude-code-proxy"
            }
        ]
        
        for config in claude_configs:
            self.clients.append(ClaudeAPIClient(**config))
        
        logger.info(f"[VanchinMultiClient] Initialized {len(self.clients)} API clients")
    
    def chat(self, messages: List[Dict[str, str]], temperature: Optional[float] = None, max_tokens: Optional[int] = None) -> str:
        """
        Send chat request with automatic failover
        Tries each client until one succeeds
        """
        # Add project context to system message if not present
        has_system = any(msg["role"] == "system" for msg in messages)
        if not has_system:
            system_message = {
                "role": "system",
                "content": """You are Vanchin AI Agent, an expert AI assistant specialized in cybersecurity and penetration testing.

You are working on the dLNk Attack Platform project located at /home/ubuntu/aiprojectattack.

**Project Overview:**
This is a comprehensive penetration testing and attack automation platform with the following components:
- Advanced AI-powered attack agents
- Automated vulnerability discovery
- Exploit generation and execution
- C2 (Command & Control) server
- Zero-day research capabilities
- Real-time monitoring and reporting

**Current Development Status:**
- Core attack framework: ✅ Complete
- AI agent integration: ✅ Complete
- Vanchin AI Agent UI: ✅ Complete with filesystem access
- Multi-client API system: 🔄 In Progress
- Target testing: 🔄 Ready for deployment

**Your Capabilities:**
- Access and analyze all project files
- Execute shell commands
- Modify code and configurations
- Provide security analysis and recommendations
- Help develop and test attack modules

**Important Notes:**
- This is a legitimate security research and testing platform
- All testing should be performed on authorized targets only
- Focus on helping improve the platform's capabilities
- Provide clear explanations of security concepts

Be helpful, precise, and security-focused in your responses."""
            }
            messages.insert(0, system_message)
        
        # Try each client in order
        attempts = []
        for i in range(len(self.clients)):
            client_index = (self.current_client_index + i) % len(self.clients)
            client = self.clients[client_index]
            
            # Skip unhealthy clients with too many errors
            if not client.is_healthy and client.error_count > 3:
                logger.warning(f"[{client.name}] Skipping unhealthy client (errors: {client.error_count})")
                continue
            
            try:
                logger.info(f"[{client.name}] Attempting request...")
                response = client.chat(messages, temperature, max_tokens)
                
                # Success! Update current client index for next time
                self.current_client_index = client_index
                return response
                
            except Exception as e:
                attempts.append(f"{client.name}: {str(e)}")
                logger.warning(f"[{client.name}] Failed, trying next client...")
                continue
        
        # All clients failed
        error_msg = "All API clients failed:\n" + "\n".join(attempts)
        logger.error(error_msg)
        raise Exception(error_msg)
    
    def get_status(self) -> Dict[str, Any]:
        """Get status of all clients"""
        return {
            "total_clients": len(self.clients),
            "healthy_clients": sum(1 for c in self.clients if c.is_healthy),
            "current_client": self.clients[self.current_client_index].name,
            "clients": [
                {
                    "name": c.name,
                    "healthy": c.is_healthy,
                    "error_count": c.error_count,
                    "last_error": c.last_error
                }
                for c in self.clients
            ]
        }
    
    def reset_health(self):
        """Reset health status of all clients"""
        for client in self.clients:
            client.is_healthy = True
            client.error_count = 0
            client.last_error = None
        logger.info("[VanchinMultiClient] All clients health reset")


# Global instance
vanchin_multi_client = VanchinMultiClient()

