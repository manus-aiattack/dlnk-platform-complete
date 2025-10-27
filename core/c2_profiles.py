"""
C2 (Command and Control) Profiles Module
Defines various C2 communication profiles for covert channels
"""

from typing import Dict, List, Optional
from dataclasses import dataclass
import json

@dataclass
class C2Profile:
    """Base C2 Profile"""
    name: str
    protocol: str
    host: str
    port: int
    encryption: bool = True
    obfuscation: bool = True
    
    def to_dict(self) -> Dict:
        return {
            'name': self.name,
            'protocol': self.protocol,
            'host': self.host,
            'port': self.port,
            'encryption': self.encryption,
            'obfuscation': self.obfuscation
        }

@dataclass
class HTTPProfile(C2Profile):
    """HTTP/HTTPS C2 Profile"""
    user_agent: str = "Mozilla/5.0"
    headers: Optional[Dict[str, str]] = None
    
    def __post_init__(self):
        if self.headers is None:
            self.headers = {}

@dataclass
class DNSProfile(C2Profile):
    """DNS C2 Profile"""
    dns_server: str = "8.8.8.8"
    query_type: str = "TXT"
    domain: str = ""

@dataclass
class DoHProfile(C2Profile):
    """DNS over HTTPS C2 Profile"""
    doh_server: str = "https://dns.google/dns-query"
    domain: str = ""

# Predefined C2 profiles
PROFILES = {
    'http_default': HTTPProfile(
        name='HTTP Default',
        protocol='http',
        host='127.0.0.1',
        port=8080,
        encryption=False
    ),
    'https_secure': HTTPProfile(
        name='HTTPS Secure',
        protocol='https',
        host='127.0.0.1',
        port=443,
        encryption=True
    ),
    'dns_covert': DNSProfile(
        name='DNS Covert',
        protocol='dns',
        host='8.8.8.8',
        port=53,
        domain='localhost:8000'
    ),
    'doh_covert': DoHProfile(
        name='DoH Covert',
        protocol='doh',
        host='dns.google',
        port=443,
        doh_server='https://dns.google/dns-query',
        domain='localhost:8000'
    )
}

def get_profile(profile_name: str) -> Optional[C2Profile]:
    """Get a C2 profile by name"""
    return PROFILES.get(profile_name)

def list_profiles() -> List[str]:
    """List all available C2 profiles"""
    return list(PROFILES.keys())

def create_custom_profile(profile_type: str, **kwargs) -> C2Profile:
    """Create a custom C2 profile"""
    if profile_type == 'http':
        return HTTPProfile(**kwargs)
    elif profile_type == 'dns':
        return DNSProfile(**kwargs)
    elif profile_type == 'doh':
        return DoHProfile(**kwargs)
    else:
        raise ValueError(f"Unknown profile type: {profile_type}")

__all__ = [
    'C2Profile',
    'HTTPProfile',
    'DNSProfile',
    'DoHProfile',
    'PROFILES',
    'get_profile',
    'list_profiles',
    'create_custom_profile'
]

