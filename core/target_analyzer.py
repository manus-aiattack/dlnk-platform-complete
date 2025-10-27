"""
dLNk Attack Platform - Target Analyzer
Analyzes target for reconnaissance
"""

import aiohttp
import asyncio
from typing import Dict, Any, List
from urllib.parse import urlparse
from loguru import logger
import socket
import ssl
import re


class TargetAnalyzer:
    """Analyzes target website for reconnaissance"""
    
    def __init__(self):
        self.timeout = aiohttp.ClientTimeout(total=30)
    
    async def analyze(self, target_url: str) -> Dict[str, Any]:
        """
        Comprehensive target analysis
        
        Returns:
            Target information including:
            - Domain info
            - Server info
            - Technology stack
            - Endpoints
            - Security headers
        """
        logger.info(f"🔍 Analyzing target: {target_url}")
        
        parsed = urlparse(target_url)
        domain = parsed.netloc or parsed.path
        
        results = {
            "url": target_url,
            "domain": domain,
            "scheme": parsed.scheme or "http",
            "ip_address": None,
            "server": None,
            "technologies": [],
            "endpoints": [],
            "security_headers": {},
            "cookies": [],
            "forms": [],
            "inputs": [],
            "links": [],
            "subdomains": [],
            "open_ports": [],
            "ssl_info": {},
            "cms": None,
            "framework": None,
            "programming_language": None
        }
        
        try:
            # Resolve IP
            results["ip_address"] = await self._resolve_ip(domain)
            
            # HTTP Analysis
            http_info = await self._analyze_http(target_url)
            results.update(http_info)
            
            # Port Scanning
            results["open_ports"] = await self._scan_ports(results["ip_address"])
            
            # SSL Analysis
            if parsed.scheme == "https":
                results["ssl_info"] = await self._analyze_ssl(domain)
            
            # Technology Detection
            results["technologies"] = await self._detect_technologies(target_url, http_info)
            
            # CMS Detection
            results["cms"] = await self._detect_cms(target_url, http_info)
            
            # Framework Detection
            results["framework"] = await self._detect_framework(http_info)
            
            logger.info(f"✅ Target analysis complete")
            logger.info(f"   IP: {results['ip_address']}")
            logger.info(f"   Server: {results['server']}")
            logger.info(f"   Technologies: {len(results['technologies'])}")
            logger.info(f"   Endpoints: {len(results['endpoints'])}")
            
        except Exception as e:
            logger.error(f"❌ Target analysis failed: {e}")
            results["error"] = str(e)
        
        return results
    
    async def _resolve_ip(self, domain: str) -> str:
        """Resolve domain to IP address"""
        try:
            loop = asyncio.get_event_loop()
            ip = await loop.getaddrinfo(domain, None)
            return ip[0][4][0]
        except Exception as e:
            logger.warning(f"Failed to resolve IP: {e}")
            return None
    
    async def _analyze_http(self, target_url: str) -> Dict[str, Any]:
        """Analyze HTTP response"""
        results = {
            "server": None,
            "security_headers": {},
            "cookies": [],
            "forms": [],
            "inputs": [],
            "links": [],
            "endpoints": []
        }
        
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(target_url, allow_redirects=True) as response:
                    # Server header
                    results["server"] = response.headers.get("Server", "Unknown")
                    
                    # Security headers
                    security_headers = [
                        "X-Frame-Options",
                        "X-XSS-Protection",
                        "X-Content-Type-Options",
                        "Strict-Transport-Security",
                        "Content-Security-Policy",
                        "X-Permitted-Cross-Domain-Policies"
                    ]
                    
                    for header in security_headers:
                        if header in response.headers:
                            results["security_headers"][header] = response.headers[header]
                    
                    # Cookies
                    if "Set-Cookie" in response.headers:
                        results["cookies"] = response.headers.getall("Set-Cookie")
                    
                    # Parse HTML
                    html = await response.text()
                    
                    # Find forms
                    forms = re.findall(r'<form[^>]*>(.*?)</form>', html, re.DOTALL | re.IGNORECASE)
                    results["forms"] = [{"html": form} for form in forms]
                    
                    # Find inputs
                    inputs = re.findall(r'<input[^>]*>', html, re.IGNORECASE)
                    results["inputs"] = inputs
                    
                    # Find links
                    links = re.findall(r'href=["\']([^"\']+)["\']', html)
                    results["links"] = list(set(links))[:100]  # Limit to 100
                    
                    # Common endpoints
                    common_endpoints = [
                        "/admin", "/login", "/api", "/wp-admin", "/phpmyadmin",
                        "/dashboard", "/panel", "/console", "/api/v1", "/api/v2",
                        "/swagger", "/graphql", "/robots.txt", "/sitemap.xml"
                    ]
                    
                    for endpoint in common_endpoints:
                        try:
                            async with session.head(target_url + endpoint) as ep_response:
                                if ep_response.status < 400:
                                    results["endpoints"].append({
                                        "path": endpoint,
                                        "status": ep_response.status
                                    })
                        except Exception as e:
                            print("Error occurred")
        
        except Exception as e:
            logger.warning(f"HTTP analysis failed: {e}")
        
        return results
    
    async def _scan_ports(self, ip_address: str) -> List[int]:
        """Scan common ports"""
        if not ip_address:
            return []
        
        common_ports = [21, 22, 23, 25, 53, 80, 443, 3306, 3389, 5432, 8080, 8443]
        open_ports = []
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip_address, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except Exception as e:
                print("Error occurred")
        
        return open_ports
    
    async def _analyze_ssl(self, domain: str) -> Dict[str, Any]:
        """Analyze SSL certificate"""
        ssl_info = {}
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    ssl_info = {
                        "version": ssock.version(),
                        "cipher": ssock.cipher(),
                        "issuer": dict(x[0] for x in cert.get("issuer", [])),
                        "subject": dict(x[0] for x in cert.get("subject", [])),
                        "notBefore": cert.get("notBefore"),
                        "notAfter": cert.get("notAfter")
                    }
        except Exception as e:
            logger.warning(f"SSL analysis failed: {e}")
        
        return ssl_info
    
    async def _detect_technologies(
        self,
        target_url: str,
        http_info: Dict[str, Any]
    ) -> List[str]:
        """Detect technologies used"""
        technologies = []
        
        # Server-based detection
        server = http_info.get("server", "").lower()
        if "nginx" in server:
            technologies.append("Nginx")
        if "apache" in server:
            technologies.append("Apache")
        if "iis" in server:
            technologies.append("IIS")
        
        # Header-based detection
        headers_str = str(http_info.get("security_headers", {})).lower()
        if "php" in headers_str:
            technologies.append("PHP")
        if "asp.net" in headers_str:
            technologies.append("ASP.NET")
        
        # Cookie-based detection
        cookies_str = str(http_info.get("cookies", [])).lower()
        if "phpsessid" in cookies_str:
            technologies.append("PHP")
        if "jsessionid" in cookies_str:
            technologies.append("Java")
        if "asp.net" in cookies_str:
            technologies.append("ASP.NET")
        
        return list(set(technologies))
    
    async def _detect_cms(
        self,
        target_url: str,
        http_info: Dict[str, Any]
    ) -> str:
        """Detect CMS"""
        try:
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                # WordPress
                async with session.head(target_url + "/wp-admin") as response:
                    if response.status < 400:
                        return "WordPress"
                
                # Joomla
                async with session.head(target_url + "/administrator") as response:
                    if response.status < 400:
                        return "Joomla"
                
                # Drupal
                async with session.head(target_url + "/user/login") as response:
                    if response.status < 400:
                        return "Drupal"
        except Exception as e:
            print("Error occurred")
        
        return None
    
    async def _detect_framework(self, http_info: Dict[str, Any]) -> str:
        """Detect web framework"""
        server = http_info.get("server", "").lower()
        headers_str = str(http_info).lower()
        
        if "express" in headers_str:
            return "Express.js"
        if "django" in headers_str:
            return "Django"
        if "flask" in headers_str:
            return "Flask"
        if "laravel" in headers_str:
            return "Laravel"
        if "spring" in headers_str:
            return "Spring"
        
        return None

