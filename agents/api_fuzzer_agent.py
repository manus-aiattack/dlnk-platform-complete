import asyncio
from core.base_agent import BaseAgent
from core.data_models import AgentData, AttackPhase, Strategy, APIFuzzerReport, ErrorType # Added ErrorType
from core.api_schema_parser import OpenAPIParser, APIEndpoint, APIParameter
from core.graphql_fuzzer import GraphQLIntrospector
from core.oauth_handler import OAuthHandler
import requests
import json
import asyncio
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse


class APIFuzzerAgent(BaseAgent):
    """Advanced API fuzzing agent with OpenAPI and GraphQL support"""

    supported_phases = [AttackPhase.INITIAL_FOOTHOLD]
    required_tools = ["requests", "yaml"]

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.report_class = APIFuzzerReport
        self.openapi_parser = None
        self.graphql_introspector = None
        self.oauth_handler = OAuthHandler()
        self.fuzz_results = []
        self.vulnerabilities_found = []

    async def setup(self):
        """Asynchronous setup method for APIFuzzerAgent."""
        # Initialize fuzzing components
        self.fuzz_results = []
        self.vulnerabilities_found = []
        self.openapi_parser = None
        self.graphql_introspector = None
        self.log("APIFuzzerAgent setup completed")

    async def run(self, strategy: Strategy = None, **kwargs) -> AgentData:
        """Execute comprehensive API fuzzing"""
        try:
            target_url = await self.context_manager.get_context('target_url')
            if not target_url:
                return self.create_report(errors=["Target URL not found in context."], error_type=ErrorType.CONFIGURATION, summary="APIFuzzer failed: Target URL missing.")
            
            base_url = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"

            # Discover API endpoints
            api_endpoints = await self._discover_api_endpoints(base_url)

            # Test each discovered endpoint
            for endpoint in api_endpoints:
                await self._fuzz_endpoint(endpoint, base_url)

            # Generate report
            return self.create_report(
                endpoints_tested=len(api_endpoints),
                vulnerabilities_found=len(self.vulnerabilities_found),
                fuzz_results=self.fuzz_results,
                vulnerabilities=self.vulnerabilities_found,
                summary=f"APIFuzzer completed. Tested {len(api_endpoints)} endpoints, found {len(self.vulnerabilities_found)} vulnerabilities."
            )

        except Exception as e:
            return self.create_report(
                errors=[f"API fuzzing failed: {str(e)}"],
                error_type=ErrorType.LOGIC,
                summary=f"APIFuzzer failed due to an unexpected error: {e}"
            )
    async def _discover_api_endpoints(self, base_url: str) -> List[APIEndpoint]:
        """Discover API endpoints using various methods"""
        endpoints = []

        # Try to find OpenAPI/Swagger documentation
        swagger_urls = [
            f"{base_url}/swagger.json",
            f"{base_url}/swagger.yaml",
            f"{base_url}/api-docs",
            f"{base_url}/openapi.json",
            f"{base_url}/openapi.yaml",
            f"{base_url}/docs/swagger.json",
            f"{base_url}/api/swagger.json"
        ]

        for swagger_url in swagger_urls:
            try:
                # Try to load the schema to see if it's a valid OpenAPI/Swagger file
                parser = OpenAPIParser(schema_path=swagger_url)
                if parser.schema:
                    self.openapi_parser = parser
                    endpoints.extend(self.openapi_parser.get_endpoints())
                    break
            except Exception:
                continue # Ignore errors and try the next URL

        # Try GraphQL introspection
        graphql_endpoints = [
            f"{base_url}/graphql",
            f"{base_url}/api/graphql",
            f"{base_url}/query"
        ]

        for graphql_url in graphql_endpoints:
            self.graphql_introspector = GraphQLIntrospector(graphql_url)
            if self.graphql_introspector.introspect_schema():
                # Convert GraphQL queries to API endpoints
                graphql_endpoints = self._convert_graphql_to_endpoints()
                endpoints.extend(graphql_endpoints)
                break

        # If no schema found, try common API patterns
        if not endpoints:
            endpoints = await self._discover_common_endpoints(base_url)

        return endpoints

    async def _fuzz_endpoint(self, endpoint: APIEndpoint, base_url: str):
        """Fuzz a specific API endpoint"""
        full_url = urljoin(base_url, endpoint.path)

        # Generate fuzz payloads
        fuzz_payloads = self._generate_fuzz_payloads(endpoint)

        for payload in fuzz_payloads:
            try:
                response = await self._send_request(endpoint.method, full_url, payload)

                # Analyze response for vulnerabilities
                vulnerabilities = self._analyze_response(
                    response, endpoint, payload)
                if vulnerabilities:
                    self.vulnerabilities_found.extend(vulnerabilities)

                # Store result
                self.fuzz_results.append({
                    'endpoint': endpoint.path,
                    'method': endpoint.method,
                    'payload': payload,
                    'status_code': response.status_code,
                    'response_time': response.elapsed.total_seconds(),
                    'response_size': len(response.content),
                    'vulnerabilities': vulnerabilities
                })

            except Exception as e:
                self.fuzz_results.append({
                    'endpoint': endpoint.path,
                    'method': endpoint.method,
                    'payload': payload,
                    'error': str(e)
                })

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute api fuzzer agent"""
        try:
            target = strategy.context.get('target_url', '')
            
            # Call existing method
            if asyncio.iscoroutinefunction(self.run):
                results = await self.run(target)
            else:
                results = self.run(target)
            
            return AgentData(
                agent_name=self.__class__.__name__,
                success=True,
                summary=f"{self.__class__.__name__} completed successfully",
                errors=[],
                execution_time=0,
                memory_usage=0,
                cpu_usage=0,
                context={'results': results}
            )
        except Exception as e:
            return AgentData(
                agent_name=self.__class__.__name__,
                success=False,
                summary=f"{self.__class__.__name__} failed",
                errors=[str(e)],
                execution_time=0,
                memory_usage=0,
                cpu_usage=0,
                context={}
            )

    def _generate_fuzz_payloads(self, endpoint: APIEndpoint) -> List[Dict[str, Any]]:
        """Generate fuzzing payloads for an endpoint"""
        payloads = []

        # Basic payload
        basic_payload = {}
        for param in endpoint.parameters:
            if param.required:
                basic_payload[param.name] = self._get_default_value(param)
        payloads.append(basic_payload)

        # Fuzzing payloads
        for param in endpoint.parameters:
            fuzz_values = self._get_fuzz_values(param)
            for fuzz_value in fuzz_values:
                payload = basic_payload.copy()
                payload[param.name] = fuzz_value
                payloads.append(payload)

        return payloads

    def _get_fuzz_values(self, param: APIParameter) -> List[Any]:
        """Get fuzzing values for a parameter"""
        fuzz_values = []

        # Common injection payloads
        injection_payloads = [
            "' OR 1=1 --",
            "<script>alert(1)</script>",
            "../../etc/passwd",
            "{{7*7}}",
            "null",
            "",
            "0",
            "-1",
            "999999999"
        ]

        # Type-specific fuzzing
        if param.type == 'string':
            fuzz_values.extend(injection_payloads)
            if param.enum_values:
                fuzz_values.extend(param.enum_values)
        elif param.type == 'integer':
            fuzz_values.extend([0, -1, 999999999, "0", "-1"])
        elif param.type == 'boolean':
            fuzz_values.extend([True, False, "true", "false", 1, 0])

        return fuzz_values

    def _get_default_value(self, param: APIParameter) -> Any:
        """Get default value for a parameter"""
        if param.default_value is not None:
            return param.default_value

        if param.type == 'string':
            return "test"
        elif param.type == 'integer':
            return 1
        elif param.type == 'boolean':
            return True
        else:
            return None

    async def _send_request(self, method: str, url: str, payload: Dict[str, Any]) -> requests.Response:
        """Send HTTP request with payload asynchronously"""
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'dLNkdLNk-APIFuzzer/1.0'
        }

        loop = asyncio.get_running_loop()

        if method.upper() == 'GET':
            response = await loop.run_in_executor(None, lambda: requests.get(
                url, params=payload, headers=headers, timeout=30))
        elif method.upper() == 'POST':
            response = await loop.run_in_executor(None, lambda: requests.post(
                url, json=payload, headers=headers, timeout=30))
        elif method.upper() == 'PUT':
            response = await loop.run_in_executor(None, lambda: requests.put(
                url, json=payload, headers=headers, timeout=30))
        elif method.upper() == 'DELETE':
            response = await loop.run_in_executor(None, lambda: requests.delete(
                url, json=payload, headers=headers, timeout=30))
        else:
            response = await loop.run_in_executor(None, lambda: requests.request(
                method, url, json=payload, headers=headers, timeout=30))

        return response

    def _analyze_response(self, response: requests.Response, endpoint: APIEndpoint, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze response for potential vulnerabilities"""
        vulnerabilities = []

        # Check for SQL injection
        if self._detect_sql_injection(response):
            vulnerabilities.append({
                'type': 'SQL Injection',
                'endpoint': endpoint.path,
                'method': endpoint.method,
                'payload': payload,
                'evidence': response.text[:500]
            })

        # Check for XSS
        if self._detect_xss(response):
            vulnerabilities.append({
                'type': 'Cross-Site Scripting',
                'endpoint': endpoint.path,
                'method': endpoint.method,
                'payload': payload,
                'evidence': response.text[:500]
            })

        # Check for path traversal
        if self._detect_path_traversal(response):
            vulnerabilities.append({
                'type': 'Path Traversal',
                'endpoint': endpoint.path,
                'method': endpoint.method,
                'payload': payload,
                'evidence': response.text[:500]
            })

        # Check for information disclosure
        if self._detect_information_disclosure(response):
            vulnerabilities.append({
                'type': 'Information Disclosure',
                'endpoint': endpoint.path,
                'method': endpoint.method,
                'payload': payload,
                'evidence': response.text[:500]
            })

        return vulnerabilities

    def _detect_sql_injection(self, response: requests.Response) -> bool:
        """Detect SQL injection in response"""
        sql_indicators = [
            'mysql_fetch_array',
            'ORA-01756',
            'Microsoft OLE DB Provider',
            'SQLServer JDBC Driver',
            'PostgreSQL query failed',
            'Warning: mysql_',
            'valid MySQL result',
            'MySqlClient.',
            'SQL syntax'
        ]

        response_text = response.text.lower()
        return any(indicator.lower() in response_text for indicator in sql_indicators)

    def _detect_xss(self, response: requests.Response) -> bool:
        """Detect XSS in response"""
        xss_indicators = [
            '<script>alert(1)</script>',
            'javascript:alert(1)',
            'onerror=alert(1)',
            'onload=alert(1)'
        ]

        response_text = response.text
        return any(indicator in response_text for indicator in xss_indicators)

    def _detect_path_traversal(self, response: requests.Response) -> bool:
        """Detect path traversal in response"""
        path_indicators = [
            'root:x:0:0:',
            '[boot loader]',
            'bin/bash',
            'etc/passwd',
            'windows/system32'
        ]

        response_text = response.text.lower()
        return any(indicator in response_text for indicator in path_indicators)

    def _detect_information_disclosure(self, response: requests.Response) -> bool:
        """Detect information disclosure in response"""
        info_indicators = [
            'stack trace',
            'exception',
            'error in',
            'warning:',
            'notice:',
            'fatal error',
            'internal server error'
        ]

        response_text = response.text.lower()
        return any(indicator in response_text for indicator in info_indicators)

    def _convert_graphql_to_endpoints(self) -> List[APIEndpoint]:
        """Convert GraphQL queries to API endpoints"""
        endpoints = []

        if self.graphql_introspector:
            # Create endpoint for GraphQL queries
            query_endpoint = APIEndpoint(
                path="/graphql",
                method="POST",
                parameters=[],
                responses={200: {"description": "GraphQL response"}},
                security_requirements=[],
                tags=["graphql"]
            )
            endpoints.append(query_endpoint)

        return endpoints

    async def _discover_common_endpoints(self, base_url: str) -> List[APIEndpoint]:
        """Discover common API endpoints when no schema is available"""
        common_paths = [
            "/api/users",
            "/api/auth/login",
            "/api/auth/register",
            "/api/admin/users",
            "/api/v1/users",
            "/api/v2/users",
            "/rest/users",
            "/graphql",
            "/api/graphql"
        ]

        endpoints = []
        for path in common_paths:
            endpoint = APIEndpoint(
                path=path,
                method="GET",
                parameters=[],
                responses={},
                security_requirements=[],
                tags=["discovered"]
            )
            endpoints.append(endpoint)

        return endpoints
