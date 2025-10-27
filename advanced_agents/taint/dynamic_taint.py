"""
Dynamic Taint Analysis Engine
Tracks data flow to detect vulnerabilities
"""

import asyncio
from core.base_agent import BaseAgent
from core.data_models import AgentData, Strategy
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict
import logging

log = logging.getLogger(__name__)


class DynamicTaintAnalyzer:
    """
    Dynamic Taint Analysis Engine
    
    Features:
    - Track tainted data flow
    - Detect injection vulnerabilities
    - Identify dangerous sinks
    - Generate exploit chains
    """
    
    def __init__(self):
        self.taint_sources = set()
        self.taint_sinks = set()
        self.taint_map = defaultdict(set)  # variable -> taint sources
        self.data_flow = []  # Track data flow
        
        self._initialize_sources_and_sinks()
    
    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute attack"""
        try:
            target = strategy.context.get('target_url', '')
            
            # Implement attack logic here
            results = {'status': 'not_implemented'}
            
            return AgentData(
                agent_name=self.__class__.__name__,
                success=True,
                summary=f"{self.__class__.__name__} executed",
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

    def _initialize_sources_and_sinks(self):
        """Initialize taint sources and sinks"""
        
        # Taint sources (user input)
        self.taint_sources = {
            'GET', 'POST', 'PUT', 'DELETE',  # HTTP methods
            'request.args', 'request.form', 'request.json',  # Flask
            '$_GET', '$_POST', '$_REQUEST', '$_COOKIE',  # PHP
            'req.query', 'req.body', 'req.params',  # Express.js
            'input()', 'raw_input()', 'sys.argv',  # Python
        }
        
        # Taint sinks (dangerous operations)
        self.taint_sinks = {
            # SQL
            'execute', 'executemany', 'query', 'raw',
            'mysql_query', 'mysqli_query', 'pg_query',
            
            # Command execution
            'system', 'exec', 'shell_exec', 'passthru', 'popen',
            'subprocess.call', 'subprocess.run', 'os.system',
            
            # File operations
            'fopen', 'file_get_contents', 'readfile', 'include', 'require',
            'open', 'read', 'write',
            
            # Code evaluation
            'eval', 'assert', 'create_function',
            
            # Output
            'echo', 'print', 'printf', 'render_template',
            
            # Deserialization
            'unserialize', 'pickle.loads', 'yaml.load',
        }
    
    async def analyze_code(
        self,
        code: str,
        language: str = 'python'
    ) -> Dict:
        """
        Analyze code for taint flow vulnerabilities
        
        Args:
            code: Source code to analyze
            language: Programming language
        
        Returns:
            Analysis results with vulnerabilities
        """
        log.info(f"[TaintAnalyzer] Analyzing {language} code...")
        
        # Parse code and build data flow graph
        data_flow = await self._build_data_flow_graph(code, language)
        
        # Track taint propagation
        taint_flows = await self._track_taint_propagation(data_flow)
        
        # Detect vulnerabilities
        vulnerabilities = await self._detect_vulnerabilities(taint_flows)
        
        results = {
            'success': True,
            'language': language,
            'taint_flows': len(taint_flows),
            'vulnerabilities': vulnerabilities,
            'data_flow_graph': data_flow
        }
        
        log.info(f"[TaintAnalyzer] Found {len(vulnerabilities)} vulnerabilities")
        
        return results
    
    async def _build_data_flow_graph(
        self,
        code: str,
        language: str
    ) -> List[Dict]:
        """Build data flow graph from code"""
        
        # This is a simplified version
        # In production, use proper AST parsing
        
        data_flow = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Detect assignments
            if '=' in line and not line.startswith('if') and not line.startswith('while'):
                parts = line.split('=', 1)
                if len(parts) == 2:
                    lhs = parts[0].strip()
                    rhs = parts[1].strip()
                    
                    flow_node = {
                        'line': i,
                        'type': 'assignment',
                        'target': lhs,
                        'source': rhs,
                        'tainted': self._is_taint_source(rhs)
                    }
                    data_flow.append(flow_node)
            
            # Detect function calls
            if '(' in line and ')' in line:
                func_name = line.split('(')[0].strip().split()[-1]
                
                flow_node = {
                    'line': i,
                    'type': 'call',
                    'function': func_name,
                    'is_sink': func_name in self.taint_sinks,
                    'arguments': self._extract_arguments(line)
                }
                data_flow.append(flow_node)
        
        return data_flow
    
    def _is_taint_source(self, expression: str) -> bool:
        """Check if expression is a taint source"""
        
        for source in self.taint_sources:
            if source in expression:
                return True
        return False
    
    def _extract_arguments(self, line: str) -> List[str]:
        """Extract function arguments"""
        
        try:
            start = line.index('(')
            end = line.rindex(')')
            args_str = line[start+1:end]
            
            # Simple argument splitting (doesn't handle nested calls)
            args = [arg.strip() for arg in args_str.split(',')]
            return args
        except:
            return []
    
    async def _track_taint_propagation(
        self,
        data_flow: List[Dict]
    ) -> List[Dict]:
        """Track taint propagation through data flow"""
        
        tainted_vars = set()
        taint_flows = []
        
        for node in data_flow:
            if node['type'] == 'assignment':
                target = node['target']
                source = node['source']
                
                # Check if source is tainted
                is_tainted = node['tainted']
                
                # Check if source uses tainted variables
                for var in tainted_vars:
                    if var in source:
                        is_tainted = True
                        break
                
                if is_tainted:
                    tainted_vars.add(target)
                    
                    taint_flow = {
                        'line': node['line'],
                        'type': 'propagation',
                        'target': target,
                        'source': source,
                        'tainted_vars': list(tainted_vars)
                    }
                    taint_flows.append(taint_flow)
            
            elif node['type'] == 'call' and node['is_sink']:
                # Check if any argument is tainted
                tainted_args = []
                for arg in node['arguments']:
                    for var in tainted_vars:
                        if var in arg:
                            tainted_args.append(arg)
                            break
                
                if tainted_args:
                    taint_flow = {
                        'line': node['line'],
                        'type': 'sink',
                        'function': node['function'],
                        'tainted_args': tainted_args
                    }
                    taint_flows.append(taint_flow)
        
        return taint_flows
    
    async def _detect_vulnerabilities(
        self,
        taint_flows: List[Dict]
    ) -> List[Dict]:
        """Detect vulnerabilities from taint flows"""
        
        vulnerabilities = []
        
        for flow in taint_flows:
            if flow['type'] == 'sink':
                vuln = await self._classify_vulnerability(flow)
                if vuln:
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def _classify_vulnerability(self, flow: Dict) -> Optional[Dict]:
        """Classify vulnerability type from taint flow"""
        
        function = flow['function']
        
        # SQL Injection
        if function in ['execute', 'query', 'mysql_query', 'mysqli_query']:
            return {
                'type': 'sql_injection',
                'severity': 'CRITICAL',
                'line': flow['line'],
                'function': function,
                'tainted_args': flow['tainted_args'],
                'description': f"SQL Injection via {function} with tainted input",
                'cwe': 'CWE-89',
                'cvss': 9.8
            }
        
        # Command Injection
        elif function in ['system', 'exec', 'shell_exec', 'os.system']:
            return {
                'type': 'command_injection',
                'severity': 'CRITICAL',
                'line': flow['line'],
                'function': function,
                'tainted_args': flow['tainted_args'],
                'description': f"Command Injection via {function} with tainted input",
                'cwe': 'CWE-78',
                'cvss': 9.9
            }
        
        # Path Traversal
        elif function in ['fopen', 'open', 'readfile', 'include']:
            return {
                'type': 'path_traversal',
                'severity': 'HIGH',
                'line': flow['line'],
                'function': function,
                'tainted_args': flow['tainted_args'],
                'description': f"Path Traversal via {function} with tainted input",
                'cwe': 'CWE-22',
                'cvss': 7.5
            }
        
        # Code Injection
        elif function in ['eval', 'assert', 'exec']:
            return {
                'type': 'code_injection',
                'severity': 'CRITICAL',
                'line': flow['line'],
                'function': function,
                'tainted_args': flow['tainted_args'],
                'description': f"Code Injection via {function} with tainted input",
                'cwe': 'CWE-94',
                'cvss': 9.8
            }
        
        # XSS
        elif function in ['echo', 'print', 'render_template']:
            return {
                'type': 'xss',
                'severity': 'HIGH',
                'line': flow['line'],
                'function': function,
                'tainted_args': flow['tainted_args'],
                'description': f"Cross-Site Scripting via {function} with tainted input",
                'cwe': 'CWE-79',
                'cvss': 7.3
            }
        
        return None
    
    async def analyze_http_request(
        self,
        request_data: Dict
    ) -> Dict:
        """
        Analyze HTTP request for taint sources
        
        Args:
            request_data: HTTP request data
        
        Returns:
            Taint analysis results
        """
        log.info("[TaintAnalyzer] Analyzing HTTP request...")
        
        taint_sources_found = []
        
        # Check query parameters
        if 'query_params' in request_data:
            for param, value in request_data['query_params'].items():
                taint_sources_found.append({
                    'source': 'query_param',
                    'name': param,
                    'value': value,
                    'tainted': True
                })
        
        # Check POST data
        if 'post_data' in request_data:
            for param, value in request_data['post_data'].items():
                taint_sources_found.append({
                    'source': 'post_data',
                    'name': param,
                    'value': value,
                    'tainted': True
                })
        
        # Check cookies
        if 'cookies' in request_data:
            for cookie, value in request_data['cookies'].items():
                taint_sources_found.append({
                    'source': 'cookie',
                    'name': cookie,
                    'value': value,
                    'tainted': True
                })
        
        # Check headers
        if 'headers' in request_data:
            dangerous_headers = ['User-Agent', 'Referer', 'X-Forwarded-For']
            for header in dangerous_headers:
                if header in request_data['headers']:
                    taint_sources_found.append({
                        'source': 'header',
                        'name': header,
                        'value': request_data['headers'][header],
                        'tainted': True
                    })
        
        return {
            'success': True,
            'taint_sources': taint_sources_found,
            'total_sources': len(taint_sources_found)
        }


if __name__ == '__main__':
    async def test():
        analyzer = DynamicTaintAnalyzer()
        
        # Test code analysis
        test_code = """
user_input = request.args.get('id')
query = "SELECT * FROM users WHERE id = " + user_input
result = execute(query)
print(result)
"""
        
        results = await analyzer.analyze_code(test_code, 'python')
        
        print("Taint Analysis Results:")
        print(f"Taint flows: {results['taint_flows']}")
        print(f"Vulnerabilities: {len(results['vulnerabilities'])}")
        
        if results['vulnerabilities']:
            print("\nVulnerabilities found:")
            for vuln in results['vulnerabilities']:
                print(f"  - Line {vuln['line']}: {vuln['type']} ({vuln['severity']})")
                print(f"    {vuln['description']}")
                print(f"    CWE: {vuln['cwe']}, CVSS: {vuln['cvss']}")
    
    asyncio.run(test())

