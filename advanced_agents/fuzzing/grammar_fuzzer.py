"""
Grammar-Based Fuzzer for dLNk Attack Platform
Generates inputs based on grammar specifications
"""

import asyncio
from core.base_agent import BaseAgent
from core.data_models import AgentData, Strategy
import random
from typing import Dict, List, Optional, Any
import logging

log = logging.getLogger(__name__)


class GrammarFuzzer:
    """
    Grammar-Based Fuzzer
    
    Features:
    - Generate inputs from grammar
    - Support for complex data formats
    - Mutation-based generation
    - Context-aware fuzzing
    """
    
    def __init__(self):
        self.grammars = self._load_default_grammars()
        self.generated_inputs = []
    
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

    def _load_default_grammars(self) -> Dict:
        """Load default grammar specifications"""
        
        return {
            'http_request': {
                '<start>': ['<method> <path> <version>\r\n<headers>\r\n\r\n<body>'],
                '<method>': ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH'],
                '<path>': ['/', '/api', '/admin', '/api/<resource>'],
                '<resource>': ['users', 'products', 'orders', 'config'],
                '<version>': ['HTTP/1.0', 'HTTP/1.1', 'HTTP/2.0'],
                '<headers>': ['<header>', '<header>\r\n<headers>'],
                '<header>': [
                    'Host: <host>',
                    'User-Agent: <user_agent>',
                    'Content-Type: <content_type>',
                    'Authorization: <auth>',
                    'Cookie: <cookie>'
                ],
                '<host>': ['localhost', 'example.com', '127.0.0.1'],
                '<user_agent>': ['Mozilla/5.0', 'curl/7.0', 'dLNk-Fuzzer/1.0'],
                '<content_type>': ['application/json', 'application/xml', 'text/html'],
                '<auth>': ['Bearer <token>', 'Basic <base64>'],
                '<token>': ['eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'],
                '<base64>': ['YWRtaW46cGFzc3dvcmQ='],
                '<cookie>': ['session=<session_id>'],
                '<session_id>': ['abc123', 'xyz789'],
                '<body>': ['', '<json>', '<xml>'],
                '<json>': ['{"key": "<value>"}', '{"id": <number>}'],
                '<xml>': ['<root><item><value></item></root>'],
                '<value>': ['test', 'admin', '../../etc/passwd', '<script>alert(1)</script>'],
                '<number>': ['1', '0', '-1', '999999']
            },
            
            'sql_query': {
                '<start>': ['<select>', '<insert>', '<update>', '<delete>'],
                '<select>': ['SELECT <columns> FROM <table> <where>'],
                '<insert>': ['INSERT INTO <table> (<columns>) VALUES (<values>)'],
                '<update>': ['UPDATE <table> SET <assignments> <where>'],
                '<delete>': ['DELETE FROM <table> <where>'],
                '<columns>': ['*', '<column>', '<column>, <columns>'],
                '<column>': ['id', 'name', 'email', 'password', 'admin'],
                '<table>': ['users', 'products', 'orders', 'admin_users'],
                '<where>': ['', 'WHERE <condition>'],
                '<condition>': [
                    '<column> = <value>',
                    '<column> > <number>',
                    '<column> LIKE <pattern>',
                    '<condition> AND <condition>',
                    '<condition> OR <condition>'
                ],
                '<assignments>': ['<column> = <value>', '<column> = <value>, <assignments>'],
                '<values>': ['<value>', '<value>, <values>'],
                '<value>': ["'test'", "'admin'", "1", "NULL", "' OR 1=1--"],
                '<pattern>': ["'%admin%'", "'%test%'"],
                '<number>': ['0', '1', '999', '-1']
            },
            
            'json_object': {
                '<start>': ['<object>'],
                '<object>': ['{<members>}'],
                '<members>': ['<pair>', '<pair>, <members>'],
                '<pair>': ['"<key>": <value>'],
                '<key>': ['id', 'name', 'email', 'password', 'admin', 'role'],
                '<value>': [
                    '<string>',
                    '<number>',
                    '<boolean>',
                    '<null>',
                    '<object>',
                    '<array>'
                ],
                '<string>': [
                    '"test"',
                    '"admin"',
                    '"../../etc/passwd"',
                    '"<script>alert(1)</script>"',
                    '"{{7*7}}"'
                ],
                '<number>': ['0', '1', '-1', '999999', '1.5'],
                '<boolean>': ['true', 'false'],
                '<null>': ['null'],
                '<array>': ['[<elements>]'],
                '<elements>': ['<value>', '<value>, <elements>']
            },
            
            'xml_document': {
                '<start>': ['<?xml version="1.0"?><document>'],
                '<document>': ['<root><elements></root>'],
                '<root>': ['<element>'],
                '<elements>': ['<element>', '<element><elements>'],
                '<element>': [
                    '<user><name><value></name></user>',
                    '<item><id><number></id></item>',
                    '<config><setting><value></setting></config>',
                    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
                ],
                '<value>': ['test', 'admin', '../../etc/passwd'],
                '<number>': ['1', '0', '-1']
            },
            
            'url': {
                '<start>': ['<scheme>://<host><path><query>'],
                '<scheme>': ['http', 'https', 'file', 'ftp'],
                '<host>': ['localhost', 'example.com', '127.0.0.1', '169.254.169.254'],
                '<path>': ['/', '/api', '/admin', '/api/<resource>'],
                '<resource>': ['users', 'config', 'files'],
                '<query>': ['', '?<params>'],
                '<params>': ['<param>', '<param>&<params>'],
                '<param>': [
                    'id=<number>',
                    'name=<value>',
                    'file=<file_path>',
                    'url=<url_value>'
                ],
                '<number>': ['1', '0', '-1', '999'],
                '<value>': ['test', 'admin', '<script>alert(1)</script>'],
                '<file_path>': ['test.txt', '../../etc/passwd', '/etc/shadow'],
                '<url_value>': ['http://localhost', 'http://169.254.169.254']
            }
        }
    
    async def generate_inputs(
        self,
        grammar_name: str,
        count: int = 100,
        max_depth: int = 10
    ) -> List[str]:
        """
        Generate inputs from grammar
        
        Args:
            grammar_name: Name of grammar to use
            count: Number of inputs to generate
            max_depth: Maximum expansion depth
        
        Returns:
            List of generated inputs
        """
        log.info(f"[GrammarFuzzer] Generating {count} inputs from {grammar_name} grammar")
        
        if grammar_name not in self.grammars:
            log.error(f"[GrammarFuzzer] Grammar not found: {grammar_name}")
            return []
        
        grammar = self.grammars[grammar_name]
        inputs = []
        
        for i in range(count):
            try:
                input_str = self._expand_grammar(grammar, '<start>', max_depth)
                inputs.append(input_str)
            except Exception as e:
                log.error(f"[GrammarFuzzer] Failed to generate input {i}: {e}")
        
        self.generated_inputs.extend(inputs)
        
        log.info(f"[GrammarFuzzer] Generated {len(inputs)} inputs")
        
        return inputs
    
    def _expand_grammar(
        self,
        grammar: Dict,
        symbol: str,
        max_depth: int,
        depth: int = 0
    ) -> str:
        """Expand grammar symbol"""
        
        if depth > max_depth:
            # Reached max depth, return simple expansion
            return self._simple_expansion(grammar, symbol)
        
        # Not a non-terminal
        if symbol not in grammar:
            return symbol
        
        # Choose random expansion
        expansions = grammar[symbol]
        expansion = random.choice(expansions)
        
        # Expand all non-terminals in the expansion
        result = expansion
        
        # Find all non-terminals (symbols in angle brackets)
        import re
        non_terminals = re.findall(r'<[^>]+>', expansion)
        
        for nt in non_terminals:
            expanded = self._expand_grammar(grammar, nt, max_depth, depth + 1)
            result = result.replace(nt, expanded, 1)
        
        return result
    
    def _simple_expansion(self, grammar: Dict, symbol: str) -> str:
        """Simple expansion without recursion"""
        
        if symbol not in grammar:
            return symbol
        
        expansions = grammar[symbol]
        
        # Choose shortest expansion
        shortest = min(expansions, key=len)
        
        # Remove non-terminals
        import re
        result = re.sub(r'<[^>]+>', '', shortest)
        
        return result
    
    async def mutate_inputs(
        self,
        inputs: List[str],
        mutation_rate: float = 0.1
    ) -> List[str]:
        """
        Mutate existing inputs
        
        Args:
            inputs: Input strings to mutate
            mutation_rate: Probability of mutation per character
        
        Returns:
            Mutated inputs
        """
        log.info(f"[GrammarFuzzer] Mutating {len(inputs)} inputs")
        
        mutated = []
        
        for input_str in inputs:
            mutated_str = self._mutate_string(input_str, mutation_rate)
            mutated.append(mutated_str)
        
        return mutated
    
    def _mutate_string(self, s: str, mutation_rate: float) -> str:
        """Mutate a string"""
        
        result = []
        
        for char in s:
            if random.random() < mutation_rate:
                # Apply mutation
                mutation_type = random.choice([
                    'flip_bit',
                    'insert_char',
                    'delete_char',
                    'replace_char'
                ])
                
                if mutation_type == 'flip_bit':
                    # Flip a bit in the character
                    char_code = ord(char)
                    bit_pos = random.randint(0, 7)
                    char_code ^= (1 << bit_pos)
                    result.append(chr(char_code % 128))
                
                elif mutation_type == 'insert_char':
                    # Insert random character
                    result.append(char)
                    result.append(chr(random.randint(32, 126)))
                
                elif mutation_type == 'delete_char':
                    # Delete character (skip it)
                    pass
                
                elif mutation_type == 'replace_char':
                    # Replace with random character
                    result.append(chr(random.randint(32, 126)))
            else:
                result.append(char)
        
        return ''.join(result)
    
    async def add_custom_grammar(self, name: str, grammar: Dict):
        """Add custom grammar specification"""
        
        self.grammars[name] = grammar
        log.info(f"[GrammarFuzzer] Added custom grammar: {name}")
    
    async def crossover_inputs(
        self,
        inputs: List[str],
        count: int = 50
    ) -> List[str]:
        """
        Generate new inputs by crossing over existing inputs
        
        Args:
            inputs: Input strings to crossover
            count: Number of crossover inputs to generate
        
        Returns:
            Crossover inputs
        """
        log.info(f"[GrammarFuzzer] Generating {count} crossover inputs")
        
        crossover_inputs = []
        
        for i in range(count):
            # Select two random inputs
            if len(inputs) < 2:
                break
            
            parent1 = random.choice(inputs)
            parent2 = random.choice(inputs)
            
            # Crossover at random point
            if len(parent1) > 0 and len(parent2) > 0:
                point1 = random.randint(0, len(parent1))
                point2 = random.randint(0, len(parent2))
                
                child = parent1[:point1] + parent2[point2:]
                crossover_inputs.append(child)
        
        return crossover_inputs


if __name__ == '__main__':
    async def test():
        fuzzer = GrammarFuzzer()
        
        # Test HTTP request generation
        http_requests = await fuzzer.generate_inputs('http_request', count=5)
        
        print("Generated HTTP Requests:")
        for i, req in enumerate(http_requests, 1):
            print(f"\n--- Request {i} ---")
            print(req)
        
        # Test SQL query generation
        sql_queries = await fuzzer.generate_inputs('sql_query', count=3)
        
        print("\n\nGenerated SQL Queries:")
        for i, query in enumerate(sql_queries, 1):
            print(f"{i}. {query}")
        
        # Test mutation
        mutated = await fuzzer.mutate_inputs(http_requests[:2], mutation_rate=0.2)
        
        print("\n\nMutated Requests:")
        for i, req in enumerate(mutated, 1):
            print(f"\n--- Mutated {i} ---")
            print(req)
    
    asyncio.run(test())

