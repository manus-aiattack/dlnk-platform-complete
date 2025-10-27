"""
Crash Analyzer Agent
Automatic crash analysis and exploitability assessment
"""

import asyncio
from core.base_agent import BaseAgent
from core.data_models import AgentData, Strategy
import subprocess
import re
from typing import Dict, List, Optional
from pathlib import Path
import logging

log = logging.getLogger(__name__)


class CrashAnalyzer:
    """
    Automatic Crash Analysis and Exploitability Assessment
    
    Features:
    - Crash type detection (segfault, abort, etc.)
    - Exploitability scoring
    - Stack trace analysis
    - Register state analysis
    - Crash deduplication
    """
    
    def __init__(self):
        self.crash_signatures = {}
    
    async def run(self, target: Dict) -> Dict:
        """
        Main entry point for crash analysis
        
        Args:
            target: Dict containing:
                - crash_file: Path to crash input
                - binary_path: Path to target binary
                - analyze_exploitability: Perform exploitability analysis
        
        Returns:
            Dict with crash analysis results
        """
        crash_file = target.get('crash_file')
        binary_path = target.get('binary_path')
        analyze_exploitability = target.get('analyze_exploitability', True)
        
        if not crash_file or not binary_path:
            return {
                'success': False,
                'error': 'Missing crash_file or binary_path'
            }
        
        try:
            result = await self.analyze_crash(
                crash_file=crash_file,
                binary_path=binary_path,
                analyze_exploitability=analyze_exploitability
            )
            
            return result
        
        except Exception as e:
            log.error(f"[CrashAnalyzer] Error: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def analyze_crash(
        self,
        crash_file: str,
        binary_path: str,
        analyze_exploitability: bool = True
    ) -> Dict:
        """
        Analyze a crash
        
        Args:
            crash_file: Path to crash input
            binary_path: Path to target binary
            analyze_exploitability: Perform exploitability analysis
        
        Returns:
            Dict with crash analysis
        """
        log.info(f"[CrashAnalyzer] Analyzing crash: {crash_file}")
        
        result = {
            'success': True,
            'crash_file': crash_file,
            'binary': binary_path,
            'crash_type': None,
            'signal': None,
            'exploitability': None,
            'stack_trace': [],
            'registers': {},
            'signature': None
        }
        
        # Run binary with crash input under GDB
        gdb_output = await self._run_with_gdb(binary_path, crash_file)
        
        # Parse crash information
        result['crash_type'] = self._detect_crash_type(gdb_output)
        result['signal'] = self._extract_signal(gdb_output)
        result['stack_trace'] = self._extract_stack_trace(gdb_output)
        result['registers'] = self._extract_registers(gdb_output)
        
        # Generate crash signature
        result['signature'] = self._generate_signature(result)
        
        # Exploitability analysis
        if analyze_exploitability:
            result['exploitability'] = await self._assess_exploitability(result)
        
        return result
    
    async def _run_with_gdb(self, binary_path: str, crash_file: str) -> str:
        """Run binary with crash input under GDB"""
        
        gdb_commands = f"""
set pagination off
set confirm off
run < {crash_file}
info registers
backtrace
quit
"""
        
        try:
            # Write GDB commands to file
            cmd_file = Path('/tmp/gdb_commands.txt')
            with open(cmd_file, 'w') as f:
                f.write(gdb_commands)
            
            # Run GDB
            result = subprocess.run(
                ['gdb', '-batch', '-x', str(cmd_file), binary_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            return result.stdout + result.stderr
        
        except subprocess.TimeoutExpired:
            return "GDB timeout"
        except Exception as e:
            log.error(f"[CrashAnalyzer] GDB failed: {e}")
            return ""
    
    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute crash analyzer"""
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

    def _detect_crash_type(self, gdb_output: str) -> str:
        """Detect crash type from GDB output"""
        
        if 'SIGSEGV' in gdb_output:
            if 'invalid permissions' in gdb_output:
                return 'segfault_write'
            elif 'address 0x' in gdb_output:
                return 'segfault_read'
            else:
                return 'segfault'
        
        elif 'SIGABRT' in gdb_output:
            return 'abort'
        
        elif 'SIGILL' in gdb_output:
            return 'illegal_instruction'
        
        elif 'SIGFPE' in gdb_output:
            return 'floating_point_exception'
        
        elif 'SIGBUS' in gdb_output:
            return 'bus_error'
        
        elif 'stack smashing detected' in gdb_output:
            return 'stack_smashing'
        
        elif 'double free' in gdb_output:
            return 'double_free'
        
        elif 'heap corruption' in gdb_output:
            return 'heap_corruption'
        
        else:
            return 'unknown'
    
    def _extract_signal(self, gdb_output: str) -> Optional[str]:
        """Extract signal from GDB output"""
        
        match = re.search(r'Program received signal (SIG\\w+)', gdb_output)
        if match:
            return match.group(1)
        
        return None
    
    def _extract_stack_trace(self, gdb_output: str) -> List[str]:
        """Extract stack trace from GDB output"""
        
        stack_trace = []
        
        # Find backtrace section
        bt_match = re.search(r'#0\\s+(.+?)(?:#1|$)', gdb_output, re.DOTALL)
        if bt_match:
            lines = bt_match.group(0).split('\\n')
            for line in lines:
                if line.strip().startswith('#'):
                    stack_trace.append(line.strip())
        
        return stack_trace
    
    def _extract_registers(self, gdb_output: str) -> Dict:
        """Extract register values from GDB output"""
        
        registers = {}
        
        # Extract common registers
        reg_patterns = {
            'rip': r'rip\\s+0x([0-9a-f]+)',
            'rsp': r'rsp\\s+0x([0-9a-f]+)',
            'rbp': r'rbp\\s+0x([0-9a-f]+)',
            'rax': r'rax\\s+0x([0-9a-f]+)',
            'rbx': r'rbx\\s+0x([0-9a-f]+)',
            'rcx': r'rcx\\s+0x([0-9a-f]+)',
            'rdx': r'rdx\\s+0x([0-9a-f]+)',
        }
        
        for reg_name, pattern in reg_patterns.items():
            match = re.search(pattern, gdb_output, re.IGNORECASE)
            if match:
                registers[reg_name] = match.group(1)
        
        return registers
    
    def _generate_signature(self, crash_info: Dict) -> str:
        """Generate unique crash signature"""
        
        # Use crash type + top of stack trace
        signature_parts = [
            crash_info.get('crash_type', 'unknown'),
            crash_info.get('signal', 'unknown')
        ]
        
        # Add top 3 stack frames
        stack_trace = crash_info.get('stack_trace', [])
        for frame in stack_trace[:3]:
            # Extract function name
            func_match = re.search(r'in\\s+(\\w+)', frame)
            if func_match:
                signature_parts.append(func_match.group(1))
        
        return '_'.join(signature_parts)
    
    async def _assess_exploitability(self, crash_info: Dict) -> Dict:
        """
        Assess exploitability of crash
        
        Returns:
            Dict with exploitability assessment
        """
        score = 0
        reasons = []
        
        crash_type = crash_info.get('crash_type', '')
        registers = crash_info.get('registers', {})
        
        # High exploitability indicators
        if crash_type in ['segfault_write', 'heap_corruption', 'double_free']:
            score += 50
            reasons.append(f"Crash type {crash_type} is highly exploitable")
        
        # Check if RIP is controlled
        rip = registers.get('rip', '0')
        if rip and rip.startswith(('41', '42', '43', '44')):  # AAAA, BBBB, etc.
            score += 40
            reasons.append("RIP appears to be controlled")
        
        # Check for stack smashing
        if crash_type == 'stack_smashing':
            score += 30
            reasons.append("Stack buffer overflow detected")
        
        # Medium exploitability
        if crash_type in ['segfault_read', 'segfault']:
            score += 20
            reasons.append("Segfault may be exploitable")
        
        # Low exploitability
        if crash_type in ['abort', 'illegal_instruction']:
            score += 10
            reasons.append("Low exploitability crash type")
        
        # Determine rating
        if score >= 70:
            rating = 'HIGH'
        elif score >= 40:
            rating = 'MEDIUM'
        elif score >= 20:
            rating = 'LOW'
        else:
            rating = 'UNLIKELY'
        
        return {
            'score': score,
            'rating': rating,
            'reasons': reasons
        }
    
    async def deduplicate_crashes(self, crashes: List[Dict]) -> Dict:
        """
        Deduplicate crashes based on signatures with advanced hashing
        
        Args:
            crashes: List of crash analysis results
        
        Returns:
            Dict with unique crashes and deduplication stats
        """
        import hashlib
        
        unique_crashes = {}
        duplicate_count = 0
        
        for crash in crashes:
            # Generate enhanced signature
            signature_data = [
                crash.get('crash_type', ''),
                crash.get('signal', ''),
                str(crash.get('stack_trace', [])[:5]),  # Top 5 frames
                crash.get('registers', {}).get('rip', '')
            ]
            
            # Create hash-based signature
            signature_str = '|'.join(signature_data)
            signature_hash = hashlib.sha256(signature_str.encode()).hexdigest()[:16]
            
            if signature_hash not in unique_crashes:
                unique_crashes[signature_hash] = {
                    'signature': signature_hash,
                    'crash_type': crash.get('crash_type'),
                    'exploitability': crash.get('exploitability', {}),
                    'first_seen': crash.get('crash_file'),
                    'count': 1,
                    'examples': [crash]
                }
            else:
                unique_crashes[signature_hash]['count'] += 1
                if len(unique_crashes[signature_hash]['examples']) < 5:
                    unique_crashes[signature_hash]['examples'].append(crash)
                duplicate_count += 1
        
        return {
            'unique_count': len(unique_crashes),
            'total_count': len(crashes),
            'duplicate_count': duplicate_count,
            'deduplication_rate': f"{(duplicate_count / len(crashes) * 100):.2f}%" if crashes else "0%",
            'unique_crashes': unique_crashes
        }
    
    async def prioritize_crashes(self, crashes: List[Dict]) -> List[Dict]:
        """
        Prioritize crashes by exploitability and uniqueness
        
        Args:
            crashes: List of crash analysis results
        
        Returns:
            Sorted list of crashes (highest priority first)
        """
        def calculate_priority(crash: Dict) -> int:
            priority = 0
            
            # Exploitability score (0-100)
            exploitability = crash.get('exploitability', {})
            priority += exploitability.get('score', 0)
            
            # Crash type priority
            crash_type = crash.get('crash_type', '')
            type_priority = {
                'segfault_write': 50,
                'heap_corruption': 45,
                'double_free': 40,
                'stack_smashing': 35,
                'segfault_read': 20,
                'segfault': 15,
                'abort': 10,
                'illegal_instruction': 5
            }
            priority += type_priority.get(crash_type, 0)
            
            # RIP control bonus
            registers = crash.get('registers', {})
            rip = registers.get('rip', '0')
            if rip and rip.startswith(('41', '42', '43', '44')):
                priority += 50
            
            return priority
        
        # Sort by priority (descending)
        prioritized = sorted(crashes, key=calculate_priority, reverse=True)
        
        # Add priority score to each crash
        for crash in prioritized:
            crash['priority_score'] = calculate_priority(crash)
        
        return prioritized
    
    async def generate_exploitability_report(self, crashes: List[Dict]) -> Dict:
        """
        Generate comprehensive exploitability report
        
        Args:
            crashes: List of crash analysis results
        
        Returns:
            Dict with exploitability statistics and recommendations
        """
        if not crashes:
            return {'error': 'No crashes to analyze'}
        
        # Deduplicate
        dedup_result = await self.deduplicate_crashes(crashes)
        unique_crashes = list(dedup_result['unique_crashes'].values())
        
        # Prioritize
        prioritized = await self.prioritize_crashes(unique_crashes)
        
        # Statistics
        exploitability_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNLIKELY': 0}
        crash_type_counts = {}
        
        for crash in unique_crashes:
            # Count exploitability ratings
            rating = crash.get('exploitability', {}).get('rating', 'UNLIKELY')
            exploitability_counts[rating] = exploitability_counts.get(rating, 0) + 1
            
            # Count crash types
            crash_type = crash.get('crash_type', 'unknown')
            crash_type_counts[crash_type] = crash_type_counts.get(crash_type, 0) + 1
        
        # Top exploitable crashes
        top_exploitable = prioritized[:10]
        
        return {
            'summary': {
                'total_crashes': len(crashes),
                'unique_crashes': dedup_result['unique_count'],
                'deduplication_rate': dedup_result['deduplication_rate'],
                'high_exploitability': exploitability_counts['HIGH'],
                'medium_exploitability': exploitability_counts['MEDIUM'],
                'low_exploitability': exploitability_counts['LOW']
            },
            'exploitability_distribution': exploitability_counts,
            'crash_type_distribution': crash_type_counts,
            'top_exploitable_crashes': top_exploitable,
            'recommendations': self._generate_recommendations(exploitability_counts, crash_type_counts)
        }
    
    def _generate_recommendations(self, exploitability_counts: Dict, crash_type_counts: Dict) -> List[str]:
        """
        Generate recommendations based on crash analysis
        
        Args:
            exploitability_counts: Exploitability distribution
            crash_type_counts: Crash type distribution
        
        Returns:
            List of recommendations
        """
        recommendations = []
        
        if exploitability_counts.get('HIGH', 0) > 0:
            recommendations.append(
                f"⚠️ Found {exploitability_counts['HIGH']} highly exploitable crashes - prioritize these for exploit development"
            )
        
        if crash_type_counts.get('heap_corruption', 0) > 0:
            recommendations.append(
                f"🔥 Found {crash_type_counts['heap_corruption']} heap corruption crashes - excellent candidates for exploitation"
            )
        
        if crash_type_counts.get('stack_smashing', 0) > 0:
            recommendations.append(
                f"📊 Found {crash_type_counts['stack_smashing']} stack buffer overflows - classic exploitation targets"
            )
        
        if exploitability_counts.get('MEDIUM', 0) > 5:
            recommendations.append(
                f"💡 {exploitability_counts['MEDIUM']} medium exploitability crashes - may be exploitable with additional analysis"
            )
        
        if not recommendations:
            recommendations.append(
                "ℹ️ No high-priority exploitable crashes found - consider adjusting fuzzing strategy"
            )
        
        return recommendations


if __name__ == '__main__':
    async def test():
        analyzer = CrashAnalyzer()
        
        result = await analyzer.run({
            'crash_file': '/tmp/crash_input',
            'binary_path': '/usr/bin/file',
            'analyze_exploitability': True
        })
        
        print(f"Analysis result: {result}")
    
    asyncio.run(test())

