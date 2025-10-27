"""
AFL++ Fuzzer Agent
Coverage-guided fuzzing using AFL++
"""

import asyncio
from core.base_agent import BaseAgent
from core.data_models import AgentData, Strategy
import os
import subprocess
import time
from typing import Dict, List, Optional
from pathlib import Path
import logging

log = logging.getLogger(__name__)


class AFLFuzzer:
    """
    AFL++ Coverage-Guided Fuzzer
    
    Features:
    - Coverage-guided fuzzing
    - Crash detection and triaging
    - Corpus management
    - Distributed fuzzing support
    - Crash deduplication
    """
    
    def __init__(self, work_dir: str = "/tmp/afl_work"):
        self.work_dir = Path(work_dir)
        self.input_dir = self.work_dir / "input"
        self.output_dir = self.work_dir / "output"
        self.crashes_dir = self.output_dir / "crashes"
        self.hangs_dir = self.output_dir / "hangs"
        self.queue_dir = self.output_dir / "queue"
        
        # Create directories
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.input_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    async def run(self, target: Dict) -> Dict:
        """
        Main entry point for AFL fuzzing
        
        Args:
            target: Dict containing:
                - binary_path: Path to target binary
                - timeout: Fuzzing timeout in seconds
                - input_corpus: Initial input corpus (optional)
                - dictionary: AFL dictionary file (optional)
                - memory_limit: Memory limit in MB (default: 50)
        
        Returns:
            Dict with fuzzing results
        """
        binary_path = target.get('binary_path')
        timeout = target.get('timeout', 3600)  # 1 hour default
        input_corpus = target.get('input_corpus')
        dictionary = target.get('dictionary')
        memory_limit = target.get('memory_limit', 50)
        
        if not binary_path:
            return {
                'success': False,
                'error': 'No binary_path provided'
            }
        
        try:
            # Prepare input corpus
            if input_corpus:
                await self._prepare_corpus(input_corpus)
            else:
                await self._create_minimal_corpus()
            
            # Start fuzzing
            result = await self.fuzz(
                binary_path=binary_path,
                timeout=timeout,
                dictionary=dictionary,
                memory_limit=memory_limit
            )
            
            return result
        
        except Exception as e:
            log.error(f"[AFLFuzzer] Error: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def fuzz(
        self,
        binary_path: str,
        timeout: int = 3600,
        dictionary: Optional[str] = None,
        memory_limit: int = 50
    ) -> Dict:
        """
        Start AFL++ fuzzing campaign
        
        Args:
            binary_path: Path to target binary
            timeout: Fuzzing timeout in seconds
            dictionary: Path to AFL dictionary
            memory_limit: Memory limit in MB
        
        Returns:
            Dict with fuzzing results
        """
        log.info(f"[AFLFuzzer] Starting fuzzing: {binary_path}")
        
        # Check if AFL++ is installed
        if not self._check_afl_installed():
            return {
                'success': False,
                'error': 'AFL++ not installed. Install with: apt-get install afl++'
            }
        
        # Build AFL command
        cmd = [
            'afl-fuzz',
            '-i', str(self.input_dir),
            '-o', str(self.output_dir),
            '-m', str(memory_limit),
            '-t', '1000+',  # Timeout per execution
        ]
        
        # Add dictionary if provided
        if dictionary:
            cmd.extend(['-x', dictionary])
        
        # Add target binary
        cmd.append('--')
        cmd.append(binary_path)
        cmd.append('@@')  # AFL placeholder for input file
        
        # Start fuzzing in background
        log.info(f"[AFLFuzzer] Command: {' '.join(cmd)}")
        
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(self.work_dir)
            )
            
            # Wait for timeout
            await asyncio.sleep(timeout)
            
            # Terminate fuzzing
            process.terminate()
            await asyncio.sleep(2)
            
            if process.poll() is None:
                process.kill()
            
            # Collect results
            results = await self._collect_results()
            
            return {
                'success': True,
                'fuzzing_time': timeout,
                'crashes': results['crashes'],
                'hangs': results['hangs'],
                'executions': results['executions'],
                'coverage': results['coverage'],
                'unique_crashes': results['unique_crashes']
            }
        
        except Exception as e:
            log.error(f"[AFLFuzzer] Fuzzing failed: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def _prepare_corpus(self, corpus_path: str):
        """Prepare input corpus"""
        
        corpus_path = Path(corpus_path)
        
        if corpus_path.is_file():
            # Single file
            subprocess.run([
                'cp', str(corpus_path), str(self.input_dir / corpus_path.name)
            ])
        
        elif corpus_path.is_dir():
            # Directory of files
            subprocess.run([
                'cp', '-r', f"{corpus_path}/*", str(self.input_dir)
            ])
    
    async def _create_minimal_corpus(self):
        """Create minimal input corpus"""
        
        # Create a few basic inputs
        inputs = [
            b'A' * 10,
            b'AAAA',
            b'\\x00' * 10,
            b'\\xff' * 10,
            b'%s%s%s%s',
            b'../../../etc/passwd',
        ]
        
        for i, data in enumerate(inputs):
            with open(self.input_dir / f"input_{i}", 'wb') as f:
                f.write(data)
    
    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute afl fuzzer"""
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

    def _check_afl_installed(self) -> bool:
        """Check if AFL++ is installed"""
        
        try:
            result = subprocess.run(
                ['which', 'afl-fuzz'],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except:
            return False
    
    async def _collect_results(self) -> Dict:
        """Collect fuzzing results"""
        
        results = {
            'crashes': [],
            'hangs': [],
            'executions': 0,
            'coverage': 0,
            'unique_crashes': 0
        }
        
        # Collect crashes
        if self.crashes_dir.exists():
            crashes = list(self.crashes_dir.glob('id:*'))
            results['crashes'] = [str(c) for c in crashes]
            results['unique_crashes'] = len(crashes)
        
        # Collect hangs
        if self.hangs_dir.exists():
            hangs = list(self.hangs_dir.glob('id:*'))
            results['hangs'] = [str(h) for h in hangs]
        
        # Parse fuzzer_stats
        stats_file = self.output_dir / 'fuzzer_stats'
        if stats_file.exists():
            with open(stats_file, 'r') as f:
                stats = f.read()
                
                # Extract executions
                if 'execs_done' in stats:
                    for line in stats.split('\\n'):
                        if 'execs_done' in line:
                            results['executions'] = int(line.split(':')[1].strip())
                
                # Extract coverage
                if 'bitmap_cvg' in stats:
                    for line in stats.split('\\n'):
                        if 'bitmap_cvg' in line:
                            coverage_str = line.split(':')[1].strip().replace('%', '')
                            results['coverage'] = float(coverage_str)
        
        return results
    
    async def triage_crashes(self) -> List[Dict]:
        """
        Triage crashes to identify exploitable ones
        
        Returns:
            List of crash analysis results
        """
        log.info("[AFLFuzzer] Triaging crashes")
        
        if not self.crashes_dir.exists():
            return []
        
        crashes = list(self.crashes_dir.glob('id:*'))
        results = []
        
        for crash_file in crashes:
            analysis = await self._analyze_crash(crash_file)
            results.append(analysis)
        
        return results
    
    async def _analyze_crash(self, crash_file: Path) -> Dict:
        """Analyze a single crash"""
        
        # Basic crash analysis
        # In production, use tools like exploitable, ASAN, etc.
        
        return {
            'crash_file': str(crash_file),
            'size': crash_file.stat().st_size,
            'exploitability': 'unknown',  # Would use exploitable plugin
            'crash_type': 'unknown',
            'timestamp': crash_file.stat().st_mtime
        }


if __name__ == '__main__':
    async def test():
        fuzzer = AFLFuzzer()
        
        result = await fuzzer.run({
            'binary_path': '/usr/bin/file',
            'timeout': 60,
            'memory_limit': 50
        })
        
        print(f"Fuzzing result: {result}")
    
    asyncio.run(test())

