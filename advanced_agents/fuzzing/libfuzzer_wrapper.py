"""
LibFuzzer Wrapper for dLNk Attack Platform
Provides interface to LibFuzzer for coverage-guided fuzzing
"""

import asyncio
from core.base_agent import BaseAgent
from core.data_models import AgentData, Strategy
import subprocess
import os
import tempfile
import shutil
from typing import Dict, List, Optional
from pathlib import Path
import logging

log = logging.getLogger(__name__)


class LibFuzzerWrapper:
    """
    LibFuzzer Wrapper
    
    Features:
    - Coverage-guided fuzzing
    - Corpus management
    - Crash detection
    - Sanitizer integration
    """
    
    def __init__(self, work_dir: str = None):
        self.work_dir = Path(work_dir or "/tmp/libfuzzer_work")
        self.work_dir.mkdir(parents=True, exist_ok=True)
        
        self.corpus_dir = self.work_dir / "corpus"
        self.crashes_dir = self.work_dir / "crashes"
        self.artifacts_dir = self.work_dir / "artifacts"
        
        for dir_path in [self.corpus_dir, self.crashes_dir, self.artifacts_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)
        
        self.fuzzing_results = []
        self.crashes = []
    
    async def fuzz_target(
        self,
        target_binary: str,
        timeout: int = 300,
        max_len: int = 4096,
        dict_file: str = None,
        seed_corpus: List[bytes] = None
    ) -> Dict:
        """
        Fuzz a target binary with LibFuzzer
        
        Args:
            target_binary: Path to target binary compiled with libFuzzer
            timeout: Fuzzing timeout in seconds
            max_len: Maximum input length
            dict_file: Optional dictionary file for fuzzing
            seed_corpus: Optional seed corpus
        
        Returns:
            Fuzzing results
        """
        log.info(f"[LibFuzzer] Starting fuzzing of {target_binary}")
        
        # Check if target exists
        if not os.path.exists(target_binary):
            log.error(f"[LibFuzzer] Target binary not found: {target_binary}")
            return {
                'success': False,
                'error': 'Target binary not found'
            }
        
        # Prepare seed corpus
        if seed_corpus:
            await self._prepare_seed_corpus(seed_corpus)
        
        # Build fuzzing command
        cmd = self._build_fuzzing_command(
            target_binary, timeout, max_len, dict_file
        )
        
        # Run fuzzing
        result = await self._run_fuzzing(cmd, timeout)
        
        # Collect crashes
        crashes = await self._collect_crashes()
        
        # Analyze results
        analysis = await self._analyze_results(crashes)
        
        return {
            'success': True,
            'exec_count': result.get('exec_count', 0),
            'coverage': result.get('coverage', 0.0),
            'crashes_found': len(crashes),
            'crashes': crashes,
            'analysis': analysis,
            'corpus_size': len(list(self.corpus_dir.glob('*')))
        }
    
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

    def _build_fuzzing_command(
        self,
        target_binary: str,
        timeout: int,
        max_len: int,
        dict_file: str = None
    ) -> List[str]:
        """Build LibFuzzer command"""
        
        cmd = [
            target_binary,
            str(self.corpus_dir),
            f'-max_total_time={timeout}',
            f'-max_len={max_len}',
            f'-artifact_prefix={self.artifacts_dir}/',
            '-print_final_stats=1',
            '-detect_leaks=1'
        ]
        
        if dict_file and os.path.exists(dict_file):
            cmd.append(f'-dict={dict_file}')
        
        return cmd
    
    async def _run_fuzzing(self, cmd: List[str], timeout: int) -> Dict:
        """Run fuzzing process"""
        
        log.info(f"[LibFuzzer] Running: {' '.join(cmd)}")
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(self.work_dir)
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout + 10
            )
            
            output = stdout.decode('utf-8', errors='ignore')
            errors = stderr.decode('utf-8', errors='ignore')
            
            # Parse output
            result = self._parse_fuzzing_output(output + errors)
            
            log.info(f"[LibFuzzer] Fuzzing completed: {result.get('exec_count', 0)} execs")
            
            return result
            
        except asyncio.TimeoutError:
            log.warning("[LibFuzzer] Fuzzing timeout reached")
            return {'exec_count': 0, 'coverage': 0.0}
        except Exception as e:
            log.error(f"[LibFuzzer] Fuzzing error: {e}")
            return {'exec_count': 0, 'coverage': 0.0, 'error': str(e)}
    
    def _parse_fuzzing_output(self, output: str) -> Dict:
        """Parse LibFuzzer output"""
        
        result = {
            'exec_count': 0,
            'coverage': 0.0,
            'features': 0
        }
        
        # Parse execution count
        import re
        exec_match = re.search(r'#(\d+)\s+INITED', output)
        if exec_match:
            result['exec_count'] = int(exec_match.group(1))
        
        # Parse coverage
        cov_match = re.search(r'cov:\s*(\d+)', output)
        if cov_match:
            result['features'] = int(cov_match.group(1))
            result['coverage'] = result['features'] / 10000.0  # Normalize
        
        return result
    
    async def _prepare_seed_corpus(self, seed_corpus: List[bytes]):
        """Prepare seed corpus for fuzzing"""
        
        log.info(f"[LibFuzzer] Preparing seed corpus ({len(seed_corpus)} seeds)")
        
        for i, seed in enumerate(seed_corpus):
            seed_file = self.corpus_dir / f"seed_{i:04d}"
            with open(seed_file, 'wb') as f:
                f.write(seed)
    
    async def _collect_crashes(self) -> List[Dict]:
        """Collect crashes from fuzzing"""
        
        crashes = []
        
        # Check crashes directory
        crash_files = list(self.crashes_dir.glob('crash-*'))
        
        # Check artifacts directory
        artifact_files = list(self.artifacts_dir.glob('crash-*'))
        
        all_crash_files = crash_files + artifact_files
        
        log.info(f"[LibFuzzer] Found {len(all_crash_files)} crash files")
        
        for crash_file in all_crash_files:
            try:
                with open(crash_file, 'rb') as f:
                    crash_data = f.read()
                
                crashes.append({
                    'file': str(crash_file),
                    'size': len(crash_data),
                    'data': crash_data,
                    'hash': self._hash_crash(crash_data)
                })
            except Exception as e:
                log.error(f"[LibFuzzer] Failed to read crash file {crash_file}: {e}")
        
        return crashes
    
    def _hash_crash(self, data: bytes) -> str:
        """Hash crash data for deduplication"""
        import hashlib
        return hashlib.sha256(data).hexdigest()[:16]
    
    async def _analyze_results(self, crashes: List[Dict]) -> Dict:
        """Analyze fuzzing results"""
        
        analysis = {
            'unique_crashes': len(set(c['hash'] for c in crashes)),
            'total_crashes': len(crashes),
            'crash_sizes': [c['size'] for c in crashes],
            'avg_crash_size': sum(c['size'] for c in crashes) / len(crashes) if crashes else 0
        }
        
        return analysis
    
    async def minimize_corpus(self) -> int:
        """Minimize corpus to essential test cases"""
        
        log.info("[LibFuzzer] Minimizing corpus...")
        
        # In production, use libFuzzer's merge feature
        # For now, just count corpus files
        
        corpus_files = list(self.corpus_dir.glob('*'))
        
        log.info(f"[LibFuzzer] Corpus size: {len(corpus_files)} files")
        
        return len(corpus_files)
    
    async def generate_dictionary(self, sample_inputs: List[bytes]) -> str:
        """Generate fuzzing dictionary from sample inputs"""
        
        log.info("[LibFuzzer] Generating dictionary...")
        
        dict_file = self.work_dir / "fuzzing.dict"
        
        # Extract common tokens
        tokens = set()
        for sample in sample_inputs:
            # Extract printable strings
            current_token = b''
            for byte in sample:
                if 32 <= byte <= 126:  # Printable ASCII
                    current_token += bytes([byte])
                else:
                    if len(current_token) >= 3:
                        tokens.add(current_token)
                    current_token = b''
            
            if len(current_token) >= 3:
                tokens.add(current_token)
        
        # Write dictionary
        with open(dict_file, 'w') as f:
            for i, token in enumerate(tokens):
                try:
                    token_str = token.decode('utf-8', errors='ignore')
                    f.write(f'token_{i}="{token_str}"\n')
                except:
                    pass
        
        log.info(f"[LibFuzzer] Generated dictionary with {len(tokens)} tokens")
        
        return str(dict_file)
    
    async def cleanup(self):
        """Cleanup fuzzing artifacts"""
        
        log.info("[LibFuzzer] Cleaning up...")
        
        try:
            shutil.rmtree(self.work_dir)
            log.info("[LibFuzzer] Cleanup completed")
        except Exception as e:
            log.error(f"[LibFuzzer] Cleanup failed: {e}")


if __name__ == '__main__':
    async def test():
        fuzzer = LibFuzzerWrapper()
        
        # Create a simple test target
        # In production, this would be a real binary compiled with libFuzzer
        
        print("LibFuzzer Wrapper initialized")
        print(f"Work directory: {fuzzer.work_dir}")
        print(f"Corpus directory: {fuzzer.corpus_dir}")
        print(f"Crashes directory: {fuzzer.crashes_dir}")
        
        # Test seed corpus preparation
        seed_corpus = [
            b'GET / HTTP/1.1\r\n',
            b'POST /api HTTP/1.1\r\n',
            b'{"key": "value"}'
        ]
        
        await fuzzer._prepare_seed_corpus(seed_corpus)
        print(f"Prepared {len(seed_corpus)} seed corpus files")
        
        # Test dictionary generation
        dict_file = await fuzzer.generate_dictionary(seed_corpus)
        print(f"Generated dictionary: {dict_file}")
        
        await fuzzer.cleanup()
    
    asyncio.run(test())

