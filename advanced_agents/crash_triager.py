"""
Crash Triage System
วิเคราะห์ crashes จาก fuzzing และประเมิน exploitability
"""

import os
import asyncio
import subprocess
import re
from typing import Dict, List, Any, Optional
from datetime import datetime
from core.logger import log
from core.base_agent import BaseAgent
from core.data_models import AgentData, AttackPhase


class CrashTriager(BaseAgent):
    """
    Triage crashes and determine exploitability
    
    Features:
    - Analyze crash type (SIGSEGV, SIGABRT, etc.)
    - Determine exploitability
    - Extract crash information
    - Prioritize crashes by severity
    """
    
    supported_phases = [AttackPhase.EXPLOITATION, AttackPhase.POST_EXPLOITATION]
    required_tools = []
    
    def __init__(self, context_manager=None, orchestrator=None, workspace_dir: str = None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        if workspace_dir is None:
            workspace_dir = os.getenv("WORKSPACE_DIR", "workspace")
        self.workspace_dir = workspace_dir
        os.makedirs(workspace_dir, exist_ok=True)
    
    async def run(self, directive: str, context: Dict[str, Any]) -> AgentData:
        """
        Main entry point for CrashTriager
        
        Args:
            directive: "triage" or "analyze"
            context: Dict containing crash_file, binary, and other parameters
        
        Returns:
            AgentData with execution results
        """
        try:
            log.info(f"[CrashTriager] Starting execution with directive: {directive}")
            
            crash_file = context.get("crash_file")
            binary = context.get("binary")
            
            if not crash_file or not binary:
                return AgentData(
                    agent_name="CrashTriager",
                    success=False,
                    data={"error": "crash_file and binary are required"}
                )
            
            result = await self.triage_crash(crash_file, binary)
            
            return AgentData(
                agent_name="CrashTriager",
                success=result.get("exploitable", False),
                data=result
            )
        
        except Exception as e:
            log.error(f"[CrashTriager] Error: {e}")
            return AgentData(
                agent_name="CrashTriager",
                success=False,
                data={"error": str(e)}
            )
    

    async def triage_crash(self, crash_file: str, binary: str) -> Dict:
        """
        Analyze crash and determine exploitability
        
        Args:
            crash_file: Path to crash input file
            binary: Path to target binary
        
        Returns:
            Dict with crash analysis
        """
        try:
            log.info(f"[CrashTriager] Triaging crash: {crash_file}")
            
            # Run with GDB to get crash info
            gdb_output = await self._run_gdb_analysis(crash_file, binary)
            
            # Parse crash information
            crash_info = self._parse_gdb_output(gdb_output)
            
            # Determine crash type
            crash_type = self._parse_crash_type(gdb_output)
            
            # Assess exploitability
            exploitability = self._assess_exploitability(crash_type, crash_info)
            
            # Extract additional information
            registers = self._extract_registers(gdb_output)
            backtrace = self._extract_backtrace(gdb_output)
            
            result = {
                "crash_file": crash_file,
                "binary": binary,
                "crash_type": crash_type,
                "exploitable": exploitability["exploitable"],
                "severity": exploitability["severity"],
                "confidence": exploitability.get("confidence", "medium"),
                "registers": registers,
                "backtrace": backtrace,
                "details": crash_info,
                "timestamp": datetime.now().isoformat()
            }
            
            # Save triage results
            self._save_triage_results(crash_file, result)
            
            if result["exploitable"]:
                log.success(f"[CrashTriager] Exploitable crash found! Severity: {result['severity']}")
            else:
                log.info(f"[CrashTriager] Non-exploitable crash. Type: {crash_type}")
            
            return result
            
        except Exception as e:
            log.error(f"[CrashTriager] Triage failed: {e}")
            return {
                "crash_file": crash_file,
                "binary": binary,
                "error": str(e),
                "exploitable": False,
                "severity": "unknown"
            }
    
    async def triage_multiple_crashes(self, crash_dir: str, binary: str) -> List[Dict]:
        """
        Triage multiple crashes from a directory
        
        Args:
            crash_dir: Directory containing crash files
            binary: Path to target binary
        
        Returns:
            List of crash analysis results
        """
        import glob
        
        crash_files = glob.glob(f"{crash_dir}/*")
        log.info(f"[CrashTriager] Triaging {len(crash_files)} crashes")
        
        results = []
        for crash_file in crash_files:
            result = await self.triage_crash(crash_file, binary)
            results.append(result)
            
            # Small delay to avoid overwhelming the system
            await asyncio.sleep(0.1)
        
        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
        results.sort(key=lambda x: severity_order.get(x.get("severity", "unknown"), 99))
        
        # Summary
        exploitable_count = sum(1 for r in results if r.get("exploitable"))
        log.info(f"[CrashTriager] Found {exploitable_count}/{len(results)} exploitable crashes")
        
        return results
    
    async def _run_gdb_analysis(self, crash_file: str, binary: str) -> str:
        """
        Run GDB to analyze crash
        
        Args:
            crash_file: Path to crash input
            binary: Path to binary
        
        Returns:
            GDB output as string
        """
        # Create GDB command file
        gdb_commands = f"""
set pagination off
set confirm off
run < {crash_file}
info registers
backtrace
quit
"""
        
        cmd_file = f"/tmp/gdb_commands_{os.getpid()}.txt"
        with open(cmd_file, 'w') as f:
            f.write(gdb_commands)
        
        try:
            # Run GDB
            process = await asyncio.create_subprocess_exec(
                'gdb', '-batch', '-x', cmd_file, binary,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=30.0
            )
            
            output = stdout.decode('utf-8', errors='ignore')
            
            # Clean up
            os.remove(cmd_file)
            
            return output
            
        except asyncio.TimeoutError:
            log.warning("[CrashTriager] GDB analysis timed out")
            return ""
        except FileNotFoundError:
            log.error("[CrashTriager] GDB not found. Install with: apt-get install gdb")
            return ""
        except Exception as e:
            log.error(f"[CrashTriager] GDB analysis failed: {e}")
            return ""
    
    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute crash triager"""
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

    def _parse_gdb_output(self, gdb_output: str) -> Dict:
        """Parse GDB output for crash information"""
        
        info = {
            "signal": None,
            "fault_address": None,
            "instruction": None
        }
        
        # Extract signal
        signal_match = re.search(r'Program received signal (\w+)', gdb_output)
        if signal_match:
            info["signal"] = signal_match.group(1)
        
        # Extract fault address
        fault_match = re.search(r'0x([0-9a-f]+) in', gdb_output)
        if fault_match:
            info["fault_address"] = fault_match.group(1)
        
        # Extract instruction
        inst_match = re.search(r'=>\s+0x[0-9a-f]+.*?:\s+(.+)', gdb_output)
        if inst_match:
            info["instruction"] = inst_match.group(1).strip()
        
        return info
    
    def _parse_crash_type(self, gdb_output: str) -> str:
        """
        Determine crash type from GDB output
        
        Returns:
            Crash type string
        """
        if "SIGSEGV" in gdb_output:
            # Determine if read, write, or execute
            if "write" in gdb_output.lower() or "Cannot access memory" in gdb_output:
                return "write_access_violation"
            elif "read" in gdb_output.lower():
                return "read_access_violation"
            elif "execute" in gdb_output.lower() or "Cannot execute" in gdb_output:
                return "execute_access_violation"
            else:
                return "segmentation_fault"
        
        elif "SIGABRT" in gdb_output:
            if "corrupted" in gdb_output.lower() or "heap" in gdb_output.lower():
                return "heap_corruption"
            else:
                return "abort"
        
        elif "SIGILL" in gdb_output:
            return "illegal_instruction"
        
        elif "SIGFPE" in gdb_output:
            return "floating_point_exception"
        
        elif "SIGBUS" in gdb_output:
            return "bus_error"
        
        else:
            return "unknown"
    
    def _assess_exploitability(self, crash_type: str, crash_info: Dict) -> Dict:
        """
        Assess exploitability based on crash type and information
        
        Returns:
            Dict with exploitability assessment
        """
        # Exploitability mapping
        exploitability_map = {
            "write_access_violation": {
                "exploitable": True,
                "severity": "high",
                "confidence": "high",
                "reason": "Write access violation can lead to arbitrary write"
            },
            "execute_access_violation": {
                "exploitable": True,
                "severity": "critical",
                "confidence": "high",
                "reason": "Execute access violation indicates potential code execution"
            },
            "heap_corruption": {
                "exploitable": True,
                "severity": "high",
                "confidence": "medium",
                "reason": "Heap corruption can be exploited for arbitrary code execution"
            },
            "segmentation_fault": {
                "exploitable": True,
                "severity": "medium",
                "confidence": "medium",
                "reason": "Segmentation fault may be exploitable depending on context"
            },
            "read_access_violation": {
                "exploitable": False,
                "severity": "low",
                "confidence": "high",
                "reason": "Read access violation typically not exploitable"
            },
            "illegal_instruction": {
                "exploitable": True,
                "severity": "medium",
                "confidence": "low",
                "reason": "Illegal instruction may indicate control flow hijacking"
            },
            "abort": {
                "exploitable": False,
                "severity": "info",
                "confidence": "high",
                "reason": "Abort signal typically not exploitable"
            },
            "floating_point_exception": {
                "exploitable": False,
                "severity": "low",
                "confidence": "high",
                "reason": "FPE typically not exploitable"
            },
            "bus_error": {
                "exploitable": True,
                "severity": "medium",
                "confidence": "medium",
                "reason": "Bus error may indicate memory corruption"
            },
            "unknown": {
                "exploitable": False,
                "severity": "info",
                "confidence": "low",
                "reason": "Unknown crash type"
            }
        }
        
        return exploitability_map.get(crash_type, exploitability_map["unknown"])
    
    def _extract_registers(self, gdb_output: str) -> Dict:
        """Extract register values from GDB output"""
        
        registers = {}
        
        # Common registers to extract
        reg_patterns = [
            r'rax\s+0x([0-9a-f]+)',
            r'rbx\s+0x([0-9a-f]+)',
            r'rcx\s+0x([0-9a-f]+)',
            r'rdx\s+0x([0-9a-f]+)',
            r'rsi\s+0x([0-9a-f]+)',
            r'rdi\s+0x([0-9a-f]+)',
            r'rbp\s+0x([0-9a-f]+)',
            r'rsp\s+0x([0-9a-f]+)',
            r'rip\s+0x([0-9a-f]+)',
            r'eax\s+0x([0-9a-f]+)',
            r'ebx\s+0x([0-9a-f]+)',
            r'ecx\s+0x([0-9a-f]+)',
            r'edx\s+0x([0-9a-f]+)',
            r'esi\s+0x([0-9a-f]+)',
            r'edi\s+0x([0-9a-f]+)',
            r'ebp\s+0x([0-9a-f]+)',
            r'esp\s+0x([0-9a-f]+)',
            r'eip\s+0x([0-9a-f]+)',
        ]
        
        for pattern in reg_patterns:
            match = re.search(pattern, gdb_output)
            if match:
                reg_name = pattern.split(r'\s')[0]
                registers[reg_name] = match.group(1)
        
        return registers
    
    def _extract_backtrace(self, gdb_output: str) -> List[str]:
        """Extract backtrace from GDB output"""
        
        backtrace = []
        
        # Find backtrace section
        bt_match = re.search(r'#0\s+(.+?)(?:\n(?!#)\n|$)', gdb_output, re.DOTALL)
        if bt_match:
            bt_lines = bt_match.group(0).split('\n')
            for line in bt_lines:
                if line.strip().startswith('#'):
                    backtrace.append(line.strip())
        
        return backtrace
    
    def _save_triage_results(self, crash_file: str, results: Dict) -> str:
        """Save triage results to file"""
        import json
        
        filename = f"{self.workspace_dir}/triage_{os.path.basename(crash_file)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        log.info(f"[CrashTriager] Triage results saved to {filename}")
        return filename

