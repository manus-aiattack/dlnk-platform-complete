import asyncio
import os
from typing import List, Dict, Any, Optional
from core.base_agent import BaseAgent
from core.data_models import AgentData, FuzzingReport, Strategy, AttackPhase, ErrorType
from core.logger import log
from config import settings

class AFLAgent(BaseAgent):
    supported_phases = [AttackPhase.INITIAL_FOOTHOLD]
    required_tools = ["afl-fuzz"] # Assuming AFL++ is installed and aliased as afl-fuzz

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.report_class = FuzzingReport
        self.fuzz_output_dir = os.path.join(settings.WORKSPACE_DIR, "fuzzing_results", "afl")
        os.makedirs(self.fuzz_output_dir, exist_ok=True)

    async def run(self, strategy: Strategy = None, **kwargs) -> FuzzingReport:
        target_binary = strategy.context.get("target_binary")
        input_dir = strategy.context.get("input_dir") # Directory with seed inputs
        fuzz_duration = strategy.context.get("fuzz_duration", 3600) # Default 1 hour
        target_args = strategy.context.get("target_args", "@@") # Arguments for the target binary

        if not target_binary or not input_dir:
            return self.create_report(
                errors=["Missing 'target_binary' or 'input_dir' in strategy context."],
                summary="AFLAgent requires target binary and input directory.",
                error_type=ErrorType.CONFIGURATION
            )

        if not os.path.exists(target_binary):
            return self.create_report(
                errors=[f"Target binary not found: {target_binary}"],
                summary=f"AFLAgent failed: Target binary {target_binary} not found.",
                error_type=ErrorType.CONFIGURATION
            )
        if not os.path.isdir(input_dir):
            return self.create_report(
                errors=[f"Input directory not found: {input_dir}"],
                summary=f"AFLAgent failed: Input directory {input_dir} not found.",
                error_type=ErrorType.CONFIGURATION
            )

        session_name = f"afl_fuzz_{os.path.basename(target_binary)}_{os.urandom(4).hex()}"
        output_session_dir = os.path.join(self.fuzz_output_dir, session_name)
        
        # AFL++ command
        # -i: input directory
        # -o: output directory
        # -t: timeout for each test case (ms)
        # -m: memory limit (MB)
        # -V: fuzzing duration (seconds)
        # @@: AFL syntax for input file location (will be replaced by AFL with actual test case)
        afl_command = [
            "afl-fuzz",
            "-i", input_dir,
            "-o", output_session_dir,
            "-t", "100", # 100ms timeout
            "-m", "256", # 256MB memory limit
            "-V", str(fuzz_duration),
            "--", target_binary
        ]
        
        # Append target arguments if provided
        if target_args:
            afl_command.extend(target_args.split())

        log.info(f"AFLAgent: Starting fuzzing for {target_binary} with command: {' '.join(afl_command)}")

        try:
            process = await asyncio.create_subprocess_exec(
                *afl_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            stdout_str = stdout.decode(errors='ignore')
            stderr_str = stderr.decode(errors='ignore')

            if process.returncode == 0:
                summary = f"AFLAgent completed fuzzing for {target_binary}. Output in {output_session_dir}."
                errors = []
                error_type = None
            else:
                summary = f"AFLAgent fuzzing for {target_binary} finished with errors or crashes. Output in {output_session_dir}."
                errors = [f"AFLAgent stderr: {stderr_str}"]
                error_type = ErrorType.LOGIC
                log.error(f"AFLAgent stderr: {stderr_str}")

            return self.create_report(
                summary=summary,
                errors=errors,
                error_type=error_type,
                target_url=target_binary, # Using target_binary as target_url for consistency
                raw_output=stdout_str + stderr_str,
                findings=[{"type": "fuzz_output_dir", "path": output_session_dir}]
            )

        except FileNotFoundError:
            return self.create_report(
                errors=["afl-fuzz command not found. Is AFL++ installed and in PATH?"],
                summary="AFLAgent failed: afl-fuzz not found.",
                error_type=ErrorType.CONFIGURATION
            )
        except Exception as e:
            return self.create_report(
                errors=[f"An unexpected error occurred during AFL fuzzing: {e}"],
                summary=f"AFLAgent failed due to unexpected error: {e}",
                error_type=ErrorType.LOGIC
            )

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute afl agent"""
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
