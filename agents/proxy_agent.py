from core.logger import log
from core.data_models import AgentData, Strategy
import subprocess
import os
import asyncio
import time
import socket
from typing import Optional, Dict

from core.base_agent import BaseAgent
from core.data_models import Strategy, ProxyReport, ErrorType, AttackPhase


class ProxyAgent(BaseAgent):
    supported_phases = [AttackPhase.RECONNAISSANCE, AttackPhase.INITIAL_FOOTHOLD] # Can be used in multiple phases

    def __init__(self, context_manager=None, orchestrator=None, **kwargs):
        super().__init__(context_manager, orchestrator, **kwargs)
        self.proxy_process: Optional[asyncio.subprocess.Process] = None
        self.proxy_port = 8080  # Default mitmproxy port
        self.report_class = ProxyReport

    async def _health_check(self, timeout=15) -> bool:
        """Checks if the proxy is ready to accept connections."""
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                reader, writer = await asyncio.open_connection("127.0.0.1", self.proxy_port)
                writer.close()
                await writer.wait_closed()
                log.success("Proxy health check passed. Port is open.")
                return True
            except (socket.timeout, ConnectionRefusedError):
                await asyncio.sleep(0.5)
        log.error(
            f"Proxy health check failed. Port {self.proxy_port} did not open within {timeout} seconds.")
        return False

    async def _start_proxy(self) -> Dict:
        """Starts the mitmproxy subprocess and waits for it to be ready."""
        log.phase("ProxyAgent: Starting HTTP/HTTPS proxy...")
        if self.proxy_process and self.proxy_process.returncode is None:
            summary = "Proxy is already running."
            log.warning(f"ProxyAgent: {summary}")
            return {"summary": summary, "proxy_status": "already_running", "proxy_port": self.proxy_port}

        try:
            log_file_path = os.path.join(self.context_manager.workspace_dir, "proxy_traffic.jsonl")
            if os.path.exists(log_file_path):
                os.remove(log_file_path)

            addon_path = os.path.join(self.context_manager.workspace_dir, "proxy_addon.py")
            command = [
                "mitmdump",
                "-s", addon_path,
                "--listen-port", str(self.proxy_port),
                "--set", "block_global=false"
            ]

            self.proxy_process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            log.info(
                f"ProxyAgent: mitmdump process started (PID: {self.proxy_process.pid}). Waiting for health check...")

            if not await self._health_check():
                await self._stop_proxy()  # Clean up if health check fails
                return {"summary": "Proxy failed to start or become healthy.", "errors": ["Proxy health check failed."]}

            summary = f"Proxy started successfully on port {self.proxy_port}."
            log.success(f"ProxyAgent: {summary}")
            return {"summary": summary, "proxy_status": "started", "proxy_port": self.proxy_port}

        except FileNotFoundError:
            error = "'mitmdump' command not found. Please install mitmproxy and ensure it is in your PATH."
            log.critical(error)
            return {"summary": "Failed to start proxy: mitmdump not found.", "errors": [error]}
        except Exception as e:
            error = f"Failed to start mitmproxy: {e}"
            log.critical(f"ProxyAgent: {error}", exc_info=True)
            return {"summary": "Failed to start proxy due to an unexpected error.", "errors": [error]}

    async def _stop_proxy(self) -> Dict:
        """Stops the mitmproxy subprocess."""
        log.phase("ProxyAgent: Stopping proxy...")
        if self.proxy_process and self.proxy_process.returncode is None:
            self.proxy_process.terminate()
            try:
                await asyncio.wait_for(self.proxy_process.wait(), timeout=10)
                log.success("ProxyAgent: Proxy stopped gracefully.")
                summary = "Proxy stopped successfully."
            except asyncio.TimeoutError:
                self.proxy_process.kill()
                await self.proxy_process.wait()
                log.warning("ProxyAgent: mitmproxy did not terminate gracefully, killing process.")
                summary = "Proxy killed after failing to stop gracefully."
            self.proxy_process = None
            return {"summary": summary, "proxy_status": "stopped"}
        else:
            summary = "Proxy was not running."
            log.info(f"ProxyAgent: {summary}")
            return {"summary": summary, "proxy_status": "not_running"}

    async def run(self, strategy: Strategy, **kwargs) -> ProxyReport:
        action = strategy.context.get("action", "start") # Default to starting

        if action == "start":
            result = await self._start_proxy()
        elif action == "stop":
            result = await self._stop_proxy()
        else:
            result = {"summary": f"Unknown action '{action}' for ProxyAgent.", "errors": [f"Invalid action: {action}"]}

        # Create a standardized report
        return self.create_report(
            summary=result.get("summary"),
            errors=result.get("errors"),
            error_type=ErrorType.LOGIC if result.get("errors") else None,
            proxy_status=result.get("proxy_status"),
            proxy_port=result.get("proxy_port")
        )

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute proxy agent"""
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

    def get_proxy_env(self) -> dict:
        """Returns the environment variables needed to use the proxy."""
        proxy_url = f"http://127.0.0.1:{self.proxy_port}"
        cert_path = os.path.join(os.path.expanduser(
            "~"), ".mitmproxy", "mitmproxy-ca-cert.pem")
        return {
            "http_proxy": proxy_url,
            "https_proxy": proxy_url,
            # This is often needed for command-line tools that use Python's requests library
            "REQUESTS_CA_BUNDLE": cert_path,
            # This is for other tools that might need the CA explicitly
            "SSL_CERT_FILE": cert_path}
