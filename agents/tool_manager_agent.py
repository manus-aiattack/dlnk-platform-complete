import asyncio
from core.base_agent import BaseAgent
from core.data_models import AgentData, Strategy, ErrorType, ToolManagerReport
from core.logger import log
import os
import time

class ToolManagerAgent(BaseAgent):
    """
    Manages the dynamic installation and configuration of tools.
    """
    required_tools = [] # This agent manages tools, so it doesn't strictly require external ones for itself

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.pubsub_manager = self.orchestrator.pubsub_manager
        self.report_class = ToolManagerReport
        self.tool_install_commands = {
            "nmap": "sudo apt-get update && sudo apt-get install -y nmap",
            "nuclei": "go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest",
            "subfinder": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "theharvester": "sudo apt-get install -y theharvester",
            "dirsearch": "pip install dirsearch",
            "whatweb": "sudo apt-get install -y whatweb",
            "feroxbuster": "curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-linux.sh | sudo bash",
            "sqlmap": "sudo apt-get install -y sqlmap",
            "hydra": "sudo apt-get install -y hydra",
            "wpscan": "sudo apt-get install -y wpscan",
            "commix": "sudo apt-get install -y commix",
            "dalfox": "go install github.com/hahwul/dalfox@latest",
            "katana": "go install github.com/projectdiscovery/katana/cmd/katana@latest",
            "ffuf": "go install github.com/ffuf/ffuf@latest",
            "gitleaks": "go install github.com/zricethezav/gitleaks@latest",
            "testssl.sh": "git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh",
            "impacket": "pip install impacket",
            "python-nmap": "pip install python-nmap"
            # Add more tools and their installation commands as needed
        }

    async def run(self, strategy: Strategy) -> ToolManagerReport:
        start_time = time.time()
        directive = strategy.directive
        
        if "install tool" in directive:
            tool_name = strategy.context.get("tool_name")
            if tool_name:
                return await self.install_tool(tool_name, start_time)
            else:
                end_time = time.time()
                return self.create_report(
                    errors=["Tool name not specified for installation."],
                    error_type=ErrorType.CONFIGURATION,
                    summary="Tool installation failed: Tool name missing.",
                    action="install tool"
                )
        elif "configure tool" in directive:
            tool_name = strategy.context.get("tool_name")
            config_data = strategy.context.get("config_data")
            if tool_name and config_data:
                return await self.configure_tool(tool_name, config_data, start_time)
            else:
                end_time = time.time()
                return self.create_report(
                    errors=["Tool name or config data not specified for configuration."],
                    error_type=ErrorType.CONFIGURATION,
                    summary="Tool configuration failed: Missing tool name or config data.",
                    action="configure tool"
                )
        elif "verify tool" in directive:
            tool_name = strategy.context.get("tool_name")
            if tool_name:
                return await self.verify_tool(tool_name, start_time)
            else:
                end_time = time.time()
                return self.create_report(
                    errors=["Tool name not specified for verification."],
                    error_type=ErrorType.CONFIGURATION,
                    summary="Tool verification failed: Tool name missing.",
                    action="verify tool"
                )
        else:
            end_time = time.time()
            return self.create_report(
                errors=[f"Unknown directive for ToolManagerAgent: {directive}"],
                error_type=ErrorType.LOGIC,
                summary=f"Unknown directive for ToolManagerAgent: {directive}",
                action="unknown"
            )

    async def install_tool(self, tool_name: str, start_time: float) -> ToolManagerReport:
        log.info(f"ToolManagerAgent: Attempting to install tool: {tool_name}")
        install_command = self.tool_install_commands.get(tool_name)

        if not install_command:
            end_time = time.time()
            return self.create_report(
                errors=[f"Installation command for tool '{tool_name}' not found."],
                error_type=ErrorType.CONFIGURATION,
                summary=f"Tool installation failed: No installation command for '{tool_name}'.",
                tool_name=tool_name,
                action="install tool"
            )

        try:
            log.info(f"ToolManagerAgent: Executing installation command: {install_command}")
            result = await self.orchestrator.run_shell_command(install_command)

            if result["exit_code"] == 0:
                log.success(f"ToolManagerAgent: Successfully installed tool: {tool_name}")
                await self.pubsub_manager.publish(
                    "tool_events",
                    {
                        "event_type": "TOOL_INSTALLED",
                        "tool_name": tool_name,
                        "timestamp": time.time()
                    }
                )
                end_time = time.time()
                return self.create_report(
                    summary=f"Tool '{tool_name}' installed successfully.",
                    tool_name=tool_name,
                    action="install tool",
                    output=result.get("stdout")
                )
            else:
                error_message = result["stderr"] or f"Installation failed with exit code {result['exit_code']}"
                log.error(f"ToolManagerAgent: Failed to install tool '{tool_name}': {error_message}")
                end_time = time.time()
                return self.create_report(
                    errors=[f"Failed to install tool '{tool_name}': {error_message}"],
                    error_type=ErrorType.LOGIC,
                    summary=f"Tool installation failed for '{tool_name}'.",
                    tool_name=tool_name,
                    action="install tool",
                    output=result.get("stdout") + result.get("stderr")
                )

        except Exception as e:
            log.error(f"ToolManagerAgent: An unexpected error occurred during installation of '{tool_name}': {e}", exc_info=True)
            end_time = time.time()
            return self.create_report(
                errors=[f"An unexpected error occurred during installation: {e}"],
                error_type=ErrorType.LOGIC,
                summary=f"Tool installation failed due to unexpected error: {e}",
                tool_name=tool_name,
                action="install tool"
            )

    async def configure_tool(self, tool_name: str, config_data: dict, start_time: float) -> ToolManagerReport:
        log.info(f"ToolManagerAgent: Attempting to configure tool: {tool_name}")
        
        # Implement actual configuration based on tool type
        try:
            config_applied = False
            config_details = []
            
            # Metasploit configuration
            if tool_name == "metasploit":
                if "database" in config_data:
                    db_config = config_data["database"]
                    result = await self.orchestrator.run_shell_command(
                        f"msfdb init && msfconsole -x 'db_connect {db_config}; exit'"
                    )
                    config_applied = result["exit_code"] == 0
                    config_details.append("Database configured")
            
            # Nmap configuration
            elif tool_name == "nmap":
                if "timing" in config_data:
                    # Store in environment or config file
                    import os
                    os.environ["NMAP_TIMING"] = str(config_data["timing"])
                    config_applied = True
                    config_details.append(f"Timing template set to {config_data['timing']}")
            
            # Impacket configuration
            elif tool_name == "impacket":
                if "target_domain" in config_data:
                    # Store in context for later use
                    if self.context_manager:
                        self.context_manager.set("impacket_domain", config_data["target_domain"])
                    config_applied = True
                    config_details.append(f"Target domain set to {config_data['target_domain']}")
            
            # Generic configuration via config file
            else:
                config_file = f"/tmp/{tool_name}.conf"
                import json
                with open(config_file, 'w') as f:
                    json.dump(config_data, f, indent=2)
                config_applied = True
                config_details.append(f"Configuration written to {config_file}")
            
            end_time = time.time()
            if config_applied:
                summary = f"Tool '{tool_name}' configured successfully: {', '.join(config_details)}"
                log.success(f"ToolManagerAgent: {summary}")
                return self.create_report(
                    summary=summary,
                    tool_name=tool_name,
                    action="configure tool",
                    output=str(config_data)
                )
            else:
                summary = f"No configuration applied for '{tool_name}' - tool may not require configuration"
                log.info(f"ToolManagerAgent: {summary}")
                return self.create_report(
                    summary=summary,
                    tool_name=tool_name,
                    action="configure tool"
                )
        
        except Exception as e:
            log.error(f"ToolManagerAgent: Configuration failed: {e}")
            end_time = time.time()
            return self.create_report(
                errors=[str(e)],
                error_type=ErrorType.LOGIC,
                summary=f"Configuration for '{tool_name}' failed: {e}",
                tool_name=tool_name,
                action="configure tool"
            )

    async def verify_tool(self, tool_name: str, start_time: float) -> ToolManagerReport:
        log.info(f"ToolManagerAgent: Verifying installation of tool: {tool_name}")
        
        # Implement comprehensive verification based on tool type
        # Map tool names to verification commands
        verification_commands = {
            "nmap": "nmap --version",
            "metasploit": "msfconsole --version",
            "sqlmap": "sqlmap --version",
            "nikto": "nikto -Version",
            "wpscan": "wpscan --version",
            "gobuster": "gobuster version",
            "ffuf": "ffuf -V",
            "hydra": "hydra -h | head -1",
            "john": "john --version",
            "hashcat": "hashcat --version",
            "aircrack-ng": "aircrack-ng --version",
            "burpsuite": "which burpsuite",
            "wireshark": "wireshark --version",
            "tcpdump": "tcpdump --version",
            "testssl.sh": "testssl.sh --version",
            "impacket": "python3 -c 'import impacket; print(impacket.__version__)'",
            "python-nmap": "python3 -c 'import nmap; print(nmap.__version__)'",
            "requests": "python3 -c 'import requests; print(requests.__version__)'",
            "beautifulsoup4": "python3 -c 'import bs4; print(bs4.__version__)'"
        }
        
        check_command = verification_commands.get(tool_name, f"which {tool_name}")


        try:
            result = await self.orchestrator.run_shell_command(check_command)
            if result["exit_code"] == 0:
                summary = f"Tool '{tool_name}' verified successfully."
                log.success(f"ToolManagerAgent: {summary}")
                end_time = time.time()
                return self.create_report(
                    summary=summary,
                    tool_name=tool_name,
                    action="verify tool",
                    output=result.get("stdout")
                )
            else:
                error_message = result["stderr"] or f"Verification failed with exit code {result['exit_code']}"
                log.warning(f"ToolManagerAgent: Tool '{tool_name}' verification failed: {error_message}")
                end_time = time.time()
                return self.create_report(
                    errors=[f"Tool '{tool_name}' verification failed: {error_message}"],
                    error_type=ErrorType.LOGIC,
                    summary=f"Tool '{tool_name}' verification failed.",
                    tool_name=tool_name,
                    action="verify tool",
                    output=result.get("stdout") + result.get("stderr")
                )
        except Exception as e:
            log.error(f"ToolManagerAgent: An unexpected error occurred during verification of '{tool_name}': {e}", exc_info=True)
            end_time = time.time()
            return self.create_report(
                errors=[f"An unexpected error occurred during verification: {e}"],
                error_type=ErrorType.LOGIC,
                summary=f"Tool verification failed due to unexpected error: {e}",
                tool_name=tool_name,
                action="verify tool"
            )

    async def execute(self, strategy: Strategy) -> AgentData:
        """Execute tool manager agent"""
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
