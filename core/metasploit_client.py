# core/metasploit_client.py

import pymetasploit3.msfrpc
from config import settings
from core.logger import log


class MetasploitClient:
    def __init__(self):
        self.client = None
        try:
            self.client = pymetasploit3.msfrpc.MsfRpcClient(
                password=settings.MSF_RPC_PASS,
                port=settings.MSF_RPC_PORT,
                user=settings.MSF_RPC_USER,
                ssl=False
            )
            if self.client.authenticated:
                log.success(
                    "Successfully authenticated with Metasploit RPC daemon.")
            else:
                log.error("Failed to authenticate with Metasploit RPC daemon.")
                self.client = None

        except Exception as e:
            log.error(f"Failed to connect to Metasploit RPC daemon: {e}")

    def is_connected(self) -> bool:
        return self.client is not None and self.client.authenticated

    def execute_module(self, module_type: str, module_name: str, options: dict) -> dict:
        if not self.is_connected():
            return {"error": "Not connected to Metasploit RPC."}

        try:
            module = self.client.modules.use(module_type, module_name)
            for key, value in options.items():
                module[key] = value

            result = module.execute()
            return result
        except Exception as e:
            log.error(f"Failed to execute Metasploit module: {e}")
            return {"error": str(e)}

    def list_sessions(self) -> dict:
        if not self.is_connected():
            return {"error": "Not connected to Metasploit RPC."}

        return self.client.sessions.list

    def get_session(self, session_id: str):
        if not self.is_connected():
            return None

        return self.client.sessions.session(session_id)
