import os
import base64
import random
from typing import Dict, Any


class PayloadManager:
    """
    Manages the storage, retrieval, and obfuscation of payloads.
    """

    def __init__(self, payload_depot_path: str = "payload_depot"):
        self.payload_depot_path = payload_depot_path
        if not os.path.exists(self.payload_depot_path):
            os.makedirs(self.payload_depot_path, exist_ok=True)

    def get_payload(self, name: str, obfuscate: bool = False) -> Dict[str, Any] | None:
        """
        Retrieves a payload by name, optionally obfuscating it.

        Args:
            name: The name of the payload file to retrieve.
            obfuscate: Whether to apply on-the-fly obfuscation.

        Returns:
            A dictionary containing payload data, or None if not found.
        """
        try:
            payload_path = os.path.join(self.payload_depot_path, name)
            with open(payload_path, "r") as f:
                content = f.read()

            if obfuscate:
                method, obfuscated_content = self._obfuscate_payload(content)
                return {
                    "name": name,
                    "content": obfuscated_content,
                    "obfuscation_method": method}

            return {
                "name": name,
                "content": content,
                "obfuscation_method": "none"}
        except FileNotFoundError:
            return None

    def _obfuscate_payload(self, content: str) -> str:
        """
        Applies a random obfuscation technique (Base64 or XOR).

        Args:
            content: The payload content to obfuscate.

        Returns:
            A tuple containing the obfuscation method and the obfuscated payload.
        """
        method = random.choice(['base64', 'xor'])

        if method == 'base64':
            return 'base64', base64.b64encode(content.encode()).decode()

        elif method == 'xor':
            key = os.urandom(4)
            encoded_content = bytearray()
            for i, byte in enumerate(content.encode()):
                encoded_content.append(byte ^ key[i % len(key)])
            return 'xor', key.hex() + base64.b64encode(bytes(encoded_content)).decode()

    def list_payloads(self) -> list[str]:
        """
        Lists all available payloads in the depot.

        Returns:
            A list of payload names.
        """
        return os.listdir(self.payload_depot_path)
