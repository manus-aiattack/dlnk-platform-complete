
from core.logger import log
from core.redis_client import redis_client
import json
from core.data_models import VulnerabilityFinding, PrivilegeEscalationVector


class KnowledgeBaseManager:
    def __init__(self):
        if not redis_client:
            log.critical(
                "Redis client is not available. KnowledgeBaseManager cannot function.")
            raise ConnectionError("Failed to connect to Redis.")
        self.redis = redis_client
        self.prefix = "kb:"

    def add_vulnerability(self, finding: VulnerabilityFinding):
        """Adds a structured vulnerability finding to the KB."""
        if not finding.cve:
            return
        try:
            key = f"{self.prefix}vulnerability:{finding.cve}"
            self.redis.hset(key, mapping={
                "score": finding.score,
                "description": finding.description,
                "port": finding.port,
                "protocol": finding.protocol
            })
            log.info(
                f"Added vulnerability {finding.cve} to the knowledge base.")
        except Exception as e:
            log.error(f"Failed to add vulnerability {finding.cve} to KB: {e}")

    def add_heuristic(self, heuristic_type: str, key: str, value: dict):
        """Adds a learned heuristic to the KB."""
        try:
            redis_key=f"{self.prefix}heuristic:{heuristic_type}:{key}"
            self.redis.set(redis_key, json.dumps(value))
            log.info(f"Added heuristic '{key}' to the knowledge base.")
        except Exception as e:
            log.error(f"Failed to add heuristic to KB: {e}")

    def search_by_tag(self, tag: str) -> list:
        """Searches for entries by a specific tag (e.g., CVE, RCE)."""
        # This is a simplified search. A real implementation would use Redis Search.
        results=[]
        try:
            for key in self.redis.scan_iter(f"{self.prefix}vulnerability:*C*V*E*-*{tag}*"):
                results.append(self.redis.hgetall(key))
        except Exception as e:
            log.error(f"Error searching KB by tag '{tag}': {e}")
        return results
