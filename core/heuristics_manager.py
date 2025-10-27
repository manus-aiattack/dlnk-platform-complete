
from core.logger import log
from core.redis_client import get_redis_client # Changed from redis_client
import json
import time
from enum import Enum


def _prepare_for_json(obj):
    if isinstance(obj, dict):
        return {k: _prepare_for_json(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_prepare_for_json(i) for i in obj]
    elif isinstance(obj, Enum):
        return obj.name
    return obj


class HeuristicsManager:
    def __init__(self):
        self.redis = None # Initialize redis client to None
        self.success_prefix = "heuristic:success:"
        self.failure_prefix = "heuristic:failure:"

    async def setup(self):
        """Asynchronously sets up the Redis client connection."""
        try:
            self.redis = await get_redis_client()
        except ConnectionError as e:
            log.critical(f"HeuristicsManager failed to connect to Redis: {e}")
            raise

    async def add_heuristic(self, heuristic_type: str, key: str, strategy: dict, report: dict, context_snapshot: dict):
        """
        Adds or updates a learned heuristic based on a successful action.
        """
        if not self.redis:
            log.error("Redis client not initialized in HeuristicsManager.")
            return
        try:
            redis_key = f"{self.success_prefix}{heuristic_type}"
            strategy_to_store = _prepare_for_json(strategy)
            report_to_store = _prepare_for_json(report)
            context_to_store = _prepare_for_json(context_snapshot)
            value = {
                "strategy": strategy_to_store,
                "report_data": report_to_store,
                "context_snapshot": context_to_store,
                "timestamp": time.time()}
            await self.redis.hset(redis_key, key, json.dumps(value)) # Await Redis operation
            log.info(f"Added successful heuristic for {heuristic_type}: {key}")
        except Exception as e:
            log.error(
                f"Failed to add successful heuristic for {heuristic_type}: {e}")

    async def add_failed_heuristic(self, heuristic_type: str, key: str, strategy: dict, report: dict, context_snapshot: dict):
        """
        Adds a record of a failed action.
        """
        if not self.redis:
            log.error("Redis client not initialized in HeuristicsManager.")
            return
        try:
            redis_key = f"{self.failure_prefix}{heuristic_type}"
            strategy_to_store = _prepare_for_json(strategy)
            report_to_store = _prepare_for_json(report)
            context_to_store = _prepare_for_json(context_snapshot)

            value = {
                "strategy": strategy_to_store,
                "report_data": report_to_store,
                "context_snapshot": context_to_store,
                "timestamp": time.time()}
            await self.redis.hset(redis_key, key, json.dumps(value)) # Await Redis operation
            log.info(f"Added failed heuristic for {heuristic_type}: {key} (Error Type: {report.get('error_type', 'UNKNOWN')})")
        except Exception as e:
            log.error(
                f"Failed to add failed heuristic for {heuristic_type}: {e}")

    async def get_heuristics_by_type(self, heuristic_type: str) -> dict:
        """
        Retrieves all successful heuristics of a specific type.
        """
        if not self.redis:
            log.error("Redis client not initialized in HeuristicsManager.")
            return {}
        try:
            redis_key = f"{self.success_prefix}{heuristic_type}"
            raw_heuristics = await self.redis.hgetall(redis_key) # Await Redis operation

            deserialized_heuristics = {}
            for key, value in raw_heuristics.items():
                deserialized_heuristics[key] = json.loads(value)

            return deserialized_heuristics
        except Exception as e:
            log.error(f"Failed to get heuristics for {heuristic_type}: {e}")
            return {}

    async def get_all_heuristics(self) -> dict:
        """
        Retrieves all learned successful heuristics across all types.
        """
        if not self.redis:
            log.error("Redis client not initialized in HeuristicsManager.")
            return {}
        all_heuristics = {}
        try:
            key_list = []
            async for key in self.redis.scan_iter(f"{self.success_prefix}*"):
                key_list.append(key.decode('utf-8'))

            for key in key_list:
                heuristic_type = key.replace(self.success_prefix, "", 1)
                all_heuristics[heuristic_type] = await self.get_heuristics_by_type(
                    heuristic_type)
            return all_heuristics
        except Exception as e:
            log.error(f"Failed to get all heuristics: {e}")
            return {}

    async def get_all_failed_heuristics(self) -> dict:
        """
        Retrieves all learned failed heuristics across all types.
        """
        if not self.redis:
            log.error("Redis client not initialized in HeuristicsManager.")
            return {}
        all_failed = {}
        try:
            key_list = []
            async for key in self.redis.scan_iter(f"{self.failure_prefix}*"):
                key_list.append(key.decode('utf-8'))

            for key in key_list:
                heuristic_type = key.replace(self.failure_prefix, "", 1)
                raw_heuristics = await self.redis.hgetall(key) # Await Redis operation
                deserialized = {}
                for h_key, h_val in raw_heuristics.items():
                    deserialized[h_key] = json.loads(h_val)
                all_failed[heuristic_type] = deserialized
            return all_failed
        except Exception as e:
            log.error(f"Failed to get all failed heuristics: {e}")
            return {}

    async def get_successful_actions(self) -> dict:
        """Alias for get_all_heuristics for compatibility."""
        return await self.get_all_heuristics()

    async def get_failed_actions(self) -> dict:
        """Alias for get_all_failed_heuristics for compatibility."""
        return await self.get_all_failed_heuristics()
