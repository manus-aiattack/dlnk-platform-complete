import json
from core.logger import log
from core.redis_client import get_redis_client # Changed from redis_client
from core.data_models import Credential
from typing import List


class TargetModel:
    def __init__(self, hostname):
        self.hostname = hostname
        self.ip_addresses = set()
        self.technologies = set()
        self.waf = None
        self.api_endpoints = set()
        self.file_upload_points = []
        self.authentication_details = {}
        self.confirmed_vulnerabilities = []
        self.failed_hypotheses = set()
        self.completed_actions = set()
        self.web_root_path = None
        self.binaries = []
        self.credentials = []

        # --- Post-Exploitation State Flags ---
        self.has_shell: bool = False
        self.shell_ids: List[str] = []
        self.data_harvested: bool = False
        self.data_exfiltrated: bool = False
        self.persistence_established: bool = False
        self.defensive_tools: List[str] = []

        # Initialize all report attributes to None
        self.recon_data = None
        self.waf_report = None
        self.triage_report = None
        self.vulnerability_report = None
        self.exploit_report = None
        self.post_ex_report = None
        self.privilege_escalation_report = None
        self.data_dump_report = None
        self.persistence_report = None
        self.lateral_movement_report = None
        self.bola_report = None
        self.rate_limit_report = None
        self.auth_report = None
        self.xss_report = None
        self.ddos_report = None
        self.bot_deployment_report = None
        self.internal_scan_report = None

    def update_from_internal_scan_report(self, report):
        log.info(
            f"Updating target model with internal scan report for {self.hostname}")
        self.internal_scan_report = report

    def to_dict(self):
        """Serializes the model to a dictionary for JSON storage."""
        serializable_data = self.__dict__.copy()
        if 'credentials' in serializable_data:
            serializable_data['credentials'] = [cred.to_dict()
                                                for cred in serializable_data['credentials']]

        for key, value in serializable_data.items():
            if isinstance(value, set):
                serializable_data[key] = list(value)
            elif hasattr(value, 'to_dict'):
                serializable_data[key] = value.to_dict()
            elif hasattr(value, '__dict__'):
                serializable_data[key] = value.__dict__
        return serializable_data

    @classmethod
    def from_dict(cls, data, logger):
        hostname = data.get("hostname")
        if not hostname:
            logger.error(
                "Cannot create TargetModel from dict: hostname is missing.")
            return None

        model = cls(hostname)

        if 'credentials' in data and data['credentials']:
            model.credentials = [Credential(**cred_data)
                                 for cred_data in data['credentials']]
            del data['credentials']  # Avoid processing it again in the loop

        for key, value in data.items():
            if hasattr(model, key):
                if isinstance(getattr(model, key), set) and isinstance(value, list):
                    setattr(model, key, set(value))
                else:
                    setattr(model, key, value)
        return model

    # All update methods remain the same
    def update_from_triage_report(self, report):
        log.info(
            f"Updating target model with triage report for {self.hostname}")
        self.triage_report = report

    def update_from_scanner_report(self, report):
        log.info(
            f"Updating target model with scanner report for {self.hostname}")
        self.scanner_report = report

    def update_from_vulnerability_report(self, report):
        log.info(
            f"Updating target model with vulnerability report for {self.hostname}")
        self.vulnerability_report = report

    def update_from_exploit_result(self, result):
        log.info(
            f"Updating target model with exploit result for {self.hostname}")
        self.exploit_report = result

    def update_from_post_ex_report(self, report):
        log.info(
            f"Updating target model with post-ex report for {self.hostname}")
        self.post_ex_report = report

    def update_from_privilege_escalation_report(self, report):
        log.info(
            f"Updating target model with privilege escalation report for {self.hostname}")
        self.privilege_escalation_report = report

    def update_from_data_dump_report(self, report):
        log.info(
            f"Updating target model with data dump report for {self.hostname}")
        self.data_dump_report = report

    def update_from_persistence_report(self, report):
        log.info(
            f"Updating target model with persistence report for {self.hostname}")
        self.persistence_report = report

    def update_from_lateral_movement_report(self, report):
        log.info(
            f"Updating target model with lateral movement report for {self.hostname}")
        self.lateral_movement_report = report

    def update_from_bola_report(self, report):
        log.info(f"Updating target model with BOLA report for {self.hostname}")
        self.bola_report = report

    def update_from_rate_limit_report(self, report):
        log.info(
            f"Updating target model with Rate Limit report for {self.hostname}")
        self.rate_limit_report = report

    def update_from_auth_report(self, report):
        log.info(f"Updating target model with Auth report for {self.hostname}")
        self.auth_report = report

    def update_from_xss_report(self, report):
        log.info(f"Updating target model with XSS report for {self.hostname}")
        self.xss_report = report

    def update_from_ddos_report(self, report):
        log.info(f"Updating target model with DDoS report for {self.hostname}")
        self.ddos_report = report

    def update_from_bot_deployment_report(self, report):
        log.info(
            f"Updating target model with Bot Deployment report for {self.hostname}")
        self.bot_deployment_report = report


class TargetModelManager:
    def __init__(self, logger):
        self.logger = logger
        self.targets = {}  # In-memory cache for target models
        self.redis_key_prefix = "target:"
        self.redis = None # Initialize redis client to None

    async def setup(self):
        """Asynchronously sets up the Redis client connection."""
        try:
            self.redis = await get_redis_client()
        except ConnectionError as e:
            self.logger.critical(f"TargetModelManager failed to connect to Redis: {e}")
            raise

    async def get_or_create_target(self, hostname) -> TargetModel:
        if hostname in self.targets:
            return self.targets[hostname]

        if not self.redis:
            self.logger.error("Cannot fetch from Redis; client not available.")
            # Fallback to in-memory only if Redis is down
            target = TargetModel(hostname)
            self.targets[hostname] = target
            return target

        redis_key = f"{self.redis_key_prefix}{hostname}"
        try:
            stored_data = await self.redis.get(redis_key) # Await Redis operation
            if stored_data:
                data = json.loads(stored_data)
                target = TargetModel.from_dict(data, self.logger)
                self.targets[hostname] = target
                self.logger.info(
                    f"Loaded existing state for target from Redis: {hostname}")
                return target
        except Exception as e:
            self.logger.error(
                f"Failed to load target state from Redis for key {redis_key}: {e}")

        self.logger.info(f"Creating new target model for {hostname}")
        target = TargetModel(hostname)
        self.targets[hostname] = target
        await self.save_model(target)  # Save the new model to Redis immediately
        return target

    def get_target(self, hostname) -> TargetModel | None:
        return self.targets.get(hostname)

    def get_all_targets(self) -> list[TargetModel]:
        return list(self.targets.values())

    async def save_model(self, target_model: TargetModel):
        """Saves a single target model to Redis."""
        if not self.redis:
            self.logger.error("Cannot save to Redis; client not available.")
            return

        hostname = target_model.hostname
        redis_key = f"{self.redis_key_prefix}{hostname}"
        try:
            json_data = json.dumps(target_model.to_dict(), default=str)
            await self.redis.set(redis_key, json_data) # Await Redis operation
            self.logger.info(
                f"Successfully saved target state to Redis for {hostname}")
        except Exception as e:
            self.logger.error(
                f"Failed to save target state to Redis for {hostname}: {e}")

    def compare_states(self, old_model: TargetModel, new_model: TargetModel) -> dict:
        """Compares two TargetModel states and returns a summary of differences."""
        if not old_model or not new_model:
            return {"error": "One or both models are null."}

        diff = {}
        # Compare sets
        new_vulns = new_model.confirmed_vulnerabilities - \
            old_model.confirmed_vulnerabilities
        if new_vulns:
            diff["new_vulnerabilities"] = list(new_vulns)

        new_tech = new_model.technologies - old_model.technologies
        if new_tech:
            diff["new_technologies"] = list(new_tech)

        # Compare simple values
        if new_model.waf and new_model.waf != old_model.waf:
            diff["waf_changed"] = {"from": old_model.waf, "to": new_model.waf}

        # Compare reports (check for presence)
        if new_model.post_ex_report and not old_model.post_ex_report:
            diff["new_post_ex_report"] = "Post-exploitation data acquired."

        if new_model.persistence_report and not old_model.persistence_report:
            diff["new_persistence_report"] = "Persistence mechanism established."

        return diff

    async def save_all_models(self):
        """Saves all in-memory target models to Redis."""
        if not self.targets:
            self.logger.info("No target models in memory to save.")
            return
        self.logger.info(f"Saving all {len(self.targets)} models to Redis...")
        for target_model in self.targets.values():
            await self.save_model(target_model) # Await save_model

    async def load_all_models(self):
        """Loads all target models from Redis into the in-memory cache."""
        if not self.redis:
            self.logger.error("Cannot load from Redis; client not available.")
            return self.targets

        self.logger.info(f"Loading all target models from Redis...")
        try:
            keys = []
            async for key in self.redis.scan_iter(f"{self.redis_key_prefix}*"):
                keys.append(key)

            for key in keys:
                hostname = key.decode('utf-8').replace(self.redis_key_prefix, "", 1)
                if hostname not in self.targets:  # Avoid overwriting models already in memory
                    stored_data = await self.redis.get(key) # Await Redis operation
                    if stored_data:
                        data = json.loads(stored_data)
                        target = TargetModel.from_dict(data, self.logger)
                        self.targets[hostname] = target
                        self.logger.info(
                            f"Successfully loaded state for target from Redis: {hostname}")
        except Exception as e:
            self.logger.error(f"Failed to load models from Redis: {e}")
        return self.targets
