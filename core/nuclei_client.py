# core/nuclei_client.py

import subprocess
import json
import os
from typing import List, Dict
from core.logger import log
import config


class NucleiClient:
    """
    A client to interact with Nuclei for vulnerability scanning, optimized for JSON output.
    """

    def __init__(self):
        self.nuclei_path = config.NUCLEI_PATH
        # The base path where all nuclei-templates are stored.
        self.templates_base_path = os.path.expanduser(
            config.NUCLEI_TEMPLATES_PATH)
        log.info(
            f"Initializing NucleiClient. Path: {self.nuclei_path}, Templates Base: {self.templates_base_path}")
        self.update_templates()

    def is_installed(self) -> bool:
        try:
            subprocess.run([self.nuclei_path, "-version"],
                           capture_output=True, check=True, text=True)
            log.info("Nuclei is installed and accessible.")
            return True
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            log.error(f"Nuclei is not installed or not in PATH: {e}")
            return False

    def update_templates(self):
        log.info("Checking for Nuclei template updates...")
        try:
            # Run `nuclei -update-templates` command
            process = subprocess.run(
                [self.nuclei_path, "-ut"],
                capture_output=True,
                text=True,
                check=True
            )
            log.success("Nuclei templates updated successfully.")
            log.info(process.stdout)
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            log.error(f"Failed to update Nuclei templates: {e}")
            if hasattr(e, 'stderr') and e.stderr:
                log.error(e.stderr)

    def get_templates_path(self) -> str:
        return self.templates_base_path

    def run_scan(self, target_url: str, templates: List[str] = None, tags: List[str] = None, severities: List[str] = None, exclude_templates: List[str] = None) -> List[Dict]:
        """
        Runs a Nuclei scan with advanced template and filtering options.
        """
        if not self.is_installed():
            log.error("Cannot run Nuclei scan: Nuclei is not installed.")
            return []

        command = [self.nuclei_path, "-u", target_url,
                   "-json", "-silent", "-no-color"]

        if templates:
            for t in templates:
                command.extend(["-t", t])
        if tags:
            command.extend(["-tags", ",".join(tags)])
        if severities:
            command.extend(["-severity", ",".join(severities)])
        if exclude_templates:
            for et in exclude_templates:
                command.extend(["-et", et])

        # If no specific filters are provided, run a default set of checks.
        if not templates and not tags and not severities:
            log.warning(
                "No specific Nuclei templates or filters specified. Running with default high/critical severity checks.")
            command.extend(["-severity", "high,critical"])

        log.info(f"Running Nuclei scan with command: {' '.join(command)}")
        findings = []
        try:
            # Use a context manager to ensure the process is handled correctly
            with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as process:
                for line in process.stdout:
                    try:
                        finding = json.loads(line)
                        findings.append(finding)
                    except json.JSONDecodeError:
                        log.warning(
                            f"Could not decode JSON line from Nuclei output: {line.strip()}")

                stderr_output = process.stderr.read()
                if stderr_output:
                    log.warning(
                        f"Nuclei scan produced stderr output: {stderr_output.strip()}")

            log.success(
                f"Nuclei scan completed. Found {len(findings)} potential vulnerabilities.")
            return findings

        except FileNotFoundError:
            log.error(
                f"Nuclei executable not found at {self.nuclei_path}. Ensure it's installed and in PATH.")
            return []
        except Exception as e:
            log.error(
                f"An unexpected error occurred during Nuclei scan: {e}",
                exc_info=True)
            return []
