
import httpx
import asyncio
from config import settings
import time
import time
from core.logger import log
import time
import time


class NVDClient:
    """A client for interacting with the NVD API."""

    def __init__(self):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.api_key = settings.NVD_API_KEY
        self.headers = {'apiKey': self.api_key} if self.api_key else {}
        self.client = httpx.AsyncClient(headers=self.headers, timeout=60)
        self.request_delay = 0.6 if self.api_key else 6.0
        self.last_request_time = 0

    async def _enforce_rate_limit(self):
        current_time = time.time()
        time_since_last_request = current_time - self.last_request_time
        if time_since_last_request < self.request_delay:
            await asyncio.sleep(self.request_delay - time_since_last_request)
        self.last_request_time = time.time()

    async def search_by_cve(self, cve_id: str) -> dict | None:
        """Searches for a specific CVE ID."""
        await self._enforce_rate_limit()

        try:
            log.info(f"NVD Client: Searching for {cve_id}...")
            response = await self.client.get(f"{self.base_url}?cveId={cve_id}")
            response.raise_for_status()
            data = response.json()

            if data.get('vulnerabilities'):
                log.success(f"NVD Client: Found data for {cve_id}.")
                return data['vulnerabilities'][0].get('cve')
            else:
                log.warning(f"NVD Client: No data found for {cve_id}.")
                return None

        except httpx.RequestError as e:
            log.error(f"NVD Client: Failed to connect to NVD API: {e}")
            return None
        except (KeyError, IndexError) as e:
            log.error(
                f"NVD Client: Unexpected response structure for {cve_id}: {e}")
            return None

    async def search_by_keyword(self, keyword: str) -> list[dict] | None:
        """Searches for CVEs by keyword."""
        await self._enforce_rate_limit()

        try:
            log.info(f"NVD Client: Searching for keyword '{keyword}'...")
            params = {'keywordSearch': keyword}
            response = await self.client.get(self.base_url, params=params)
            response.raise_for_status()
            data = response.json()

            if data.get('vulnerabilities'):
                log.success(
                    f"NVD Client: Found {len(data.get('vulnerabilities'))} CVEs for keyword '{keyword}'.")
                return [v.get('cve') for v in data.get('vulnerabilities')]
            else:
                log.warning(
                    f"NVD Client: No data found for keyword '{keyword}'.")
                return None

        except httpx.RequestError as e:
            log.error(f"NVD Client: Failed to connect to NVD API: {e}")
            return None
        except (KeyError, IndexError) as e:
            log.error(
                f"NVD Client: Unexpected response structure for keyword '{keyword}': {e}")
            return None
