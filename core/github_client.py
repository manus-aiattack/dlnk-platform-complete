import httpx
from core.logger import log
from config import settings


class GitHubClient:
    """A client for interacting with the GitHub API to find exploits."""

    def __init__(self):
        self.base_url = "https://api.github.com"
        self.api_key = settings.GITHUB_TOKEN
        self.headers = {
            'Authorization': f'token {self.api_key}',
            'Accept': 'application/vnd.github.v3+json'
        } if self.api_key else {
            'Accept': 'application/vnd.github.v3+json'
        }
        self.client = httpx.AsyncClient(headers=self.headers, timeout=60)

    async def search_exploits(self, query: str) -> list[dict] | None:
        """Searches for repositories containing exploit code related to the query."""
        try:
            # Advanced query: search in name, description, and readme for more relevance
            search_query = f'{query} in:name,description,readme exploit poc cve language:python language:go language:ruby language:c'
            log.info(
                f"GitHub Client: Searching for exploits with query: '{search_query}'...")

            # Sort by best match, then by stars and forks as a fallback
            params = {'q': search_query, 'sort': 'best-match', 'order': 'desc'}
            response = await self.client.get(
                f"{self.base_url}/search/repositories", params=params)
            response.raise_for_status()
            data = response.json()

            if data.get('items'):
                log.success(
                    f"GitHub Client: Found {len(data.get('items'))} potential exploit repositories.")
                # Sort by a combination of stars and forks for better relevance
                sorted_items = sorted(data.get('items'), key=lambda x: x.get(
                    'stargazers_count', 0) + x.get('forks_count', 0), reverse=True)
                return [
                    {
                        'name': item.get('full_name'),
                        'url': item.get('html_url'),
                        'description': item.get('description'),
                        'stars': item.get('stargazers_count'),
                        'forks': item.get('forks_count')}
                    for item in sorted_items
                ]
            else:
                log.warning(
                    f"GitHub Client: No exploit repositories found for query '{query}'.")
                return None

        except httpx.RequestError as e:
            log.error(f"GitHub Client: Failed to connect to GitHub API: {e}")
            return None
        except (KeyError, IndexError) as e:
            log.error(
                f"GitHub Client: Unexpected response structure for query '{query}': {e}")
            return None
