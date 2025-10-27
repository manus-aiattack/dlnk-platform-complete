import yaml
import json
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
import requests

class APIParameter(BaseModel):
    """Data model for an API parameter."""
    name: str
    in_: str = Field(..., alias="in")
    description: Optional[str] = None
    required: bool = False
    schema_: Optional[Dict[str, Any]] = Field(None, alias="schema")

class APIEndpoint(BaseModel):
    """Data model for an API endpoint."""
    path: str
    method: str
    summary: Optional[str] = None
    description: Optional[str] = None
    parameters: List[APIParameter] = []
    responses: Dict[str, Any] = {}
    security: List[Dict[str, Any]] = []

class OpenAPIParser:
    """
    Parses OpenAPI/Swagger documentation to discover API endpoints.
    """

    def __init__(self, schema_path: str):
        """
        Initializes the parser with the path to the schema file or URL.

        Args:
            schema_path: The path to the OpenAPI schema file (JSON or YAML) or a URL.
        """
        self.schema_path = schema_path
        self.schema = self._load_schema()

    def _load_schema(self) -> Dict[str, Any]:
        """
        Loads the OpenAPI schema from a file or URL.
        Supports both JSON and YAML formats.
        """
        try:
            if self.schema_path.startswith("http"):
                response = requests.get(self.schema_path)
                response.raise_for_status()
                if self.schema_path.endswith(".json"):
                    return response.json()
                else:
                    return yaml.safe_load(response.text)
            else:
                with open(self.schema_path, "r") as f:
                    if self.schema_path.endswith(".json"):
                        return json.load(f)
                    else:
                        return yaml.safe_load(f)
        except Exception as e:
            print(f"Error loading schema: {e}")
            return {}

    def get_endpoints(self) -> List[APIEndpoint]:
        """
        Parses the schema and returns a list of API endpoints.
        """
        endpoints = []
        paths = self.schema.get("paths", {})
        for path, path_item in paths.items():
            for method, operation in path_item.items():
                if method in ["get", "post", "put", "delete", "patch", "options", "head"]:
                    parameters = [APIParameter(**param) for param in operation.get("parameters", [])]
                    endpoint = APIEndpoint(
                        path=path,
                        method=method,
                        summary=operation.get("summary"),
                        description=operation.get("description"),
                        parameters=parameters,
                        responses=operation.get("responses", {}),
                        security=operation.get("security", []),
                    )
                    endpoints.append(endpoint)
        return endpoints

    def get_high_risk_endpoints(self) -> List[APIEndpoint]:
        """
        Identifies and returns a list of high-risk endpoints.
        This is a simple implementation that looks for keywords in the summary and description.
        """
        high_risk_keywords = ["payment", "user", "admin", "account", "password", "credit_card"]
        high_risk_endpoints = []
        for endpoint in self.get_endpoints():
            summary = endpoint.summary.lower() if endpoint.summary else ""
            description = endpoint.description.lower() if endpoint.description else ""
            if any(keyword in summary or keyword in description for keyword in high_risk_keywords):
                high_risk_endpoints.append(endpoint)
        return high_risk_endpoints