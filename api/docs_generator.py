"""
API Documentation Generator
Automatically generates OpenAPI/Swagger documentation
"""

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from typing import Dict, Any
import json


def custom_openapi(app: FastAPI) -> Dict[str, Any]:
    """
    Generate custom OpenAPI schema with enhanced documentation
    """
    if app.openapi_schema:
        return app.openapi_schema
    
    openapi_schema = get_openapi(
        title="dLNk Attack Platform API",
        version="2.0.0",
        description="""
# dLNk Attack Platform API

AI-Powered Cybersecurity Testing Platform

## Authentication

All API endpoints require an API key. Include your key in the `X-API-Key` header:

```bash
curl -H "X-API-Key: your-api-key" https://api.dlnk.com/api/v1/attacks
```

## Rate Limiting

- **Free tier**: 100 requests/hour
- **Pro tier**: 1000 requests/hour
- **Enterprise**: Unlimited

## Endpoints

### Attack Management
- `POST /api/v1/attacks` - Launch new attack
- `GET /api/v1/attacks/{id}` - Get attack status
- `GET /api/v1/attacks` - List all attacks
- `DELETE /api/v1/attacks/{id}` - Cancel attack

### Authentication
- `POST /api/v1/auth/login` - Login with API key
- `POST /api/v1/auth/verify` - Verify API key

### Admin
- `GET /api/v1/admin/keys` - List API keys
- `POST /api/v1/admin/keys` - Create API key
- `DELETE /api/v1/admin/keys/{id}` - Revoke API key
- `GET /api/v1/admin/stats` - Get statistics

### Statistics
- `GET /api/v1/stats/dashboard` - Dashboard statistics
- `GET /api/v1/stats/attack-history` - Attack history data

## WebSocket

Real-time updates via WebSocket:

```javascript
const ws = new WebSocket('ws://localhost:8000/ws');
ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    console.log('Update:', data);
};
```

## Error Responses

All errors follow this format:

```json
{
    "detail": "Error message",
    "error_code": "ERROR_CODE",
    "timestamp": "2025-10-26T12:00:00Z"
}
```

### Common Error Codes

- `401` - Unauthorized (Invalid API key)
- `403` - Forbidden (Insufficient permissions)
- `404` - Not Found
- `429` - Too Many Requests (Rate limit exceeded)
- `500` - Internal Server Error

## Examples

### Launch Attack

```bash
curl -X POST https://api.dlnk.com/api/v1/attacks \\
  -H "X-API-Key: your-api-key" \\
  -H "Content-Type: application/json" \\
  -d '{
    "target_url": "https://example.com",
    "mode": "auto"
  }'
```

### Get Attack Status

```bash
curl https://api.dlnk.com/api/v1/attacks/abc123 \\
  -H "X-API-Key: your-api-key"
```

### List Attacks

```bash
curl https://api.dlnk.com/api/v1/attacks?limit=10&status=running \\
  -H "X-API-Key: your-api-key"
```

## SDKs

Official SDKs available for:
- Python
- JavaScript/TypeScript
- Go
- Ruby

## Support

- Documentation: https://docs.dlnk.com
- API Status: https://status.dlnk.com
- Support: support@dlnk.com
        """,
        routes=app.routes,
    )
    
    # Add security schemes
    openapi_schema["components"]["securitySchemes"] = {
        "APIKeyHeader": {
            "type": "apiKey",
            "in": "header",
            "name": "X-API-Key",
            "description": "API Key for authentication"
        }
    }
    
    # Add security requirement to all endpoints
    for path in openapi_schema["paths"].values():
        for operation in path.values():
            if isinstance(operation, dict):
                operation["security"] = [{"APIKeyHeader": []}]
    
    # Add tags
    openapi_schema["tags"] = [
        {
            "name": "Authentication",
            "description": "API key authentication and verification"
        },
        {
            "name": "Attacks",
            "description": "Attack management and execution"
        },
        {
            "name": "Admin",
            "description": "Administrative operations (Admin only)"
        },
        {
            "name": "Statistics",
            "description": "Statistics and analytics"
        },
        {
            "name": "WebSocket",
            "description": "Real-time updates via WebSocket"
        }
    ]
    
    # Add examples
    openapi_schema["components"]["examples"] = {
        "AttackRequest": {
            "summary": "Launch Attack",
            "value": {
                "target_url": "https://example.com",
                "mode": "auto",
                "agents": ["SQLMapAgent", "XSSHunter"]
            }
        },
        "AttackResponse": {
            "summary": "Attack Response",
            "value": {
                "attack_id": "abc123",
                "target_url": "https://example.com",
                "status": "running",
                "progress": 25,
                "started_at": "2025-10-26T12:00:00Z"
            }
        }
    }
    
    app.openapi_schema = openapi_schema
    return app.openapi_schema


def generate_api_docs(app: FastAPI, output_file: str = "api_documentation.json"):
    """
    Generate API documentation and save to file
    """
    schema = custom_openapi(app)
    
    with open(output_file, 'w') as f:
        json.dump(schema, f, indent=2)
    
    print(f"API documentation generated: {output_file}")
    return schema


def generate_markdown_docs(app: FastAPI, output_file: str = "API_DOCUMENTATION.md"):
    """
    Generate Markdown documentation
    """
    schema = custom_openapi(app)
    
    md_content = f"""# {schema['info']['title']}

Version: {schema['info']['version']}

{schema['info']['description']}

## Base URL

```
http://localhost:8000
```

## Authentication

All API endpoints require an API key in the `X-API-Key` header.

## Endpoints

"""
    
    # Generate endpoint documentation
    for path, methods in schema['paths'].items():
        for method, details in methods.items():
            if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                md_content += f"### {method.upper()} {path}\n\n"
                md_content += f"{details.get('summary', 'No description')}\n\n"
                
                if 'description' in details:
                    md_content += f"{details['description']}\n\n"
                
                # Parameters
                if 'parameters' in details:
                    md_content += "**Parameters:**\n\n"
                    for param in details['parameters']:
                        required = " (required)" if param.get('required') else ""
                        md_content += f"- `{param['name']}` ({param['in']}){required}: {param.get('description', '')}\n"
                    md_content += "\n"
                
                # Request body
                if 'requestBody' in details:
                    md_content += "**Request Body:**\n\n"
                    md_content += "```json\n"
                    md_content += "{\n  // Request body schema\n}\n"
                    md_content += "```\n\n"
                
                # Responses
                if 'responses' in details:
                    md_content += "**Responses:**\n\n"
                    for code, response in details['responses'].items():
                        md_content += f"- `{code}`: {response.get('description', '')}\n"
                    md_content += "\n"
                
                md_content += "---\n\n"
    
    with open(output_file, 'w') as f:
        f.write(md_content)
    
    print(f"Markdown documentation generated: {output_file}")
    return md_content


if __name__ == "__main__":
    from api.main import app
    
    # Generate JSON documentation
    generate_api_docs(app)
    
    # Generate Markdown documentation
    generate_markdown_docs(app)

