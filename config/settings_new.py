"""
Configuration settings for dLNk Attack Platform
All settings are loaded from environment variables
"""

import os
from pathlib import Path
from config.env_loader import (
    get_env, get_env_int, get_env_float, get_env_bool,
    get_database_url, get_redis_url, get_c2_domain
)

# Base paths
BASE_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = BASE_DIR

# Workspace configuration
WORKSPACE_DIR = get_env("WORKSPACE_DIR", str(BASE_DIR / "workspace"))
LOGS_DIR = get_env("LOGS_DIR", str(BASE_DIR / "logs"))
DATA_DIR = get_env("DATA_DIR", str(BASE_DIR / "data"))
REPORTS_DIR = get_env("REPORTS_DIR", str(BASE_DIR / "reports"))

# Create directories if they don't exist
os.makedirs(WORKSPACE_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

# Logging configuration
LOG_LEVEL = get_env("LOG_LEVEL", "INFO")
LOG_FILE = os.path.join(LOGS_DIR, "dlnk.log")
JSON_LOG_FILE = os.path.join(LOGS_DIR, "dlnk.json")

# Database configuration
DATABASE_URL = get_database_url()
REDIS_URL = get_redis_url()
REDIS_HOST = get_env("REDIS_HOST", "localhost")
REDIS_PORT = get_env_int("REDIS_PORT", 6379, min_value=1, max_value=65535)
REDIS_DB = get_env_int("REDIS_DB", 0, min_value=0, max_value=15)

# API configuration
API_HOST = get_env("API_HOST", "0.0.0.0")
API_PORT = get_env_int("API_PORT", 8000, min_value=1, max_value=65535)
API_DEBUG = get_env_bool("API_DEBUG", False)

# Web dashboard configuration
WEB_HOST = get_env("WEB_HOST", "0.0.0.0")
WEB_PORT = get_env_int("WEB_PORT", 3000, min_value=1, max_value=65535)
WEB_DEBUG = get_env_bool("WEB_DEBUG", False)

# Security configuration
SECRET_KEY = get_env("SECRET_KEY", "dlnk-dlnk-secret-key-change-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = get_env_int("JWT_EXPIRATION_HOURS", 24, min_value=1)

# Agent configuration
MAX_CONCURRENT_AGENTS = get_env_int("MAX_CONCURRENT_AGENTS", 5, min_value=1, max_value=100)
AGENT_TIMEOUT = get_env_int("AGENT_TIMEOUT", 300, min_value=1)  # 5 minutes
AGENT_RETRY_ATTEMPTS = get_env_int("AGENT_RETRY_ATTEMPTS", 3, min_value=0, max_value=10)

# Workflow configuration
DEFAULT_WORKFLOW = os.path.join(BASE_DIR, "config", "default_workflow.yaml")
WORKFLOW_TIMEOUT = get_env_int("WORKFLOW_TIMEOUT", 3600, min_value=1)  # 1 hour

# Target configuration
TARGET_TIMEOUT = get_env_int("TARGET_TIMEOUT", 600, min_value=1)  # 10 minutes
MAX_TARGETS = get_env_int("MAX_TARGETS", 100, min_value=1)

# External tools configuration
NMAP_PATH = get_env("NMAP_PATH", "nmap")
METASPLOIT_PATH = get_env("METASPLOIT_PATH", "/usr/share/metasploit-framework")
NUCLEI_PATH = get_env("NUCLEI_PATH", "nuclei")
SQLMAP_PATH = get_env("SQLMAP_PATH", "sqlmap")
WPSCAN_PATH = get_env("WPSCAN_PATH", "wpscan")

# LLM configuration
LLM_PROVIDER = get_env("LLM_PROVIDER", "ollama")
LLM_API_KEY = get_env("LLM_API_KEY", "")
LLM_MODEL = get_env("LLM_MODEL", "mixtral:latest")

# Ollama configuration
OLLAMA_HOST = get_env("OLLAMA_HOST", "localhost")
OLLAMA_PORT = get_env_int("OLLAMA_PORT", 11434, min_value=1, max_value=65535)
OLLAMA_BASE_URL = get_env("OLLAMA_BASE_URL", f"http://{OLLAMA_HOST}:{OLLAMA_PORT}")
OLLAMA_MODEL = get_env("OLLAMA_MODEL", "mixtral:latest")
OLLAMA_TIMEOUT = get_env_int("OLLAMA_TIMEOUT", 300, min_value=1)
LLM_TEMPERATURE = get_env_float("LLM_TEMPERATURE", 0.7, min_value=0.0, max_value=2.0)

# C2 (Command & Control) Configuration
C2_HOST = get_env("C2_HOST", "localhost")
C2_PORT = get_env_int("C2_PORT", 8000, min_value=1, max_value=65535)
C2_PROTOCOL = get_env("C2_PROTOCOL", "http")
C2_DOMAIN = get_c2_domain()

# Web Shell Configuration
WEBSHELL_DEFAULT_PASSWORD = get_env("WEBSHELL_PASSWORD", "changeme")

# Feature flags
SIMULATION_MODE = get_env_bool("SIMULATION_MODE", False)  # False = Live Attack Mode
ENABLE_PERSISTENCE = get_env_bool("ENABLE_PERSISTENCE", True)
ENABLE_LATERAL_MOVEMENT = get_env_bool("ENABLE_LATERAL_MOVEMENT", True)
ENABLE_DATA_EXFILTRATION = get_env_bool("ENABLE_DATA_EXFILTRATION", True)
ENABLE_PRIVILEGE_ESCALATION = get_env_bool("ENABLE_PRIVILEGE_ESCALATION", True)

# Performance configuration
CACHE_ENABLED = get_env_bool("CACHE_ENABLED", True)
CACHE_TTL = get_env_int("CACHE_TTL", 3600, min_value=1)  # 1 hour

# Reporting configuration
REPORT_FORMAT = get_env("REPORT_FORMAT", "html")  # html, pdf, json
REPORT_INCLUDE_PAYLOADS = get_env_bool("REPORT_INCLUDE_PAYLOADS", False)
REPORT_INCLUDE_LOGS = get_env_bool("REPORT_INCLUDE_LOGS", True)

# Proxy configuration
PROXY_ENABLED = get_env_bool("PROXY_ENABLED", False)
PROXY_URL = get_env("PROXY_URL", "")
PROXY_USERNAME = get_env("PROXY_USERNAME", "")
PROXY_PASSWORD = get_env("PROXY_PASSWORD", "")

# Rate limiting
RATE_LIMIT_ENABLED = get_env_bool("RATE_LIMIT_ENABLED", True)
RATE_LIMIT_REQUESTS = get_env_int("RATE_LIMIT_REQUESTS", 100, min_value=1)
RATE_LIMIT_WINDOW = get_env_int("RATE_LIMIT_WINDOW", 60, min_value=1)  # seconds

# Notification configuration
NOTIFICATION_ENABLED = get_env_bool("NOTIFICATION_ENABLED", False)
NOTIFICATION_WEBHOOK = get_env("NOTIFICATION_WEBHOOK", "")
NOTIFICATION_EMAIL = get_env("NOTIFICATION_EMAIL", "")


# Print configuration summary (for debugging)
def print_config_summary():
    """Print configuration summary"""
    print("=" * 60)
    print("dLNk Attack Platform Configuration")
    print("=" * 60)
    print(f"Database URL: {DATABASE_URL[:30]}...")
    print(f"Redis URL: {REDIS_URL}")
    print(f"API: {API_HOST}:{API_PORT}")
    print(f"Web: {WEB_HOST}:{WEB_PORT}")
    print(f"LLM Provider: {LLM_PROVIDER}")
    print(f"Ollama: {OLLAMA_BASE_URL}")
    print(f"C2 Domain: {C2_DOMAIN}")
    print(f"Simulation Mode: {SIMULATION_MODE}")
    print("=" * 60)


if __name__ == "__main__":
    print_config_summary()

