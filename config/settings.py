"""
Configuration settings for dLNk dLNk Framework
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Base paths
BASE_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = BASE_DIR

# Workspace configuration
WORKSPACE_DIR = os.getenv("WORKSPACE_DIR", str(BASE_DIR / "workspace"))
LOGS_DIR = os.getenv("LOGS_DIR", str(BASE_DIR / "logs"))
DATA_DIR = os.getenv("DATA_DIR", str(BASE_DIR / "data"))
REPORTS_DIR = os.getenv("REPORTS_DIR", str(BASE_DIR / "reports"))

# Create directories if they don't exist
os.makedirs(WORKSPACE_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

# Logging configuration
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE = os.path.join(LOGS_DIR, "dlnk.log")
JSON_LOG_FILE = os.path.join(LOGS_DIR, "dlnk.json")

# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://dlnk_user:dlnk_password@localhost/dlnk_attack_db")

# PostgreSQL individual settings (for legacy code compatibility)
DATABASE_HOST = os.getenv("DB_HOST", "localhost")
DATABASE_PORT = int(os.getenv("DB_PORT", 5432))
DATABASE_USER = os.getenv("DB_USER", "dlnk_user")
DATABASE_PASSWORD = os.getenv("DB_PASSWORD", "")
DATABASE_NAME = os.getenv("DB_NAME", "dlnk")

# Redis configuration
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))

# API configuration
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", 8000))
API_DEBUG = os.getenv("API_DEBUG", "False").lower() == "true"

# Web dashboard configuration
WEB_HOST = os.getenv("WEB_HOST", "0.0.0.0")
WEB_PORT = int(os.getenv("WEB_PORT", 3000))
WEB_DEBUG = os.getenv("WEB_DEBUG", "False").lower() == "true"

# Security configuration
SECRET_KEY = os.getenv("SECRET_KEY", "dlnk-dlnk-secret-key-change-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

# Agent configuration
MAX_CONCURRENT_AGENTS = int(os.getenv("MAX_CONCURRENT_AGENTS", 5))
AGENT_TIMEOUT = int(os.getenv("AGENT_TIMEOUT", 300))  # 5 minutes
AGENT_RETRY_ATTEMPTS = int(os.getenv("AGENT_RETRY_ATTEMPTS", 3))

# Workflow configuration
DEFAULT_WORKFLOW = os.path.join(BASE_DIR, "config", "default_workflow.yaml")
WORKFLOW_TIMEOUT = int(os.getenv("WORKFLOW_TIMEOUT", 3600))  # 1 hour

# Target configuration
TARGET_TIMEOUT = int(os.getenv("TARGET_TIMEOUT", 600))  # 10 minutes
MAX_TARGETS = int(os.getenv("MAX_TARGETS", 100))

# External tools configuration
NMAP_PATH = os.getenv("NMAP_PATH", "nmap")
METASPLOIT_PATH = os.getenv("METASPLOIT_PATH", "/usr/share/metasploit-framework")
NUCLEI_PATH = os.getenv("NUCLEI_PATH", "nuclei")
SQLMAP_PATH = os.getenv("SQLMAP_PATH", "sqlmap")
WPSCAN_PATH = os.getenv("WPSCAN_PATH", "wpscan")

# LLM configuration
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "ollama")
LLM_API_KEY = os.getenv("LLM_API_KEY", "")
LLM_MODEL = os.getenv("LLM_MODEL", "mixtral:latest")

# Ollama configuration
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "mixtral:latest")
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", 300))
LLM_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0.7"))

# Vanchin AI configuration
VANCHIN_API_URL = os.getenv("VANCHIN_API_URL", "https://vanchin.streamlake.ai/api/gateway/v1/endpoints/chat/completions")
VANCHIN_MODEL = os.getenv("VANCHIN_MODEL", "ep-x4jt3z-1761493764663181818")
VANCHIN_API_KEYS = os.getenv("VANCHIN_API_KEYS", "")
VANCHIN_MAX_TOKENS = int(os.getenv("VANCHIN_MAX_TOKENS", 150000))
VANCHIN_RATE_LIMIT = int(os.getenv("VANCHIN_RATE_LIMIT", 20))

# Feature flags
SIMULATION_MODE = os.getenv("SIMULATION_MODE", "False").lower() == "true"  # False = Live Attack Mode
ENABLE_PERSISTENCE = os.getenv("ENABLE_PERSISTENCE", "True").lower() == "true"
ENABLE_LATERAL_MOVEMENT = os.getenv("ENABLE_LATERAL_MOVEMENT", "True").lower() == "true"
ENABLE_DATA_EXFILTRATION = os.getenv("ENABLE_DATA_EXFILTRATION", "True").lower() == "true"
ENABLE_PRIVILEGE_ESCALATION = os.getenv("ENABLE_PRIVILEGE_ESCALATION", "True").lower() == "true"

# Performance configuration
CACHE_ENABLED = os.getenv("CACHE_ENABLED", "True").lower() == "true"
CACHE_TTL = int(os.getenv("CACHE_TTL", 3600))  # 1 hour

# Reporting configuration
REPORT_FORMAT = os.getenv("REPORT_FORMAT", "html")  # html, pdf, json
REPORT_INCLUDE_PAYLOADS = os.getenv("REPORT_INCLUDE_PAYLOADS", "False").lower() == "true"
REPORT_INCLUDE_LOGS = os.getenv("REPORT_INCLUDE_LOGS", "True").lower() == "true"

# Proxy configuration
PROXY_ENABLED = os.getenv("PROXY_ENABLED", "False").lower() == "true"
PROXY_URL = os.getenv("PROXY_URL", "")
PROXY_USERNAME = os.getenv("PROXY_USERNAME", "")
PROXY_PASSWORD = os.getenv("PROXY_PASSWORD", "")

# Rate limiting
RATE_LIMIT_ENABLED = os.getenv("RATE_LIMIT_ENABLED", "True").lower() == "true"
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", 100))
RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", 60))  # seconds

# Notification configuration
NOTIFICATION_ENABLED = os.getenv("NOTIFICATION_ENABLED", "False").lower() == "true"
NOTIFICATION_WEBHOOK = os.getenv("NOTIFICATION_WEBHOOK", "")
NOTIFICATION_EMAIL = os.getenv("NOTIFICATION_EMAIL", "")

