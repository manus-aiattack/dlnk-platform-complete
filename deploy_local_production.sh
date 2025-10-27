#!/bin/bash
# dLNk Attack Platform - Local Production Deployment Script
# For WSL2 Ubuntu with Ollama

set -e

echo "=========================================="
echo "dLNk Attack Platform - Production Deploy"
echo "=========================================="
echo ""

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Configuration
PROJECT_DIR="/mnt/c/projecattack/manus"
VENV_DIR="$PROJECT_DIR/venv"
LOG_DIR="$PROJECT_DIR/logs"
DATA_DIR="$PROJECT_DIR/data"

# Check if running in WSL
if ! grep -qi microsoft /proc/version; then
    echo -e "${RED}✗ This script is designed for WSL2${NC}"
    echo "Please run on your WSL2 Ubuntu environment"
    exit 1
fi

echo -e "${BLUE}[1/8] Checking environment...${NC}"
cd "$PROJECT_DIR" || exit 1

# Check Ollama
if ! command -v ollama &> /dev/null; then
    echo -e "${RED}✗ Ollama not found${NC}"
    exit 1
fi

# Check if Ollama is running
if ! ollama list &> /dev/null; then
    echo -e "${BLUE}Starting Ollama...${NC}"
    ollama serve &
    sleep 5
fi

echo -e "${GREEN}✓ Ollama is running${NC}"
ollama list

echo ""
echo -e "${BLUE}[2/8] Activating virtual environment...${NC}"
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
fi

source "$VENV_DIR/bin/activate"
echo -e "${GREEN}✓ Virtual environment activated${NC}"

echo ""
echo -e "${BLUE}[3/8] Installing dependencies...${NC}"
pip install -q --upgrade pip
pip install -q -r requirements.txt
echo -e "${GREEN}✓ Dependencies installed${NC}"

echo ""
echo -e "${BLUE}[4/8] Creating directories...${NC}"
mkdir -p "$LOG_DIR"
mkdir -p "$DATA_DIR"
mkdir -p "$DATA_DIR/reports"
mkdir -p "$DATA_DIR/exploits"
mkdir -p "$DATA_DIR/sessions"
echo -e "${GREEN}✓ Directories created${NC}"

echo ""
echo -e "${BLUE}[5/8] Configuring environment...${NC}"

# Create .env file if not exists
if [ ! -f "$PROJECT_DIR/.env" ]; then
    cat > "$PROJECT_DIR/.env" << 'ENVEOF'
# dLNk Attack Platform - Production Configuration

# LLM Configuration (Ollama)
LLM_PROVIDER=localai
LOCALAI_BASE_URL=http://localhost:11434/v1
LOCALAI_MODEL=mixtral:latest
LOCALAI_API_KEY=ollama

# Alternative models (uncomment to use)
# LOCALAI_MODEL=llama3:8b-instruct-fp16
# LOCALAI_MODEL=codellama:latest
# LOCALAI_MODEL=mistral:latest

# Server Configuration
HOST=0.0.0.0
PORT=8000
DEBUG=false
WORKERS=4

# Database Configuration (Optional - will use file-based storage if not set)
# POSTGRES_HOST=localhost
# POSTGRES_PORT=5432
# POSTGRES_DB=dlnk
# POSTGRES_USER=dlnk
# POSTGRES_PASSWORD=changeme

# Redis Configuration (Optional)
# REDIS_HOST=localhost
# REDIS_PORT=6379
# REDIS_PASSWORD=

# Security
SECRET_KEY=$(openssl rand -hex 32)
JWT_SECRET=$(openssl rand -hex 32)
ALLOWED_HOSTS=*

# Logging
LOG_LEVEL=INFO
LOG_FILE=logs/dlnk.log

# Attack Configuration
MAX_CONCURRENT_ATTACKS=5
ATTACK_TIMEOUT=3600
ENABLE_AUTO_EXPLOIT=true

# C2 Configuration (REQUIRED)
C2_DOMAIN=
C2_PROTOCOL=http

# Network Configuration
HTTP_TIMEOUT=30
MAX_RETRIES=3
USER_AGENT=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36

# Proxy Configuration (Optional)
# HTTP_PROXY=
# HTTPS_PROXY=
# NO_PROXY=localhost,127.0.0.1

ENVEOF
    echo -e "${GREEN}✓ Created .env file${NC}"
else
    echo -e "${GREEN}✓ .env file already exists${NC}"
fi

echo ""
echo -e "${BLUE}[6/8] Testing Ollama connection...${NC}"
python3 << 'PYTEST'
import sys
import requests

try:
    response = requests.get("http://localhost:11434/api/tags", timeout=5)
    if response.status_code == 200:
        models = response.json().get("models", [])
        print(f"✓ Ollama connected - {len(models)} models available")
        for model in models:
            print(f"  - {model['name']}")
        sys.exit(0)
    else:
        print(f"✗ Ollama responded with status {response.status_code}")
        sys.exit(1)
except Exception as e:
    print(f"✗ Failed to connect to Ollama: {e}")
    sys.exit(1)
PYTEST

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Ollama connection successful${NC}"
else
    echo -e "${RED}✗ Ollama connection failed${NC}"
    echo "Please ensure Ollama is running: ollama serve"
    exit 1
fi

echo ""
echo -e "${BLUE}[7/8] Testing system imports...${NC}"
python3 << 'PYTEST2'
import sys
sys.path.insert(0, '.')

try:
    from core.orchestrator import Orchestrator
    from core.logger import log
    print("✓ Core imports successful")
    print("✓ System is ready")
except Exception as e:
    print(f"✗ Import failed: {e}")
    sys.exit(1)
PYTEST2

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ System imports successful${NC}"
else
    echo -e "${RED}✗ System imports failed${NC}"
    exit 1
fi

echo ""
echo -e "${BLUE}[8/8] Starting production server...${NC}"
echo ""
echo "=========================================="
echo -e "${GREEN}✓ Production deployment complete!${NC}"
echo "=========================================="
echo ""
echo "Server will start on: http://0.0.0.0:8000"
echo "Local access: http://localhost:8000"
echo "Network access: http://172.26.203.21:8000"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

# Start the server
python3 startup.py

# If startup.py doesn't work, try alternative
if [ $? -ne 0 ]; then
    echo "Trying alternative startup method..."
    uvicorn web.api:app --host 0.0.0.0 --port 8000 --workers 4
fi

