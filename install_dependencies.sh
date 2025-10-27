#!/bin/bash

# dLNk - Complete Dependencies Installation Script
# For Python 3.11

set -e

echo "🚀 dLNk Dependencies Installation"
echo "=================================="
echo ""

# Check Python version
PYTHON_VERSION=$(python --version 2>&1 | awk '{print $2}')
echo "✅ Python version: $PYTHON_VERSION"
echo ""

# Check if in venv
if [[ "$VIRTUAL_ENV" == "" ]]; then
    echo "❌ Error: Not in virtual environment!"
    echo "Please run: source venv/bin/activate"
    exit 1
fi

echo "✅ Virtual environment: $VIRTUAL_ENV"
echo ""

# Upgrade pip
echo "📦 Upgrading pip..."
pip install --upgrade pip setuptools wheel
echo ""

# Install pydantic first (Python 3.11 compatible version)
echo "📦 Installing pydantic (Python 3.11 compatible)..."
pip install "pydantic>=2.5.3"
echo ""

# Install from requirements-production.txt (production only)
echo "📦 Installing dependencies from requirements-production.txt..."
pip install -r requirements-production.txt
echo ""

# Install additional packages
echo "📦 Installing additional packages..."
pip install angr || echo "⚠️ angr installation failed (optional)"
echo ""

# Verify installations
echo "🔍 Verifying installations..."
echo ""

echo "Checking critical packages:"
python -c "import fastapi; print(f'  ✅ fastapi: {fastapi.__version__}')" || echo "  ❌ fastapi: FAILED"
python -c "import uvicorn; print(f'  ✅ uvicorn: {uvicorn.__version__}')" || echo "  ❌ uvicorn: FAILED"
python -c "import asyncpg; print(f'  ✅ asyncpg: {asyncpg.__version__}')" || echo "  ❌ asyncpg: FAILED"
python -c "import aiohttp; print(f'  ✅ aiohttp: {aiohttp.__version__}')" || echo "  ❌ aiohttp: FAILED"
python -c "import pydantic; print(f'  ✅ pydantic: {pydantic.__version__}')" || echo "  ❌ pydantic: FAILED"
python -c "import redis; print(f'  ✅ redis: {redis.__version__}')" || echo "  ❌ redis: FAILED"
python -c "import bs4; print(f'  ✅ beautifulsoup4: {bs4.__version__}')" || echo "  ❌ beautifulsoup4: FAILED"
python -c "import yaml; print(f'  ✅ pyyaml: {yaml.__version__}')" || echo "  ❌ pyyaml: FAILED"
python -c "import aiofiles; print(f'  ✅ aiofiles: {aiofiles.__version__}')" || echo "  ❌ aiofiles: FAILED"
python -c "import loguru; print(f'  ✅ loguru: {loguru.__version__}')" || echo "  ❌ loguru: FAILED"
python -c "import boto3; print(f'  ✅ boto3: {boto3.__version__}')" || echo "  ❌ boto3: FAILED"
python -c "import pymetasploit3; print('  ✅ pymetasploit3: installed')" || echo "  ❌ pymetasploit3: FAILED"

echo ""
echo "✅ Installation complete!"
echo ""
echo "Next steps:"
echo "  1. Setup PostgreSQL: docker run -d --name dlnk_postgres ..."
echo "  2. Setup environment: export DATABASE_URL=..."
echo "  3. Start server: python -m uvicorn api.main:app --host 0.0.0.0 --port 8000"
echo ""

