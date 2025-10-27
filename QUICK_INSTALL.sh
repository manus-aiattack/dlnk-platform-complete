#!/bin/bash

# dLNk Quick Install Script for Ubuntu 24.04
# Handles virtual environment automatically

set -e

echo "🚀 dLNk Attack Platform - Quick Install"
echo "========================================"
echo ""

# Detect Python version
if command -v python3.12 &> /dev/null; then
    PYTHON_CMD=python3.12
    PYTHON_VERSION="3.12"
elif command -v python3.11 &> /dev/null; then
    PYTHON_CMD=python3.11
    PYTHON_VERSION="3.11"
elif command -v python3 &> /dev/null; then
    PYTHON_CMD=python3
    PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
else
    echo "❌ Python 3 not found!"
    exit 1
fi

echo "✅ Detected Python $PYTHON_VERSION"

# Install Python venv and dev packages
echo "📦 Installing Python $PYTHON_VERSION venv and dev packages..."
sudo apt update
sudo apt install -y python${PYTHON_VERSION}-venv python${PYTHON_VERSION}-dev

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment with Python $PYTHON_VERSION..."
    $PYTHON_CMD -m venv venv
fi

# Activate virtual environment
echo "✅ Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "📦 Upgrading pip..."
pip install --upgrade pip setuptools wheel

# Install dependencies
echo "📦 Installing dependencies..."
pip install -r requirements-production.txt

echo ""
echo "✅ Installation complete!"
echo ""
echo "📋 Next steps:"
echo ""
echo "1. Activate virtual environment:"
echo "   source venv/bin/activate"
echo ""
echo "2. Create .env file:"
echo "   cp env.template .env"
echo ""
echo "3. Run the server:"
echo "   python startup.py"
echo ""
echo "   OR"
echo ""
echo "   uvicorn api.main_api:app --host 0.0.0.0 --port 8000"
echo ""
echo "4. Access the system:"
echo "   http://localhost:8000"
echo "   http://localhost:8000/docs"
echo ""

