#!/bin/bash

# dLNk dLNk Attack Platform - Quick Start Script
# สำหรับ Ubuntu/Debian/WSL

set -e

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                                                               ║"
echo "║      █████╗ ██████╗ ███████╗██╗  ██╗                        ║"
echo "║     ██╔══██╗██╔══██╗██╔════╝╚██╗██╔╝                        ║"
echo "║     ███████║██████╔╝█████╗   ╚███╔╝                         ║"
echo "║     ██╔══██║██╔═══╝ ██╔══╝   ██╔██╗                         ║"
echo "║     ██║  ██║██║     ███████╗██╔╝ ██╗                        ║"
echo "║     ╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝                        ║"
echo "║                                                               ║"
echo "║        DLNK ATTACK PLATFORM v2.0                         ║"
echo "║        Quick Start Installation                              ║"
echo "║                                                               ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Check if running on WSL
if grep -qi microsoft /proc/version; then
    echo "✅ Detected WSL environment"
    IS_WSL=true
else
    echo "✅ Detected Linux environment"
    IS_WSL=false
fi

# Check Python version
echo ""
echo "Checking Python version..."
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found. Please install Python 3.8 or higher."
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
echo "✅ Python $PYTHON_VERSION found"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo ""
    echo "Creating virtual environment..."
    python3 -m venv venv
    echo "✅ Virtual environment created"
fi

# Activate virtual environment
echo ""
echo "Activating virtual environment..."
source venv/bin/activate
echo "✅ Virtual environment activated"

# Install Python dependencies
echo ""
echo "Installing Python dependencies..."
if [ -f "requirements-full.txt" ]; then
    pip install -r requirements-full.txt
elif [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
else
    echo "⚠️  No requirements file found, installing basic dependencies..."
    pip install fastapi uvicorn asyncpg aiohttp pyyaml requests beautifulsoup4 rich psutil
fi
echo "✅ Python dependencies installed"

# Check if Ollama is installed
echo ""
echo "Checking Ollama..."
if ! command -v ollama &> /dev/null; then
    echo "⚠️  Ollama not found"
    echo ""
    echo "Ollama is required for AI-powered attacks."
    echo "Please install Ollama from: https://ollama.ai"
    echo ""
    read -p "Continue without Ollama? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
else
    echo "✅ Ollama found"
    
    # Check if mixtral model is available
    if ollama list | grep -q "mixtral"; then
        echo "✅ mixtral model found"
    else
        echo "⚠️  mixtral model not found"
        echo ""
        read -p "Download mixtral:latest model? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo "Downloading mixtral:latest (this may take a while)..."
            ollama pull mixtral:latest
            echo "✅ mixtral model downloaded"
        fi
    fi
fi

# Check if PostgreSQL is installed
echo ""
echo "Checking PostgreSQL..."
if ! command -v psql &> /dev/null; then
    echo "⚠️  PostgreSQL not found"
    echo ""
    echo "PostgreSQL is required for the database."
    echo "Install with: sudo apt install postgresql postgresql-contrib"
    echo ""
    read -p "Continue without PostgreSQL? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
else
    echo "✅ PostgreSQL found"
fi

# Check if .env file exists
echo ""
if [ ! -f ".env" ]; then
    echo "Creating .env file from template..."
    if [ -f "env.template" ]; then
        cp env.template .env
        echo "✅ .env file created"
        echo ""
        echo "⚠️  Please edit .env file with your configuration:"
        echo "   - DATABASE_URL"
        echo "   - OLLAMA_HOST"
        echo "   - Notification settings (optional)"
        echo ""
        read -p "Press Enter to continue..."
    else
        echo "⚠️  env.template not found, creating basic .env..."
        cat > .env << EOF
SIMULATION_MODE=False
DATABASE_URL=postgresql://dlnk:dlnk_password@localhost:5432/dlnk_dlnk
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=mixtral:latest
LLM_PROVIDER=ollama
LLM_MODEL=mixtral:latest
WORKSPACE_DIR=workspace
LOOT_DIR=workspace/loot
EOF
        echo "✅ Basic .env file created"
    fi
else
    echo "✅ .env file exists"
fi

# Run startup script
echo ""
echo "Running system initialization..."
python3 startup.py

echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                                                               ║"
echo "║  ✅ Installation Complete!                                    ║"
echo "║                                                               ║"
echo "║  To start the API server:                                    ║"
echo "║    source venv/bin/activate                                  ║"
echo "║    python api/main.py                                        ║"
echo "║                                                               ║"
echo "║  Or use:                                                     ║"
echo "║    ./run.sh                                                  ║"
echo "║                                                               ║"
echo "║  API will be available at:                                   ║"
echo "║    http://localhost:8000                                     ║"
echo "║                                                               ║"
echo "║  API Documentation:                                          ║"
echo "║    http://localhost:8000/docs                                ║"
echo "║                                                               ║"
echo "║  Admin Key saved in: ADMIN_KEY.txt                           ║"
echo "║                                                               ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

