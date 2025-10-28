#!/bin/bash

# Connext Connext Security Platform - Run Script

set -e

# Activate virtual environment
if [ -d "venv" ]; then
    source venv/bin/activate
else
    echo "❌ Virtual environment not found. Run ./quickstart.sh first."
    exit 1
fi

# Check if .env exists
if [ ! -f ".env" ]; then
    echo "❌ .env file not found. Run ./quickstart.sh first."
    exit 1
fi

# Start API server
echo "Starting Connext API Server..."
echo ""
python3 api/main.py

