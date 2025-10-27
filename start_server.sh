#!/usr/bin/env bash
# Quick Start Script for dLNk API Server

set -e

echo "========================================================"
echo "Starting dLNk Attack Platform API Server"
echo "========================================================"
echo ""

# Set PYTHONPATH
export PYTHONPATH="$(pwd):$PYTHONPATH"

# Check if .env exists
if [ ! -f ".env" ]; then
    echo "⚠️  .env file not found - creating from template..."
    if [ -f ".env.template" ]; then
        cp .env.template .env
    fi
fi

# Check if workspace exists
if [ ! -d "workspace" ]; then
    echo "📁 Creating workspace directory..."
    mkdir -p workspace logs data reports config
fi

# Start the server
echo "🚀 Starting API server on http://0.0.0.0:8000"
echo ""
echo "API Documentation: http://localhost:8000/docs"
echo "Health Check: http://localhost:8000/health"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

python3 main.py server

