#!/bin/bash

echo "=== Manus Project Setup ==="
echo ""

# Check if running in WSL
if grep -qi microsoft /proc/version; then
    echo "✓ Detected WSL environment"
fi

# Create virtual environment
echo "Creating virtual environment..."
python3 -m venv venv

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip

# Install requirements
echo "Installing requirements..."
pip install -r requirements.txt

echo ""
echo "=== Setup Complete ==="
echo ""
echo "To activate the virtual environment, run:"
echo "  source venv/bin/activate"
echo ""
echo "To start the API server, run:"
echo "  python3 api/main_integrated.py"
echo ""
echo "To start the frontend, run:"
echo "  cd frontend && npm install && npm run dev"
echo ""
