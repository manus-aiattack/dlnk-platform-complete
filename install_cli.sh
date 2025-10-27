#!/bin/bash
# dLNk CLI Installation Script

set -e

echo "🎯 dLNk Attack Platform - CLI Installation"
echo "=========================================="
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed"
    exit 1
fi

echo "✅ Python 3 found"

# Install dependencies
echo "📦 Installing dependencies..."
pip3 install click rich aiohttp --quiet

# Make executable
chmod +x cli/dlnk.py

# Create symlink
if [ -w /usr/local/bin ]; then
    ln -sf "$(pwd)/cli/dlnk.py" /usr/local/bin/dlnk
    echo "✅ Installed to /usr/local/bin/dlnk"
else
    echo "⚠️  Cannot write to /usr/local/bin"
    echo "💡 Run with sudo or add to PATH manually:"
    echo "   export PATH=\"\$PATH:$(pwd)/cli\""
fi

echo ""
echo "✅ Installation complete!"
echo ""
echo "Setup:"
echo "  export DLNK_API_KEY='your_api_key_here'"
echo "  export DLNK_API_URL='http://localhost:8000'  # optional"
echo ""
echo "Usage:"
echo "  dlnk attack https://localhost:8000"
echo "  dlnk status <attack_id>"
echo "  dlnk history"
echo "  dlnk admin keys"
echo ""
echo "For help:"
echo "  dlnk --help"
echo ""

