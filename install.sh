#!/bin/bash
echo "🦅 dLNk dLNk Framework - Quick Install"
echo "Powered by dLNk Framework"
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found"
    exit 1
fi

echo "✅ Python found: $(python3 --version)"

# Install essential packages only
echo "📦 Installing essential packages..."
pip3 install -q openai requests pyyaml click rich 2>/dev/null || pip3 install openai requests pyyaml click rich

echo "✅ Installation complete!"
echo ""
echo "🚀 Quick start:"
echo "   python3 main.py --help"
echo "   python3 dlnk_ai_system.py"
echo ""
