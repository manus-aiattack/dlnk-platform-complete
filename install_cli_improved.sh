#!/bin/bash
# Install dLNk CLI - Improved Version

set -e

echo "Installing dLNk CLI..."

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is required"
    exit 1
fi

# Install dependencies
echo "Installing dependencies..."
pip3 install click rich requests --quiet

# Make CLI executable
chmod +x cli/dlnk_cli_improved.py

# Create symlink
INSTALL_DIR="/usr/local/bin"
if [ -w "$INSTALL_DIR" ]; then
    ln -sf "$(pwd)/cli/dlnk_cli_improved.py" "$INSTALL_DIR/dlnk"
    echo "✓ CLI installed to $INSTALL_DIR/dlnk"
else
    echo "Note: Cannot write to $INSTALL_DIR"
    echo "Run with sudo or add to PATH manually:"
    echo "  export PATH=\"\$PATH:$(pwd)/cli\""
fi

# Initialize config
echo "Initializing configuration..."
python3 cli/dlnk_cli_improved.py config init || true

echo ""
echo "✓ Installation complete!"
echo ""
echo "Usage:"
echo "  dlnk --help"
echo "  dlnk attack https://example.com"
echo "  dlnk history"
echo ""
