#!/usr/bin/env bash
# Install dLNk CLI Wrapper to system PATH

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLI_SCRIPT="${SCRIPT_DIR}/dlnk"

echo "================================================"
echo "dLNk CLI Wrapper Installation"
echo "================================================"
echo ""

# Check if script exists
if [ ! -f "${CLI_SCRIPT}" ]; then
    echo "❌ Error: dlnk script not found at ${CLI_SCRIPT}"
    exit 1
fi

# Make sure it's executable
chmod +x "${CLI_SCRIPT}"

# Determine installation location
if [ -w "/usr/local/bin" ]; then
    INSTALL_DIR="/usr/local/bin"
elif [ -w "$HOME/.local/bin" ]; then
    INSTALL_DIR="$HOME/.local/bin"
    mkdir -p "${INSTALL_DIR}"
else
    echo "⚠️  Warning: Neither /usr/local/bin nor ~/.local/bin is writable"
    echo "Creating symlink in ~/.local/bin (you may need to add it to PATH)"
    INSTALL_DIR="$HOME/.local/bin"
    mkdir -p "${INSTALL_DIR}"
fi

# Create symlink
INSTALL_PATH="${INSTALL_DIR}/dlnk"

if [ -L "${INSTALL_PATH}" ] || [ -f "${INSTALL_PATH}" ]; then
    echo "⚠️  Removing existing installation at ${INSTALL_PATH}"
    rm -f "${INSTALL_PATH}"
fi

ln -s "${CLI_SCRIPT}" "${INSTALL_PATH}"

echo "✅ dLNk CLI installed to: ${INSTALL_PATH}"
echo ""

# Check if it's in PATH
if command -v dlnk &> /dev/null; then
    echo "✅ dlnk is now available in your PATH"
    echo ""
    echo "Try running: dlnk --help"
else
    echo "⚠️  ${INSTALL_DIR} is not in your PATH"
    echo ""
    echo "Add this line to your ~/.bashrc or ~/.zshrc:"
    echo "    export PATH=\"${INSTALL_DIR}:\$PATH\""
    echo ""
    echo "Then run: source ~/.bashrc (or ~/.zshrc)"
fi

echo ""
echo "================================================"
echo "Installation Complete"
echo "================================================"

