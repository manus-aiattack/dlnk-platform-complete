#!/usr/bin/env bash
# dLNk - Quick Setup Script

set -e

echo "================================"
echo "dLNk Quick Setup"
echo "================================"
echo ""

# 1. Fix .env
echo "[1/5] Fixing .env file..."
if ! grep -q "^C2_DOMAIN=" .env 2>/dev/null; then
    echo "C2_DOMAIN=localhost:8000" >> .env
    echo "✅ Added C2_DOMAIN"
else
    echo "✅ C2_DOMAIN already exists"
fi

# Change to SQLite
sed -i 's|DATABASE_URL=postgresql.*|DATABASE_URL=sqlite:///workspace/dlnk.db|' .env
echo "✅ Using SQLite database"
echo ""

# 2. Upgrade pydantic
echo "[2/5] Upgrading pydantic..."
pip3 install --upgrade pydantic pydantic-settings --quiet
echo "✅ Pydantic upgraded"
echo ""

# 3. Create workspace
echo "[3/5] Creating workspace..."
mkdir -p workspace workspace/loot workspace/loot/exfiltrated logs reports data
echo "✅ Workspace created"
echo ""

# 4. Initialize database
echo "[4/5] Initializing database..."
export PYTHONPATH="$(pwd):$PYTHONPATH"
python3 -c "
import sys
sys.path.insert(0, '.')
from api.services.database_sqlite import DatabaseManager
db = DatabaseManager()
print('✅ Database initialized')
" 2>/dev/null || echo "⚠️  Database init skipped"
echo ""

# 5. Start server
echo "[5/5] Starting API server..."
echo ""
echo "================================"
echo "Starting dLNk API Server..."
echo "================================"
echo ""
echo "API will be available at:"
echo "  - http://localhost:8000"
echo "  - http://localhost:8000/docs"
echo ""
echo "Press Ctrl+C to stop"
echo ""

export PYTHONPATH="$(pwd):$PYTHONPATH"
python3 main.py server

