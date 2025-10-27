#!/bin/bash
# Migrate better files from dlnk_FINAL to root

set -e

echo "=== Migrating Better Files from dlnk_FINAL ==="

# Backup original files first
mkdir -p /tmp/manus_backup

# 1. core/orchestrator.py (AI-driven version)
echo "Backing up and replacing core/orchestrator.py..."
cp core/orchestrator.py /tmp/manus_backup/orchestrator.py.root
cp dlnk_FINAL/core/orchestrator.py core/orchestrator.py

# 2. core/session_manager.py
echo "Backing up and replacing core/session_manager.py..."
cp core/session_manager.py /tmp/manus_backup/session_manager.py.root
cp dlnk_FINAL/core/session_manager.py core/session_manager.py

# 3. api/routes/admin.py
echo "Backing up and replacing api/routes/admin.py..."
cp api/routes/admin.py /tmp/manus_backup/admin.py.root
cp dlnk_FINAL/api/routes/admin.py api/routes/admin.py

# 4. agents/zero_day_hunter_weaponized.py
echo "Backing up and replacing agents/zero_day_hunter_weaponized.py..."
cp agents/zero_day_hunter_weaponized.py /tmp/manus_backup/zero_day_hunter_weaponized.py.root
cp dlnk_FINAL/agents/zero_day_hunter_weaponized.py agents/zero_day_hunter_weaponized.py

# 5. Copy unique files from dlnk_FINAL
echo "Copying unique files..."
cp dlnk_FINAL/check_agent.py ./
mkdir -p services
cp dlnk_FINAL/services/monitoring_service.py services/

# 6. Copy auth_routes.py if different
if [ -f "dlnk_FINAL/api/routes/auth_routes.py" ]; then
    echo "Copying api/routes/auth_routes.py..."
    cp dlnk_FINAL/api/routes/auth_routes.py api/routes/
fi

echo "=== Migration Complete ==="
echo "Backups saved to: /tmp/manus_backup/"
