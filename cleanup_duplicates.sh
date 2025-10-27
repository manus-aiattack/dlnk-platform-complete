#!/bin/bash
# Clean up duplicate files and directories

echo "=== Cleaning Up Duplicates ==="

# 1. Remove dlnk_FINAL (already migrated better files)
echo "Removing dlnk_FINAL directory..."
rm -rf dlnk_FINAL/

# 2. Remove duplicate API files (keep main_complete.py as main.py)
echo "Cleaning up API files..."
cd api
# Backup current main.py
cp main.py main_original.py
# Use main_complete.py as the new main.py
cp main_complete.py main.py
# Remove old versions
rm -f main_api.py main_old.py main_integrated.py
cd ..

# 3. Remove test files from root (keep in tests/ directory only)
echo "Removing test files from root..."
rm -f test_*.py
rm -f fix_*.py
rm -f apply_*.py
rm -f check_admin.py
rm -f system_audit.py

# 4. Remove temporary/old files
echo "Removing temporary files..."
rm -f TEST_COMMIT.txt
rm -f test_write_commit.txt
rm -f WORK_SUMMARY.txt
rm -f COMMANDS.txt
rm -f audit_final.txt
rm -f AUDIT_REPORT.txt
rm -f AUDIT_REPORT_COMPREHENSIVE.txt

# 5. Remove duplicate shell scripts
echo "Removing duplicate scripts..."
rm -f fix_*.sh
rm -f quick-*.sh
rm -f validate-*.sh
rm -f wsl-fix.sh

# 6. Remove apex_predator_FINAL if it's a duplicate
if [ -d "apex_predator_FINAL" ]; then
    echo "Removing apex_predator_FINAL..."
    rm -rf apex_predator_FINAL/
fi

# 7. Remove dlnk symlink/directory if exists
if [ -e "dlnk" ]; then
    echo "Removing dlnk..."
    rm -rf dlnk
fi

echo "=== Cleanup Complete ==="
echo "Removed:"
echo "  - dlnk_FINAL/"
echo "  - Duplicate API files"
echo "  - Test files from root"
echo "  - Temporary files"
echo "  - Old scripts"
