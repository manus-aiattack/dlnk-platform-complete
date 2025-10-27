#!/usr/bin/env python3
"""
SQLite to PostgreSQL Migration Script
Automatically migrate all SQLite usage to PostgreSQL
"""

import re
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)


class SQLiteMigrator:
    """Migrate SQLite code to PostgreSQL"""
    
    def __init__(self):
        self.base_path = Path("/home/ubuntu/aiprojectattack")
        self.files_migrated = 0
        self.changes_made = 0
    
    def migrate_all(self):
        """Migrate all files"""
        log.info("Starting SQLite to PostgreSQL migration...")
        
        # Files to migrate
        files_to_migrate = [
            "production_server.py",
            "run_production.py",
            "api/services/database.py",
            "api/services/database_simple.py",
            "config/settings.py",
        ]
        
        for file_path in files_to_migrate:
            full_path = self.base_path / file_path
            if full_path.exists():
                self.migrate_file(full_path)
        
        log.info(f"✅ Migration complete: {self.files_migrated} files, {self.changes_made} changes")
    
    def migrate_file(self, file_path: Path):
        """Migrate single file"""
        log.info(f"Migrating {file_path.name}...")
        
        try:
            content = file_path.read_text()
            original_content = content
            
            # Replace SQLite imports
            content = re.sub(
                r'import sqlite3',
                'import asyncpg',
                content
            )
            
            # Replace sqlite:/// connections
            content = re.sub(
                r'sqlite:///[^\s"\']+',
                'postgresql://dlnk_user:dlnk_password@localhost/dlnk_attack_db',
                content
            )
            
            # Replace sqlite3.connect
            content = re.sub(
                r'sqlite3\.connect\([^)]+\)',
                'await asyncpg.connect("postgresql://dlnk_user:dlnk_password@localhost/dlnk_attack_db")',
                content
            )
            
            # Replace :memory:
            content = re.sub(
                r':memory:',
                'postgresql://dlnk_user:dlnk_password@localhost/dlnk_attack_db',
                content
            )
            
            # Add async if needed
            if 'await asyncpg.connect' in content and 'async def' not in content:
                # Find function definitions and make them async
                content = re.sub(
                    r'\ndef (connect|get_db|init_db)\(',
                    r'\nasync def \1(',
                    content
                )
            
            if content != original_content:
                file_path.write_text(content)
                self.files_migrated += 1
                changes = content.count('postgresql://') - original_content.count('postgresql://')
                self.changes_made += changes
                log.info(f"  ✅ {file_path.name}: {changes} changes")
            else:
                log.info(f"  ⏭️  {file_path.name}: No changes needed")
                
        except Exception as e:
            log.error(f"  ❌ {file_path.name}: {e}")


def main():
    migrator = SQLiteMigrator()
    migrator.migrate_all()


if __name__ == "__main__":
    main()

