#!/usr/bin/env python3
"""
Loot Management CLI Commands
"""

import click
import json
import sys
from pathlib import Path
from datetime import datetime
from tabulate import tabulate

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.logger import log
from config.settings import WORKSPACE_DIR


@click.group(name='loot')
def loot_group():
    """Loot management commands"""
    pass


@loot_group.command(name='summary')
def loot_summary():
    """Show loot summary"""
    try:
        loot_dir = Path(WORKSPACE_DIR) / 'loot'
        
        if not loot_dir.exists():
            log.warning("No loot directory found")
            return
        
        # Count loot by category
        categories = {
            "database_dumps": 0,
            "credentials": 0,
            "session_tokens": 0,
            "files": 0,
            "webshells": 0,
            "c2_agents": 0
        }
        
        total_size = 0
        
        for category in categories.keys():
            cat_dir = loot_dir / category
            if cat_dir.exists():
                files = list(cat_dir.glob("*"))
                categories[category] = len(files)
                total_size += sum(f.stat().st_size for f in files if f.is_file())
        
        # Display summary
        log.info("=" * 60)
        log.info("🏴‍☠️  LOOT SUMMARY")
        log.info("=" * 60)
        
        table_data = []
        for category, count in categories.items():
            table_data.append([
                category.replace("_", " ").title(),
                count
            ])
        
        print(tabulate(table_data, headers=["Category", "Count"], tablefmt="grid"))
        
        log.info(f"\n📊 Total Items: {sum(categories.values())}")
        log.info(f"💾 Total Size: {total_size / (1024 * 1024):.2f} MB")
        log.info(f"📁 Loot Directory: {loot_dir}")
        log.info("=" * 60)
        
    except Exception as e:
        log.error(f"Failed to get loot summary: {e}")
        sys.exit(1)


@loot_group.command(name='list')
@click.argument('category')
def loot_list(category: str):
    """List loot in a specific category"""
    try:
        valid_categories = ["database_dumps", "credentials", "session_tokens", "files", "webshells", "c2_agents"]
        
        if category not in valid_categories:
            log.error(f"Invalid category. Must be one of: {', '.join(valid_categories)}")
            sys.exit(1)
        
        loot_dir = Path(WORKSPACE_DIR) / 'loot' / category
        
        if not loot_dir.exists():
            log.warning(f"No loot found in category: {category}")
            return
        
        files = list(loot_dir.glob("*"))
        
        if not files:
            log.warning(f"No loot found in category: {category}")
            return
        
        # Display list
        log.info("=" * 80)
        log.info(f"📦 LOOT: {category.replace('_', ' ').upper()}")
        log.info("=" * 80)
        
        table_data = []
        for file_path in sorted(files, key=lambda f: f.stat().st_mtime, reverse=True):
            if file_path.is_file():
                stat = file_path.stat()
                table_data.append([
                    file_path.name,
                    f"{stat.st_size / 1024:.2f} KB",
                    datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                ])
        
        print(tabulate(table_data, headers=["Filename", "Size", "Modified"], tablefmt="grid"))
        
        log.info(f"\n📊 Total: {len(files)} files")
        log.info("=" * 80)
        
    except Exception as e:
        log.error(f"Failed to list loot: {e}")
        sys.exit(1)


@loot_group.command(name='view')
@click.argument('category')
@click.argument('filename')
def loot_view(category: str, filename: str):
    """View content of a loot file"""
    try:
        # Security: Prevent path traversal
        if ".." in filename or "/" in filename:
            log.error("Invalid filename")
            sys.exit(1)
        
        loot_file = Path(WORKSPACE_DIR) / 'loot' / category / filename
        
        if not loot_file.exists() or not loot_file.is_file():
            log.error(f"File not found: {loot_file}")
            sys.exit(1)
        
        log.info("=" * 80)
        log.info(f"📄 VIEWING: {filename}")
        log.info("=" * 80)
        
        # Try to read as text
        try:
            with open(loot_file, 'r') as f:
                content = f.read()
            
            # Try to parse as JSON for pretty printing
            try:
                data = json.loads(content)
                print(json.dumps(data, indent=2))
            except json.JSONDecodeError:
                # Not JSON, print as-is
                print(content)
        
        except UnicodeDecodeError:
            # Binary file
            log.warning("Binary file - showing hex dump (first 512 bytes)")
            with open(loot_file, 'rb') as f:
                data = f.read(512)
            
            # Hex dump
            for i in range(0, len(data), 16):
                hex_part = ' '.join(f'{b:02x}' for b in data[i:i+16])
                ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16])
                print(f"{i:08x}  {hex_part:<48}  {ascii_part}")
        
        log.info("=" * 80)
        
    except Exception as e:
        log.error(f"Failed to view loot: {e}")
        sys.exit(1)


@loot_group.command(name='export')
@click.argument('category')
@click.argument('output_dir')
def loot_export(category: str, output_dir: str):
    """Export all loot from a category to a directory"""
    try:
        import shutil
        
        loot_dir = Path(WORKSPACE_DIR) / 'loot' / category
        output_path = Path(output_dir)
        
        if not loot_dir.exists():
            log.error(f"Category not found: {category}")
            sys.exit(1)
        
        # Create output directory
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Copy all files
        files = list(loot_dir.glob("*"))
        
        if not files:
            log.warning(f"No files to export in category: {category}")
            return
        
        log.info(f"Exporting {len(files)} files to {output_path}...")
        
        for file_path in files:
            if file_path.is_file():
                dest = output_path / file_path.name
                shutil.copy2(file_path, dest)
                log.success(f"Exported: {file_path.name}")
        
        log.success(f"Export completed: {len(files)} files exported to {output_path}")
        
    except Exception as e:
        log.error(f"Failed to export loot: {e}")
        sys.exit(1)


@loot_group.command(name='delete')
@click.argument('category')
@click.argument('filename')
@click.confirmation_option(prompt='Are you sure you want to delete this file?')
def loot_delete(category: str, filename: str):
    """Delete a loot file"""
    try:
        # Security: Prevent path traversal
        if ".." in filename or "/" in filename:
            log.error("Invalid filename")
            sys.exit(1)
        
        loot_file = Path(WORKSPACE_DIR) / 'loot' / category / filename
        
        if not loot_file.exists() or not loot_file.is_file():
            log.error(f"File not found: {loot_file}")
            sys.exit(1)
        
        loot_file.unlink()
        log.success(f"Deleted: {filename}")
        
    except Exception as e:
        log.error(f"Failed to delete loot: {e}")
        sys.exit(1)


@loot_group.command(name='reports')
def loot_reports():
    """List all loot reports"""
    try:
        reports_dir = Path(WORKSPACE_DIR) / 'loot'
        
        if not reports_dir.exists():
            log.warning("No loot directory found")
            return
        
        reports = list(reports_dir.glob("loot_report_*.json"))
        
        if not reports:
            log.warning("No loot reports found")
            return
        
        log.info("=" * 100)
        log.info("📋 LOOT REPORTS")
        log.info("=" * 100)
        
        table_data = []
        for report_file in sorted(reports, key=lambda f: f.stat().st_mtime, reverse=True):
            try:
                with open(report_file, 'r') as f:
                    report_data = json.load(f)
                
                table_data.append([
                    report_file.name,
                    report_data.get("target", "unknown"),
                    len(report_data.get("loot", [])),
                    report_data.get("timestamp", ""),
                    f"{report_file.stat().st_size / 1024:.2f} KB"
                ])
            except Exception as e:
                log.error(f"Failed to read report {report_file}: {e}")
        
        print(tabulate(table_data, headers=["Filename", "Target", "Loot Count", "Timestamp", "Size"], tablefmt="grid"))
        
        log.info(f"\n📊 Total Reports: {len(reports)}")
        log.info("=" * 100)
        
    except Exception as e:
        log.error(f"Failed to list reports: {e}")
        sys.exit(1)


@loot_group.command(name='report')
@click.argument('report_file')
def loot_report_view(report_file: str):
    """View a specific loot report"""
    try:
        # Security: Prevent path traversal
        if ".." in report_file or "/" in report_file:
            log.error("Invalid filename")
            sys.exit(1)
        
        report_path = Path(WORKSPACE_DIR) / 'loot' / report_file
        
        if not report_path.exists():
            log.error(f"Report not found: {report_file}")
            sys.exit(1)
        
        with open(report_path, 'r') as f:
            report_data = json.load(f)
        
        log.info("=" * 100)
        log.info("📋 LOOT REPORT")
        log.info("=" * 100)
        log.info(f"Attack ID: {report_data.get('attack_id', 'unknown')}")
        log.info(f"Target: {report_data.get('target', 'unknown')}")
        log.info(f"Timestamp: {report_data.get('timestamp', '')}")
        log.info(f"Total Loot Items: {len(report_data.get('loot', []))}")
        log.info("=" * 100)
        
        # Display loot items
        loot_items = report_data.get('loot', [])
        
        if loot_items:
            log.info("\n🏴‍☠️ LOOT ITEMS:")
            
            for i, item in enumerate(loot_items, 1):
                log.info(f"\n[{i}] {item.get('type', 'unknown').upper()}")
                log.info(f"    Target: {item.get('target', 'N/A')}")
                log.info(f"    Timestamp: {item.get('timestamp', 'N/A')}")
                
                if item.get('data'):
                    log.info(f"    Data: {json.dumps(item['data'], indent=8)}")
                
                if item.get('file_path'):
                    log.info(f"    File: {item['file_path']}")
        
        log.info("\n" + "=" * 100)
        
    except Exception as e:
        log.error(f"Failed to view report: {e}")
        sys.exit(1)


if __name__ == '__main__':
    loot_group()

