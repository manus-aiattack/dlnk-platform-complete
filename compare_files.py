#!/usr/bin/env python3
"""
Compare files between root and dlnk_FINAL directories
Generate report of differences
"""

import os
import sys
from pathlib import Path
from difflib import unified_diff

def get_file_info(filepath):
    """Get file information"""
    if not os.path.exists(filepath):
        return None
    
    stat = os.stat(filepath)
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    
    return {
        'size': stat.st_size,
        'lines': len(lines),
        'mtime': stat.st_mtime
    }

def compare_directories(root_dir, dlnk_dir, output_file):
    """Compare all Python files between directories"""
    
    results = []
    
    # Get all Python files in both directories
    root_files = set()
    dlnk_files = set()
    
    for root, dirs, files in os.walk(root_dir):
        # Skip dlnk_FINAL in root
        if 'dlnk_FINAL' in root:
            continue
        for f in files:
            if f.endswith('.py'):
                rel_path = os.path.relpath(os.path.join(root, f), root_dir)
                root_files.add(rel_path)
    
    for root, dirs, files in os.walk(dlnk_dir):
        for f in files:
            if f.endswith('.py'):
                rel_path = os.path.relpath(os.path.join(root, f), dlnk_dir)
                dlnk_files.add(rel_path)
    
    # Files in both
    common_files = root_files & dlnk_files
    # Files only in root
    root_only = root_files - dlnk_files
    # Files only in dlnk_FINAL
    dlnk_only = dlnk_files - root_files
    
    print(f"Common files: {len(common_files)}")
    print(f"Root only: {len(root_only)}")
    print(f"dlnk_FINAL only: {len(dlnk_only)}")
    
    # Compare common files
    for rel_path in sorted(common_files):
        root_path = os.path.join(root_dir, rel_path)
        dlnk_path = os.path.join(dlnk_dir, rel_path)
        
        root_info = get_file_info(root_path)
        dlnk_info = get_file_info(dlnk_path)
        
        if root_info and dlnk_info:
            diff = root_info['lines'] - dlnk_info['lines']
            
            results.append({
                'file': rel_path,
                'root_lines': root_info['lines'],
                'dlnk_lines': dlnk_info['lines'],
                'diff': diff,
                'status': 'root_bigger' if diff > 0 else 'dlnk_bigger' if diff < 0 else 'same'
            })
    
    # Write report
    with open(output_file, 'w') as f:
        f.write("# File Comparison Report: Root vs dlnk_FINAL\n\n")
        
        f.write("## Summary\n\n")
        f.write(f"- Common files: {len(common_files)}\n")
        f.write(f"- Files only in root: {len(root_only)}\n")
        f.write(f"- Files only in dlnk_FINAL: {len(dlnk_only)}\n\n")
        
        f.write("## Files Only in Root\n\n")
        for filepath in sorted(root_only):
            f.write(f"- `{filepath}`\n")
        
        f.write("\n## Files Only in dlnk_FINAL\n\n")
        for filepath in sorted(dlnk_only):
            f.write(f"- `{filepath}`\n")
        
        f.write("\n## Common Files Comparison\n\n")
        f.write("| File | Root Lines | dlnk Lines | Diff | Recommendation |\n")
        f.write("|------|------------|------------|------|----------------|\n")
        
        for item in sorted(results, key=lambda x: abs(x['diff']), reverse=True):
            if item['diff'] == 0:
                continue
            
            recommendation = "Keep root" if item['diff'] > 0 else "**Use dlnk_FINAL**"
            f.write(f"| `{item['file']}` | {item['root_lines']} | {item['dlnk_lines']} | {item['diff']:+d} | {recommendation} |\n")
    
    print(f"\nReport written to: {output_file}")

if __name__ == '__main__':
    root_dir = '/home/ubuntu/manus'
    dlnk_dir = '/home/ubuntu/manus/dlnk_FINAL'
    output_file = '/home/ubuntu/manus/FILE_COMPARISON_REPORT.md'
    
    compare_directories(root_dir, dlnk_dir, output_file)
