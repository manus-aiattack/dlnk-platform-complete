import os
import json
import gzip
import shutil
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from pathlib import Path
from core.logger import log
from config import settings


class ReportManager:
    """Manages report storage, archival, and cleanup"""

    def __init__(self, base_path: str = "reports"):
        self.base_path = Path(base_path)
        self.archive_path = self.base_path / "archive"
        self.temp_path = self.base_path / "temp"
        self.max_file_age_days = getattr(settings, 'REPORT_MAX_AGE_DAYS', 30)
        self.max_reports_per_cycle = getattr(
            settings, 'MAX_REPORTS_PER_CYCLE', 100)
        self.compression_enabled = getattr(
            settings, 'REPORT_COMPRESSION', True)

        self._ensure_directories()

    def _ensure_directories(self):
        """Create necessary directories"""
        for path in [self.base_path, self.archive_path, self.temp_path]:
            path.mkdir(parents=True, exist_ok=True)

    def save_report(self, report_data: Dict[str, Any],
                    cycle_id: str, agent_name: str,
                    compress: bool = None) -> str:
        """Save report to disk with optional compression"""
        if compress is None:
            compress = self.compression_enabled

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{agent_name}_{cycle_id}_{timestamp}.json"

        if compress:
            filename += ".gz"
            filepath = self.base_path / filename
            with gzip.open(filepath, 'wt') as f:
                json.dump(report_data, f, indent=2)
        else:
            filepath = self.base_path / filename
            with open(filepath, 'w') as f:
                json.dump(report_data, f, indent=2)

        log.info(f"Saved report: {filename}")
        return str(filepath)

    def load_report(self, filepath: str) -> Optional[Dict[str, Any]]:
        """Load report from disk with automatic decompression detection"""
        try:
            if filepath.endswith('.gz'):
                with gzip.open(filepath, 'rt') as f:
                    return json.load(f)
            else:
                with open(filepath, 'r') as f:
                    return json.load(f)
        except Exception as e:
            log.error(f"Failed to load report {filepath}: {e}")
            return None

    def archive_old_reports(self, days_old: int = None) -> int:
        """Archive reports older than specified days"""
        if days_old is None:
            days_old = self.max_file_age_days

        cutoff_date = datetime.now() - timedelta(days=days_old)
        archived_count = 0

        for filepath in self.base_path.glob("*.json*"):
            if filepath.is_file():
                file_time = datetime.fromtimestamp(filepath.stat().st_mtime)
                if file_time < cutoff_date:
                    archive_path = self.archive_path / filepath.name
                    shutil.move(str(filepath), str(archive_path))
                    archived_count += 1
                    log.info(f"Archived report: {filepath.name}")

        log.info(f"Archived {archived_count} old reports")
        return archived_count

    def cleanup_temp_files(self) -> int:
        """Clean up temporary files"""
        cleaned_count = 0

        for filepath in self.temp_path.glob("*"):
            if filepath.is_file():
                filepath.unlink()
                cleaned_count += 1

        log.info(f"Cleaned up {cleaned_count} temporary files")
        return cleaned_count

    def get_report_stats(self) -> Dict[str, Any]:
        """Get statistics about stored reports"""
        stats = {
            "total_reports": 0,
            "total_size_mb": 0,
            "compressed_reports": 0,
            "uncompressed_reports": 0,
            "oldest_report": None,
            "newest_report": None}

        oldest_time = None
        newest_time = None

        for filepath in self.base_path.glob("*.json*"):
            if filepath.is_file():
                stats["total_reports"] += 1
                stats["total_size_mb"] += filepath.stat().st_size / \
                    (1024 * 1024)

                if filepath.name.endswith('.gz'):
                    stats["compressed_reports"] += 1
                else:
                    stats["uncompressed_reports"] += 1

                file_time = datetime.fromtimestamp(filepath.stat().st_mtime)
                if oldest_time is None or file_time < oldest_time:
                    oldest_time = file_time
                    stats["oldest_report"] = filepath.name

                if newest_time is None or file_time > newest_time:
                    newest_time = file_time
                    stats["newest_report"] = filepath.name

        return stats

    def optimize_storage(self) -> Dict[str, Any]:
        """Optimize storage by compressing old reports and cleaning up"""
        results = {
            "archived_reports": 0,
            "compressed_reports": 0,
            "cleaned_temp_files": 0,
            "space_saved_mb": 0}

        # Archive old reports
        results["archived_reports"] = self.archive_old_reports()

        # Compress uncompressed reports older than 7 days
        cutoff_date = datetime.now() - timedelta(days=7)
        for filepath in self.base_path.glob("*.json"):
            if filepath.is_file():
                file_time = datetime.fromtimestamp(filepath.stat().st_mtime)
                if file_time < cutoff_date:
                    # Compress the file
                    compressed_path = filepath.with_suffix(
                        filepath.suffix + '.gz')
                    with open(filepath, 'rb') as f_in:
                        with gzip.open(compressed_path, 'wb') as f_out:
                            shutil.copyfileobj(f_in, f_out)

                    # Remove original and update stats
                    original_size = filepath.stat().st_size
                    filepath.unlink()
                    results["compressed_reports"] += 1
                    results["space_saved_mb"] += (original_size -
                                                  compressed_path.stat().st_size) / (1024 * 1024)

        # Clean up temporary files
        results["cleaned_temp_files"] = self.cleanup_temp_files()

        log.info(f"Storage optimization completed: {results}")
        return results
