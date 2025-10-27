"""
File Service for dLNk Attack Platform
Unified file management for exfiltrated data
"""

import os
import asyncio
import aiofiles
import zipfile
import hashlib
from datetime import datetime
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, asdict
from pathlib import Path
import mimetypes


@dataclass
class FileInfo:
    """File information data model"""
    id: str
    attack_id: str
    filename: str
    filepath: str
    size: int
    mime_type: str
    hash_md5: str
    hash_sha256: str
    source: str  # e.g., "database_dump", "file_download", "credential_harvest"
    created_at: str
    metadata: Dict[str, Any]


class FileService:
    """
    Unified File Service
    
    Manages exfiltrated files across all interfaces
    """
    
    def __init__(self, loot_dir: str, database_service):
        """
        Initialize File Service
        
        Args:
            loot_dir: Directory to store exfiltrated files
            database_service: Database service instance
        """
        self.loot_dir = Path(loot_dir)
        self.loot_dir.mkdir(parents=True, exist_ok=True)
        self.db = database_service
    
    async def save_file(
        self,
        attack_id: str,
        filename: str,
        content: bytes,
        source: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> FileInfo:
        """
        Save an exfiltrated file
        
        Args:
            attack_id: Attack ID
            filename: Original filename
            content: File content
            source: Source of the file
            metadata: Additional metadata
            
        Returns:
            FileInfo object
        """
        # Create attack directory
        attack_dir = self.loot_dir / attack_id
        attack_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate unique filename
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        safe_filename = self._sanitize_filename(filename)
        filepath = attack_dir / f"{timestamp}_{safe_filename}"
        
        # Save file
        async with aiofiles.open(filepath, 'wb') as f:
            await f.write(content)
        
        # Calculate hashes
        md5_hash = hashlib.md5(content).hexdigest()
        sha256_hash = hashlib.sha256(content).hexdigest()
        
        # Get mime type
        mime_type, _ = mimetypes.guess_type(filename)
        if not mime_type:
            mime_type = "application/octet-stream"
        
        # Create file info
        file_info = FileInfo(
            id=sha256_hash[:16],  # Use first 16 chars of SHA256 as ID
            attack_id=attack_id,
            filename=filename,
            filepath=str(filepath),
            size=len(content),
            mime_type=mime_type,
            hash_md5=md5_hash,
            hash_sha256=sha256_hash,
            source=source,
            created_at=datetime.utcnow().isoformat(),
            metadata=metadata or {}
        )
        
        # Store in database
        await self.db.save_file_info(asdict(file_info))
        
        return file_info
    
    async def list_files(
        self,
        attack_id: str,
        source: Optional[str] = None
    ) -> List[FileInfo]:
        """
        List files for an attack
        
        Args:
            attack_id: Attack ID
            source: Filter by source
            
        Returns:
            List of FileInfo objects
        """
        filters = {"attack_id": attack_id}
        if source:
            filters["source"] = source
        
        files_data = await self.db.list_files(filters)
        return [FileInfo(**data) for data in files_data]
    
    async def get_file(self, file_id: str) -> Optional[FileInfo]:
        """
        Get file information
        
        Args:
            file_id: File ID
            
        Returns:
            FileInfo object or None if not found
        """
        file_data = await self.db.get_file(file_id)
        if file_data:
            return FileInfo(**file_data)
        return None
    
    async def download_file(self, file_id: str) -> Optional[bytes]:
        """
        Download file content
        
        Args:
            file_id: File ID
            
        Returns:
            File content as bytes or None if not found
        """
        file_info = await self.get_file(file_id)
        if not file_info:
            return None
        
        filepath = Path(file_info.filepath)
        if not filepath.exists():
            return None
        
        async with aiofiles.open(filepath, 'rb') as f:
            return await f.read()
    
    async def delete_file(self, file_id: str) -> bool:
        """
        Delete a file
        
        Args:
            file_id: File ID
            
        Returns:
            True if deleted successfully
        """
        file_info = await self.get_file(file_id)
        if not file_info:
            return False
        
        # Delete physical file
        filepath = Path(file_info.filepath)
        if filepath.exists():
            filepath.unlink()
        
        # Delete from database
        return await self.db.delete_file(file_id)
    
    async def create_zip(
        self,
        attack_id: str,
        file_ids: Optional[List[str]] = None
    ) -> Optional[bytes]:
        """
        Create a ZIP archive of files
        
        Args:
            attack_id: Attack ID
            file_ids: List of file IDs to include (None = all files)
            
        Returns:
            ZIP file content as bytes or None if no files
        """
        # Get files to zip
        if file_ids:
            files = []
            for file_id in file_ids:
                file_info = await self.get_file(file_id)
                if file_info:
                    files.append(file_info)
        else:
            files = await self.list_files(attack_id)
        
        if not files:
            return None
        
        # Create ZIP in memory
        import io
        zip_buffer = io.BytesIO()
        
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            for file_info in files:
                filepath = Path(file_info.filepath)
                if filepath.exists():
                    # Add file to ZIP with relative path
                    arcname = f"{file_info.source}/{file_info.filename}"
                    zip_file.write(filepath, arcname)
        
        return zip_buffer.getvalue()
    
    async def get_total_size(self, attack_id: str) -> int:
        """
        Get total size of all files for an attack
        
        Args:
            attack_id: Attack ID
            
        Returns:
            Total size in bytes
        """
        files = await self.list_files(attack_id)
        return sum(f.size for f in files)
    
    async def cleanup_attack_files(self, attack_id: str) -> int:
        """
        Delete all files for an attack
        
        Args:
            attack_id: Attack ID
            
        Returns:
            Number of files deleted
        """
        files = await self.list_files(attack_id)
        count = 0
        
        for file_info in files:
            if await self.delete_file(file_info.id):
                count += 1
        
        # Remove attack directory if empty
        attack_dir = self.loot_dir / attack_id
        if attack_dir.exists() and not any(attack_dir.iterdir()):
            attack_dir.rmdir()
        
        return count
    
    def _sanitize_filename(self, filename: str) -> str:
        """
        Sanitize filename to prevent path traversal
        
        Args:
            filename: Original filename
            
        Returns:
            Sanitized filename
        """
        # Remove path components
        filename = os.path.basename(filename)
        
        # Remove dangerous characters
        dangerous_chars = ['/', '\\', '..', '\x00']
        for char in dangerous_chars:
            filename = filename.replace(char, '_')
        
        # Limit length
        if len(filename) > 255:
            name, ext = os.path.splitext(filename)
            filename = name[:250] + ext
        
        return filename
    
    async def get_file_stats(self, attack_id: str) -> Dict[str, Any]:
        """
        Get file statistics for an attack
        
        Args:
            attack_id: Attack ID
            
        Returns:
            Dictionary with statistics
        """
        files = await self.list_files(attack_id)
        
        # Group by source
        by_source = {}
        for file_info in files:
            source = file_info.source
            if source not in by_source:
                by_source[source] = {"count": 0, "size": 0}
            by_source[source]["count"] += 1
            by_source[source]["size"] += file_info.size
        
        return {
            "total_files": len(files),
            "total_size": sum(f.size for f in files),
            "by_source": by_source,
            "mime_types": list(set(f.mime_type for f in files))
        }

