"""
Report Service for dLNk Attack Platform
Unified report generation across all formats
"""

import asyncio
import json
from datetime import datetime
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
import aiofiles


class ReportFormat(str, Enum):
    """Report formats"""
    HTML = "html"
    JSON = "json"
    MARKDOWN = "md"
    PDF = "pdf"
    TEXT = "txt"


@dataclass
class Report:
    """Report data model"""
    id: str
    attack_id: str
    format: ReportFormat
    title: str
    filepath: str
    size: int
    created_at: str
    metadata: Dict[str, Any]


class ReportService:
    """
    Unified Report Service
    
    Generates attack reports in multiple formats
    """
    
    def __init__(self, reports_dir: str, database_service, attack_service):
        """
        Initialize Report Service
        
        Args:
            reports_dir: Directory to store reports
            database_service: Database service instance
            attack_service: Attack service instance
        """
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.db = database_service
        self.attack_service = attack_service
    
    async def generate_report(
        self,
        attack_id: str,
        format: ReportFormat = ReportFormat.HTML,
        options: Optional[Dict[str, Any]] = None
    ) -> Report:
        """
        Generate attack report
        
        Args:
            attack_id: Attack ID
            format: Report format
            options: Additional options
            
        Returns:
            Report object
        """
        # Get attack results
        results = await self.attack_service.get_attack_results(attack_id)
        if not results:
            raise ValueError(f"Attack {attack_id} not found or has no results")
        
        # Generate report content based on format
        if format == ReportFormat.HTML:
            content = await self._generate_html_report(results, options)
        elif format == ReportFormat.JSON:
            content = await self._generate_json_report(results, options)
        elif format == ReportFormat.MARKDOWN:
            content = await self._generate_markdown_report(results, options)
        elif format == ReportFormat.TEXT:
            content = await self._generate_text_report(results, options)
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        # Save report
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"report_{attack_id}_{timestamp}.{format.value}"
        filepath = self.reports_dir / filename
        
        async with aiofiles.open(filepath, 'w', encoding='utf-8') as f:
            await f.write(content)
        
        # Create report object
        report = Report(
            id=f"{attack_id}_{timestamp}",
            attack_id=attack_id,
            format=format,
            title=f"Attack Report - {results.target_url}",
            filepath=str(filepath),
            size=len(content.encode('utf-8')),
            created_at=datetime.utcnow().isoformat(),
            metadata=options or {}
        )
        
        # Store in database
        await self.db.save_report(asdict(report))
        
        return report
    
    async def _generate_html_report(
        self,
        results: Any,
        options: Optional[Dict[str, Any]]
    ) -> str:
        """Generate HTML report"""
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Attack Report - {results.target_url}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }}
        .section {{
            background: white;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .vulnerability {{
            border-left: 4px solid #dc3545;
            padding: 15px;
            margin: 10px 0;
            background: #fff5f5;
        }}
        .severity-critical {{ border-left-color: #dc3545; }}
        .severity-high {{ border-left-color: #fd7e14; }}
        .severity-medium {{ border-left-color: #ffc107; }}
        .severity-low {{ border-left-color: #28a745; }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}
        .stat {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            text-align: center;
        }}
        .stat-value {{
            font-size: 32px;
            font-weight: bold;
            color: #667eea;
        }}
        .stat-label {{
            color: #6c757d;
            margin-top: 5px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }}
        th {{
            background: #f8f9fa;
            font-weight: 600;
        }}
        code {{
            background: #f8f9fa;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🎯 dLNk Attack Report</h1>
        <p><strong>Target:</strong> {results.target_url}</p>
        <p><strong>Attack Type:</strong> {results.attack_type}</p>
        <p><strong>Status:</strong> {results.status}</p>
        <p><strong>Execution Time:</strong> {results.execution_time:.2f}s</p>
    </div>
    
    <div class="section">
        <h2>📊 Summary</h2>
        <div class="stats">
            <div class="stat">
                <div class="stat-value">{len(results.vulnerabilities)}</div>
                <div class="stat-label">Vulnerabilities</div>
            </div>
            <div class="stat">
                <div class="stat-value">{len(results.exfiltrated_data)}</div>
                <div class="stat-label">Files Exfiltrated</div>
            </div>
            <div class="stat">
                <div class="stat-value">{len(results.shells)}</div>
                <div class="stat-label">Shells Obtained</div>
            </div>
            <div class="stat">
                <div class="stat-value">{len(results.credentials)}</div>
                <div class="stat-label">Credentials Found</div>
            </div>
        </div>
    </div>
    
    <div class="section">
        <h2>🔓 Vulnerabilities Found</h2>
        {"".join([f'''
        <div class="vulnerability severity-{v.get('severity', 'low').lower()}">
            <h3>{v.get('type', 'Unknown')} - {v.get('severity', 'Unknown').upper()}</h3>
            <p><strong>Location:</strong> <code>{v.get('location', 'N/A')}</code></p>
            <p><strong>Description:</strong> {v.get('description', 'No description')}</p>
            <p><strong>Impact:</strong> {v.get('impact', 'Unknown')}</p>
            <p><strong>Remediation:</strong> {v.get('remediation', 'No remediation provided')}</p>
        </div>
        ''' for v in results.vulnerabilities])}
    </div>
    
    <div class="section">
        <h2>📁 Exfiltrated Data</h2>
        <table>
            <tr>
                <th>Filename</th>
                <th>Size</th>
                <th>Type</th>
            </tr>
            {"".join([f'''
            <tr>
                <td>{f.get('filename', 'Unknown')}</td>
                <td>{f.get('size', 0)} bytes</td>
                <td>{f.get('type', 'Unknown')}</td>
            </tr>
            ''' for f in results.exfiltrated_data])}
        </table>
    </div>
    
    <div class="section">
        <h2>🔐 Credentials Found</h2>
        <table>
            <tr>
                <th>Type</th>
                <th>Username</th>
                <th>Source</th>
            </tr>
            {"".join([f'''
            <tr>
                <td>{c.get('type', 'Unknown')}</td>
                <td><code>{c.get('username', 'N/A')}</code></td>
                <td>{c.get('source', 'Unknown')}</td>
            </tr>
            ''' for c in results.credentials])}
        </table>
    </div>
    
    <div class="section">
        <p style="text-align: center; color: #6c757d;">
            Generated by dLNk Attack Platform<br>
            {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
        </p>
    </div>
</body>
</html>"""
        return html
    
    async def _generate_json_report(
        self,
        results: Any,
        options: Optional[Dict[str, Any]]
    ) -> str:
        """Generate JSON report"""
        report_data = {
            "attack_id": results.attack_id,
            "target_url": results.target_url,
            "attack_type": results.attack_type,
            "status": results.status,
            "execution_time": results.execution_time,
            "timestamp": datetime.utcnow().isoformat(),
            "summary": {
                "vulnerabilities_count": len(results.vulnerabilities),
                "exfiltrated_files_count": len(results.exfiltrated_data),
                "shells_count": len(results.shells),
                "credentials_count": len(results.credentials)
            },
            "vulnerabilities": results.vulnerabilities,
            "exfiltrated_data": results.exfiltrated_data,
            "shells": results.shells,
            "credentials": results.credentials,
            "metadata": results.metadata
        }
        return json.dumps(report_data, indent=2)
    
    async def _generate_markdown_report(
        self,
        results: Any,
        options: Optional[Dict[str, Any]]
    ) -> str:
        """Generate Markdown report"""
        md = f"""# dLNk Attack Report

## Target Information
- **URL**: {results.target_url}
- **Attack Type**: {results.attack_type}
- **Status**: {results.status}
- **Execution Time**: {results.execution_time:.2f}s
- **Generated**: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}

## Summary
- **Vulnerabilities Found**: {len(results.vulnerabilities)}
- **Files Exfiltrated**: {len(results.exfiltrated_data)}
- **Shells Obtained**: {len(results.shells)}
- **Credentials Found**: {len(results.credentials)}

## Vulnerabilities

"""
        for v in results.vulnerabilities:
            md += f"""### {v.get('type', 'Unknown')} [{v.get('severity', 'Unknown').upper()}]
- **Location**: `{v.get('location', 'N/A')}`
- **Description**: {v.get('description', 'No description')}
- **Impact**: {v.get('impact', 'Unknown')}
- **Remediation**: {v.get('remediation', 'No remediation provided')}

"""
        
        md += """## Exfiltrated Data

| Filename | Size | Type |
|----------|------|------|
"""
        for f in results.exfiltrated_data:
            md += f"| {f.get('filename', 'Unknown')} | {f.get('size', 0)} bytes | {f.get('type', 'Unknown')} |\n"
        
        md += """\n## Credentials Found

| Type | Username | Source |
|------|----------|--------|
"""
        for c in results.credentials:
            md += f"| {c.get('type', 'Unknown')} | `{c.get('username', 'N/A')}` | {c.get('source', 'Unknown')} |\n"
        
        md += "\n---\n*Generated by dLNk Attack Platform*\n"
        return md
    
    async def _generate_text_report(
        self,
        results: Any,
        options: Optional[Dict[str, Any]]
    ) -> str:
        """Generate plain text report"""
        text = f"""dLNk ATTACK REPORT
{'=' * 80}

TARGET INFORMATION
  URL: {results.target_url}
  Attack Type: {results.attack_type}
  Status: {results.status}
  Execution Time: {results.execution_time:.2f}s
  Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}

SUMMARY
  Vulnerabilities Found: {len(results.vulnerabilities)}
  Files Exfiltrated: {len(results.exfiltrated_data)}
  Shells Obtained: {len(results.shells)}
  Credentials Found: {len(results.credentials)}

VULNERABILITIES
{'-' * 80}
"""
        for i, v in enumerate(results.vulnerabilities, 1):
            text += f"""
{i}. {v.get('type', 'Unknown')} [{v.get('severity', 'Unknown').upper()}]
   Location: {v.get('location', 'N/A')}
   Description: {v.get('description', 'No description')}
   Impact: {v.get('impact', 'Unknown')}
   Remediation: {v.get('remediation', 'No remediation provided')}
"""
        
        text += f"\n{'-' * 80}\nGenerated by dLNk Attack Platform\n"
        return text
    
    async def list_reports(
        self,
        attack_id: Optional[str] = None,
        limit: int = 100
    ) -> List[Report]:
        """
        List reports
        
        Args:
            attack_id: Filter by attack ID
            limit: Maximum number of results
            
        Returns:
            List of Report objects
        """
        filters = {}
        if attack_id:
            filters["attack_id"] = attack_id
        
        reports_data = await self.db.list_reports(filters, limit)
        return [Report(**data) for data in reports_data]
    
    async def get_report(self, report_id: str) -> Optional[Report]:
        """
        Get report information
        
        Args:
            report_id: Report ID
            
        Returns:
            Report object or None if not found
        """
        report_data = await self.db.get_report(report_id)
        if report_data:
            return Report(**report_data)
        return None
    
    async def delete_report(self, report_id: str) -> bool:
        """
        Delete a report
        
        Args:
            report_id: Report ID
            
        Returns:
            True if deleted successfully
        """
        report = await self.get_report(report_id)
        if not report:
            return False
        
        # Delete physical file
        filepath = Path(report.filepath)
        if filepath.exists():
            filepath.unlink()
        
        # Delete from database
        return await self.db.delete_report(report_id)

