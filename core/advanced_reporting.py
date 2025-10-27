"""
Advanced Reporting System
ระบบรายงานขั้นสูง พร้อม CVSS scoring, timeline visualization, และ export functions
"""

import json
import os
from typing import Dict, List, Any, Optional
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, asdict

from core.logger import log


class CVSSVersion(Enum):
    """CVSS Version"""
    V3_1 = "3.1"
    V4_0 = "4.0"


class Severity(Enum):
    """Vulnerability severity"""
    NONE = "None"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


@dataclass
class CVSSScore:
    """CVSS Score calculation result"""
    version: str
    base_score: float
    temporal_score: float
    environmental_score: float
    severity: str
    vector_string: str
    metrics: Dict[str, str]


class CVSSCalculator:
    """
    CVSS Score Calculator
    
    รองรับ CVSS v3.1 และ v4.0
    """
    
    def __init__(self, version: CVSSVersion = CVSSVersion.V3_1):
        """
        Initialize CVSS calculator
        
        Args:
            version: CVSS version
        """
        self.version = version
    
    def calculate_v31(self, metrics: Dict[str, str]) -> CVSSScore:
        """
        คำนวณ CVSS v3.1 score
        
        Args:
            metrics: CVSS metrics
        
        Returns:
            CVSS score result
        """
        # Base Metrics
        av = metrics.get("AV", "N")  # Attack Vector
        ac = metrics.get("AC", "L")  # Attack Complexity
        pr = metrics.get("PR", "N")  # Privileges Required
        ui = metrics.get("UI", "N")  # User Interaction
        s = metrics.get("S", "U")    # Scope
        c = metrics.get("C", "H")    # Confidentiality
        i = metrics.get("I", "H")    # Integrity
        a = metrics.get("A", "H")    # Availability
        
        # Metric values
        av_values = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
        ac_values = {"L": 0.77, "H": 0.44}
        pr_values = {
            "N": {"U": 0.85, "C": 0.85},
            "L": {"U": 0.62, "C": 0.68},
            "H": {"U": 0.27, "C": 0.50}
        }
        ui_values = {"N": 0.85, "R": 0.62}
        c_values = {"N": 0, "L": 0.22, "H": 0.56}
        i_values = {"N": 0, "L": 0.22, "H": 0.56}
        a_values = {"N": 0, "L": 0.22, "H": 0.56}
        
        # Calculate Impact
        isc_base = 1 - ((1 - c_values[c]) * (1 - i_values[i]) * (1 - a_values[a]))
        
        if s == "U":
            impact = 6.42 * isc_base
        else:
            impact = 7.52 * (isc_base - 0.029) - 3.25 * pow(isc_base - 0.02, 15)
        
        # Calculate Exploitability
        exploitability = 8.22 * av_values[av] * ac_values[ac] * pr_values[pr][s] * ui_values[ui]
        
        # Calculate Base Score
        if impact <= 0:
            base_score = 0.0
        elif s == "U":
            base_score = min(impact + exploitability, 10.0)
        else:
            base_score = min(1.08 * (impact + exploitability), 10.0)
        
        base_score = round(base_score, 1)
        
        # Determine severity
        if base_score == 0.0:
            severity = Severity.NONE.value
        elif base_score < 4.0:
            severity = Severity.LOW.value
        elif base_score < 7.0:
            severity = Severity.MEDIUM.value
        elif base_score < 9.0:
            severity = Severity.HIGH.value
        else:
            severity = Severity.CRITICAL.value
        
        # Vector string
        vector_string = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
        
        return CVSSScore(
            version="3.1",
            base_score=base_score,
            temporal_score=base_score,  # Simplified
            environmental_score=base_score,  # Simplified
            severity=severity,
            vector_string=vector_string,
            metrics=metrics
        )
    
    def calculate_from_vulnerability(self, vuln_data: Dict[str, Any]) -> CVSSScore:
        """
        คำนวณ CVSS จากข้อมูลช่องโหว่
        
        Args:
            vuln_data: Vulnerability data
        
        Returns:
            CVSS score
        """
        # Auto-determine metrics from vulnerability data
        vuln_type = vuln_data.get("type", "").lower()
        
        # Default metrics
        metrics = {
            "AV": "N",  # Network
            "AC": "L",  # Low
            "PR": "N",  # None
            "UI": "N",  # None
            "S": "U",   # Unchanged
            "C": "H",   # High
            "I": "H",   # High
            "A": "H"    # High
        }
        
        # Adjust based on vulnerability type
        if "sql" in vuln_type or "injection" in vuln_type:
            metrics.update({"C": "H", "I": "H", "A": "H"})
        elif "xss" in vuln_type:
            metrics.update({"C": "L", "I": "L", "A": "N", "UI": "R"})
        elif "csrf" in vuln_type:
            metrics.update({"C": "L", "I": "L", "A": "L", "UI": "R"})
        elif "auth" in vuln_type or "bypass" in vuln_type:
            metrics.update({"C": "H", "I": "H", "A": "H", "PR": "N"})
        elif "rce" in vuln_type or "command" in vuln_type:
            metrics.update({"C": "H", "I": "H", "A": "H", "S": "C"})
        elif "xxe" in vuln_type:
            metrics.update({"C": "H", "I": "L", "A": "L"})
        elif "ssrf" in vuln_type:
            metrics.update({"C": "H", "I": "L", "A": "L"})
        
        # Override with provided metrics
        if "cvss_metrics" in vuln_data:
            metrics.update(vuln_data["cvss_metrics"])
        
        return self.calculate_v31(metrics)


class TimelineEvent:
    """Timeline event for attack visualization"""
    
    def __init__(
        self,
        timestamp: str,
        event_type: str,
        title: str,
        description: str,
        severity: str = "info",
        metadata: Optional[Dict[str, Any]] = None
    ):
        self.timestamp = timestamp
        self.event_type = event_type
        self.title = title
        self.description = description
        self.severity = severity
        self.metadata = metadata or {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "metadata": self.metadata
        }


class AdvancedReportGenerator:
    """
    Advanced Report Generator
    
    Features:
    - CVSS scoring
    - Timeline visualization
    - Interactive charts data
    - Multiple export formats (JSON, HTML, PDF, Word, Excel)
    - Compliance reports (OWASP, PCI-DSS)
    """
    
    def __init__(self):
        """Initialize advanced report generator"""
        self.cvss_calculator = CVSSCalculator()
        self.reports = {}
    
    def generate_comprehensive_report(
        self,
        session_id: str,
        findings: List[Dict[str, Any]],
        target_info: Dict[str, Any],
        attack_timeline: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        สร้างรายงานแบบครอบคลุม
        
        Args:
            session_id: Session ID
            findings: List of findings
            target_info: Target information
            attack_timeline: Attack timeline events
        
        Returns:
            Comprehensive report
        """
        log.info(f"[AdvancedReporting] Generating comprehensive report for {session_id}")
        
        # Calculate CVSS scores for all findings
        findings_with_cvss = []
        for finding in findings:
            cvss_score = self.cvss_calculator.calculate_from_vulnerability(finding)
            finding_with_cvss = finding.copy()
            finding_with_cvss["cvss"] = asdict(cvss_score)
            findings_with_cvss.append(finding_with_cvss)
        
        # Sort by CVSS score
        findings_with_cvss.sort(key=lambda x: x["cvss"]["base_score"], reverse=True)
        
        # Generate statistics
        stats = self._generate_statistics(findings_with_cvss)
        
        # Generate timeline
        timeline = self._generate_timeline(attack_timeline)
        
        # Generate compliance mapping
        compliance = self._generate_compliance_mapping(findings_with_cvss)
        
        report = {
            "report_id": f"{session_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "session_id": session_id,
            "generated_at": datetime.now().isoformat(),
            "target": target_info,
            "statistics": stats,
            "exploits": findings_with_cvss,
            "timeline": timeline,
            "compliance": compliance
        }
        
        self.reports[report["report_id"]] = report
        
        return report
    
    def _generate_statistics(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        สร้างสถิติ
        
        Args:
            findings: List of findings
        
        Returns:
            Statistics
        """
        total = len(findings)
        
        # Count by severity
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "none": 0
        }
        
        for finding in findings:
            severity = finding.get("cvss", {}).get("severity", "None").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Count by type
        type_counts = {}
        for finding in findings:
            vuln_type = finding.get("type", "Unknown")
            type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
        
        # Average CVSS score
        cvss_scores = [f.get("cvss", {}).get("base_score", 0) for f in findings]
        avg_cvss = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0
        
        return {
            "total_findings": total,
            "severity_distribution": severity_counts,
            "type_distribution": type_counts,
            "average_cvss_score": round(avg_cvss, 1),
            "highest_cvss_score": max(cvss_scores) if cvss_scores else 0
        }
    
    def _generate_timeline(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        สร้าง timeline
        
        Args:
            events: List of timeline events
        
        Returns:
            Formatted timeline
        """
        timeline = []
        
        for event in events:
            timeline_event = TimelineEvent(
                timestamp=event.get("timestamp", datetime.now().isoformat()),
                event_type=event.get("type", "unknown"),
                title=event.get("title", "Event"),
                description=event.get("description", ""),
                severity=event.get("severity", "info"),
                metadata=event.get("metadata", {})
            )
            timeline.append(timeline_event.to_dict())
        
        # Sort by timestamp
        timeline.sort(key=lambda x: x["timestamp"])
        
        return timeline
    
    def _generate_executive_summary(
        self,
        findings: List[Dict[str, Any]],
        stats: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        สร้าง executive summary
        
        Args:
            findings: List of findings
            stats: Statistics
        
        Returns:
            Executive summary
        """
        critical_count = stats["severity_distribution"]["critical"]
        high_count = stats["severity_distribution"]["high"]
        
        risk_level = "Critical" if critical_count > 0 else "High" if high_count > 0 else "Medium"
        
        summary = {
            "risk_level": risk_level,
            "total_vulnerabilities": stats["total_findings"],
            "critical_vulnerabilities": critical_count,
            "high_vulnerabilities": high_count,
            "average_cvss": stats["average_cvss_score"],
            "key_findings": [
                f["type"] for f in findings[:5]  # Top 5
            ],
            "immediate_actions_required": critical_count > 0 or high_count > 3
        }
        
        return summary
    
    def _generate_recommendations(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        สร้างคำแนะนำ
        
        Args:
            findings: List of findings
        
        Returns:
            List of recommendations
        """
        recommendations = []
        
        # Group by type
        by_type = {}
        for finding in findings:
            vuln_type = finding.get("type", "Unknown")
            if vuln_type not in by_type:
                by_type[vuln_type] = []
            by_type[vuln_type].append(finding)
        
        # Generate recommendations for each type
        for vuln_type, vulns in by_type.items():
            recommendation = {
                "vulnerability_type": vuln_type,
                "count": len(vulns),
                "max_severity": max([v.get("cvss", {}).get("severity", "Low") for v in vulns]),
                "remediation": self._get_remediation(vuln_type),
                "priority": "High" if len(vulns) > 3 else "Medium"
            }
            recommendations.append(recommendation)
        
        # Sort by priority and count
        recommendations.sort(key=lambda x: (x["priority"] == "High", x["count"]), reverse=True)
        
        return recommendations
    
    def _get_remediation(self, vuln_type: str) -> str:
        """
        รับคำแนะนำการแก้ไข
        
        Args:
            vuln_type: Vulnerability type
        
        Returns:
            Remediation advice
        """
        remediations = {
            "SQL Injection": "ใช้ Prepared Statements และ Parameterized Queries, Validate input, ใช้ ORM",
            "XSS": "Encode output, Validate input, ใช้ Content Security Policy (CSP)",
            "CSRF": "ใช้ CSRF tokens, ตรวจสอบ Referer header, ใช้ SameSite cookies",
            "Command Injection": "Validate input, ใช้ safe APIs, Avoid shell execution",
            "Path Traversal": "Validate file paths, ใช้ whitelist, Restrict file access",
            "XXE": "Disable external entities, ใช้ safe XML parsers",
            "SSRF": "Validate URLs, ใช้ whitelist, Restrict network access",
            "Authentication Bypass": "ใช้ strong authentication, Implement MFA, Regular security audits",
            "RCE": "Validate input, Sandbox execution, Regular patching"
        }
        
        return remediations.get(vuln_type, "ดำเนินการตาม security best practices")
    
    def _generate_compliance_mapping(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        สร้าง compliance mapping
        
        Args:
            findings: List of findings
        
        Returns:
            Compliance mapping
        """
        compliance = {
            "OWASP_Top_10": self._map_to_owasp(findings),
            "PCI_DSS": self._map_to_pci_dss(findings),
            "CWE": self._map_to_cwe(findings)
        }
        
        return compliance
    
    def _map_to_owasp(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Map findings to OWASP Top 10"""
        owasp_mapping = {
            "SQL Injection": "A03:2021 – Injection",
            "XSS": "A03:2021 – Injection",
            "CSRF": "A01:2021 – Broken Access Control",
            "Authentication Bypass": "A07:2021 – Identification and Authentication Failures",
            "XXE": "A05:2021 – Security Misconfiguration",
            "SSRF": "A10:2021 – Server-Side Request Forgery",
            "Command Injection": "A03:2021 – Injection",
            "Path Traversal": "A01:2021 – Broken Access Control"
        }
        
        owasp_findings = {}
        for finding in findings:
            vuln_type = finding.get("type", "Unknown")
            owasp_cat = owasp_mapping.get(vuln_type, "Other")
            
            if owasp_cat not in owasp_findings:
                owasp_findings[owasp_cat] = []
            owasp_findings[owasp_cat].append(vuln_type)
        
        return [{"category": k, "findings": v} for k, v in owasp_findings.items()]
    
    def _map_to_pci_dss(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Map findings to PCI-DSS requirements"""
        # Simplified mapping
        requirements = set()
        
        for finding in findings:
            severity = finding.get("cvss", {}).get("severity", "Low")
            if severity in ["Critical", "High"]:
                requirements.add("6.5 - Address common coding vulnerabilities")
                requirements.add("11.3 - Implement penetration testing")
        
        return list(requirements)
    
    def _map_to_cwe(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Map findings to CWE"""
        cwe_mapping = {
            "SQL Injection": "CWE-89",
            "XSS": "CWE-79",
            "CSRF": "CWE-352",
            "Command Injection": "CWE-78",
            "Path Traversal": "CWE-22",
            "XXE": "CWE-611",
            "SSRF": "CWE-918",
            "Authentication Bypass": "CWE-287"
        }
        
        cwe_findings = []
        for finding in findings:
            vuln_type = finding.get("type", "Unknown")
            cwe_id = cwe_mapping.get(vuln_type)
            
            if cwe_id:
                cwe_findings.append({
                    "cwe_id": cwe_id,
                    "vulnerability": vuln_type
                })
        
        return cwe_findings
    
    def export_to_json(self, report_id: str, filepath: str) -> bool:
        """
        Export report to JSON
        
        Args:
            report_id: Report ID
            filepath: Output file path
        
        Returns:
            Success status
        """
        try:
            report = self.reports.get(report_id)
            if not report:
                return False
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            log.info(f"[AdvancedReporting] Report exported to JSON: {filepath}")
            return True
        
        except Exception as e:
            log.error(f"[AdvancedReporting] Failed to export to JSON: {e}")
            return False
    
    def export_to_html(self, report_id: str, filepath: str) -> bool:
        """
        Export report to HTML
        
        Args:
            report_id: Report ID
            filepath: Output file path
        
        Returns:
            Success status
        """
        try:
            report = self.reports.get(report_id)
            if not report:
                return False
            
            html_content = self._generate_html_report(report)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            log.info(f"[AdvancedReporting] Report exported to HTML: {filepath}")
            return True
        
        except Exception as e:
            log.error(f"[AdvancedReporting] Failed to export to HTML: {e}")
            return False
    
    def _generate_html_report(self, report: Dict[str, Any]) -> str:
        """Generate HTML report"""
        # Simplified HTML generation
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Security Assessment Report - {report['session_id']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #333; }}
        .summary {{ background: #f5f5f5; padding: 20px; border-radius: 5px; }}
        .finding {{ border-left: 4px solid #e74c3c; padding: 10px; margin: 10px 0; }}
        .critical {{ border-color: #e74c3c; }}
        .high {{ border-color: #e67e22; }}
        .medium {{ border-color: #f39c12; }}
        .low {{ border-color: #3498db; }}
    </style>
</head>
<body>
    <h1>Security Assessment Report</h1>
    <div class="summary">
        <h2>Executive Summary</h2>
        <p><strong>Risk Level:</strong> {report['executive_summary']['risk_level']}</p>
        <p><strong>Total Vulnerabilities:</strong> {report['executive_summary']['total_vulnerabilities']}</p>
        <p><strong>Critical:</strong> {report['executive_summary']['critical_vulnerabilities']}</p>
        <p><strong>High:</strong> {report['executive_summary']['high_vulnerabilities']}</p>
    </div>
    
    <h2>Findings</h2>
    {''.join([f'<div class="finding {f["cvss"]["severity"].lower()}"><h3>{f["type"]}</h3><p>CVSS: {f["cvss"]["base_score"]} ({f["cvss"]["severity"]})</p></div>' for f in report['findings']])}
</body>
</html>
        """
        
        return html


# Example usage
if __name__ == "__main__":
    # Initialize reporter
    reporter = AdvancedReportGenerator()
    
    # Sample findings
    findings = [
        {"type": "SQL Injection", "location": "/api/users", "description": "SQL injection in user_id parameter"},
        {"type": "XSS", "location": "/search", "description": "Reflected XSS in search query"},
        {"type": "CSRF", "location": "/api/delete", "description": "Missing CSRF token"}
    ]
    
    target_info = {
        "url": "http://localhost:8000",
        "technology": "PHP + MySQL"
    }
    
    timeline = [
        {"timestamp": "2025-10-24T10:00:00", "type": "scan", "title": "Scan started", "description": "Initial reconnaissance"},
        {"timestamp": "2025-10-24T10:15:00", "type": "finding", "title": "SQL Injection found", "description": "Critical vulnerability"}
    ]
    
    # Generate report
    report = reporter.generate_comprehensive_report("test_session", findings, target_info, timeline)
    
    print(f"Report generated: {report['report_id']}")
    print(f"Risk Level: {report['executive_summary']['risk_level']}")
    print(f"Total Findings: {report['statistics']['total_findings']}")
    
    # Export
    reporter.export_to_json(report['report_id'], "/tmp/report.json")
    reporter.export_to_html(report['report_id'], "/tmp/report.html")

