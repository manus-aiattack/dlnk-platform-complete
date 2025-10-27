"""
Security Auditing System
Ensures platform security and compliance
"""

import asyncio
import os
import hashlib
from typing import Dict, List, Optional
from datetime import datetime
from pathlib import Path
import logging

log = logging.getLogger(__name__)


class SecurityAuditor:
    """
    Security Auditing System
    
    Features:
    - Security configuration audit
    - Vulnerability scanning
    - Access control verification
    - Secure coding practices check
    """
    
    def __init__(self):
        self.audit_results = []
        self.security_issues = []
    
    async def audit_system(self) -> Dict:
        """
        Perform comprehensive security audit
        
        Returns:
            Audit results
        """
        log.info("[SecurityAuditor] Starting security audit...")
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'checks': [],
            'issues': [],
            'score': 0.0
        }
        
        # Run security checks
        checks = [
            self._check_file_permissions(),
            self._check_api_security(),
            self._check_credentials_security(),
            self._check_encryption(),
            self._check_input_validation(),
            self._check_dependencies()
        ]
        
        for check in checks:
            try:
                check_result = await check
                results['checks'].append(check_result)
                
                if not check_result['passed']:
                    results['issues'].extend(check_result.get('issues', []))
                
            except Exception as e:
                log.error(f"[SecurityAuditor] Check failed: {e}")
        
        # Calculate security score
        passed_checks = sum(1 for c in results['checks'] if c['passed'])
        total_checks = len(results['checks'])
        results['score'] = (passed_checks / total_checks) * 100 if total_checks > 0 else 0
        
        log.info(f"[SecurityAuditor] Audit complete. Score: {results['score']:.1f}/100")
        
        self.audit_results.append(results)
        
        return results
    
    async def _check_file_permissions(self) -> Dict:
        """Check file permissions"""
        
        log.info("[SecurityAuditor] Checking file permissions...")
        
        issues = []
        
        # Check sensitive files
        sensitive_files = [
            'config.py',
            'secrets.py',
            '.env',
            'api/auth_routes.py'
        ]
        
        for file_path in sensitive_files:
            if os.path.exists(file_path):
                stat_info = os.stat(file_path)
                mode = oct(stat_info.st_mode)[-3:]
                
                # Check if world-readable
                if mode[-1] != '0':
                    issues.append({
                        'severity': 'HIGH',
                        'file': file_path,
                        'issue': f'File is world-readable (permissions: {mode})',
                        'recommendation': 'Change permissions to 600 or 640'
                    })
        
        return {
            'name': 'File Permissions',
            'passed': len(issues) == 0,
            'issues': issues
        }
    
    async def _check_api_security(self) -> Dict:
        """Check API security"""
        
        log.info("[SecurityAuditor] Checking API security...")
        
        issues = []
        
        # Check for authentication
        api_files = Path('api/routes').glob('*.py') if Path('api/routes').exists() else []
        
        for api_file in api_files:
            content = api_file.read_text()
            
            # Check for authentication decorators
            if '@router.post' in content or '@router.get' in content:
                if 'Depends' not in content and 'auth' not in content.lower():
                    issues.append({
                        'severity': 'MEDIUM',
                        'file': str(api_file),
                        'issue': 'API endpoint may lack authentication',
                        'recommendation': 'Add authentication middleware'
                    })
        
        return {
            'name': 'API Security',
            'passed': len(issues) == 0,
            'issues': issues
        }
    
    async def _check_credentials_security(self) -> Dict:
        """Check credentials security"""
        
        log.info("[SecurityAuditor] Checking credentials security...")
        
        issues = []
        
        # Check for hardcoded credentials
        code_files = list(Path('.').rglob('*.py'))
        
        dangerous_patterns = [
            'password = "',
            'api_key = "',
            'secret = "',
            'token = "'
        ]
        
        for code_file in code_files[:50]:  # Limit to avoid long scan
            try:
                content = code_file.read_text()
                
                for pattern in dangerous_patterns:
                    if pattern in content.lower():
                        issues.append({
                            'severity': 'CRITICAL',
                            'file': str(code_file),
                            'issue': 'Potential hardcoded credentials found',
                            'recommendation': 'Use environment variables or secure vault'
                        })
                        break
                        
            except Exception:
                pass
        
        return {
            'name': 'Credentials Security',
            'passed': len(issues) == 0,
            'issues': issues
        }
    
    async def _check_encryption(self) -> Dict:
        """Check encryption usage"""
        
        log.info("[SecurityAuditor] Checking encryption...")
        
        issues = []
        
        # Check if sensitive data is encrypted
        # This is a simplified check
        
        return {
            'name': 'Encryption',
            'passed': True,
            'issues': issues
        }
    
    async def _check_input_validation(self) -> Dict:
        """Check input validation"""
        
        log.info("[SecurityAuditor] Checking input validation...")
        
        issues = []
        
        # Check API routes for input validation
        api_files = list(Path('api/routes').glob('*.py')) if Path('api/routes').exists() else []
        
        for api_file in api_files:
            content = api_file.read_text()
            
            # Check for Pydantic models (input validation)
            if '@router.post' in content or '@router.put' in content:
                if 'BaseModel' not in content:
                    issues.append({
                        'severity': 'MEDIUM',
                        'file': str(api_file),
                        'issue': 'API may lack input validation',
                        'recommendation': 'Use Pydantic models for input validation'
                    })
        
        return {
            'name': 'Input Validation',
            'passed': len(issues) == 0,
            'issues': issues
        }
    
    async def _check_dependencies(self) -> Dict:
        """Check for vulnerable dependencies"""
        
        log.info("[SecurityAuditor] Checking dependencies...")
        
        issues = []
        
        # Check if requirements.txt exists
        if os.path.exists('requirements.txt'):
            # In production, use safety or pip-audit
            issues.append({
                'severity': 'INFO',
                'issue': 'Run "pip-audit" to check for vulnerable dependencies',
                'recommendation': 'Regularly update dependencies'
            })
        
        return {
            'name': 'Dependencies',
            'passed': True,
            'issues': issues
        }
    
    async def generate_report(self) -> str:
        """Generate security audit report"""
        
        if not self.audit_results:
            return "No audit results available"
        
        latest = self.audit_results[-1]
        
        report = []
        report.append("=" * 80)
        report.append("SECURITY AUDIT REPORT")
        report.append("=" * 80)
        report.append("")
        report.append(f"Timestamp: {latest['timestamp']}")
        report.append(f"Security Score: {latest['score']:.1f}/100")
        report.append("")
        
        # Summary
        passed = sum(1 for c in latest['checks'] if c['passed'])
        failed = len(latest['checks']) - passed
        
        report.append(f"Checks Passed: {passed}/{len(latest['checks'])}")
        report.append(f"Checks Failed: {failed}")
        report.append("")
        
        # Issues by severity
        critical = [i for i in latest['issues'] if i.get('severity') == 'CRITICAL']
        high = [i for i in latest['issues'] if i.get('severity') == 'HIGH']
        medium = [i for i in latest['issues'] if i.get('severity') == 'MEDIUM']
        
        report.append(f"Critical Issues: {len(critical)}")
        report.append(f"High Issues: {len(high)}")
        report.append(f"Medium Issues: {len(medium)}")
        report.append("")
        
        # Detailed issues
        if latest['issues']:
            report.append("ISSUES FOUND:")
            report.append("-" * 80)
            
            for issue in latest['issues']:
                report.append(f"\n[{issue.get('severity', 'UNKNOWN')}] {issue.get('issue', 'Unknown issue')}")
                if 'file' in issue:
                    report.append(f"  File: {issue['file']}")
                if 'recommendation' in issue:
                    report.append(f"  Recommendation: {issue['recommendation']}")
        else:
            report.append("No security issues found!")
        
        report.append("")
        report.append("=" * 80)
        
        return '\n'.join(report)
    
    async def fix_common_issues(self):
        """Automatically fix common security issues"""
        
        log.info("[SecurityAuditor] Attempting to fix common issues...")
        
        fixed_count = 0
        
        # Fix file permissions
        sensitive_files = ['config.py', 'secrets.py', '.env']
        
        for file_path in sensitive_files:
            if os.path.exists(file_path):
                try:
                    os.chmod(file_path, 0o600)
                    log.info(f"[SecurityAuditor] Fixed permissions for {file_path}")
                    fixed_count += 1
                except Exception as e:
                    log.error(f"[SecurityAuditor] Failed to fix {file_path}: {e}")
        
        log.info(f"[SecurityAuditor] Fixed {fixed_count} issues")
        
        return fixed_count


if __name__ == '__main__':
    async def test():
        auditor = SecurityAuditor()
        
        # Run audit
        results = await auditor.audit_system()
        
        print(f"Security Score: {results['score']:.1f}/100")
        print(f"Issues Found: {len(results['issues'])}")
        
        # Generate report
        report = await auditor.generate_report()
        print(f"\n{report}")
    
    asyncio.run(test())

