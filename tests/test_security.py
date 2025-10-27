"""
Security Testing for dLNk Attack Platform
Tests security controls, input validation, and protection mechanisms
"""

import asyncio
import pytest
import aiohttp
from typing import Dict, List


class SecurityTest:
    """Security testing suite"""
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.vulnerabilities = []
    
    async def test_sql_injection(self, endpoint: str) -> Dict:
        """
        Test SQL injection vulnerabilities
        
        Args:
            endpoint: API endpoint to test
        
        Returns:
            Test results
        """
        print(f"\n[SQL Injection Test] Testing {endpoint}")
        
        # Common SQL injection payloads
        payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin'--",
            "' UNION SELECT NULL--",
            "1' AND '1'='1",
            "1' AND '1'='2",
            "' DROP TABLE users--",
        ]
        
        vulnerabilities = []
        
        async with aiohttp.ClientSession() as session:
            for payload in payloads:
                try:
                    # Test in query parameter
                    async with session.get(
                        f"{self.base_url}{endpoint}",
                        params={'id': payload}
                    ) as response:
                        content = await response.text()
                        
                        # Check for SQL error messages
                        sql_errors = [
                            'sql syntax',
                            'mysql_fetch',
                            'postgresql',
                            'sqlite',
                            'ora-',
                            'syntax error'
                        ]
                        
                        if any(error in content.lower() for error in sql_errors):
                            vulnerabilities.append({
                                'type': 'SQL Injection',
                                'payload': payload,
                                'endpoint': endpoint,
                                'severity': 'HIGH'
                            })
                            print(f"⚠️  Potential SQL injection found with payload: {payload}")
                
                except Exception as e:
                    pass
        
        if not vulnerabilities:
            print("✅ No SQL injection vulnerabilities detected")
        
        return {
            'test': 'SQL Injection',
            'endpoint': endpoint,
            'vulnerabilities': vulnerabilities,
            'passed': len(vulnerabilities) == 0
        }
    
    async def test_xss(self, endpoint: str) -> Dict:
        """
        Test Cross-Site Scripting (XSS) vulnerabilities
        
        Args:
            endpoint: API endpoint to test
        
        Returns:
            Test results
        """
        print(f"\n[XSS Test] Testing {endpoint}")
        
        # Common XSS payloads
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
        ]
        
        vulnerabilities = []
        
        async with aiohttp.ClientSession() as session:
            for payload in payloads:
                try:
                    async with session.get(
                        f"{self.base_url}{endpoint}",
                        params={'q': payload}
                    ) as response:
                        content = await response.text()
                        
                        # Check if payload is reflected without encoding
                        if payload in content:
                            vulnerabilities.append({
                                'type': 'XSS',
                                'payload': payload,
                                'endpoint': endpoint,
                                'severity': 'MEDIUM'
                            })
                            print(f"⚠️  Potential XSS found with payload: {payload}")
                
                except Exception as e:
                    pass
        
        if not vulnerabilities:
            print("✅ No XSS vulnerabilities detected")
        
        return {
            'test': 'XSS',
            'endpoint': endpoint,
            'vulnerabilities': vulnerabilities,
            'passed': len(vulnerabilities) == 0
        }
    
    async def test_authentication(self) -> Dict:
        """
        Test authentication mechanisms
        
        Returns:
            Test results
        """
        print(f"\n[Authentication Test]")
        
        issues = []
        
        async with aiohttp.ClientSession() as session:
            # Test 1: Access protected endpoint without token
            try:
                async with session.get(f"{self.base_url}/api/targets") as response:
                    if response.status == 200:
                        issues.append({
                            'issue': 'Protected endpoint accessible without authentication',
                            'severity': 'CRITICAL'
                        })
                        print("⚠️  Protected endpoint accessible without authentication")
                    else:
                        print("✅ Protected endpoints require authentication")
            except Exception as e:
                pass
            
            # Test 2: Weak password acceptance
            weak_passwords = ['123456', 'password', 'admin', '12345678']
            for pwd in weak_passwords:
                try:
                    async with session.post(
                        f"{self.base_url}/auth/register",
                        json={
                            'username': 'testuser',
                            'password': pwd,
                            'email': 'test@test.com'
                        }
                    ) as response:
                        if response.status == 201:
                            issues.append({
                                'issue': f'Weak password accepted: {pwd}',
                                'severity': 'MEDIUM'
                            })
                            print(f"⚠️  Weak password accepted: {pwd}")
                except Exception as e:
                    pass
            
            # Test 3: JWT token validation
            invalid_tokens = [
                'invalid.token.here',
                'Bearer fake_token',
                ''
            ]
            
            for token in invalid_tokens:
                try:
                    headers = {'Authorization': f'Bearer {token}'}
                    async with session.get(
                        f"{self.base_url}/api/targets",
                        headers=headers
                    ) as response:
                        if response.status == 200:
                            issues.append({
                                'issue': 'Invalid JWT token accepted',
                                'severity': 'CRITICAL'
                            })
                            print("⚠️  Invalid JWT token accepted")
                            break
                except Exception as e:
                    pass
        
        if not issues:
            print("✅ Authentication mechanisms are secure")
        
        return {
            'test': 'Authentication',
            'issues': issues,
            'passed': len(issues) == 0
        }
    
    async def test_authorization(self) -> Dict:
        """
        Test authorization and access control
        
        Returns:
            Test results
        """
        print(f"\n[Authorization Test]")
        
        issues = []
        
        # Test IDOR (Insecure Direct Object Reference)
        async with aiohttp.ClientSession() as session:
            # Try to access other users' resources
            test_ids = ['1', '2', '999', '../admin', '../../etc/passwd']
            
            for test_id in test_ids:
                try:
                    async with session.get(
                        f"{self.base_url}/api/targets/{test_id}"
                    ) as response:
                        if response.status == 200:
                            issues.append({
                                'issue': f'Possible IDOR vulnerability with ID: {test_id}',
                                'severity': 'HIGH'
                            })
                            print(f"⚠️  Possible IDOR vulnerability")
                except Exception as e:
                    pass
        
        if not issues:
            print("✅ Authorization controls are working")
        
        return {
            'test': 'Authorization',
            'issues': issues,
            'passed': len(issues) == 0
        }
    
    async def test_rate_limiting(self, endpoint: str = '/auth/login') -> Dict:
        """
        Test rate limiting implementation
        
        Args:
            endpoint: Endpoint to test
        
        Returns:
            Test results
        """
        print(f"\n[Rate Limiting Test] Testing {endpoint}")
        
        async with aiohttp.ClientSession() as session:
            # Send many requests rapidly
            responses = []
            for i in range(150):
                try:
                    async with session.post(
                        f"{self.base_url}{endpoint}",
                        json={'username': 'test', 'password': 'test'}
                    ) as response:
                        responses.append(response.status)
                except Exception as e:
                    pass
            
            # Check if any requests were rate limited (429 status)
            rate_limited = any(status == 429 for status in responses)
            
            if rate_limited:
                print("✅ Rate limiting is implemented")
            else:
                print("⚠️  No rate limiting detected")
            
            return {
                'test': 'Rate Limiting',
                'endpoint': endpoint,
                'rate_limited': rate_limited,
                'passed': rate_limited
            }
    
    async def test_input_validation(self) -> Dict:
        """
        Test input validation
        
        Returns:
            Test results
        """
        print(f"\n[Input Validation Test]")
        
        issues = []
        
        async with aiohttp.ClientSession() as session:
            # Test with invalid data types
            invalid_inputs = [
                {'name': 12345, 'host': 'test'},  # Invalid type
                {'name': 'x' * 10000, 'host': 'test'},  # Too long
                {'name': '', 'host': ''},  # Empty
                {'name': None, 'host': None},  # Null
            ]
            
            for invalid_input in invalid_inputs:
                try:
                    async with session.post(
                        f"{self.base_url}/api/targets",
                        json=invalid_input
                    ) as response:
                        if response.status == 201:
                            issues.append({
                                'issue': f'Invalid input accepted: {invalid_input}',
                                'severity': 'MEDIUM'
                            })
                            print(f"⚠️  Invalid input accepted")
                except Exception as e:
                    pass
        
        if not issues:
            print("✅ Input validation is working")
        
        return {
            'test': 'Input Validation',
            'issues': issues,
            'passed': len(issues) == 0
        }
    
    async def test_security_headers(self) -> Dict:
        """
        Test security headers
        
        Returns:
            Test results
        """
        print(f"\n[Security Headers Test]")
        
        missing_headers = []
        
        required_headers = [
            'X-Content-Type-Options',
            'X-Frame-Options',
            'X-XSS-Protection',
            'Strict-Transport-Security',
            'Content-Security-Policy'
        ]
        
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{self.base_url}/health") as response:
                headers = response.headers
                
                for header in required_headers:
                    if header not in headers:
                        missing_headers.append(header)
                        print(f"⚠️  Missing security header: {header}")
        
        if not missing_headers:
            print("✅ All security headers present")
        
        return {
            'test': 'Security Headers',
            'missing_headers': missing_headers,
            'passed': len(missing_headers) == 0
        }
    
    def generate_report(self, results: List[Dict]) -> str:
        """Generate security test report"""
        report = "\n" + "="*60 + "\n"
        report += "SECURITY TEST REPORT\n"
        report += "="*60 + "\n\n"
        
        total_tests = len(results)
        passed_tests = sum(1 for r in results if r.get('passed', False))
        
        report += f"Total Tests: {total_tests}\n"
        report += f"Passed: {passed_tests}\n"
        report += f"Failed: {total_tests - passed_tests}\n\n"
        
        for result in results:
            report += f"\nTest: {result.get('test', 'Unknown')}\n"
            report += f"Status: {'✅ PASSED' if result.get('passed') else '❌ FAILED'}\n"
            
            if 'vulnerabilities' in result and result['vulnerabilities']:
                report += f"Vulnerabilities found: {len(result['vulnerabilities'])}\n"
            
            if 'issues' in result and result['issues']:
                report += f"Issues found: {len(result['issues'])}\n"
        
        report += "\n" + "="*60 + "\n"
        
        return report


# Test cases
@pytest.mark.asyncio
async def test_security_suite():
    """Run complete security test suite"""
    tester = SecurityTest()
    
    results = []
    
    # Run all tests
    results.append(await tester.test_sql_injection('/api/targets'))
    results.append(await tester.test_xss('/api/search'))
    results.append(await tester.test_authentication())
    results.append(await tester.test_authorization())
    results.append(await tester.test_rate_limiting())
    results.append(await tester.test_input_validation())
    results.append(await tester.test_security_headers())
    
    # Generate report
    report = tester.generate_report(results)
    print(report)
    
    # Assert all tests passed
    assert all(r.get('passed', False) for r in results), "Some security tests failed"


if __name__ == '__main__':
    async def main():
        tester = SecurityTest()
        
        print("\n" + "="*60)
        print("SECURITY TEST SUITE")
        print("="*60)
        
        results = []
        results.append(await tester.test_sql_injection('/api/targets'))
        results.append(await tester.test_xss('/api/search'))
        results.append(await tester.test_authentication())
        results.append(await tester.test_authorization())
        results.append(await tester.test_rate_limiting())
        results.append(await tester.test_input_validation())
        results.append(await tester.test_security_headers())
        
        report = tester.generate_report(results)
        print(report)
    
    asyncio.run(main())

