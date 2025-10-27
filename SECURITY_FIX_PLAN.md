# Security Fix Plan for Manus AI Platform

## 🚨 Critical Security Issues Summary

Based on comprehensive security scans (semgrep, bandit), we have identified **151 security issues** requiring immediate attention before production deployment.

## 📊 Priority Classification

### 🔴 CRITICAL (Fix Immediately - Within 24 hours)
1. **Dockerfile Security Issues**
   - Missing USER directive (running as root)
   - Insecure file permissions (0o755 instead of 0o644)

2. **JWT Security Vulnerabilities**
   - Hardcoded JWT secrets in `advanced_agents/auth_bypass.py`
   - Unverified JWT tokens (verify=False)
   - Use of 'none' algorithm in JWT tokens

3. **Hardcoded Secrets**
   - SSH passwords detected in agent files
   - API keys and credentials hardcoded

4. **Code Injection Risks**
   - Use of `eval()` with dynamic content
   - Untrusted input in `importlib.import_module()`
   - Pickle deserialization vulnerabilities

5. **XML External Entity (XXE) Attacks**
   - Native XML parser used with untrusted input

### 🟠 HIGH Priority (Fix Within 48 hours)
1. **SQL Injection Risks**
2. **Command Injection Vulnerabilities**
3. **Path Traversal Issues**
4. **Insecure File Permissions**
5. **Weak Cryptographic Practices**

### 🟡 MEDIUM Priority (Fix Within 1 week)
1. **Information Disclosure**
2. **Weak Random Number Generation**
3. **Inadequate Input Validation**
4. **Missing Security Headers**

## 🔧 Detailed Fix Implementation Plan

### Phase 1: Critical Security Fixes (Day 1)

#### 1.1 Dockerfile Security Hardening
```bash
# Create secure Dockerfile with non-root user
FROM node:18-alpine AS builder

# Create non-root user early
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nodejs -u 1001

# Use non-root user for all operations
USER nodejs

# Set proper file permissions
COPY --chown=nodejs:nodejs . .
RUN chmod -R 644 /app
```

#### 1.2 JWT Security Implementation
**File: `core/security_manager.py`**
- Remove hardcoded JWT secrets
- Implement environment variable-based secret management
- Add JWT verification and proper algorithm validation
- Add token expiration and refresh mechanisms

**Fix for `advanced_agents/auth_bypass.py`:**
```python
# BEFORE (VULNERABLE)
jwt.decode(token, "hardcoded_secret", verify=False, algorithm="none")

# AFTER (SECURE)
import os
from cryptography.fernet import Fernet

JWT_SECRET = os.getenv('JWT_SECRET_KEY')
if not JWT_SECRET:
    raise ValueError("JWT_SECRET_KEY environment variable is required")

jwt.decode(token, JWT_SECRET, verify=True, algorithms=["HS256"])
```

#### 1.3 Hardcoded Secrets Removal
**Files to fix:**
- `agents/pivoting/network_pivot.py`
- `agents/post_exploitation/lateral_movement.py`

**Implementation:**
```python
# Use environment variables for sensitive data
import os

SSH_PASSWORD = os.getenv('SSH_PASSWORD')
if not SSH_PASSWORD:
    raise ValueError("SSH_PASSWORD environment variable is required")
```

#### 1.4 Code Injection Prevention
**File: `advanced_agents/symbolic/constraint_solver.py`**
```python
# BEFORE (VULNERABLE)
eval(user_input)

# AFTER (SECURE)
import ast

def safe_eval(expression):
    """Safely evaluate mathematical expressions only"""
    try:
        # Parse and validate the expression
        parsed = ast.parse(expression, mode='eval')

        # Only allow specific node types (numbers, operators, etc.)
        for node in ast.walk(parsed):
            if not isinstance(node, (ast.Expression, ast.BinOp, ast.UnaryOp,
                                    ast.operator, ast.unaryop, ast.Constant)):
                raise ValueError("Unsafe expression")

        return eval(compile(parsed, '<string>', 'eval'))
    except:
        raise ValueError("Invalid expression")
```

#### 1.5 XML External Entity Protection
**File: `agents/nmap_parser_agent.py`**
```python
# BEFORE (VULNERABLE)
import xml.etree.ElementTree as ET
ET.parse(xml_file)

# AFTER (SECURE)
from defusedxml import ElementTree as ET
ET.parse(xml_file)
```

### Phase 2: High Priority Fixes (Day 2)

#### 2.1 SQL Injection Prevention
**Implementation:**
```python
# Use parameterized queries instead of string concatenation
import sqlite3

def safe_query(user_input):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # SAFE: Parameterized query
    cursor.execute("SELECT * FROM users WHERE username = ?", (user_input,))
    return cursor.fetchall()
```

#### 2.2 Command Injection Prevention
```python
# BEFORE (VULNERABLE)
os.system(f"ping {user_input}")

# AFTER (SECURE)
import subprocess
import shlex

def safe_command(user_input):
    # Validate and sanitize input
    if not re.match(r'^[a-zA-Z0-9.-]+$', user_input):
        raise ValueError("Invalid input")

    # Use subprocess with list arguments
    result = subprocess.run(['ping', '-c', '4', user_input],
                          capture_output=True, text=True)
    return result.stdout
```

#### 2.3 File Permission Fix
```bash
# Fix file permissions across the codebase
find . -name "*.py" -exec chmod 644 {} \;
find . -name "*.json" -exec chmod 644 {} \;
find . -name "*.md" -exec chmod 644 {} \;
```

### Phase 3: Medium Priority Fixes (Week 1)

#### 3.1 Input Validation Framework
**File: `core/input_validator.py`**
```python
import re
from typing import Optional

class InputValidator:
    @staticmethod
    def validate_email(email: str) -> bool:
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    @staticmethod
    def validate_hostname(hostname: str) -> bool:
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        return re.match(pattern, hostname) is not None
```

#### 3.2 Security Headers Implementation
**File: `core/middleware.py`**
```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer

def setup_security_headers(app: FastAPI):
    # CORS Configuration
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["https://yourdomain.com"],
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["*"],
        allow_credentials=True,
    )

    # Security Headers
    @app.middleware("http")
    async def security_headers(request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response
```

## 📋 Security Checklist

### Pre-Deployment Security Validation
- [ ] All Dockerfiles use non-root users
- [ ] No hardcoded secrets in codebase
- [ ] JWT implementation follows security best practices
- [ ] All input validation implemented
- [ ] SQL injection prevention in place
- [ ] XML parsing uses defusedxml
- [ ] File permissions set correctly
- [ ] Security headers implemented
- [ ] Rate limiting configured
- [ ] Logging and monitoring for security events

### Testing Requirements
- [ ] Security unit tests for all authentication functions
- [ ] Integration tests for API security
- [ ] Penetration testing of deployed environment
- [ ] Automated security scanning in CI/CD pipeline

## 🚀 Implementation Timeline

| Day | Tasks | Owner | Status |
|-----|-------|-------|--------|
| 1   | Critical fixes (Dockerfile, JWT, Secrets) | Security Team | ⏳ |
| 2   | High priority fixes (Injection, Permissions) | Dev Team | ⏳ |
| 3-5 | Medium priority fixes (Validation, Headers) | Dev Team | ⏳ |
| 6   | Security testing and validation | QA Team | ⏳ |
| 7   | Final security review and sign-off | Security Lead | ⏳ |

## 📈 Success Metrics

- **Security Score**: Achieve 0 critical vulnerabilities
- **Compliance**: Pass all security scan requirements
- **Performance**: No degradation in system performance
- **Coverage**: 100% of identified issues resolved

## ⚠️ Rollback Plan

If security fixes introduce instability:
1. Deploy previous stable version
2. Revert individual security changes incrementally
3. Maintain backup of working configuration
4. Document all changes for audit trail

---

**Next Steps**: Begin with Phase 1 critical fixes immediately. These vulnerabilities pose immediate risk to the platform and must be resolved before any production deployment.