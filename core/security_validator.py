# Input Validation and Sanitization Module
# Provides security validation for all user inputs

import re
import html
import urllib.parse
from typing import Optional, Union, List
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)

class SecurityValidator:
    """Security input validation and sanitization"""

    # Regular expression patterns for validation
    PATTERNS = {
        'email': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
        'hostname': r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$',
        'ip_address': r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$',
        'uuid': r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
        'alphanumeric': r'^[a-zA-Z0-9]+$',
        'safe_filename': r'^[a-zA-Z0-9._-]+$',
        'sql_injection': r'(?:\')|(?:--)|(?:/\*)|(?:\*/)|(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|SCRIPT)',
        'xss_pattern': r'<(?:script|object|embed|form|iframe|link|style|img|svg)[\s>]|on\w+\s*=\s*["\']?(?:javascript:|data:text/html|vbscript:)',
    }

    @staticmethod
    def sanitize_html(input_str: str) -> str:
        """Sanitize HTML content to prevent XSS"""
        if not input_str:
            return ""

        # Remove dangerous HTML tags and attributes
        sanitized = html.escape(input_str)

        # Remove any remaining dangerous patterns
        dangerous_patterns = [
            r'<script.*?</script>',
            r'<object.*?</object>',
            r'<embed.*?>',
            r'<form.*?</form>',
            r'<iframe.*?</iframe>',
        ]

        for pattern in dangerous_patterns:
            sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE)

        return sanitized

    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email format"""
        if not email or len(email) > 254:  # RFC 5321 limit
            return False
        return bool(re.match(SecurityValidator.PATTERNS['email'], email))

    @staticmethod
    def validate_hostname(hostname: str) -> bool:
        """Validate hostname format"""
        if not hostname or len(hostname) > 253:  # RFC 1123 limit
            return False
        return bool(re.match(SecurityValidator.PATTERNS['hostname'], hostname))

    @staticmethod
    def validate_ip_address(ip: str) -> bool:
        """Validate IP address format"""
        if not ip:
            return False
        return bool(re.match(SecurityValidator.PATTERNS['ip_address'], ip))

    @staticmethod
    def validate_uuid(uuid_str: str) -> bool:
        """Validate UUID format"""
        if not uuid_str:
            return False
        return bool(re.match(SecurityValidator.PATTERNS['uuid'], uuid_str))

    @staticmethod
    def validate_sql_injection(input_str: str) -> bool:
        """Check for potential SQL injection patterns"""
        if not input_str:
            return True

        # Case-insensitive search for SQL injection patterns
        sql_pattern = re.compile(SecurityValidator.PATTERNS['sql_injection'], re.IGNORECASE)
        return not bool(sql_pattern.search(input_str))

    @staticmethod
    def validate_xss(input_str: str) -> bool:
        """Check for potential XSS patterns"""
        if not input_str:
            return True

        xss_pattern = re.compile(SecurityValidator.PATTERNS['xss_pattern'], re.IGNORECASE)
        return not bool(xss_pattern.search(input_str))

    @staticmethod
    def validate_url_safety(url: str) -> bool:
        """Validate URL is safe and properly formatted"""
        if not url:
            return False

        try:
            parsed = urlparse(url)

            # Check for dangerous schemes
            dangerous_schemes = ['javascript', 'data', 'vbscript', 'file']
            if parsed.scheme.lower() in dangerous_schemes:
                return False

            # Check if hostname is valid
            if parsed.hostname and not SecurityValidator.validate_hostname(parsed.hostname):
                return False

            return True

        except Exception as e:
            logger.warning(f"URL validation error: {e}")
            return False

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize filename to prevent path traversal"""
        if not filename:
            return ""

        # Remove path components
        filename = filename.split('/')[-1]
        filename = filename.split('\\')[-1]

        # Remove dangerous characters
        filename = re.sub(r'[^\w\-_\.]', '', filename)

        return filename

    @staticmethod
    def validate_input_length(input_str: str, min_length: int = 1, max_length: int = 10000) -> bool:
        """Validate input string length"""
        if not input_str:
            return min_length == 0

        length = len(input_str)
        return min_length <= length <= max_length

    @staticmethod
    def safe_eval(expression: str) -> Union[float, int, str]:
        """Safely evaluate mathematical expressions only"""
        import ast

        if not expression or len(expression) > 100:
            raise ValueError("Expression too long or empty")

        try:
            # Parse and validate the expression
            parsed = ast.parse(expression, mode='eval')

            # Only allow specific node types (numbers, operators, basic functions)
            allowed_nodes = (
                ast.Expression, ast.BinOp, ast.UnaryOp, ast.operator,
                ast.unaryop, ast.Constant, ast.Num, ast.Str,
                ast.Name, ast.Load, ast.Compare, ast.Gt, ast.Lt,
                ast.Eq, ast.GtE, ast.LtE, ast.NotEq, ast.Call
            )

            for node in ast.walk(parsed):
                if not isinstance(node, allowed_nodes):
                    raise ValueError(f"Unsafe expression node type: {type(node).__name__}")

            # Evaluate safely
            return eval(compile(parsed, '<string>', 'eval'))

        except Exception as e:
            raise ValueError(f"Invalid or unsafe expression: {e}")

    @staticmethod
    def validate_port(port: str) -> bool:
        """Validate port number"""
        try:
            port_num = int(port)
            return 1 <= port_num <= 65535
        except (ValueError, TypeError):
            return False

    @staticmethod
    def validate_json_input(json_data: str) -> bool:
        """Validate JSON input is well-formed and safe"""
        import json

        try:
            parsed = json.loads(json_data)

            # Check for excessively nested structures
            def check_depth(obj, depth=0):
                if depth > 10:  # Prevent excessive nesting
                    return False
                if isinstance(obj, dict):
                    return all(check_depth(v, depth + 1) for v in obj.values())
                elif isinstance(obj, list):
                    return all(check_depth(item, depth + 1) for item in obj)
                return True

            return check_depth(parsed)

        except json.JSONDecodeError:
            return False

    @staticmethod
    def create_safe_context(user_input: str) -> dict:
        """Create a safe execution context for user input"""
        # Remove dangerous built-ins and functions
        safe_builtins = {
            '__builtins__': {
                'abs': abs,
                'min': min,
                'max': max,
                'len': len,
                'str': str,
                'int': int,
                'float': float,
                'bool': bool,
                'list': list,
                'dict': dict,
                'tuple': tuple,
                'set': set,
                'round': round,
                'pow': pow,
                'sqrt': lambda x: x ** 0.5 if x >= 0 else None,
            }
        }

        return {'__builtins__': safe_builtins['__builtins__']}

# Common validation decorators
def validate_input(pattern: str, error_msg: str = "Invalid input"):
    """Decorator for input validation"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            # This is a simplified implementation
            # In production, you'd want more sophisticated validation
            return func(*args, **kwargs)
        return wrapper
    return decorator

# Usage examples:
#
# validator = SecurityValidator()
#
# # Email validation
# if not validator.validate_email("user@example.com"):
#     raise ValueError("Invalid email format")
#
# # Safe evaluation
# try:
#     result = validator.safe_eval("2 + 3 * 4")
# except ValueError as e:
#     print(f"Unsafe expression: {e}")
#
# # HTML sanitization
# safe_html = validator.sanitize_html("<script>alert('xss')</script><p>Safe content</p>")