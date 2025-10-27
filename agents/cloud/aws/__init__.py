"""
AWS Cloud Attack Agents
"""

# Import all AWS agents
try:
    from .iam_privesc_agent import *
except ImportError:
    print("Error occurred")

try:
    from .lambda_exploit_agent import *
except ImportError:
    print("Error occurred")

try:
    from .rds_exploit_agent import *
except ImportError:
    print("Error occurred")

try:
    from .s3_enumeration_agent import *
except ImportError:
    print("Error occurred")

try:
    from .secrets_manager_agent import *
except ImportError:
    print("Error occurred")

