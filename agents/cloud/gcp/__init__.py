"""GCP Cloud Attack Agents"""

# Import all GCP agents
try:
    from .cloud_functions_agent import *
except ImportError:
    print("Error occurred")

try:
    from .compute_engine_agent import *
except ImportError:
    print("Error occurred")

try:
    from .iam_privesc_agent import *
except ImportError:
    print("Error occurred")

try:
    from .secret_manager_agent import *
except ImportError:
    print("Error occurred")

try:
    from .storage_bucket_agent import *
except ImportError:
    print("Error occurred")
