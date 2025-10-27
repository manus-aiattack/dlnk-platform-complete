"""
Unified Enumerations for dLNk Attack Platform
Centralized enum definitions to avoid duplication and inconsistency
"""

from enum import Enum, auto


class AttackPhase(str, Enum):
    """
    Unified Attack Phase Enumeration
    Represents all phases in the cyber attack kill chain
    """
    # Reconnaissance & Information Gathering
    RECONNAISSANCE = "reconnaissance"
    TRIAGE = "triage"
    SCANNING = "scanning"
    ENUMERATION = "enumeration"
    
    # Exploitation & Access
    VULNERABILITY_DISCOVERY = "vulnerability_discovery"
    EXPLOITATION = "exploitation"
    INITIAL_FOOTHOLD = "initial_foothold"
    SHELL = "shell"
    
    # Post-Exploitation
    POST_EXPLOITATION = "post_exploitation"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    
    # Persistence & Objectives
    PERSISTENCE = "persistence"
    DATA_EXFILTRATION = "data_exfiltration"
    
    # Defense & Cleanup
    DEFENSE_EVASION = "defense_evasion"
    DISRUPTION = "disruption"
    CLEANUP = "cleanup"
    
    # Reporting & Recovery
    RECOVERY = "recovery"
    REPORTING = "reporting"


class AttackStrategy(str, Enum):
    """
    Attack Strategy Types
    Defines the overall approach and tactics for the attack
    """
    STEALTH = "stealth"  # Low and slow, evade detection
    AGGRESSIVE = "aggressive"  # Fast and comprehensive
    BALANCED = "balanced"  # Mix of stealth and speed
    TARGETED = "targeted"  # Focused on specific vulnerabilities
    ADAPTIVE = "adaptive"  # AI-driven, changes based on feedback
    ZERO_DAY_HUNTING = "zero_day_hunting"  # Focus on unknown vulnerabilities
    APT_SIMULATION = "apt_simulation"  # Advanced persistent threat tactics
    CREDENTIAL_HARVEST = "credential_harvest"  # Focus on credentials
    DATA_EXFIL = "data_exfil"  # Focus on data extraction
    FULL_COMPROMISE = "full_compromise"  # Complete takeover


class ScanIntensity(str, Enum):
    """
    Scan Intensity Levels
    Controls the aggressiveness of scanning operations
    """
    STEALTH = "stealth"  # Minimal detection risk
    NORMAL = "normal"  # Balanced approach
    AGGRESSIVE = "aggressive"  # Maximum coverage, higher detection risk


class TargetType(str, Enum):
    """
    Target Environment Types
    Categorizes the type of target being attacked
    """
    WEB_APPLICATION = "web_application"
    API = "api"
    WINDOWS_DOMAIN = "windows_domain"
    LINUX_SERVER = "linux_server"
    CLOUD_AWS = "cloud_aws"
    CLOUD_AZURE = "cloud_azure"
    CLOUD_GCP = "cloud_gcp"
    MOBILE_ANDROID = "mobile_android"
    MOBILE_IOS = "mobile_ios"
    NETWORK = "network"
    DATABASE = "database"
    IOT_DEVICE = "iot_device"
    UNKNOWN = "unknown"


class ErrorType(str, Enum):
    """
    Error Types for Agent Execution
    Categorizes different types of errors that can occur
    """
    UNKNOWN = "unknown"
    CONFIGURATION = "configuration_error"
    NETWORK = "network_error"
    LOGIC = "logic_error"
    TARGET_UNREACHABLE = "target_unreachable"
    CIRCUIT_BREAKER_OPEN = "circuit_breaker_open"
    AGENT_REPORTED_FAILURE = "agent_reported_failure"
    TIMEOUT = "timeout"
    EXECUTION_FAILED = "execution_failed"
    AUTHENTICATION_FAILED = "authentication_failed"
    AUTHORIZATION_FAILED = "authorization_failed"
    RESOURCE_EXHAUSTED = "resource_exhausted"


class VulnerabilityType(str, Enum):
    """
    Vulnerability Types
    Common vulnerability categories
    """
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    CSRF = "csrf"
    SSRF = "ssrf"
    RCE = "rce"
    LFI = "lfi"
    RFI = "rfi"
    XXE = "xxe"
    IDOR = "idor"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    BUFFER_OVERFLOW = "buffer_overflow"
    MEMORY_CORRUPTION = "memory_corruption"
    USE_AFTER_FREE = "use_after_free"
    RACE_CONDITION = "race_condition"
    DESERIALIZATION = "deserialization"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    INFORMATION_DISCLOSURE = "information_disclosure"
    MISCONFIGURATION = "misconfiguration"
    WEAK_CREDENTIALS = "weak_credentials"
    UNKNOWN = "unknown"


class ExploitType(str, Enum):
    """
    Exploit Types
    Categories of exploits that can be generated or used
    """
    REMOTE = "remote"
    LOCAL = "local"
    WEB = "web"
    NETWORK = "network"
    BINARY = "binary"
    SCRIPT = "script"
    SOCIAL_ENGINEERING = "social_engineering"
    PHYSICAL = "physical"


class PayloadType(str, Enum):
    """
    Payload Types for Exploit Delivery
    """
    REVERSE_SHELL = "reverse_shell"
    BIND_SHELL = "bind_shell"
    METERPRETER = "meterpreter"
    COMMAND_EXECUTION = "command_execution"
    FILE_UPLOAD = "file_upload"
    SQL_QUERY = "sql_query"
    XSS_PAYLOAD = "xss_payload"
    SERIALIZED_OBJECT = "serialized_object"
    CUSTOM = "custom"


class EncodingType(str, Enum):
    """
    Encoding Types for Payload Obfuscation
    """
    NONE = "none"
    BASE64 = "base64"
    URL = "url"
    HEX = "hex"
    UNICODE = "unicode"
    HTML_ENTITY = "html_entity"
    DOUBLE_URL = "double_url"
    CUSTOM = "custom"


class AgentStatus(str, Enum):
    """
    Agent Execution Status
    """
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"


class TaskPriority(str, Enum):
    """
    Task Priority Levels
    """
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


class TaskStatus(str, Enum):
    """
    Distributed Task Status
    """
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    RETRY = "retry"


class SeverityLevel(str, Enum):
    """
    Severity Levels for Vulnerabilities and Findings
    """
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class CircuitBreakerState(str, Enum):
    """
    Circuit Breaker States for Fault Tolerance
    """
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class ExplorationStrategy(str, Enum):
    """
    Symbolic Execution Exploration Strategies
    """
    DFS = "dfs"  # Depth-First Search
    BFS = "bfs"  # Breadth-First Search
    RANDOM = "random"
    COVERAGE_GUIDED = "coverage_guided"
    VULNERABILITY_GUIDED = "vulnerability_guided"


class CVSSVersion(str, Enum):
    """
    CVSS Scoring Versions
    """
    V2 = "v2"
    V3 = "v3"
    V3_1 = "v3.1"
    V4 = "v4"

