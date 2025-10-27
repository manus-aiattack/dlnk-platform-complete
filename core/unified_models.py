"""
Unified Data Models for dLNk Attack Platform
Standardized Pydantic models for all agent reports and system data
"""

from typing import List, Dict, Optional, Any, Union
from datetime import datetime
from pydantic import BaseModel, Field, field_validator, ConfigDict
import uuid

from core.unified_enums import (
    AttackPhase, AttackStrategy, ScanIntensity, TargetType,
    ErrorType, VulnerabilityType, ExploitType, PayloadType,
    AgentStatus, SeverityLevel, TaskStatus, TaskPriority
)


# ============================================================================
# Base Models
# ============================================================================

class BaseAgentReport(BaseModel):
    """
    Base class for all agent reports
    Provides common fields and validation
    """
    model_config = ConfigDict(use_enum_values=True, validate_assignment=True)
    
    # Identification
    report_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_name: str
    
    # Execution metadata
    start_time: float = Field(default=0.0)
    end_time: float = Field(default=0.0)
    execution_time: float = Field(default=0.0)
    
    # Status and results
    status: AgentStatus = AgentStatus.PENDING
    success: bool = False
    summary: str = ""
    
    # Error handling
    errors: List[str] = Field(default_factory=list)
    error_type: Optional[ErrorType] = None
    
    # Resource usage
    memory_usage: float = Field(default=0.0)  # MB
    cpu_usage: float = Field(default=0.0)  # Percentage
    
    # AI guidance and context
    guidance: List[str] = Field(default_factory=list)
    context: Dict[str, Any] = Field(default_factory=dict)
    
    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    
    def model_post_init(self, __context: Any) -> None:
        """Calculate execution time after initialization"""
        if self.start_time and self.end_time and self.execution_time == 0.0:
            self.execution_time = self.end_time - self.start_time


class BaseFinding(BaseModel):
    """
    Base class for all findings (vulnerabilities, issues, etc.)
    """
    model_config = ConfigDict(use_enum_values=True)
    
    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str
    severity: SeverityLevel = SeverityLevel.UNKNOWN
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    
    # Location information
    url: Optional[str] = None
    parameter: Optional[str] = None
    endpoint: Optional[str] = None
    
    # Evidence
    evidence: List[str] = Field(default_factory=list)
    raw_data: Optional[str] = None
    
    # Remediation
    remediation: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    
    # Metadata
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    tags: List[str] = Field(default_factory=list)


# ============================================================================
# Reconnaissance & Scanning Models
# ============================================================================

class NetworkService(BaseModel):
    """Network service information"""
    port: int
    protocol: str = "tcp"
    service: str = ""
    version: str = ""
    state: str = "open"
    banner: Optional[str] = None


class ReconnaissanceReport(BaseAgentReport):
    """
    Reconnaissance phase report
    Comprehensive information gathering results
    """
    agent_name: str = "ReconnaissanceAgent"
    
    # Target information
    target_url: str
    target_host: str
    target_ip: Optional[str] = None
    
    # Discovery results
    subdomains: List[str] = Field(default_factory=list)
    directories: List[str] = Field(default_factory=list)
    network_services: List[NetworkService] = Field(default_factory=list)
    
    # Tool outputs
    harvester_results: List[str] = Field(default_factory=list)
    whatweb_results: List[str] = Field(default_factory=list)
    nikto_results: List[str] = Field(default_factory=list)
    wapiti_results: List[str] = Field(default_factory=list)
    dnsrecon_results: List[str] = Field(default_factory=list)
    fierce_results: List[str] = Field(default_factory=list)
    feroxbuster_results: List[str] = Field(default_factory=list)
    
    # Web crawling
    crawled_urls: List[str] = Field(default_factory=list)
    forms: List[Dict[str, Any]] = Field(default_factory=list)
    parameters: List[str] = Field(default_factory=list)
    
    # Security findings
    cors_findings: List[str] = Field(default_factory=list)
    tls_scan_results: List[str] = Field(default_factory=list)
    http_servers: List[str] = Field(default_factory=list)


class WafDetectionReport(BaseAgentReport):
    """WAF (Web Application Firewall) detection report"""
    agent_name: str = "WafDetectorAgent"
    
    detected_waf: str = "None"
    waf_type: Optional[str] = None
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    detection_method: Optional[str] = None
    bypass_suggestions: List[str] = Field(default_factory=list)


class NmapScanReport(BaseAgentReport):
    """Nmap scan results"""
    agent_name: str = "NmapAgent"
    
    target: str
    scan_type: str = "default"
    open_ports: List[NetworkService] = Field(default_factory=list)
    os_detection: Optional[str] = None
    raw_output: str = ""


# ============================================================================
# Vulnerability Assessment Models
# ============================================================================

class VulnerabilityFinding(BaseFinding):
    """
    Detailed vulnerability finding
    """
    vulnerability_type: VulnerabilityType = VulnerabilityType.UNKNOWN
    
    # CVE information
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    
    # Exploit information
    exploit_available: bool = False
    exploit_db_id: Optional[str] = None
    metasploit_module: Optional[str] = None
    
    # Affected components
    affected_component: Optional[str] = None
    affected_version: Optional[str] = None
    
    # Testing details
    payload_used: Optional[str] = None
    response_time: Optional[float] = None
    http_status: Optional[int] = None


class VulnerabilityReport(BaseAgentReport):
    """
    Vulnerability scanning and assessment report
    """
    agent_name: str = "VulnerabilityScannerAgent"
    
    target: str
    target_technology: Optional[str] = None
    scan_type: str = "comprehensive"
    
    # Findings
    vulnerabilities: List[VulnerabilityFinding] = Field(default_factory=list)
    
    # Statistics
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    
    # Risk assessment
    overall_risk_score: float = Field(default=0.0, ge=0.0, le=10.0)
    
    def model_post_init(self, __context: Any) -> None:
        """Calculate statistics after initialization"""
        super().model_post_init(__context)
        self.total_vulnerabilities = len(self.vulnerabilities)
        self.critical_count = sum(1 for v in self.vulnerabilities if v.severity == SeverityLevel.CRITICAL)
        self.high_count = sum(1 for v in self.vulnerabilities if v.severity == SeverityLevel.HIGH)
        self.medium_count = sum(1 for v in self.vulnerabilities if v.severity == SeverityLevel.MEDIUM)
        self.low_count = sum(1 for v in self.vulnerabilities if v.severity == SeverityLevel.LOW)


class TriageFinding(BaseModel):
    """
    Interesting finding identified during triage
    """
    finding: str
    reasoning: str
    priority: int = Field(default=0, ge=0, le=10)
    next_steps: str = ""
    context: Dict[str, Any] = Field(default_factory=dict)


class TriageReport(BaseAgentReport):
    """
    Triage and analysis report
    AI-driven assessment of reconnaissance data
    """
    agent_name: str = "TriageAgent"
    
    # Analysis results
    original_data_summary: Dict[str, int] = Field(default_factory=dict)
    assessment: str = ""
    interesting_findings: List[TriageFinding] = Field(default_factory=list)
    
    # Scoring
    score: int = Field(default=0, ge=0, le=100)
    is_interesting: bool = False
    reasoning_for_score: str = ""
    
    # Recommendations
    recommended_next_phase: Optional[AttackPhase] = None
    recommended_agents: List[str] = Field(default_factory=list)


# ============================================================================
# Exploitation Models
# ============================================================================

class ExploitAttempt(BaseModel):
    """
    Single exploit attempt record
    """
    attempt_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    exploit_name: str
    exploit_type: ExploitType
    payload_type: PayloadType
    
    # Target information
    target_url: str
    target_parameter: Optional[str] = None
    
    # Execution details
    payload: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    # Results
    success: bool = False
    response_code: Optional[int] = None
    response_time: float = 0.0
    response_body: Optional[str] = None
    
    # Evidence
    evidence: List[str] = Field(default_factory=list)
    error_message: Optional[str] = None


class ExploitationReport(BaseAgentReport):
    """
    Exploitation phase report
    """
    agent_name: str = "ExploitationAgent"
    
    target: str
    vulnerability_type: VulnerabilityType
    
    # Exploit attempts
    attempts: List[ExploitAttempt] = Field(default_factory=list)
    successful_attempts: List[ExploitAttempt] = Field(default_factory=list)
    
    # Shell information (if successful)
    shell_obtained: bool = False
    shell_id: Optional[str] = None
    shell_type: Optional[str] = None
    
    # Statistics
    total_attempts: int = 0
    success_rate: float = 0.0
    
    def model_post_init(self, __context: Any) -> None:
        """Calculate statistics"""
        super().model_post_init(__context)
        self.total_attempts = len(self.attempts)
        self.successful_attempts = [a for a in self.attempts if a.success]
        if self.total_attempts > 0:
            self.success_rate = len(self.successful_attempts) / self.total_attempts


# ============================================================================
# Post-Exploitation Models
# ============================================================================

class PostExploitationFinding(BaseModel):
    """
    Post-exploitation finding (credential, file, etc.)
    """
    type: str  # credential, file, process, network, etc.
    description: str
    value: str
    confidence: float = Field(default=0.75, ge=0.0, le=1.0)
    sensitivity: SeverityLevel = SeverityLevel.INFO


class PostExploitationReport(BaseAgentReport):
    """
    Post-exploitation enumeration report
    """
    agent_name: str = "PostExploitationAgent"
    
    shell_id: str
    
    # System information
    privilege_level: str = "user"
    username: str = ""
    hostname: str = ""
    os_info: str = ""
    
    # Network information
    network_info: str = ""
    ip_addresses: List[str] = Field(default_factory=list)
    
    # Process and service information
    processes: str = ""
    running_services: List[str] = Field(default_factory=list)
    
    # File system
    home_dir_listing: str = ""
    interesting_files: List[str] = Field(default_factory=list)
    
    # Findings
    findings: List[PostExploitationFinding] = Field(default_factory=list)
    credentials_found: List[Dict[str, str]] = Field(default_factory=list)
    
    # Raw outputs
    raw_output: Dict[str, str] = Field(default_factory=dict)
    
    # Log cleaning
    log_cleaning_status: str = ""


class PrivilegeEscalationVector(BaseModel):
    """
    Privilege escalation opportunity
    """
    vector_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: str  # sudo, suid, kernel, service, etc.
    details: str
    command: str
    confidence: float = Field(default=0.75, ge=0.0, le=1.0)
    risk_level: SeverityLevel = SeverityLevel.MEDIUM
    cve_id: Optional[str] = None


class PrivilegeEscalationReport(BaseAgentReport):
    """
    Privilege escalation assessment report
    """
    agent_name: str = "PrivilegeEscalationAgent"
    
    shell_id: str
    current_privilege: str = "user"
    target_privilege: str = "root"
    
    # Enumeration results
    script_output: str = ""
    
    # Identified vectors
    potential_vectors: List[PrivilegeEscalationVector] = Field(default_factory=list)
    
    # Exploitation attempts
    attempted_vectors: List[str] = Field(default_factory=list)
    successful_vector: Optional[PrivilegeEscalationVector] = None
    
    # Results
    escalation_successful: bool = False
    achieved_privilege: str = "user"


# ============================================================================
# Lateral Movement Models
# ============================================================================

class DiscoveredHost(BaseModel):
    """
    Host discovered during internal network reconnaissance
    """
    ip_address: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    
    # Services
    open_ports: List[int] = Field(default_factory=list)
    services: List[NetworkService] = Field(default_factory=list)
    
    # OS detection
    os_type: Optional[str] = None
    os_version: Optional[str] = None
    
    # Vulnerability assessment
    vulnerabilities: List[str] = Field(default_factory=list)
    
    # Access status
    accessible: bool = False
    compromised: bool = False


class LateralMovementReport(BaseAgentReport):
    """
    Lateral movement and network propagation report
    """
    agent_name: str = "LateralMovementAgent"
    
    source_shell_id: str
    
    # Network discovery
    discovered_hosts: List[DiscoveredHost] = Field(default_factory=list)
    total_hosts_found: int = 0
    
    # Movement attempts
    movement_attempts: List[Dict[str, Any]] = Field(default_factory=list)
    successful_compromises: List[str] = Field(default_factory=list)
    
    # New shells obtained
    new_shells: List[str] = Field(default_factory=list)


# ============================================================================
# Persistence & Data Exfiltration Models
# ============================================================================

class PersistenceReport(BaseAgentReport):
    """
    Persistence mechanism installation report
    """
    agent_name: str = "PersistenceAgent"
    
    shell_id: str
    persistence_type: str  # cron, service, backdoor, etc.
    persistence_method: str = ""
    
    # Installation details
    installed: bool = False
    installation_path: Optional[str] = None
    trigger_mechanism: Optional[str] = None
    
    # Verification
    verified: bool = False
    verification_method: Optional[str] = None


class DataExfiltrationReport(BaseAgentReport):
    """
    Data exfiltration operation report
    """
    agent_name: str = "DataExfiltrationAgent"
    
    shell_id: str
    
    # Exfiltrated data
    exfiltrated_files: List[str] = Field(default_factory=list)
    total_size_bytes: int = 0
    
    # Exfiltration method
    exfiltration_method: str = ""  # http, dns, ftp, etc.
    destination: str = ""
    
    # Encryption and obfuscation
    encrypted: bool = False
    compression_used: bool = False


# ============================================================================
# Attack Strategy & Planning Models
# ============================================================================

class AttackStrategy(BaseModel):
    """
    AI-generated attack strategy
    """
    model_config = ConfigDict(use_enum_values=True)
    
    strategy_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    phase: AttackPhase
    strategy_type: AttackStrategy
    
    # Agent selection
    next_agent: str
    agent_parameters: Dict[str, Any] = Field(default_factory=dict)
    
    # Directive and reasoning
    directive: str
    llm_reasoning: Optional[str] = None
    
    # Confidence and alternatives
    confidence_score: float = Field(default=0.5, ge=0.0, le=1.0)
    alternative_strategies: List['AttackStrategy'] = Field(default_factory=list)
    
    # Context
    context: Dict[str, Any] = Field(default_factory=dict)
    pivot_shell_id: Optional[str] = None
    target_db: Optional[str] = None
    
    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)


class AttackPlan(BaseModel):
    """
    Complete attack plan with multiple phases
    """
    model_config = ConfigDict(use_enum_values=True)
    
    plan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target: str
    target_type: TargetType
    
    # Strategy
    overall_strategy: AttackStrategy
    phases: List[AttackStrategy] = Field(default_factory=list)
    
    # Estimates
    estimated_duration: int = 0  # minutes
    success_probability: float = Field(default=0.5, ge=0.0, le=1.0)
    risk_level: SeverityLevel = SeverityLevel.MEDIUM
    
    # Required resources
    agents_required: List[str] = Field(default_factory=list)
    tools_required: List[str] = Field(default_factory=list)
    
    # Fallback
    fallback_plan: Optional['AttackPlan'] = None
    
    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: str = "AIPlanner"


# ============================================================================
# Target & Campaign Models
# ============================================================================

class Target(BaseModel):
    """
    Attack target definition
    """
    model_config = ConfigDict(use_enum_values=True)
    
    target_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    url: str
    target_type: TargetType = TargetType.UNKNOWN
    
    # Configuration
    attack_mode: bool = True
    aggressive: bool = False
    scan_intensity: ScanIntensity = ScanIntensity.NORMAL
    
    # Vulnerability preferences
    vuln_type: Optional[VulnerabilityType] = None
    
    # Callback configuration
    callback_url: Optional[str] = None
    callback_port: Optional[int] = None
    
    # Results
    scan_results: Optional[Dict[str, Any]] = None
    
    # Metadata
    description: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    # Timestamps
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class AttackCampaign(BaseModel):
    """
    Attack campaign tracking multiple targets and phases
    """
    campaign_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str = ""
    
    # Targets
    targets: List[Target] = Field(default_factory=list)
    
    # Execution
    attack_plan: Optional[AttackPlan] = None
    current_phase: AttackPhase = AttackPhase.RECONNAISSANCE
    
    # Status
    status: TaskStatus = TaskStatus.PENDING
    progress: float = Field(default=0.0, ge=0.0, le=100.0)
    
    # Results
    reports: List[BaseAgentReport] = Field(default_factory=list)
    shells_obtained: List[str] = Field(default_factory=list)
    
    # Timestamps
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)


# Update forward references
AttackStrategy.model_rebuild()
AttackPlan.model_rebuild()

