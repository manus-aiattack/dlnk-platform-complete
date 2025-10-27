"""
Enhanced AI Planner - Advanced Decision Making & Strategy Selection
Integrates with Local LLM for intelligent attack planning
"""

import asyncio
import json
import os
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import logging

logger = logging.getLogger("dLNk")


class AttackPhase(Enum):
    """Attack phases in kill chain"""
    RECONNAISSANCE = "reconnaissance"
    SCANNING = "scanning"
    ENUMERATION = "enumeration"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    DATA_EXFILTRATION = "data_exfiltration"
    CLEANUP = "cleanup"


class TargetType(Enum):
    """Target environment types"""
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
    UNKNOWN = "unknown"


class AttackStrategy(Enum):
    """Pre-defined attack strategies"""
    STEALTH = "stealth"  # Slow, careful, evade detection
    AGGRESSIVE = "aggressive"  # Fast, loud, maximum exploitation
    BALANCED = "balanced"  # Mix of stealth and speed
    ZERO_DAY_HUNT = "zero_day_hunt"  # Focus on finding 0-days
    CREDENTIAL_HARVEST = "credential_harvest"  # Focus on credentials
    DATA_EXFIL = "data_exfil"  # Focus on data extraction
    PERSISTENCE = "persistence"  # Focus on maintaining access
    LATERAL_MOVEMENT = "lateral_movement"  # Focus on spreading
    PRIVILEGE_ESCALATION = "privilege_escalation"  # Focus on admin access
    FULL_COMPROMISE = "full_compromise"  # Complete takeover


@dataclass
class TargetIntel:
    """Target intelligence data"""
    url: Optional[str] = None
    ip: Optional[str] = None
    domain: Optional[str] = None
    target_type: TargetType = TargetType.UNKNOWN
    technologies: List[str] = None
    vulnerabilities: List[str] = None
    credentials: Dict[str, str] = None
    edr_detected: bool = False
    waf_detected: bool = False
    cloud_provider: Optional[str] = None
    os_type: Optional[str] = None
    
    def __post_init__(self):
        if self.technologies is None:
            self.technologies = []
        if self.vulnerabilities is None:
            self.vulnerabilities = []
        if self.credentials is None:
            self.credentials = {}


@dataclass
class AttackPlan:
    """Complete attack plan"""
    strategy: AttackStrategy
    phases: List[Dict[str, Any]]
    estimated_duration: int  # minutes
    success_probability: float  # 0.0 to 1.0
    risk_level: str  # low, medium, high
    agents_required: List[str]
    fallback_plan: Optional['AttackPlan'] = None


class EnhancedAIPlanner:
    """
    Enhanced AI Planner with advanced decision making
    Uses Local LLM for intelligent planning and agent selection
    """
    
    def __init__(self, llm_model_path: Optional[str] = None):
        self.llm_model_path = llm_model_path or os.getenv('LLM_MODEL_PATH', '/models/llm/mistral-7b-instruct')
        self.llm_loaded = False
        self.llm_model = None
        self.llm_tokenizer = None
        
        # Agent registry (will be populated from orchestrator)
        self.agents_registry = {}
        
        # Strategy templates
        self.strategy_templates = self._load_strategy_templates()
        
        # Agent selection weights
        self.agent_weights = self._initialize_agent_weights()
        
        logger.info("Enhanced AI Planner initialized")
    
    async def initialize_llm(self):
        """Initialize Local LLM for planning"""
        try:
            if self.llm_loaded:
                return True
            
            logger.info(f"Loading LLM from {self.llm_model_path}")
            
            # Import transformers (lazy import)
            from transformers import AutoTokenizer, AutoModelForCausalLM
            import torch
            
            # Load tokenizer and model
            self.llm_tokenizer = AutoTokenizer.from_pretrained(self.llm_model_path)
            self.llm_model = AutoModelForCausalLM.from_pretrained(
                self.llm_model_path,
                torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
                device_map="auto" if torch.cuda.is_available() else None
            )
            
            self.llm_loaded = True
            logger.info("LLM loaded successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load LLM: {e}")
            logger.warning("Falling back to rule-based planning")
            return False
    
    async def create_attack_plan(
        self,
        objective: str,
        target_intel: TargetIntel,
        strategy: Optional[AttackStrategy] = None,
        constraints: Optional[Dict[str, Any]] = None
    ) -> AttackPlan:
        """
        Create comprehensive attack plan
        
        Args:
            objective: Attack objective (e.g., "backdoor", "data_exfil", "full_compromise")
            target_intel: Intelligence about the target
            strategy: Preferred attack strategy (auto-select if None)
            constraints: Constraints (time_limit, stealth_required, etc.)
        
        Returns:
            Complete attack plan with phases and agents
        """
        logger.info(f"Creating attack plan for objective: {objective}")
        
        # Auto-select strategy if not provided
        if strategy is None:
            strategy = self._select_strategy(objective, target_intel, constraints)
        
        logger.info(f"Selected strategy: {strategy.value}")
        
        # Use LLM if available, otherwise use rule-based planning
        if self.llm_loaded:
            plan = await self._create_plan_with_llm(objective, target_intel, strategy, constraints)
        else:
            plan = await self._create_plan_rule_based(objective, target_intel, strategy, constraints)
        
        # Calculate success probability
        plan.success_probability = self._calculate_success_probability(plan, target_intel)
        
        # Create fallback plan
        if plan.success_probability < 0.7:
            logger.info("Creating fallback plan due to low success probability")
            fallback_strategy = self._select_fallback_strategy(strategy, target_intel)
            plan.fallback_plan = await self._create_plan_rule_based(
                objective, target_intel, fallback_strategy, constraints
            )
        
        logger.info(f"Attack plan created with {len(plan.phases)} phases, "
                   f"success probability: {plan.success_probability:.2%}")
        
        return plan
    
    def _select_strategy(
        self,
        objective: str,
        target_intel: TargetIntel,
        constraints: Optional[Dict[str, Any]]
    ) -> AttackStrategy:
        """Intelligently select attack strategy based on objective and target"""
        
        # Map objectives to strategies
        objective_map = {
            'backdoor': AttackStrategy.PERSISTENCE,
            'data_exfil': AttackStrategy.DATA_EXFIL,
            'full_compromise': AttackStrategy.FULL_COMPROMISE,
            'credentials': AttackStrategy.CREDENTIAL_HARVEST,
            'zero_day': AttackStrategy.ZERO_DAY_HUNT,
            'lateral': AttackStrategy.LATERAL_MOVEMENT,
            'privesc': AttackStrategy.PRIVILEGE_ESCALATION,
        }
        
        # Check objective mapping
        for key, strat in objective_map.items():
            if key in objective.lower():
                base_strategy = strat
                break
        else:
            base_strategy = AttackStrategy.BALANCED
        
        # Adjust based on constraints
        if constraints:
            if constraints.get('stealth_required'):
                return AttackStrategy.STEALTH
            if constraints.get('time_limit') and constraints['time_limit'] < 60:
                return AttackStrategy.AGGRESSIVE
        
        # Adjust based on target
        if target_intel.edr_detected or target_intel.waf_detected:
            return AttackStrategy.STEALTH
        
        return base_strategy
    
    def _select_fallback_strategy(
        self,
        primary_strategy: AttackStrategy,
        target_intel: TargetIntel
    ) -> AttackStrategy:
        """Select fallback strategy if primary fails"""
        
        fallback_map = {
            AttackStrategy.AGGRESSIVE: AttackStrategy.STEALTH,
            AttackStrategy.STEALTH: AttackStrategy.BALANCED,
            AttackStrategy.BALANCED: AttackStrategy.AGGRESSIVE,
            AttackStrategy.ZERO_DAY_HUNT: AttackStrategy.BALANCED,
        }
        
        return fallback_map.get(primary_strategy, AttackStrategy.BALANCED)
    
    async def _create_plan_with_llm(
        self,
        objective: str,
        target_intel: TargetIntel,
        strategy: AttackStrategy,
        constraints: Optional[Dict[str, Any]]
    ) -> AttackPlan:
        """Create attack plan using LLM"""
        
        # Prepare prompt for LLM
        prompt = self._build_llm_prompt(objective, target_intel, strategy, constraints)
        
        try:
            # Generate plan with LLM
            from transformers import pipeline
            
            generator = pipeline(
                "text-generation",
                model=self.llm_model,
                tokenizer=self.llm_tokenizer,
                max_new_tokens=1024,
                temperature=0.7,
                top_p=0.9,
            )
            
            response = generator(prompt)[0]['generated_text']
            
            # Parse LLM response into attack plan
            plan = self._parse_llm_response(response, strategy)
            
            return plan
            
        except Exception as e:
            logger.error(f"LLM planning failed: {e}, falling back to rule-based")
            return await self._create_plan_rule_based(objective, target_intel, strategy, constraints)
    
    async def _create_plan_rule_based(
        self,
        objective: str,
        target_intel: TargetIntel,
        strategy: AttackStrategy,
        constraints: Optional[Dict[str, Any]]
    ) -> AttackPlan:
        """Create attack plan using rule-based logic"""
        
        phases = []
        agents_required = []
        estimated_duration = 0
        
        # Get strategy template
        template = self.strategy_templates.get(strategy, self.strategy_templates[AttackStrategy.BALANCED])
        
        # Build phases based on target type and objective
        if target_intel.target_type == TargetType.WEB_APPLICATION:
            phases, agents = self._build_web_attack_phases(objective, target_intel, strategy)
        elif target_intel.target_type == TargetType.WINDOWS_DOMAIN:
            phases, agents = self._build_ad_attack_phases(objective, target_intel, strategy)
        elif target_intel.target_type in [TargetType.CLOUD_AWS, TargetType.CLOUD_AZURE, TargetType.CLOUD_GCP]:
            phases, agents = self._build_cloud_attack_phases(objective, target_intel, strategy)
        elif target_intel.target_type in [TargetType.MOBILE_ANDROID, TargetType.MOBILE_IOS]:
            phases, agents = self._build_mobile_attack_phases(objective, target_intel, strategy)
        else:
            phases, agents = self._build_generic_attack_phases(objective, target_intel, strategy)
        
        agents_required = agents
        estimated_duration = sum(phase.get('estimated_duration', 10) for phase in phases)
        
        # Determine risk level
        risk_level = "high" if strategy == AttackStrategy.AGGRESSIVE else "medium" if strategy == AttackStrategy.BALANCED else "low"
        
        return AttackPlan(
            strategy=strategy,
            phases=phases,
            estimated_duration=estimated_duration,
            success_probability=0.0,  # Will be calculated later
            risk_level=risk_level,
            agents_required=agents_required
        )
    
    def _build_web_attack_phases(
        self,
        objective: str,
        target_intel: TargetIntel,
        strategy: AttackStrategy
    ) -> Tuple[List[Dict], List[str]]:
        """Build attack phases for web applications"""
        
        phases = []
        agents = []
        
        # Phase 1: Reconnaissance
        phases.append({
            'phase': AttackPhase.RECONNAISSANCE.value,
            'agents': ['WebCrawlerAgent', 'TechnologyProfilerAgent'],
            'estimated_duration': 10,
            'description': 'Crawl website and identify technologies'
        })
        agents.extend(['WebCrawlerAgent', 'TechnologyProfilerAgent'])
        
        # Phase 2: Scanning
        if target_intel.waf_detected:
            phases.append({
                'phase': AttackPhase.SCANNING.value,
                'agents': ['WafDetectorAgent', 'WAFBypassAgent', 'VulnerabilityScanAgent'],
                'estimated_duration': 15,
                'description': 'Detect and bypass WAF, then scan for vulnerabilities'
            })
            agents.extend(['WafDetectorAgent', 'WAFBypassAgent', 'VulnerabilityScanAgent'])
        else:
            phases.append({
                'phase': AttackPhase.SCANNING.value,
                'agents': ['VulnerabilityScanAgent', 'NucleiAgent', 'SkipfishAgent'],
                'estimated_duration': 20,
                'description': 'Comprehensive vulnerability scanning'
            })
            agents.extend(['VulnerabilityScanAgent', 'NucleiAgent', 'SkipfishAgent'])
        
        # Phase 3: Exploitation
        phases.append({
            'phase': AttackPhase.EXPLOITATION.value,
            'agents': ['SqlmapAgent', 'XSS_Agent', 'SSRFAgent', 'ExploitAgent'],
            'estimated_duration': 30,
            'description': 'Exploit identified vulnerabilities'
        })
        agents.extend(['SqlmapAgent', 'XSS_Agent', 'SSRFAgent', 'ExploitAgent'])
        
        # Phase 4: Post-Exploitation (if objective requires)
        if 'backdoor' in objective.lower() or 'full' in objective.lower():
            phases.append({
                'phase': AttackPhase.POST_EXPLOITATION.value,
                'agents': ['AdvancedBackdoorAgent', 'ShellUpgraderAgent', 'AdvancedC2Agent'],
                'estimated_duration': 20,
                'description': 'Deploy backdoor and establish C2'
            })
            agents.extend(['AdvancedBackdoorAgent', 'ShellUpgraderAgent', 'AdvancedC2Agent'])
        
        # Phase 5: Data Exfiltration (if objective requires)
        if 'data' in objective.lower() or 'exfil' in objective.lower() or 'full' in objective.lower():
            phases.append({
                'phase': AttackPhase.DATA_EXFILTRATION.value,
                'agents': ['DataHarvesterAgent', 'AdvancedDataExfiltrationAgent'],
                'estimated_duration': 15,
                'description': 'Identify and exfiltrate sensitive data'
            })
            agents.extend(['DataHarvesterAgent', 'AdvancedDataExfiltrationAgent'])
        
        return phases, list(set(agents))
    
    def _build_ad_attack_phases(
        self,
        objective: str,
        target_intel: TargetIntel,
        strategy: AttackStrategy
    ) -> Tuple[List[Dict], List[str]]:
        """Build attack phases for Windows Active Directory"""
        
        phases = []
        agents = []
        
        # Phase 1: AD Enumeration
        phases.append({
            'phase': AttackPhase.ENUMERATION.value,
            'agents': ['BloodHoundAgent', 'InternalNetworkMapperAgent'],
            'estimated_duration': 15,
            'description': 'Enumerate AD structure and find attack paths'
        })
        agents.extend(['BloodHoundAgent', 'InternalNetworkMapperAgent'])
        
        # Phase 2: Credential Harvesting
        phases.append({
            'phase': AttackPhase.EXPLOITATION.value,
            'agents': ['KerberoastingAgent', 'ASREPRoastingAgent', 'CredentialHarvesterAgent'],
            'estimated_duration': 20,
            'description': 'Harvest credentials via Kerberos attacks'
        })
        agents.extend(['KerberoastingAgent', 'ASREPRoastingAgent', 'CredentialHarvesterAgent'])
        
        # Phase 3: Lateral Movement
        phases.append({
            'phase': AttackPhase.LATERAL_MOVEMENT.value,
            'agents': ['PassTheHashAgent', 'PassTheTicketAgent', 'LateralMovementAgent'],
            'estimated_duration': 25,
            'description': 'Move laterally using harvested credentials'
        })
        agents.extend(['PassTheHashAgent', 'PassTheTicketAgent', 'LateralMovementAgent'])
        
        # Phase 4: Privilege Escalation
        phases.append({
            'phase': AttackPhase.PRIVILEGE_ESCALATION.value,
            'agents': ['DCSyncAgent', 'GoldenTicketAgent', 'EnhancedPrivilegeEscalationAgent'],
            'estimated_duration': 20,
            'description': 'Escalate to Domain Admin'
        })
        agents.extend(['DCSyncAgent', 'GoldenTicketAgent', 'EnhancedPrivilegeEscalationAgent'])
        
        # Phase 5: Persistence
        if 'persist' in objective.lower() or 'backdoor' in objective.lower():
            phases.append({
                'phase': AttackPhase.PERSISTENCE.value,
                'agents': ['PersistenceAgent', 'AdvancedBackdoorAgent'],
                'estimated_duration': 15,
                'description': 'Establish persistence mechanisms'
            })
            agents.extend(['PersistenceAgent', 'AdvancedBackdoorAgent'])
        
        return phases, list(set(agents))
    
    def _build_cloud_attack_phases(
        self,
        objective: str,
        target_intel: TargetIntel,
        strategy: AttackStrategy
    ) -> Tuple[List[Dict], List[str]]:
        """Build attack phases for cloud infrastructure"""
        
        phases = []
        agents = []
        
        cloud_type = target_intel.target_type
        
        # Phase 1: Cloud Enumeration
        if cloud_type == TargetType.CLOUD_AWS:
            enum_agents = ['AWSS3EnumerationAgent', 'AWSRDSExploitAgent']
        elif cloud_type == TargetType.CLOUD_AZURE:
            enum_agents = ['AzureADEnumerationAgent', 'AzureBlobStorageAgent']
        else:  # GCP
            enum_agents = ['GCPStorageBucketAgent', 'GCPComputeEngineAgent']
        
        phases.append({
            'phase': AttackPhase.ENUMERATION.value,
            'agents': enum_agents,
            'estimated_duration': 15,
            'description': 'Enumerate cloud resources'
        })
        agents.extend(enum_agents)
        
        # Phase 2: IAM Exploitation
        if cloud_type == TargetType.CLOUD_AWS:
            iam_agents = ['AWSIAMPrivEscAgent', 'AWSSecretsManagerAgent']
        elif cloud_type == TargetType.CLOUD_AZURE:
            iam_agents = ['AzureADPrivEscAgent', 'AzureKeyVaultAgent']
        else:  # GCP
            iam_agents = ['GCPIAMPrivEscAgent', 'GCPSecretManagerAgent']
        
        phases.append({
            'phase': AttackPhase.PRIVILEGE_ESCALATION.value,
            'agents': iam_agents,
            'estimated_duration': 20,
            'description': 'Escalate IAM privileges and extract secrets'
        })
        agents.extend(iam_agents)
        
        # Phase 3: Resource Exploitation
        phases.append({
            'phase': AttackPhase.EXPLOITATION.value,
            'agents': ['AdvancedBackdoorAgent', 'AdvancedDataExfiltrationAgent'],
            'estimated_duration': 25,
            'description': 'Exploit cloud resources and exfiltrate data'
        })
        agents.extend(['AdvancedBackdoorAgent', 'AdvancedDataExfiltrationAgent'])
        
        return phases, list(set(agents))
    
    def _build_mobile_attack_phases(
        self,
        objective: str,
        target_intel: TargetIntel,
        strategy: AttackStrategy
    ) -> Tuple[List[Dict], List[str]]:
        """Build attack phases for mobile applications"""
        
        phases = []
        agents = []
        
        is_android = target_intel.target_type == TargetType.MOBILE_ANDROID
        
        # Phase 1: Static Analysis
        if is_android:
            analysis_agents = ['APKAnalysisAgent']
        else:
            analysis_agents = ['IPAAnalysisAgent']
        
        phases.append({
            'phase': AttackPhase.RECONNAISSANCE.value,
            'agents': analysis_agents,
            'estimated_duration': 10,
            'description': 'Static analysis of mobile app'
        })
        agents.extend(analysis_agents)
        
        # Phase 2: Dynamic Analysis
        if is_android:
            dynamic_agents = ['AndroidDynamicAnalysisAgent', 'AndroidSSLPinningBypassAgent']
        else:
            dynamic_agents = ['iOSDynamicAnalysisAgent', 'iOSSSLPinningBypassAgent']
        
        phases.append({
            'phase': AttackPhase.EXPLOITATION.value,
            'agents': dynamic_agents,
            'estimated_duration': 20,
            'description': 'Dynamic analysis and SSL pinning bypass'
        })
        agents.extend(dynamic_agents)
        
        # Phase 3: Data Extraction
        if is_android:
            extract_agents = ['AndroidDataExtractionAgent']
        else:
            extract_agents = ['AdvancedDataExfiltrationAgent']
        
        phases.append({
            'phase': AttackPhase.DATA_EXFILTRATION.value,
            'agents': extract_agents,
            'estimated_duration': 15,
            'description': 'Extract sensitive data from app'
        })
        agents.extend(extract_agents)
        
        return phases, list(set(agents))
    
    def _build_generic_attack_phases(
        self,
        objective: str,
        target_intel: TargetIntel,
        strategy: AttackStrategy
    ) -> Tuple[List[Dict], List[str]]:
        """Build generic attack phases for unknown targets"""
        
        phases = []
        agents = []
        
        # Phase 1: Reconnaissance
        phases.append({
            'phase': AttackPhase.RECONNAISSANCE.value,
            'agents': ['NmapScanAgent', 'PortScanAgent', 'TechnologyProfilerAgent'],
            'estimated_duration': 15,
            'description': 'Network reconnaissance and service detection'
        })
        agents.extend(['NmapScanAgent', 'PortScanAgent', 'TechnologyProfilerAgent'])
        
        # Phase 2: Vulnerability Scanning
        phases.append({
            'phase': AttackPhase.SCANNING.value,
            'agents': ['VulnerabilityScanAgent', 'NucleiAgent'],
            'estimated_duration': 20,
            'description': 'Vulnerability scanning'
        })
        agents.extend(['VulnerabilityScanAgent', 'NucleiAgent'])
        
        # Phase 3: Exploitation
        phases.append({
            'phase': AttackPhase.EXPLOITATION.value,
            'agents': ['ExploitAgent', 'MetasploitAgent'],
            'estimated_duration': 30,
            'description': 'Exploit vulnerabilities'
        })
        agents.extend(['ExploitAgent', 'MetasploitAgent'])
        
        # Phase 4: Post-Exploitation
        phases.append({
            'phase': AttackPhase.POST_EXPLOITATION.value,
            'agents': ['AdvancedBackdoorAgent', 'EnhancedPrivilegeEscalationAgent'],
            'estimated_duration': 20,
            'description': 'Post-exploitation and privilege escalation'
        })
        agents.extend(['AdvancedBackdoorAgent', 'EnhancedPrivilegeEscalationAgent'])
        
        return phases, list(set(agents))
    
    def _calculate_success_probability(
        self,
        plan: AttackPlan,
        target_intel: TargetIntel
    ) -> float:
        """Calculate estimated success probability"""
        
        base_probability = 0.7
        
        # Adjust based on target defenses
        if target_intel.edr_detected:
            base_probability -= 0.15
        if target_intel.waf_detected:
            base_probability -= 0.10
        
        # Adjust based on strategy
        if plan.strategy == AttackStrategy.STEALTH:
            base_probability += 0.05
        elif plan.strategy == AttackStrategy.AGGRESSIVE:
            base_probability -= 0.05
        
        # Adjust based on number of phases
        if len(plan.phases) > 6:
            base_probability -= 0.05
        
        # Clamp between 0.2 and 0.95
        return max(0.2, min(0.95, base_probability))
    
    def _load_strategy_templates(self) -> Dict[AttackStrategy, Dict]:
        """Load attack strategy templates"""
        return {
            AttackStrategy.STEALTH: {
                'speed': 'slow',
                'noise_level': 'low',
                'evasion_priority': 'high',
                'phases': ['recon', 'scan', 'exploit', 'persist']
            },
            AttackStrategy.AGGRESSIVE: {
                'speed': 'fast',
                'noise_level': 'high',
                'evasion_priority': 'low',
                'phases': ['scan', 'exploit', 'post_exploit']
            },
            AttackStrategy.BALANCED: {
                'speed': 'medium',
                'noise_level': 'medium',
                'evasion_priority': 'medium',
                'phases': ['recon', 'scan', 'exploit', 'post_exploit', 'persist']
            },
        }
    
    def _initialize_agent_weights(self) -> Dict[str, float]:
        """Initialize agent selection weights based on historical success"""
        # These would be updated based on actual performance
        return {}
    
    def _build_llm_prompt(
        self,
        objective: str,
        target_intel: TargetIntel,
        strategy: AttackStrategy,
        constraints: Optional[Dict[str, Any]]
    ) -> str:
        """Build prompt for LLM"""
        
        prompt = f"""You are an expert penetration tester. Based on the following data, generate the next precise, actionable attack plan to exploit the target. The goal is full system compromise.

Objective: {objective}
Target Type: {target_intel.target_type.value}
Target URL: {target_intel.url or 'N/A'}
Technologies: {', '.join(target_intel.technologies) if target_intel.technologies else 'Unknown'}
EDR Detected: {target_intel.edr_detected}
WAF Detected: {target_intel.waf_detected}
Strategy: {strategy.value}

Create an aggressive step-by-step attack plan with phases and specific agents to use. Focus on achieving remote code execution, privilege escalation, and data exfiltration.
Format as JSON with phases array containing: phase, agents, duration, description.
"""
        
        return prompt
    
    def _parse_llm_response(self, response: str, strategy: AttackStrategy) -> AttackPlan:
        """Parse LLM response into AttackPlan"""
        # Simplified parsing - in production, use more robust parsing
        try:
            # Extract JSON from response
            import re
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                return AttackPlan(
                    strategy=strategy,
                    phases=data.get('phases', []),
                    estimated_duration=data.get('estimated_duration', 60),
                    success_probability=0.0,
                    risk_level=data.get('risk_level', 'medium'),
                    agents_required=data.get('agents_required', [])
                )
        except Exception as e:
            logging.error("Error occurred")
        
        # Fallback to empty plan
        return AttackPlan(
            strategy=strategy,
            phases=[],
            estimated_duration=0,
            success_probability=0.0,
            risk_level='medium',
            agents_required=[]
        )
    
    async def replan(
        self,
        original_plan: AttackPlan,
        failed_phase: Dict[str, Any],
        context: Dict[str, Any]
    ) -> AttackPlan:
        """
        Adaptive replanning when a phase fails
        
        Args:
            original_plan: The original attack plan
            failed_phase: The phase that failed
            context: Current attack context
        
        Returns:
            Updated attack plan
        """
        logger.info(f"Replanning after failed phase: {failed_phase.get('phase')}")
        
        # Analyze failure reason
        failure_reason = context.get('failure_reason', 'unknown')
        
        # Select alternative agents
        alternative_agents = self._select_alternative_agents(
            failed_phase.get('agents', []),
            failure_reason
        )
        
        # Update failed phase with alternatives
        updated_phases = []
        for phase in original_plan.phases:
            if phase == failed_phase:
                phase['agents'] = alternative_agents
                phase['retry'] = True
            updated_phases.append(phase)
        
        # Create updated plan
        updated_plan = AttackPlan(
            strategy=original_plan.strategy,
            phases=updated_phases,
            estimated_duration=original_plan.estimated_duration + 15,  # Add time for retry
            success_probability=original_plan.success_probability * 0.8,  # Reduce probability
            risk_level=original_plan.risk_level,
            agents_required=original_plan.agents_required + alternative_agents,
            fallback_plan=original_plan.fallback_plan
        )
        
        logger.info(f"Replanning complete with {len(alternative_agents)} alternative agents")
        
        return updated_plan
    
    def _select_alternative_agents(
        self,
        failed_agents: List[str],
        failure_reason: str
    ) -> List[str]:
        """Select alternative agents when original agents fail"""
        
        alternatives_map = {
            'SqlmapAgent': ['ExploitAgent', 'APIFuzzerAgent'],
            'ExploitAgent': ['MetasploitAgent', 'NucleiAgent'],
            'VulnerabilityScanAgent': ['NucleiAgent', 'SkipfishAgent'],
            'NmapScanAgent': ['PortScanAgent'],
        }
        
        alternatives = []
        for agent in failed_agents:
            if agent in alternatives_map:
                alternatives.extend(alternatives_map[agent])
        
        return alternatives if alternatives else ['ExploitAgent']

