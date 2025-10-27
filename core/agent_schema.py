from typing import List, Dict, Any

AGENT_SCHEMA = {
    "ReconnaissanceMasterAgent": {
        "description": "Orchestrates other reconnaissance agents to perform a comprehensive scan of the target.",
        "context_requirements": []
    },
    "TriageAgent": {
        "description": "Analyzes the output of reconnaissance agents to identify interesting findings and potential vulnerabilities.",
        "context_requirements": ["recon_data"]
    },
    "WafDetectorAgent": {
        "description": "Detects the presence of a Web Application Firewall (WAF) on the target.",
        "context_requirements": ["target_url"]
    },
    "NucleiAgent": {
        "description": "Runs the Nuclei scanner to check for known vulnerabilities.",
        "context_requirements": ["target_url"]
    },
    "NmapScanAgent": {
        "description": "Runs the Nmap scanner to perform port scanning and service enumeration.",
        "context_requirements": ["target_host"]
    },
    "ExploitAgent": {
        "description": "Attempts to exploit a known vulnerability to gain an initial foothold.",
        "context_requirements": []
    },
    "MetasploitAgent": {
        "description": "Uses the Metasploit framework to exploit vulnerabilities.",
        "context_requirements": ["exploit_module"]
    },
    "PrivilegeEscalationAgent": {
        "description": "Attempts to escalate privileges on the target system.",
        "context_requirements": ["shell_id", "post_ex_report"]
    },
    "DataExfiltrationAgent": {
        "description": "Exfiltrates sensitive data from the target system.",
        "context_requirements": ["shell_id", "staging_dir"]
    },
    "ShellAgent": {
        "description": "Provides a shell on the target system.",
        "context_requirements": []
    },
    "ToolManagerAgent": {
        "description": "Installs, configures, and verifies tools on the system.",
        "context_requirements": ["tool_name", "directive"]
    }
}
