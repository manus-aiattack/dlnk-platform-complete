#!/usr/bin/env python3
"""
from core.logger import log
from core.data_models import AgentData, Strategy
DirsearchAgent - AI-Powered Directory and File Discovery Agent
Advanced directory brute-forcing with AI-driven payload generation
"""

import asyncio
import aiohttp
import random
import time
from typing import Dict, List, Any, Optional
from pathlib import Path
import json

from core.base_agent import BaseAgent
from core.data_models import AttackPhase
# from core.target import Target


class DirsearchAgent(BaseAgent):
    """Advanced AI-Powered Directory Discovery Agent"""
    
    def __init__(self, context_manager=None, orchestrator=None):
        super().__init__(context_manager, orchestrator)
        self.name = "DirsearchAgent"
        self.description = "AI-Powered Directory and File Discovery Agent"
        self.version = "2.0.0"
        self.supported_phases = [AttackPhase.RECONNAISSANCE]
        self.ai_model = "mistral:latest"
        self.learning_data = {}
        
        # Advanced payloads
        self.directory_payloads = [
            "admin", "administrator", "login", "panel", "dashboard",
            "api", "backup", "config", "database", "files",
            "uploads", "downloads", "images", "assets", "static",
            "css", "js", "js", "php", "asp", "jsp", "html",
            "xml", "json", "txt", "log", "sql", "zip", "rar",
            "wp-admin", "wp-content", "wp-includes", "wordpress",
            "phpmyadmin", "mysql", "pma", "adminer", "cpanel",
            "robots.txt", "sitemap.xml", ".htaccess", "web.config",
            "crossdomain.xml", "clientaccesspolicy.xml"
        ]
        
        # AI-generated payloads
        self.ai_payloads = []
        self.success_patterns = []
        
    async def initialize(self):
        """Initialize the agent"""
        await super().initialize()
        await self._initialize_ai_learning()
        
    async def _initialize_ai_learning(self):
        """Initialize AI learning capabilities"""
        try:
            # Load existing learning data
            learning_file = Path("workspace/dirsearch_learning.json")
            if learning_file.exists():
                with open(learning_file, "r") as f:
                    self.learning_data = json.load(f)
                    self.ai_payloads = self.learning_data.get("ai_payloads", [])
                    self.success_patterns = self.learning_data.get("success_patterns", [])
            
            log.info(f"DirsearchAgent AI learning initialized with {len(self.ai_payloads)} AI payloads")
            
        except Exception as e:
            log.warning(f"Failed to initialize AI learning: {e}")
    
    async def execute(self, target: dict, phase: AttackPhase, **kwargs) -> Dict[str, Any]:
        """Execute directory discovery attack"""
        try:
            log.info(f"Starting directory discovery on {target.url}")
            
            # AI-analyze target
            analysis = await self._ai_analyze_target(target)
            
            # Generate AI payloads
            ai_payloads = await self._generate_ai_payloads(target, analysis)
            
            # Combine with standard payloads
            all_payloads = self.directory_payloads + ai_payloads
            
            # Execute discovery
            results = await self._execute_discovery(target, all_payloads)
            
            # AI-learn from results
            await self._learn_from_results(target, results)
            
            return {
                "agent": self.name,
                "target": target.url,
                "phase": phase.value,
                "discovered_paths": results.get("discovered", []),
                "ai_payloads_used": ai_payloads,
                "success_rate": results.get("success_rate", 0),
                "analysis": analysis
            }
            
        except Exception as e:
            log.error(f"DirsearchAgent execution failed: {e}")
            return {
                "agent": self.name,
                "target": target.url,
                "phase": phase.value,
                "error": str(e),
                "discovered_paths": [],
                "ai_payloads_used": [],
                "success_rate": 0
            }
    
    async def _ai_analyze_target(self, target: dict) -> Dict[str, Any]:
        """AI-analyze target for optimal payload generation"""
        try:
            # Analyze target characteristics
            analysis = {
                "url_structure": target.url,
                "technology_stack": [],
                "common_paths": [],
                "vulnerability_indicators": [],
                "attack_vectors": []
            }
            
            # Simple heuristic analysis
            if "admin" in target.url.lower():
                analysis["common_paths"].append("admin")
                analysis["attack_vectors"].append("administrative_access")
            
            if any(tech in target.url.lower() for tech in ["wp", "wordpress"]):
                analysis["technology_stack"].append("wordpress")
                analysis["common_paths"].extend(["wp-admin", "wp-content", "wp-includes"])
            
            if any(tech in target.url.lower() for tech in ["api", "rest"]):
                analysis["attack_vectors"].append("api_discovery")
                analysis["common_paths"].extend(["api", "v1", "v2", "docs"])
            
            return analysis
            
        except Exception as e:
            log.warning(f"AI analysis failed: {e}")
            return {"error": str(e)}
    
    async def _generate_ai_payloads(self, target: dict, analysis: Dict[str, Any]) -> List[str]:
        """Generate AI-driven payloads based on target analysis"""
        try:
            ai_payloads = []
            
            # Generate payloads based on technology stack
            for tech in analysis.get("technology_stack", []):
                if tech == "wordpress":
                    ai_payloads.extend([
                        "wp-json", "wp-ajax", "wp-cron", "wp-sitemap",
                        "wp-content/uploads", "wp-content/plugins",
                        "wp-content/themes", "wp-includes/js"
                    ])
            
            # Generate payloads based on attack vectors
            for vector in analysis.get("attack_vectors", []):
                if vector == "administrative_access":
                    ai_payloads.extend([
                        "admin.php", "admin.asp", "admin.jsp",
                        "administrator", "admin-panel", "admin-area"
                    ])
                elif vector == "api_discovery":
                    ai_payloads.extend([
                        "api/v1", "api/v2", "api/docs", "api/swagger",
                        "rest", "graphql", "soap", "rpc"
                    ])
            
            # Add learned payloads
            ai_payloads.extend(self.ai_payloads[:10])  # Use top 10 learned payloads
            
            return list(set(ai_payloads))  # Remove duplicates
            
        except Exception as e:
            log.warning(f"AI payload generation failed: {e}")
            return []
    
    async def _execute_discovery(self, target: dict, payloads: List[str]) -> Dict[str, Any]:
        """Execute directory discovery"""
        try:
            discovered = []
            success_count = 0
            
            async with aiohttp.ClientSession() as session:
                for payload in payloads[:50]:  # Limit to 50 payloads for demo
                    try:
                        test_url = f"{target.url.rstrip('/')}/{payload}"
                        
                        async with session.get(test_url, timeout=5) as response:
                            if response.status == 200:
                                discovered.append({
                                    "path": payload,
                                    "url": test_url,
                                    "status": response.status,
                                    "size": len(await response.text())
                                })
                                success_count += 1
                                log.info(f"Discovered: {test_url}")
                        
                        # Rate limiting
                        await asyncio.sleep(0.1)
                        
                    except Exception as e:
                        continue
            
            success_rate = (success_count / len(payloads)) * 100 if payloads else 0
            
            return {
                "discovered": discovered,
                "success_rate": success_rate,
                "total_tested": len(payloads)
            }
            
        except Exception as e:
            log.error(f"Discovery execution failed: {e}")
            return {"discovered": [], "success_rate": 0, "total_tested": 0}
    
    async def _learn_from_results(self, target: dict, results: Dict[str, Any]):
        """Learn from discovery results"""
        try:
            # Store successful patterns
            for item in results.get("discovered", []):
                path = item.get("path", "")
                if path and path not in self.success_patterns:
                    self.success_patterns.append(path)
            
            # Update AI payloads based on success patterns
            self.ai_payloads = self.success_patterns[:20]  # Keep top 20
            
            # Save learning data
            self.learning_data = {
                "ai_payloads": self.ai_payloads,
                "success_patterns": self.success_patterns,
                "last_update": time.time()
            }
            
            learning_file = Path("workspace/dirsearch_learning.json")
            learning_file.parent.mkdir(exist_ok=True)
            
            with open(learning_file, "w") as f:
                json.dump(self.learning_data, f, indent=2)
            
            log.info(f"DirsearchAgent learned {len(self.ai_payloads)} new patterns")
            
        except Exception as e:
            log.warning(f"Learning failed: {e}")
