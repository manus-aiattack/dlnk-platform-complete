import asyncio
import json
import sqlite3
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from core.logger import log
from core.data_models import AttackPhase
import numpy as np
from collections import defaultdict
from core.context_manager import ContextManager # Import ContextManager


@dataclass
class AgentPerformance:
    agent_name: str
    phase: AttackPhase
    success_count: int = 0
    failure_count: int = 0
    total_execution_time: float = 0.0
    avg_execution_time: float = 0.0
    success_rate: float = 0.0
    last_updated: datetime = field(default_factory=datetime.now)


@dataclass
class AttackPattern:
    pattern_id: str
    target_type: str
    successful_sequence: List[str]
    success_rate: float
    avg_duration: float
    frequency: int


class LearningEngine:
    def __init__(self, context_manager: ContextManager = None): # Changed shared_data to context_manager
        self.context_manager = context_manager # Changed shared_data to context_manager
        self.db_path = "data/learning_engine.db"
        self.agent_performance = {}
        self.attack_patterns = {}
        self.target_profiles = {}

    async def load_historical_data(self):
        """Load historical performance data"""
        try:
            await self._initialize_database()
            await self._load_agent_performance()
            await self._load_attack_patterns()
            await self._load_target_profiles()

            log.info("Loaded historical learning data")

        except Exception as e:
            log.error(f"Failed to load historical data: {e}")

    async def _initialize_database(self):
        """Initialize learning database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS agent_performance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_name TEXT NOT NULL,
                phase TEXT NOT NULL,
                success_count INTEGER DEFAULT 0,
                failure_count INTEGER DEFAULT 0,
                total_execution_time REAL DEFAULT 0.0,
                avg_execution_time REAL DEFAULT 0.0,
                success_rate REAL DEFAULT 0.0,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attack_patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern_id TEXT UNIQUE NOT NULL,
                target_type TEXT NOT NULL,
                successful_sequence TEXT NOT NULL,
                success_rate REAL DEFAULT 0.0,
                avg_duration REAL DEFAULT 0.0,
                frequency INTEGER DEFAULT 1,
                last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS target_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT UNIQUE NOT NULL,
                target_type TEXT NOT NULL,
                technologies TEXT,
                vulnerabilities TEXT,
                successful_agents TEXT,
                failed_agents TEXT,
                last_attacked TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        conn.commit()
        conn.close()

    async def _load_agent_performance(self):
        """Load agent performance data from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('SELECT * FROM agent_performance')
            rows = cursor.fetchall()

            for row in rows:
                agent_name = row[1]
                phase = AttackPhase[row[2]]
                performance = AgentPerformance(
                    agent_name=agent_name,
                    phase=phase,
                    success_count=row[3],
                    failure_count=row[4],
                    total_execution_time=row[5],
                    avg_execution_time=row[6],
                    success_rate=row[7],
                    last_updated=datetime.fromisoformat(row[8])
                )

                key = f"{agent_name}_{phase.name}"
                self.agent_performance[key] = performance

            conn.close()

        except Exception as e:
            log.error(f"Failed to load agent performance: {e}")

    async def _load_attack_patterns(self):
        """Load attack patterns from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('SELECT * FROM attack_patterns')
            rows = cursor.fetchall()

            for row in rows:
                pattern = AttackPattern(
                    pattern_id=row[1],
                    target_type=row[2],
                    successful_sequence=json.loads(row[3]),
                    success_rate=row[4],
                    avg_duration=row[5],
                    frequency=row[6]
                )

                self.attack_patterns[pattern.pattern_id] = pattern

            conn.close()

        except Exception as e:
            log.error(f"Failed to load attack patterns: {e}")

    async def _load_target_profiles(self):
        """Load target profiles from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('SELECT * FROM target_profiles')
            rows = cursor.fetchall()

            for row in rows:
                profile = {
                    "target_url": row[1],
                    "target_type": row[2],
                    "technologies": json.loads(row[3]) if row[3] else [],
                    "vulnerabilities": json.loads(row[4]) if row[4] else [],
                    "successful_agents": json.loads(row[5]) if row[5] else [],
                    "failed_agents": json.loads(row[6]) if row[6] else [],
                    "last_attacked": datetime.fromisoformat(row[7])
                }

                self.target_profiles[row[1]] = profile

            conn.close()

        except Exception as e:
            log.error(f"Failed to load target profiles: {e}")

    async def get_agent_success_rate(self, agent_name: str, phase: AttackPhase) -> Optional[float]:
        """Get historical success rate for agent"""
        key = f"{agent_name}_{phase.name}"
        if key in self.agent_performance:
            return self.agent_performance[key].success_rate
        return None

    async def get_agent_avg_execution_time(self, agent_name: str) -> Optional[float]:
        """Get average execution time for agent"""
        times = []
        for performance in self.agent_performance.values():
            if performance.agent_name == agent_name:
                times.append(performance.avg_execution_time)

        if times:
            return np.mean(times)
        return None

    async def update_agent_performance(self, agent_name: str, phase: AttackPhase, result: Dict[str, Any]):
        """Update agent performance based on execution result"""
        try:
            key = f"{agent_name}_{phase.name}"

            if key not in self.agent_performance:
                self.agent_performance[key] = AgentPerformance(
                    agent_name=agent_name,
                    phase=phase
                )

            performance = self.agent_performance[key]

            # Update counts
            if result.get("success", False):
                performance.success_count += 1
            else:
                performance.failure_count += 1

            # Update execution time
            execution_time = result.get("execution_time", 0.0)
            performance.total_execution_time += execution_time

            # Calculate averages
            total_attempts = performance.success_count + performance.failure_count
            performance.avg_execution_time = performance.total_execution_time / total_attempts
            performance.success_rate = performance.success_count / total_attempts
            performance.last_updated = datetime.now()

            # Save to database
            await self._save_agent_performance(performance)

        except Exception as e:
            log.error(f"Failed to update agent performance: {e}")

    async def _save_agent_performance(self, performance: AgentPerformance):
        """Save agent performance to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                INSERT OR REPLACE INTO agent_performance 
                (agent_name, phase, success_count, failure_count, total_execution_time, 
                 avg_execution_time, success_rate, last_updated)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                performance.agent_name,
                performance.phase.name,
                performance.success_count,
                performance.failure_count,
                performance.total_execution_time,
                performance.avg_execution_time,
                performance.success_rate,
                performance.last_updated.isoformat()
            ))

            conn.commit()
            conn.close()

        except Exception as e:
            log.error(f"Failed to save agent performance: {e}")

    async def learn_attack_pattern(self, target_type: str, successful_sequence: List[str],
                                   duration: float, success: bool):
        """Learn from successful attack patterns"""
        try:
            # Create pattern ID
            pattern_id = f"{target_type}_{hash(tuple(successful_sequence))}"

            if pattern_id in self.attack_patterns:
                pattern = self.attack_patterns[pattern_id]
                pattern.frequency += 1

                if success:
                    # Update success rate
                    pattern.success_rate = (
                        (pattern.success_rate * (pattern.frequency - 1) +
                         1.0) / pattern.frequency
                    )
                else:
                    pattern.success_rate = (
                        (pattern.success_rate * (pattern.frequency - 1) +
                         0.0) / pattern.frequency
                    )

                # Update average duration
                pattern.avg_duration = (
                    (pattern.avg_duration * (pattern.frequency - 1) +
                     duration) / pattern.frequency
                )
            else:
                pattern = AttackPattern(
                    pattern_id=pattern_id,
                    target_type=target_type,
                    successful_sequence=successful_sequence,
                    success_rate=1.0 if success else 0.0,
                    avg_duration=duration,
                    frequency=1
                )

            self.attack_patterns[pattern_id] = pattern

            # Save to database
            await self._save_attack_pattern(pattern)

        except Exception as e:
            log.error(f"Failed to learn attack pattern: {e}")

    async def _save_attack_pattern(self, pattern: AttackPattern):
        """Save attack pattern to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                INSERT OR REPLACE INTO attack_patterns 
                (pattern_id, target_type, successful_sequence, success_rate, 
                 avg_duration, frequency, last_used)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                pattern.pattern_id,
                pattern.target_type,
                json.dumps(pattern.successful_sequence),
                pattern.success_rate,
                pattern.avg_duration,
                pattern.frequency,
                datetime.now().isoformat()
            ))

            conn.commit()
            conn.close()

        except Exception as e:
            log.error(f"Failed to save attack pattern: {e}")

    async def get_recommended_sequence(self, target_type: str) -> Optional[List[str]]:
        """Get recommended attack sequence for target type"""
        try:
            # Find patterns for this target type
            target_patterns = [
                pattern for pattern in self.attack_patterns.values()
                if pattern.target_type == target_type
            ]

            if not target_patterns:
                return None

            # Sort by success rate and frequency
            target_patterns.sort(
                key=lambda p: (p.success_rate, p.frequency),
                reverse=True
            )

            # Return the best pattern
            best_pattern = target_patterns[0]
            if best_pattern.success_rate > 0.5:  # Only recommend if >50% success
                return best_pattern.successful_sequence

            return None

        except Exception as e:
            log.error(f"Failed to get recommended sequence: {e}")
            return None

    async def update_target_profile(self, target_url: str, result: Dict[str, Any]):
        """Update target profile based on attack results"""
        try:
            if target_url not in self.target_profiles:
                self.target_profiles[target_url] = {
                    "target_url": target_url,
                    "target_type": "unknown",
                    "technologies": [],
                    "vulnerabilities": [],
                    "successful_agents": [],
                    "failed_agents": [],
                    "last_attacked": datetime.now()
                }

            profile = self.target_profiles[target_url]

            # Update based on result
            agent_name = result.get("agent_name", "")
            success = result.get("success", False)

            if success:
                if agent_name not in profile["successful_agents"]:
                    profile["successful_agents"].append(agent_name)
            else:
                if agent_name not in profile["failed_agents"]:
                    profile["failed_agents"].append(agent_name)

            # Update technologies and vulnerabilities if available
            if "technologies" in result:
                profile["technologies"].extend(result["technologies"])
                profile["technologies"] = list(set(profile["technologies"]))

            if "vulnerabilities" in result:
                profile["vulnerabilities"].extend(result["vulnerabilities"])
                profile["vulnerabilities"] = list(
                    set(profile["vulnerabilities"]))

            profile["last_attacked"] = datetime.now()

            # Save to database
            await self._save_target_profile(profile)

        except Exception as e:
            log.error(f"Failed to update target profile: {e}")

    async def _save_target_profile(self, profile: Dict[str, Any]):
        """Save target profile to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                INSERT OR REPLACE INTO target_profiles 
                (target_url, target_type, technologies, vulnerabilities, 
                 successful_agents, failed_agents, last_attacked)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                profile["target_url"],
                profile["target_type"],
                json.dumps(profile["technologies"]),
                json.dumps(profile["vulnerabilities"]),
                json.dumps(profile["successful_agents"]),
                json.dumps(profile["failed_agents"]),
                profile["last_attacked"].isoformat()
            ))

            conn.commit()
            conn.close()

        except Exception as e:
            log.error(f"Failed to save target profile: {e}")

    async def get_insights(self) -> Dict[str, Any]:
        """Get learning insights and statistics"""
        try:
            insights = {
                "total_agents_tracked": len(self.agent_performance),
                "total_patterns_learned": len(self.attack_patterns),
                "total_targets_profiled": len(self.target_profiles),
                "top_performing_agents": [],
                "most_common_patterns": [],
                "target_type_distribution": defaultdict(int)
            }

            # Top performing agents
            agent_success_rates = []
            for performance in self.agent_performance.values():
                if performance.success_count + performance.failure_count > 0:
                    agent_success_rates.append((
                        performance.agent_name,
                        performance.success_rate,
                        performance.success_count + performance.failure_count
                    ))

            agent_success_rates.sort(key=lambda x: x[1], reverse=True)
            insights["top_performing_agents"] = agent_success_rates[:10] if agent_success_rates else []

            # Most common patterns
            pattern_frequencies = [
                (pattern.pattern_id, pattern.frequency, pattern.success_rate)
                for pattern in self.attack_patterns.values()
            ]
            pattern_frequencies.sort(key=lambda x: x[1], reverse=True)
            insights["most_common_patterns"] = pattern_frequencies[:10]

            # Target type distribution
            for profile in self.target_profiles.values():
                insights["target_type_distribution"][profile["target_type"]] += 1

            return insights

        except Exception as e:
            log.error(f"Failed to get insights: {e}")
            return {}

    async def get_agent_recommendations(self, target_type: str, phase: AttackPhase) -> List[str]:
        """Get agent recommendations based on historical data"""
        try:
            recommendations = []

            # Get successful agents for this target type and phase
            successful_agents = []
            for profile in self.target_profiles.values():
                if profile["target_type"] == target_type:
                    successful_agents.extend(profile["successful_agents"])

            # Get agent performance for this phase
            phase_agents = []
            for performance in self.agent_performance.values():
                if performance.phase == phase and performance.success_rate > 0.5:
                    phase_agents.append(
                        (performance.agent_name, performance.success_rate))

            # Sort by success rate
            phase_agents.sort(key=lambda x: x[1], reverse=True)

            # Generate recommendations
            if phase_agents:
                top_agent = phase_agents[0]
                recommendations.append(
                    f"Consider using {top_agent[0]} (success rate: {top_agent[1]:.2%})")

            if successful_agents:
                unique_agents = list(set(successful_agents))
                recommendations.append(
                    f"Previously successful agents for {target_type}: {', '.join(unique_agents[:3])}")

            return recommendations

        except Exception as e:
            log.error(f"Failed to get agent recommendations: {e}")
            return []

    async def predict_success_probability(self, agent_name: str, target_type: str, phase: AttackPhase) -> float:
        """Predict success probability for agent on specific target type"""
        try:
            # Get base success rate for agent and phase
            base_success_rate = await self.get_agent_success_rate(agent_name, phase)
            if base_success_rate is None:
                base_success_rate = 0.5  # Default

            # Adjust based on target type success
            target_success_rate = 0.5  # Default
            for profile in self.target_profiles.values():
                if profile["target_type"] == target_type:
                    if agent_name in profile["successful_agents"]:
                        target_success_rate = 0.8
                    elif agent_name in profile["failed_agents"]:
                        target_success_rate = 0.2
                    break

            # Weighted average
            predicted_success = (base_success_rate * 0.7) + \
                (target_success_rate * 0.3)

            return min(predicted_success, 1.0)

        except Exception as e:
            log.error(f"Failed to predict success probability: {e}")
            return 0.5
