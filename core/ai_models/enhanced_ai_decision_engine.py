"""
Enhanced AI Decision Engine with ML Capabilities
ตามแผนการพัฒนา Manus AI Attack Platform Phase 1
"""

import asyncio
import json
import numpy as np
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from dataclasses import dataclass
import pickle

from .logger import log


@dataclass
class DecisionResult:
    """AI decision result"""
    decision: Dict[str, Any]
    confidence: float
    success_probability: float
    risk_score: float
    reasoning: str
    alternatives: List[Dict[str, Any]]
    execution_time_ms: int


@dataclass
class HistoricalCase:
    """Historical case for decision making"""
    situation: Dict[str, Any]
    option: Dict[str, Any]
    outcome: str  # success, failure
    timestamp: str
    context: Dict[str, Any]


class HistoryDatabase:
    """Database for storing and retrieving historical cases"""

    def __init__(self, storage_path: str = "workspace/history.db"):
        self.storage_path = storage_path
        self.history: List[HistoricalCase] = []
        self._load_history()

    def _load_history(self):
        """Load historical cases from storage"""
        try:
            # Mock implementation - would normally load from database
            log.info("History database initialized")
        except Exception as e:
            log.error(f"Failed to load history: {e}")

    async def find_similar(
        self,
        situation: Dict[str, Any],
        option: Dict[str, Any],
        max_results: int = 10
    ) -> List[HistoricalCase]:
        """Find similar historical cases"""
        # Mock similarity search
        # In real implementation, this would use vector similarity search
        similar_cases = []

        for case in self.history:
            # Simple similarity check (would use embeddings in real implementation)
            situation_match = self._calculate_situation_similarity(situation, case.situation)
            option_match = self._calculate_option_similarity(option, case.option)

            if situation_match > 0.7 or option_match > 0.7:  # Threshold for similarity
                similar_cases.append(case)

        return similar_cases[:max_results]

    def _calculate_situation_similarity(self, situation1: Dict[str, Any], situation2: Dict[str, Any]) -> float:
        """Calculate similarity between two situations"""
        # Mock implementation
        return 0.5  # Placeholder

    def _calculate_option_similarity(self, option1: Dict[str, Any], option2: Dict[str, Any]) -> float:
        """Calculate similarity between two options"""
        # Mock implementation
        return 0.5  # Placeholder

    async def store_case(
        self,
        situation: Dict[str, Any],
        option: Dict[str, Any],
        outcome: str,
        context: Dict[str, Any]
    ):
        """Store a new historical case"""
        case = HistoricalCase(
            situation=situation,
            option=option,
            outcome=outcome,
            timestamp=datetime.now().isoformat(),
            context=context
        )

        self.history.append(case)

        # Keep only recent cases (memory management)
        if len(self.history) > 1000:
            self.history = self.history[-500:]

        log.info(f"Stored historical case, total cases: {len(self.history)}")


class EnhancedAIDecisionEngine:
    """Enhanced AI Decision Engine with ML capabilities"""

    def __init__(self):
        self.model = self._load_decision_model()
        self.history_db = HistoryDatabase()
        self.confidence_threshold = 0.8
        self.risk_threshold = 0.3

    def _load_decision_model(self):
        """Load ML decision model"""
        # Mock model loading
        # In real implementation, this would load a trained ML model
        log.info("Decision model loaded")
        return None  # Placeholder

    async def make_decision(
        self,
        situation: Dict[str, Any],
        options: List[Dict[str, Any]],
        context: Dict[str, Any]
    ) -> DecisionResult:
        """
        Make AI-driven decision with confidence scoring
        """
        start_time = datetime.now()

        log.info(f"Making AI decision for situation: {situation.get('type', 'unknown')}")

        try:
            # Extract features from situation
            features = self._extract_features(situation, context)

            # Score each option
            scored_options = []
            for option in options:
                option_score = await self._score_option(
                    option=option,
                    features=features,
                    situation=situation,
                    context=context
                )
                scored_options.append(option_score)

            # Sort by score
            scored_options.sort(
                key=lambda x: x['success_probability'] * (1 - x['risk_score']),
                reverse=True
            )

            # Select best option
            best_option = scored_options[0] if scored_options else None

            if best_option:
                # Generate alternatives if confidence is low
                alternatives = []
                if best_option['confidence'] < self.confidence_threshold:
                    alternatives = await self._generate_alternatives(
                        situation=situation,
                        failed_option=best_option,
                        context=context
                    )

                execution_time = int((datetime.now() - start_time).total_seconds() * 1000)

                result = DecisionResult(
                    decision=best_option['option'],
                    confidence=best_option['confidence'],
                    success_probability=best_option['success_probability'],
                    risk_score=best_option['risk_score'],
                    reasoning=best_option['reasoning'],
                    alternatives=alternatives,
                    execution_time_ms=execution_time
                )

                # Store decision for learning
                await self._store_decision(
                    situation=situation,
                    decision=result,
                    context=context
                )

                return result
            else:
                # No valid options
                return DecisionResult(
                    decision={},
                    confidence=0.0,
                    success_probability=0.0,
                    risk_score=1.0,
                    reasoning="No valid options available",
                    alternatives=[],
                    execution_time_ms=int((datetime.now() - start_time).total_seconds() * 1000)
                )

        except Exception as e:
            log.error(f"Decision making failed: {e}")
            return DecisionResult(
                decision={},
                confidence=0.1,
                success_probability=0.1,
                risk_score=0.9,
                reasoning=f"Decision failed: {e}",
                alternatives=[],
                execution_time_ms=int((datetime.now() - start_time).total_seconds() * 1000)
            )

    async def _score_option(
        self,
        option: Dict[str, Any],
        features: np.ndarray,
        situation: Dict[str, Any],
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Score individual option"""
        try:
            # Get historical data
            similar_cases = await self.history_db.find_similar(
                situation=situation,
                option=option
            )

            # Calculate success probability
            success_prob = self._calculate_success_probability(
                option=option,
                features=features,
                similar_cases=similar_cases
            )

            # Calculate risk score
            risk_score = self._calculate_risk(
                option=option,
                context=context,
                similar_cases=similar_cases
            )

            # Calculate confidence
            confidence = self._calculate_confidence(
                success_prob=success_prob,
                risk_score=risk_score,
                similar_cases=similar_cases
            )

            # Generate reasoning
            reasoning = self._generate_reasoning(option, features, success_prob, risk_score)

            return {
                'option': option,
                'success_probability': success_prob,
                'risk_score': risk_score,
                'confidence': confidence,
                'reasoning': reasoning
            }

        except Exception as e:
            log.error(f"Failed to score option: {e}")
            return {
                'option': option,
                'success_probability': 0.5,
                'risk_score': 0.5,
                'confidence': 0.1,
                'reasoning': f"Scoring failed: {e}"
            }

    def _calculate_success_probability(
        self,
        option: Dict[str, Any],
        features: np.ndarray,
        similar_cases: List[HistoricalCase]
    ) -> float:
        """Calculate success probability using ML model and historical data"""
        if similar_cases:
            # Use historical data
            success_count = sum(1 for case in similar_cases if case.outcome == 'success')
            total_cases = len(similar_cases)
            success_rate = success_count / total_cases if total_cases > 0 else 0.5

            # If we had a real ML model, we would use it here
            # For now, use historical data
            probability = success_rate

        else:
            # No historical data - use base probability
            # This would be based on option type and general statistics
            option_type = option.get('type', 'unknown')
            base_probabilities = {
                'reconnaissance': 0.9,
                'vulnerability_scan': 0.85,
                'exploitation': 0.6,
                'post_exploitation': 0.7,
            }
            probability = base_probabilities.get(option_type, 0.5)

        return min(max(probability, 0.0), 1.0)  # Clamp between 0 and 1

    def _calculate_risk(
        self,
        option: Dict[str, Any],
        context: Dict[str, Any],
        similar_cases: List[HistoricalCase]
    ) -> float:
        """Calculate risk score for option"""
        try:
            risk_score = 0.0

            # Risk factors
            option_type = option.get('type', 'unknown')

            # Base risk by option type
            base_risk = {
                'reconnaissance': 0.1,
                'vulnerability_scan': 0.2,
                'exploitation': 0.4,
                'post_exploitation': 0.3,
            }
            risk_score += base_risk.get(option_type, 0.3)

            # Add target-specific risk
            target_security_level = context.get('target_security_level', 'medium')
            security_risk = {
                'low': 0.1,
                'medium': 0.2,
                'high': 0.4,
                'very_high': 0.6,
            }
            risk_score += security_risk.get(target_security_level, 0.3)

            # Add historical failure risk
            if similar_cases:
                failure_count = sum(1 for case in similar_cases if case.outcome == 'failure')
                failure_rate = failure_count / len(similar_cases)
                risk_score += failure_rate * 0.3

            # Add complexity risk
            complexity = option.get('complexity', 'medium')
            complexity_risk = {
                'low': 0.0,
                'medium': 0.1,
                'high': 0.2,
            }
            risk_score += complexity_risk.get(complexity, 0.1)

            return min(max(risk_score, 0.0), 1.0)  # Clamp between 0 and 1

        except Exception as e:
            log.error(f"Failed to calculate risk: {e}")
            return 0.5

    def _calculate_confidence(
        self,
        success_prob: float,
        risk_score: float,
        similar_cases: List[HistoricalCase]
    ) -> float:
        """Calculate confidence in decision"""
        try:
            confidence = 0.5  # Base confidence

            # Increase confidence based on historical data
            if similar_cases:
                confidence += min(len(similar_cases) * 0.05, 0.3)  # Max 30% from case count

            # Increase confidence based on success probability
            confidence += success_prob * 0.2

            # Decrease confidence based on risk
            confidence -= risk_score * 0.1

            # Ensure confidence is reasonable
            return min(max(confidence, 0.1), 1.0)

        except Exception as e:
            log.error(f"Failed to calculate confidence: {e}")
            return 0.3

    def _generate_reasoning(
        self,
        option: Dict[str, Any],
        features: np.ndarray,
        success_prob: float,
        risk_score: float
    ) -> str:
        """Generate human-readable reasoning for decision"""
        try:
            option_type = option.get('type', 'unknown')
            reasoning_parts = []

            # Base reasoning
            if success_prob > 0.7:
                reasoning_parts.append(f"High success probability ({success_prob:.1%})")
            elif success_prob > 0.5:
                reasoning_parts.append(f"Moderate success probability ({success_prob:.1%})")
            else:
                reasoning_parts.append(f"Low success probability ({success_prob:.1%})")

            # Risk assessment
            if risk_score < 0.3:
                reasoning_parts.append("low risk")
            elif risk_score < 0.6:
                reasoning_parts.append("moderate risk")
            else:
                reasoning_parts.append("high risk")

            # Option-specific reasoning
            if option_type == 'exploitation':
                reasoning_parts.append("targets known vulnerabilities")
            elif option_type == 'reconnaissance':
                reasoning_parts.append("gathers intelligence safely")
            elif option_type == 'post_exploitation':
                reasoning_parts.append("extends access and persistence")

            return f"Selected {option_type} because of {' and '.join(reasoning_parts)}."

        except Exception as e:
            log.error(f"Failed to generate reasoning: {e}")
            return f"Selected option with {success_prob:.1%} success probability and {risk_score:.1%} risk."

    def _extract_features(self, situation: Dict[str, Any], context: Dict[str, Any]) -> np.ndarray:
        """Extract features from situation and context"""
        try:
            # Mock feature extraction
            # In real implementation, this would use embeddings or feature vectors

            features = []

            # Situation features
            situation_type = situation.get('type', 'unknown')
            situation_complexity = situation.get('complexity', 'medium')

            # Context features
            target_type = context.get('target_type', 'web')
            security_level = context.get('security_level', 'medium')

            # Convert to numerical features
            feature_mapping = {
                'type': {'web': 0.1, 'network': 0.2, 'mobile': 0.3, 'iot': 0.4},
                'complexity': {'low': 0.1, 'medium': 0.5, 'high': 0.9},
                'target_type': {'web': 0.1, 'network': 0.2, 'mobile': 0.3, 'iot': 0.4, 'cloud': 0.5},
                'security_level': {'low': 0.1, 'medium': 0.3, 'high': 0.6, 'very_high': 0.9},
            }

            features.append(feature_mapping['type'].get(situation_type, 0.5))
            features.append(feature_mapping['complexity'].get(situation_complexity, 0.5))
            features.append(feature_mapping['target_type'].get(target_type, 0.5))
            features.append(feature_mapping['security_level'].get(security_level, 0.5))

            return np.array(features)

        except Exception as e:
            log.error(f"Failed to extract features: {e}")
            return np.array([0.5, 0.5, 0.5, 0.5])

    async def _generate_alternatives(
        self,
        situation: Dict[str, Any],
        failed_option: Dict[str, Any],
        context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate alternative options when confidence is low"""
        alternatives = []

        # Mock alternative generation
        # In real implementation, this would use AI to suggest alternatives

        base_option = failed_option['option']
        option_type = base_option.get('type', 'unknown')

        # Generate alternatives based on option type
        if option_type == 'exploitation':
            alternatives = [
                {'type': 'exploitation', 'method': 'sql_injection', 'complexity': 'medium'},
                {'type': 'exploitation', 'method': 'xss', 'complexity': 'low'},
                {'type': 'exploitation', 'method': 'command_injection', 'complexity': 'medium'},
            ]
        elif option_type == 'reconnaissance':
            alternatives = [
                {'type': 'reconnaissance', 'method': 'port_scan', 'complexity': 'low'},
                {'type': 'reconnaissance', 'method': 'subdomain_enum', 'complexity': 'medium'},
                {'type': 'reconnaissance', 'method': 'technology_detection', 'complexity': 'low'},
            ]

        # Score alternatives
        scored_alternatives = []
        features = self._extract_features(situation, context)

        for alt_option in alternatives:
            score = await self._score_option(
                option=alt_option,
                features=features,
                situation=situation,
                context=context
            )
            scored_alternatives.append(score)

        # Return top 2 alternatives
        scored_alternatives.sort(key=lambda x: x['confidence'], reverse=True)
        return [alt['option'] for alt in scored_alternatives[:2]]

    async def _store_decision(
        self,
        situation: Dict[str, Any],
        decision: DecisionResult,
        context: Dict[str, Any]
    ):
        """Store decision for future learning"""
        try:
            # Store the decision context
            decision_record = {
                'timestamp': datetime.now().isoformat(),
                'situation': situation,
                'decision': decision.decision,
                'confidence': decision.confidence,
                'success_probability': decision.success_probability,
                'risk_score': decision.risk_score,
                'context': context
            }

            # This would normally be stored in a database
            log.debug(f"Decision stored for future learning")

        except Exception as e:
            log.error(f"Failed to store decision: {e}")

    async def get_decision_metrics(self) -> Dict[str, Any]:
        """Get metrics about decision making performance"""
        return {
            'confidence_threshold': self.confidence_threshold,
            'risk_threshold': self.risk_threshold,
            'total_decisions': len(self.history_db.history),
            'average_confidence': self._calculate_average_confidence(),
            'average_success_probability': self._calculate_average_success_probability(),
            'average_risk_score': self._calculate_average_risk_score()
        }

    def _calculate_average_confidence(self) -> float:
        """Calculate average confidence across decisions"""
        # Mock implementation
        return 0.75

    def _calculate_average_success_probability(self) -> float:
        """Calculate average success probability"""
        # Mock implementation
        return 0.65

    def _calculate_average_risk_score(self) -> float:
        """Calculate average risk score"""
        # Mock implementation
        return 0.35

    async def learn_from_outcome(
        self,
        decision_id: str,
        actual_outcome: str,
        additional_context: Dict[str, Any]
    ):
        """Learn from actual decision outcome"""
        try:
            # This would update the decision model based on actual outcomes
            # Mock implementation
            log.info(f"Learning from outcome: {actual_outcome}")
            # Would normally update ML model and historical database

        except Exception as e:
            log.error(f"Failed to learn from outcome: {e}")