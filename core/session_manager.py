import asyncio
import json
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
from core.logger import log
import os
import pickle


class SessionStatus(Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class SessionData:
    session_id: str
    target_url: str
    target_host: str
    objective: str
    status: SessionStatus
    created_at: datetime
    updated_at: datetime
    current_phase: str
    progress: float
    results: Dict[str, Any]
    errors: List[str]
    agents_used: List[str]
    strategies_executed: List[str]
    vulnerabilities_found: List[Dict[str, Any]]
    exploits_generated: List[Dict[str, Any]]
    risk_score: float
    notes: List[str]


class SessionManager:
    def __init__(self, data_dir: str = "data/sessions"):
        self.data_dir = data_dir
        self.active_sessions: Dict[str, SessionData] = {}
        self.session_history: List[SessionData] = []
        self._ensure_data_dir()
        self._load_session_history()

    def _ensure_data_dir(self):
        """Ensure data directory exists"""
        try:
            os.makedirs(self.data_dir, exist_ok=True)
        except Exception as e:
            log.error(f"Failed to create data directory: {e}")

    def _load_session_history(self):
        """Load session history from disk"""
        try:
            history_file = os.path.join(self.data_dir, "session_history.json")
            if os.path.exists(history_file):
                with open(history_file, 'r') as f:
                    data = json.load(f)
                    for session_data in data:
                        session = SessionData(
                            session_id=session_data["session_id"],
                            target_url=session_data["target_url"],
                            target_host=session_data["target_host"],
                            objective=session_data["objective"],
                            status=SessionStatus(session_data["status"]),
                            created_at=datetime.fromisoformat(
                                session_data["created_at"]),
                            updated_at=datetime.fromisoformat(
                                session_data["updated_at"]),
                            current_phase=session_data["current_phase"],
                            progress=session_data["progress"],
                            results=session_data["results"],
                            errors=session_data["errors"],
                            agents_used=session_data["agents_used"],
                            strategies_executed=session_data["strategies_executed"],
                            vulnerabilities_found=session_data["vulnerabilities_found"],
                            exploits_generated=session_data["exploits_generated"],
                            risk_score=session_data["risk_score"],
                            notes=session_data["notes"]
                        )
                        self.session_history.append(session)

            log.info(
                f"Loaded {len(self.session_history)} sessions from history")

        except Exception as e:
            log.error(f"Failed to load session history: {e}")

    def _save_session_history(self):
        """Save session history to disk"""
        try:
            history_file = os.path.join(self.data_dir, "session_history.json")
            data = []
            for session in self.session_history:
                session_dict = asdict(session)
                session_dict["created_at"] = session.created_at.isoformat()
                session_dict["updated_at"] = session.updated_at.isoformat()
                session_dict["status"] = session.status.value
                data.append(session_dict)

            with open(history_file, 'w') as f:
                json.dump(data, f, indent=2)

        except Exception as e:
            log.error(f"Failed to save session history: {e}")

    def create_session(self, target_url: str, target_host: str, objective: str) -> str:
        """Create a new session"""
        try:
            session_id = str(uuid.uuid4())
            now = datetime.now()

            session = SessionData(
                session_id=session_id,
                target_url=target_url,
                target_host=target_host,
                objective=objective,
                status=SessionStatus.ACTIVE,
                created_at=now,
                updated_at=now,
                current_phase="initialization",
                progress=0.0,
                results={},
                errors=[],
                agents_used=[],
                strategies_executed=[],
                vulnerabilities_found=[],
                exploits_generated=[],
                risk_score=0.0,
                notes=[]
            )

            self.active_sessions[session_id] = session
            self.session_history.append(session)

            log.info(f"Created new session: {session_id}")
            return session_id

        except Exception as e:
            log.error(f"Failed to create session: {e}")
            return None

    def get_session(self, session_id: str) -> Optional[SessionData]:
        """Get session by ID"""
        return self.active_sessions.get(session_id)

    def update_session(self, session_id: str, updates: Dict[str, Any]) -> bool:
        """Update session data"""
        try:
            if session_id not in self.active_sessions:
                log.error(f"Session {session_id} not found")
                return False

            session = self.active_sessions[session_id]
            session.updated_at = datetime.now()

            # Update fields
            for key, value in updates.items():
                if hasattr(session, key):
                    setattr(session, key, value)

            # Save to disk
            self._save_session_to_disk(session)

            log.debug(f"Updated session {session_id}")
            return True

        except Exception as e:
            log.error(f"Failed to update session {session_id}: {e}")
            return False

    def _save_session_to_disk(self, session: SessionData):
        """Save individual session to disk"""
        try:
            session_file = os.path.join(
                self.data_dir, f"session_{session.session_id}.json")
            session_dict = asdict(session)
            session_dict["created_at"] = session.created_at.isoformat()
            session_dict["updated_at"] = session.updated_at.isoformat()
            session_dict["status"] = session.status.value

            with open(session_file, 'w') as f:
                json.dump(session_dict, f, indent=2)

        except Exception as e:
            log.error(f"Failed to save session to disk: {e}")

    def add_agent_result(self, session_id: str, agent_name: str, result: Dict[str, Any]) -> bool:
        """Add agent execution result to session"""
        try:
            if session_id not in self.active_sessions:
                return False

            session = self.active_sessions[session_id]

            # Add agent to used agents if not already present
            if agent_name not in session.agents_used:
                session.agents_used.append(agent_name)

            # Add result to session results
            if "agent_results" not in session.results:
                session.results["agent_results"] = {}

            session.results["agent_results"][agent_name] = result

            # Update progress
            session.progress = min(100.0, session.progress + 10.0)

            # Update session
            self.update_session(session_id, {"progress": session.progress})

            log.info(
                f"Added agent result for {agent_name} to session {session_id}")
            return True

        except Exception as e:
            log.error(f"Failed to add agent result: {e}")
            return False

    def add_vulnerability(self, session_id: str, vulnerability: Dict[str, Any]) -> bool:
        """Add vulnerability to session"""
        try:
            if session_id not in self.active_sessions:
                return False

            session = self.active_sessions[session_id]
            session.vulnerabilities_found.append(vulnerability)

            # Update risk score
            session.risk_score = min(
                10.0, session.risk_score + vulnerability.get("severity_score", 1.0))

            self.update_session(session_id, {"risk_score": session.risk_score})

            log.info(f"Added vulnerability to session {session_id}")
            return True

        except Exception as e:
            log.error(f"Failed to add vulnerability: {e}")
            return False

    def add_exploit(self, session_id: str, exploit: Dict[str, Any]) -> bool:
        """Add exploit to session"""
        try:
            if session_id not in self.active_sessions:
                return False

            session = self.active_sessions[session_id]
            session.exploits_generated.append(exploit)

            self.update_session(session_id, {})

            log.info(f"Added exploit to session {session_id}")
            return True

        except Exception as e:
            log.error(f"Failed to add exploit: {e}")
            return False

    def add_note(self, session_id: str, note: str) -> bool:
        """Add note to session"""
        try:
            if session_id not in self.active_sessions:
                return False

            session = self.active_sessions[session_id]
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            session.notes.append(f"[{timestamp}] {note}")

            self.update_session(session_id, {})

            log.info(f"Added note to session {session_id}")
            return True

        except Exception as e:
            log.error(f"Failed to add note: {e}")
            return False

    def update_phase(self, session_id: str, phase: str) -> bool:
        """Update current phase"""
        try:
            if session_id not in self.active_sessions:
                return False

            session = self.active_sessions[session_id]
            session.current_phase = phase

            self.update_session(session_id, {"current_phase": phase})

            log.info(f"Updated phase to {phase} for session {session_id}")
            return True

        except Exception as e:
            log.error(f"Failed to update phase: {e}")
            return False

    def complete_session(self, session_id: str, final_results: Dict[str, Any] = None) -> bool:
        """Mark session as completed"""
        try:
            if session_id not in self.active_sessions:
                return False

            session = self.active_sessions[session_id]
            session.status = SessionStatus.COMPLETED
            session.progress = 100.0
            session.updated_at = datetime.now()

            if final_results:
                session.results.update(final_results)

            # Move to history
            self.session_history.append(session)
            del self.active_sessions[session_id]

            # Save history
            self._save_session_history()

            log.info(f"Completed session {session_id}")
            return True

        except Exception as e:
            log.error(f"Failed to complete session: {e}")
            return False

    def pause_session(self, session_id: str) -> bool:
        """Pause session"""
        try:
            if session_id not in self.active_sessions:
                return False

            session = self.active_sessions[session_id]
            session.status = SessionStatus.PAUSED
            session.updated_at = datetime.now()

            self.update_session(session_id, {"status": SessionStatus.PAUSED})

            log.info(f"Paused session {session_id}")
            return True

        except Exception as e:
            log.error(f"Failed to pause session: {e}")
            return False

    def resume_session(self, session_id: str) -> bool:
        """Resume session"""
        try:
            if session_id not in self.active_sessions:
                return False

            session = self.active_sessions[session_id]
            session.status = SessionStatus.ACTIVE
            session.updated_at = datetime.now()

            self.update_session(session_id, {"status": SessionStatus.ACTIVE})

            log.info(f"Resumed session {session_id}")
            return True

        except Exception as e:
            log.error(f"Failed to resume session: {e}")
            return False

    def cancel_session(self, session_id: str) -> bool:
        """Cancel session"""
        try:
            if session_id not in self.active_sessions:
                return False

            session = self.active_sessions[session_id]
            session.status = SessionStatus.CANCELLED
            session.updated_at = datetime.now()

            # Move to history
            self.session_history.append(session)
            del self.active_sessions[session_id]

            # Save history
            self._save_session_history()

            log.info(f"Cancelled session {session_id}")
            return True

        except Exception as e:
            log.error(f"Failed to cancel session: {e}")
            return False

    def get_active_sessions(self) -> List[SessionData]:
        """Get all active sessions"""
        return list(self.active_sessions.values())

    def get_session_history(self, limit: int = 10) -> List[SessionData]:
        """Get session history"""
        return self.session_history[-limit:]

    def get_session_summary(self, session_id: str) -> Dict[str, Any]:
        """Get session summary"""
        try:
            session = self.get_session(session_id)
            if not session:
                return {"error": "Session not found"}

            return {
                "session_id": session.session_id,
                "target_url": session.target_url,
                "target_host": session.target_host,
                "objective": session.objective,
                "status": session.status.value,
                "current_phase": session.current_phase,
                "progress": session.progress,
                "risk_score": session.risk_score,
                "agents_used": len(session.agents_used),
                "vulnerabilities_found": len(session.vulnerabilities_found),
                "exploits_generated": len(session.exploits_generated),
                "created_at": session.created_at.isoformat(),
                "updated_at": session.updated_at.isoformat()
            }

        except Exception as e:
            log.error(f"Failed to get session summary: {e}")
            return {"error": str(e)}

    def cleanup_old_sessions(self, days: int = 30):
        """Clean up old sessions"""
        try:
            cutoff_date = datetime.now() - timedelta(days=days)
            old_sessions = [
                s for s in self.session_history if s.updated_at < cutoff_date]

            for session in old_sessions:
                self.session_history.remove(session)
                # Delete session file
                session_file = os.path.join(
                    self.data_dir, f"session_{session.session_id}.json")
                if os.path.exists(session_file):
                    os.remove(session_file)

            self._save_session_history()
            log.info(f"Cleaned up {len(old_sessions)} old sessions")

        except Exception as e:
            log.error(f"Failed to cleanup old sessions: {e}")

    def get_statistics(self) -> Dict[str, Any]:
        """Get session statistics"""
        try:
            total_sessions = len(self.session_history)
            active_sessions = len(self.active_sessions)
            completed_sessions = len(
                [s for s in self.session_history if s.status == SessionStatus.COMPLETED])
            failed_sessions = len(
                [s for s in self.session_history if s.status == SessionStatus.FAILED])

            total_vulnerabilities = sum(
                len(s.vulnerabilities_found) for s in self.session_history)
            total_exploits = sum(len(s.exploits_generated)
                                 for s in self.session_history)

            return {
                "total_sessions": total_sessions,
                "active_sessions": active_sessions,
                "completed_sessions": completed_sessions,
                "failed_sessions": failed_sessions,
                "total_vulnerabilities": total_vulnerabilities,
                "total_exploits": total_exploits,
                "success_rate": (completed_sessions / total_sessions * 100) if total_sessions > 0 else 0
            }

        except Exception as e:
            log.error(f"Failed to get statistics: {e}")
            return {}
