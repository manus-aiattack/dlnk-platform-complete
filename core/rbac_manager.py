from core.logger import log
from typing import List, Dict


class RBACManager:
    def __init__(self):
        # In a real system, roles and permissions would be loaded from a database.
        self.roles: Dict[str, List[str]] = {
            "admin": ["run_any_agent", "manage_users", "view_all_reports"],
            "pentester": ["run_any_agent", "view_all_reports"],
            "auditor": ["view_all_reports"],
            "guest": []
        }
        log.info("RBACManager initialized. (Note: Roles are currently hardcoded)")

    def has_permission(self, user_role: str, required_permission: str) -> bool:
        """Checks if a user with a given role has the required permission."""
        if user_role not in self.roles:
            log.warning(
                f"Attempted to check permission for an unknown role: '{user_role}'")
            return False

        user_permissions = self.roles[user_role]

        if required_permission in user_permissions:
            log.info(
                f"Permission '{required_permission}' GRANTED for role '{user_role}'.")
            return True
        else:
            log.warning(
                f"Permission '{required_permission}' DENIED for role '{user_role}'.")
            return False

    def get_user_role(self, user_id: str) -> str:
        """Retrieves the role for a given user ID."""
        # This is a placeholder. In a real system, you would look this up in a user database.
        log.info(
            f"Retrieving role for user '{user_id}'. (Defaulting to 'pentester')")
        return "pentester"
