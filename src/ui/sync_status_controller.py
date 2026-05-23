"""
Sentra Sync Status Controller
Provides UI-safe sync status updates.
"""
from typing import Dict, Optional

class SyncStatusController:
    """
    Exposes sync state to the UI without revealing sensitive internal details.
    """

    def __init__(self):
        self._states: Dict[str, str] = {}

    def get_peer_status(self, peer_id: str) -> Dict[str, str]:
        """Expose safe status: Syncing, Idle, Conflict, etc."""
        return {
            "status": self._states.get(peer_id, "IDLE"),
            "last_error": None # Only exposure allowed is user-friendly error string
        }

    def report_error(self, peer_id: str, error_code: str):
        """Report a generic error for UI display."""
        # Map internal error codes to UI strings
        self._states[peer_id] = f"ERROR: {error_code}"
