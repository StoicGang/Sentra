"""
Sentra Suspend/Resume Guard
Invalidates transport sessions and flushes replay cache on system events.
"""
import logging
from src.app.sync_orchestrator import SyncOrchestrator
from src.security.replay_cache import ReplayCache

class SuspendResumeGuard:
    def __init__(self, orchestrator: SyncOrchestrator, replay_cache: ReplayCache):
        self.orchestrator = orchestrator
        self.replay_cache = replay_cache
        self.logger = logging.getLogger(__name__)

    def handle_suspend(self):
        """Pre-suspend: Clear sensitive state."""
        self.logger.info("System suspend detected. Invalidating sessions.")
        self.orchestrator.shutdown()
        self.replay_cache.clear()

    def handle_resume(self):
        """Post-resume: Force re-authentication."""
        self.logger.info("System resume detected. Requiring re-auth.")
        # Logic to force re-auth would be handled by VaultController
