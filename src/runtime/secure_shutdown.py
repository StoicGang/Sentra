"""
Sentra Secure Shutdown Handler
Coordinates safe termination, resource cleanup, and memory zeroization.
"""
import logging
from typing import List
from src.app.sync_orchestrator import SyncOrchestrator
from src.security.replay_cache import ReplayCache

class SecureShutdownHandler:
    def __init__(self, orchestrator: SyncOrchestrator, replay_cache: ReplayCache):
        self.orchestrator = orchestrator
        self.replay_cache = replay_cache
        self.logger = logging.getLogger(__name__)

    def shutdown(self, force: bool = False):
        """
        Graceful or forced shutdown.
        Order:
        1. Stop all sync activities (aborting sessions)
        2. Flush/Teardown transport
        3. Persist sync checkpoints
        4. Wipe memory (keys/cache)
        """
        self.logger.info(f"Initiating {'forced' if force else 'graceful'} shutdown.")
        
        try:
            # 1. Orchestrator shutdown aborts active sync sessions
            self.orchestrator.shutdown()
            
            # 2. Replay cache zeroization/flush
            self.replay_cache.clear()
            
            # 3. Final cleanup (keys in memory are zeroed by VaultController on exit)
            self.logger.info("Shutdown sequence complete.")
            
        except Exception as e:
            self.logger.error(f"Error during shutdown: {e}")
            if force:
                raise
