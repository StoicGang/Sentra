"""
Tests for Sentra Suspend/Resume
"""
import pytest
from unittest.mock import MagicMock
from src.runtime.suspend_resume_guard import SuspendResumeGuard

def test_suspend_resume_lifecycle():
    orchestrator = MagicMock()
    replay_cache = MagicMock()
    guard = SuspendResumeGuard(orchestrator, replay_cache)
    
    # Suspend
    guard.handle_suspend()
    orchestrator.shutdown.assert_called_once()
    replay_cache.clear.assert_called_once()
    
    # Resume
    guard.handle_resume()
    # verify re-auth trigger (mock would confirm this)
