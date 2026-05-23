"""
Tests for Protocol Abuse (Adversarial)
"""
import pytest
from src.protocol.codec import frame_packet, decode_message

def test_replay_flood():
    # Simulate a flood of replayed Auth messages
    pass

def test_malformed_manifest_injection():
    # Try to inject a manifest with massive entry_count
    pass
