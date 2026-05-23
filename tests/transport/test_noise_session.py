"""
Tests for Sentra Noise Session Manager
Verifies handshake states, identity pinning, and replay protection.
"""
import pytest
import time
from unittest.mock import MagicMock, patch
from src.transport.noise_session import (
    NoiseSessionManager, SessionState, IdentityMismatchError, 
    HandshakeTimeoutError, NoiseSessionError
)
from src.security.replay_cache import ReplayCache, ReplayError

from cryptography.hazmat.primitives.asymmetric import x25519

# Derive actual public keys
def derive_pub(priv_bytes):
    priv = x25519.X25519PrivateKey.from_private_bytes(priv_bytes)
    return priv.public_key().public_bytes_raw()

INIT_PRIV = b'\x01' * 32
INIT_PUB = derive_pub(INIT_PRIV)

RESP_PRIV = b'\x02' * 32
RESP_PUB = derive_pub(RESP_PRIV)

def test_successful_handshake():
    # Setup
    initiator = NoiseSessionManager(INIT_PRIV, peer_static_pub=RESP_PUB, is_initiator=True)
    responder = NoiseSessionManager(RESP_PRIV, is_initiator=False)
    
    # Msg 1: I -> R
    msg1 = initiator.start_handshake()
    assert initiator.state == SessionState.HANDSHAKING
    
    msg2 = responder.receive_handshake(msg1)
    assert responder.state == SessionState.ESTABLISHED # Responder finishes on Msg 1 in IK? 
    # Wait, Noise IK:
    # -> e, es, s, ss
    # <- e, ee, se
    # So Responder finishes after read Msg 1 and write Msg 2.
    assert msg2 is not None
    
    # Msg 2: R -> I
    initiator.receive_handshake(msg2)
    assert initiator.state == SessionState.ESTABLISHED
    assert initiator.is_established
    assert responder.is_established

def test_identity_mismatch_initiator():
    # Initiator thinks Responder is RESP_PUB, but Responder is actually using wrong_priv.
    # In Noise IK, Initiator encrypts parts of Msg 1 to Responder's Static Key.
    # Responder will fail to decrypt Msg 1.
    wrong_priv = b'\x03' * 32
    initiator = NoiseSessionManager(INIT_PRIV, peer_static_pub=RESP_PUB, is_initiator=True)
    responder = NoiseSessionManager(wrong_priv, is_initiator=False)
    
    msg1 = initiator.start_handshake()
    
    with pytest.raises(IdentityMismatchError):
        responder.receive_handshake(msg1)
    assert responder.state == SessionState.FAILED

def test_untrusted_identity_responder():
    # Responder has a DeviceRepository that doesn't trust the Initiator
    repo = MagicMock()
    repo.get_trusted_device.return_value = None # Untrusted
    
    initiator = NoiseSessionManager(INIT_PRIV, peer_static_pub=RESP_PUB, is_initiator=True)
    responder = NoiseSessionManager(RESP_PRIV, is_initiator=False, device_repo=repo)
    
    msg1 = initiator.start_handshake()
    
    with pytest.raises(IdentityMismatchError):
        responder.receive_handshake(msg1)
    assert responder.state == SessionState.FAILED

def test_revoked_identity_responder():
    repo = MagicMock()
    repo.get_trusted_device.return_value = {'trust_level': 0} # Revoked
    
    initiator = NoiseSessionManager(INIT_PRIV, peer_static_pub=RESP_PUB, is_initiator=True)
    responder = NoiseSessionManager(RESP_PRIV, is_initiator=False, device_repo=repo)
    
    msg1 = initiator.start_handshake()
    
    with pytest.raises(IdentityMismatchError):
        responder.receive_handshake(msg1)

def test_handshake_replay_protection():
    replay_cache = ReplayCache()
    initiator = NoiseSessionManager(INIT_PRIV, peer_static_pub=RESP_PUB, is_initiator=True)
    responder1 = NoiseSessionManager(RESP_PRIV, is_initiator=False, replay_cache=replay_cache)
    
    msg1 = initiator.start_handshake()
    
    # First time: OK
    responder1.receive_handshake(msg1)
    
    # Second time with a NEW responder (simulating a replayed initial packet to a new session)
    responder2 = NoiseSessionManager(RESP_PRIV, is_initiator=False, replay_cache=replay_cache)
    with pytest.raises(NoiseSessionError, match="Replay attempt detected"):
        responder2.receive_handshake(msg1)

def test_handshake_timeout():
    initiator = NoiseSessionManager(INIT_PRIV, peer_static_pub=RESP_PUB, is_initiator=True)
    initiator.start_handshake()
    
    # Mock time jump
    with patch('time.time', return_value=time.time() + 100):
        # State check happens before timeout check in current implementation?
        # Actually timeout check is in receive_handshake.
        with pytest.raises(HandshakeTimeoutError):
            initiator.receive_handshake(b'\x00'*64) # Dummy data

def test_invalid_state_transition():
    session = NoiseSessionManager(INIT_PRIV, peer_static_pub=RESP_PUB, is_initiator=True)
    # Cannot encrypt before establishment
    with pytest.raises(NoiseSessionError, match="Invalid state transition"):
        session.encrypt(b'secret')

def test_malformed_handshake_payload():
    responder = NoiseSessionManager(RESP_PRIV, is_initiator=False)
    # Noise IK first message must be at least 32 bytes (ephemeral key)
    with pytest.raises(NoiseSessionError):
        responder.receive_handshake(b'short')
