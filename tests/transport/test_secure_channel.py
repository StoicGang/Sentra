"""
Tests for Sentra Secure Channel
Verifies authenticated encryption and protocol integration.
"""
import pytest
from src.transport.noise_session import NoiseSessionManager
from src.transport.secure_channel import SecureChannel, SecureChannelError

from cryptography.hazmat.primitives.asymmetric import x25519

# Derive actual public keys
def derive_pub(priv_bytes):
    priv = x25519.X25519PrivateKey.from_private_bytes(priv_bytes)
    return priv.public_key().public_bytes_raw()

# Test keys
INIT_PRIV = b'\x01' * 32
RESP_PRIV = b'\x02' * 32
RESP_PUB = derive_pub(RESP_PRIV)

@pytest.fixture
def established_channels():
    """Returns a pair of established secure channels (initiator, responder)."""
    initiator_session = NoiseSessionManager(INIT_PRIV, peer_static_pub=RESP_PUB, is_initiator=True)
    responder_session = NoiseSessionManager(RESP_PRIV, is_initiator=False)
    
    # Handshake
    msg1 = initiator_session.start_handshake()
    msg2 = responder_session.receive_handshake(msg1)
    initiator_session.receive_handshake(msg2)
    
    return SecureChannel(initiator_session), SecureChannel(responder_session)

def test_secure_channel_send_receive(established_channels):
    chan_i, chan_r = established_channels
    msg = {"type": "SYNC_PING", "data": "hello", "version": "1.0"}
    
    packet = chan_i.send_message(msg)
    
    # Packet has framing [4B Length] [Payload]
    # chan_r.receive_message expects only the payload
    received_msg = chan_r.receive_message(packet[4:])
    
    assert received_msg["type"] == "SYNC_PING"
    assert received_msg["data"] == "hello"

def test_tampered_ciphertext_rejection(established_channels):
    chan_i, chan_r = established_channels
    msg = {"type": "SECRET", "version": "1.0"}
    packet = chan_i.send_message(msg)
    
    # Tamper with the ciphertext (payload)
    tampered_payload = bytearray(packet[4:])
    tampered_payload[0] ^= 0xFF # Flip a bit
    
    with pytest.raises(SecureChannelError, match="decryption failed"):
        chan_r.receive_message(bytes(tampered_payload))

def test_out_of_order_packet_rejection(established_channels):
    chan_i, chan_r = established_channels
    
    p1 = chan_i.send_message({"msg": 1, "version": "1.0"})
    p2 = chan_i.send_message({"msg": 2, "version": "1.0"})
    
    # Deliver p2 before p1
    with pytest.raises(SecureChannelError):
        chan_r.receive_message(p2[4:])
    
    # Channel should be failed/closed now due to nonce mismatch
    assert chan_r.session.state == chan_r.session.state.FAILED

def test_duplicate_nonce_rejection(established_channels):
    chan_i, chan_r = established_channels
    p1 = chan_i.send_message({"msg": "once", "version": "1.0"})
    
    chan_r.receive_message(p1[4:])
    
    # Deliver p1 again
    with pytest.raises(SecureChannelError):
        chan_r.receive_message(p1[4:])

def test_send_before_established():
    unest_session = NoiseSessionManager(INIT_PRIV, peer_static_pub=RESP_PUB, is_initiator=True)
    chan = SecureChannel(unest_session)
    
    with pytest.raises(SecureChannelError, match="Channel not established"):
        chan.send_message({"any": "thing"})

def test_stats_tracking(established_channels):
    chan_i, chan_r = established_channels
    chan_i.send_message({"a": 1, "version": "1.0"})
    chan_i.send_message({"b": 2, "version": "1.0"})
    
    assert chan_i.stats["sent_packets"] == 2
