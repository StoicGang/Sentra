"""
Tests for Sentra Protocol Codec
Verifies framing, serialization, and adversarial robustness.
"""
import pytest
import struct
from src.protocol.codec import (
    frame_packet, encode_message, decode_message, SentraCodec,
    MalformedPacketError, ProtocolVersionError, PacketTooLargeError,
    MAX_PACKET_SIZE
)

def test_successful_roundtrip():
    msg = {"type": "TEST", "data": "hello"}
    encoded = encode_message(msg)
    # Canonical check: keys should be sorted
    assert encoded == b'{"data":"hello","type":"TEST","version":"1.0"}'
    
    decoded = decode_message(encoded)
    assert decoded["type"] == "TEST"
    assert decoded["version"] == "1.0"

def test_framing_logic():
    payload = b"testdata"
    packet = frame_packet(payload)
    assert len(packet) == 4 + 8
    assert packet[:4] == struct.pack(">I", 8)
    assert packet[4:] == payload

def test_oversized_packet_rejection():
    # Attempt to frame a packet larger than limit
    huge_data = b"x" * (MAX_PACKET_SIZE + 1)
    with pytest.raises(PacketTooLargeError):
        frame_packet(huge_data)

def test_protocol_version_mismatch():
    invalid_msg = b'{"type":"TEST","version":"99.0"}'
    with pytest.raises(ProtocolVersionError):
        decode_message(invalid_msg)

def test_malformed_json():
    with pytest.raises(MalformedPacketError):
        decode_message(b"{invalid_json}")

def test_non_dict_payload():
    with pytest.raises(MalformedPacketError):
        decode_message(b"[1, 2, 3]")

def test_incremental_parsing_basic():
    codec = SentraCodec()
    payload1 = b'{"msg":1,"version":"1.0"}'
    payload2 = b'{"msg":2,"version":"1.0"}'
    
    packet1 = frame_packet(payload1)
    packet2 = frame_packet(payload2)
    
    # Feed half of first packet
    gen = codec.parse_stream(packet1[:5])
    assert list(gen) == []
    
    # Feed rest of first packet and half of second
    gen = codec.parse_stream(packet1[5:] + packet2[:3])
    results = list(gen)
    assert len(results) == 1
    assert results[0] == payload1
    
    # Feed rest of second packet
    gen = codec.parse_stream(packet2[3:])
    results = list(gen)
    assert len(results) == 1
    assert results[0] == payload2

def test_stream_oversized_rejection():
    codec = SentraCodec()
    # Craft a header claiming 10MB
    bad_header = struct.pack(">I", 10 * 1024 * 1024)
    with pytest.raises(PacketTooLargeError):
        list(codec.parse_stream(bad_header))
    # Verify buffer was cleared
    assert len(codec._buffer) == 0

def test_stream_zero_length_packet():
    codec = SentraCodec()
    zero_header = struct.pack(">I", 0)
    payload = b'{"msg":1,"version":"1.0"}'
    packet = frame_packet(payload)
    
    # Feed zero header then valid packet
    results = list(codec.parse_stream(zero_header + packet))
    assert len(results) == 1
    assert results[0] == payload

def test_canonical_serialization_ordering():
    # Regardless of input order, output must be sorted
    msg1 = {"z": 1, "a": 2, "m": 3}
    msg2 = {"a": 2, "m": 3, "z": 1}
    assert encode_message(msg1) == encode_message(msg2)

def test_unbounded_payload_rejection():
    # Ensure decode_message handles reasonably large but valid sized blobs
    # (Checking if it crashes on empty/strange binary)
    with pytest.raises(MalformedPacketError):
        decode_message(b"\x00" * 100)
