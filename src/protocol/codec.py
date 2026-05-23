"""
Sentra Protocol Codec
Handles binary framing, canonical serialization, and incremental stream parsing.
OWASP A03: Enforces bounded parsing and strict validation of all network-received data.
"""
import json
import struct
from typing import Dict, Any, Generator, Optional, List

# --- Constants from Specification ---
PROTOCOL_VERSION = "1.0"
MAX_PACKET_SIZE = 1024 * 1024 * 5  # 5MB Hard Cap
LENGTH_PREFIX_SIZE = 4            # 4-byte Big Endian length


class CodecError(Exception):
    """Base exception for protocol codec errors."""
    pass


class MalformedPacketError(CodecError):
    """Raised when a packet structure is invalid."""
    pass


class ProtocolVersionError(CodecError):
    """Raised when the protocol version is unsupported."""
    pass


class PacketTooLargeError(CodecError):
    """Raised when a packet exceeds MAX_PACKET_SIZE."""
    pass


def frame_packet(payload: bytes) -> bytes:
    """
    Apply binary framing: [Length (4B)] [Payload].
    """
    length = len(payload)
    if length > MAX_PACKET_SIZE:
        raise PacketTooLargeError(f"Payload size {length} exceeds maximum {MAX_PACKET_SIZE}")
    
    return struct.pack(">I", length) + payload


def encode_message(msg_dict: Dict[str, Any]) -> bytes:
    """
    Canonical JSON serialization.
    Ensures deterministic field ordering for signature stability.
    """
    # Force protocol version if missing
    if "version" not in msg_dict:
        msg_dict["version"] = PROTOCOL_VERSION
        
    try:
        # separators=(',', ':') removes whitespace for minimal wire size
        serialized = json.dumps(
            msg_dict, 
            sort_keys=True, 
            separators=(',', ':'),
            ensure_ascii=False
        ).encode('utf-8')
        return serialized
    except (TypeError, ValueError) as e:
        raise MalformedPacketError(f"Failed to serialize message: {e}")


def decode_message(data: bytes) -> Dict[str, Any]:
    """
    Strict JSON decoding and validation.
    """
    try:
        msg = json.loads(data.decode('utf-8'))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise MalformedPacketError(f"Failed to decode JSON payload: {e}")

    if not isinstance(msg, dict):
        raise MalformedPacketError("Message payload must be a JSON object")

    # Version Validation
    version = msg.get("version")
    if version != PROTOCOL_VERSION:
        raise ProtocolVersionError(f"Unsupported protocol version: {version}")

    return msg


class SentraCodec:
    """
    Stateful codec for incremental stream parsing.
    Handles fragmentation and prevents unbounded buffering.
    """
    def __init__(self):
        self._buffer = bytearray()

    def parse_stream(self, chunk: bytes) -> Generator[bytes, None, None]:
        """
        Consume a chunk of bytes and yield complete payloads.
        """
        self._buffer.extend(chunk)

        while len(self._buffer) >= LENGTH_PREFIX_SIZE:
            # Peek at length prefix
            length_bytes = self._buffer[:LENGTH_PREFIX_SIZE]
            payload_length = struct.unpack(">I", length_bytes)[0]

            if payload_length > MAX_PACKET_SIZE:
                # Immediate termination on oversized packet to prevent DoS
                self._buffer.clear()
                raise PacketTooLargeError(f"Oversized packet: {payload_length} bytes")

            if payload_length == 0:
                # Discard zero-length framing to prevent infinite loops
                self._buffer = self._buffer[LENGTH_PREFIX_SIZE:]
                continue

            # Do we have the full payload?
            total_expected = LENGTH_PREFIX_SIZE + payload_length
            if len(self._buffer) >= total_expected:
                payload = self._buffer[LENGTH_PREFIX_SIZE:total_expected]
                # Slice buffer for next packet
                self._buffer = self._buffer[total_expected:]
                yield payload
            else:
                # Wait for more data
                break

    def clear(self):
        """Reset internal buffer."""
        self._buffer.clear()
