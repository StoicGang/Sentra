"""
Sentra Secure Channel
Handles authenticated encryption envelopes for P2P messages.
Integrates Noise sessions with the protocol codec.
"""
import struct
from typing import Dict, Any, Optional

from src.protocol.codec import encode_message, decode_message, frame_packet, CodecError
from src.transport.noise_session import NoiseSessionManager, SessionState

class SecureChannelError(Exception):
    """Base exception for secure channel errors."""
    pass

class SecureChannel:
    """
    High-level encrypted channel for P2P communication.
    
    Responsibilities:
    - Encapsulates Noise session encryption/decryption.
    - Enforces monotonic packet sequencing via Noise session state.
    - Handles message serialization and framing.
    """

    def __init__(self, session: NoiseSessionManager):
        self.session = session
        self._sent_count = 0
        self._recv_count = 0

    def send_message(self, msg_dict: Dict[str, Any]) -> bytes:
        """
        Serialize, encrypt, and frame a message for transmission.
        """
        if not self.session.is_established:
            raise SecureChannelError("Channel not established: session must be in ESTABLISHED state")

        try:
            # 1. Serialize
            plaintext = encode_message(msg_dict)
            
            # 2. Encrypt (Noise handles internal nonce)
            ciphertext = self.session.encrypt(plaintext)
            
            # 3. Frame
            packet = frame_packet(ciphertext)
            
            self._sent_count += 1
            return packet

        except (CodecError, Exception) as e:
            self.session.abort(f"Send failed: {e}")
            raise SecureChannelError(f"Failed to send message: {e}")

    def receive_message(self, encrypted_payload: bytes) -> Dict[str, Any]:
        """
        Decrypt and deserialize a received message payload.
        Expects the raw payload (unframed).
        """
        if not self.session.is_established:
            raise SecureChannelError("Channel not established: session must be in ESTABLISHED state")

        try:
            # 1. Decrypt (Noise handles internal nonce and authentication)
            plaintext = self.session.decrypt(encrypted_payload)
            
            # 2. Deserialize
            msg_dict = decode_message(plaintext)
            
            self._recv_count += 1
            return msg_dict

        except (CodecError, Exception) as e:
            self.session.abort(f"Receive failed: {e}")
            raise SecureChannelError(f"Failed to receive message: {e}")

    @property
    def stats(self) -> Dict[str, int]:
        return {
            "sent_packets": self._sent_count,
            "received_packets": self._recv_count
        }

    def close(self):
        """Close the underlying session."""
        self.session.close()
