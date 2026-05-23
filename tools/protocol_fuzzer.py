"""
Sentra Protocol Fuzzer
Generates malformed, truncated, and mutated packets to test transport layer robustness.
"""
import random
import struct
from src.protocol.codec import frame_packet, MAX_PACKET_SIZE

class ProtocolFuzzer:
    def __init__(self, seed: int = 42):
        self.rng = random.Random(seed)

    def generate_malformed_packet(self) -> bytes:
        """Generates a packet that is syntactically invalid."""
        case = self.rng.choice(['truncated', 'oversized', 'corrupt_header', 'junk'])
        
        if case == 'truncated':
            return b'\x00\x00\x00\x05' + b'small'
        elif case == 'oversized':
            return frame_packet(b'x' * (MAX_PACKET_SIZE + 100))
        elif case == 'corrupt_header':
            return b'\xff\xff\xff\xff' + b'data'
        else:
            return self.rng.randbytes(64)

    def mutate_packet(self, valid_packet: bytes) -> bytes:
        """Mutates a valid packet to create a malformed variant."""
        data = bytearray(valid_packet)
        # Flip a few bits
        for _ in range(3):
            idx = self.rng.randint(0, len(data) - 1)
            data[idx] ^= 0xFF
        return bytes(data)
