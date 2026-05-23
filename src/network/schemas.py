"""
Sentra P2P Protocol Schemas
Strongly typed, implementation-ready definitions for sync messages.
Uses standard Python dataclasses for deterministic serialization.
"""
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any
import json
import uuid

# --- Protocol Metadata ---
PROTOCOL_VERSION = "1.0"
MAX_PAYLOAD_SIZE = 1024 * 1024 * 5  # 5MB Hard Cap
MAX_ENTRY_COUNT = 1000             # Max entries per SYNC_DELTA

@dataclass(frozen=True)
class SentraMessage:
    """Base envelope for all Noise-encrypted messages."""
    version: str = PROTOCOL_VERSION
    msg_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: int = 0  # Unix epoch
    
    def serialize(self) -> bytes:
        return json.dumps(asdict(self), separators=(',', ':')).encode('utf-8')

# --- 1. Pairing Flow ---

@dataclass(frozen=True)
class PairingRequest(SentraMessage):
    """Initial pairing request sent by the Scanning device."""
    device_id: str = ""        # Ed25519 PK Hash
    public_key: str = ""       # Hex Ed25519 PK
    nickname: str = ""         # User-friendly name
    oob_secret_hash: str = ""  # SHA256 of QR secret

@dataclass(frozen=True)
class PairingConfirm(SentraMessage):
    """Confirmation from the Generating device."""
    accepted: bool = False
    device_id: str = ""
    public_key: str = ""

# --- 2. Session Flow ---

@dataclass(frozen=True)
class SessionInit(SentraMessage):
    """Handshake completion and HLC exchange."""
    current_hlc: str = ""      # Format: timestamp:counter:node_id
    last_synced_hlc: str = ""  # Known HLC of the peer

# --- 3. Sync Flow ---

@dataclass(frozen=True)
class EncryptedEntryBlob:
    """Standard container for an encrypted vault entry."""
    id: str
    hlc: str
    data_cipher: str           # Base64 ChaCha20-Poly1305
    nonce: str                 # Base64
    tag: str                   # Base64
    origin_device_id: str

@dataclass(frozen=True)
class DeltaRequest(SentraMessage):
    """Request for changes since last_hlc."""
    since_hlc: str = ""
    limit: int = 100

@dataclass(frozen=True)
class DeltaResponse(SentraMessage):
    """Payload of changed entries."""
    entries: List[EncryptedEntryBlob] = field(default_factory=list)
    has_more: bool = False

# --- 4. Revocation ---

@dataclass(frozen=True)
class DeviceRevoke(SentraMessage):
    """Broadcast to untrust a device."""
    target_device_id: str = ""
    signature: str = ""        # Signed by Identity Key
