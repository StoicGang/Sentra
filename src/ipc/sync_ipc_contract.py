"""
Sentra Sync IPC Contract
Defines hardened communication between CLI/UI and Backend.
Strictly forbids passing plaintext secrets or raw crypto state.
"""
from enum import Enum
from typing import Dict, Any, TypedDict, List

class IPCMessageType(Enum):
    SYNC_STATUS = "SYNC_STATUS"
    SYNC_ERROR = "SYNC_ERROR"
    PEER_CONNECTED = "PEER_CONNECTED"
    REVOKE_REQUEST = "REVOKE_REQUEST"

class SyncIPCMessage(TypedDict):
    type: str
    request_id: str
    payload: Dict[str, Any]

class IPCContract:
    """
    Validates all IPC messages.
    Ensures that forbidden fields are never included.
    """
    FORBIDDEN_FIELDS = {"vault_key", "session_key", "plaintext_password", "raw_payload"}

    @classmethod
    def validate(cls, message: SyncIPCMessage):
        # 1. Basic Structure
        if "type" not in message or "request_id" not in message:
            raise ValueError("Invalid IPC envelope")
            
        # 2. Plaintext Leakage Check
        if any(field in message.get("payload", {}) for field in cls.FORBIDDEN_FIELDS):
            raise ValueError("IPC payload contains forbidden plaintext field")

    @classmethod
    def create(cls, msg_type: IPCMessageType, request_id: str, payload: Dict[str, Any]) -> SyncIPCMessage:
        message = {"type": msg_type.value, "request_id": request_id, "payload": payload}
        cls.validate(message)
        return message
