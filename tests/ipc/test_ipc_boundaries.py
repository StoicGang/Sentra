"""
Tests for Sentra IPC Boundary Enforcement
"""
import pytest
from src.ipc.sync_ipc_contract import IPCContract

def test_ipc_payload_validation():
    # Valid
    msg = {"type": "SYNC_STATUS", "request_id": "1", "payload": {"foo": "bar"}}
    IPCContract.validate(msg)
    
    # Invalid (Forbidden field)
    msg_bad = {"type": "SYNC_STATUS", "request_id": "1", "payload": {"vault_key": "secret"}}
    with pytest.raises(ValueError, match="forbidden plaintext field"):
        IPCContract.validate(msg_bad)
    
    # Missing fields
    with pytest.raises(ValueError, match="Invalid IPC envelope"):
        IPCContract.validate({"type": "X"})
