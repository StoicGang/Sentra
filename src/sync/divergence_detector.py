"""
Sentra Divergence Detector
Detects inconsistencies and non-monotonic history changes between peers.
"""
import hashlib
import json
from typing import Dict, Any, List, Optional

from src.database_manager import DatabaseManager
from src.sync.hlc import HybridLogicalClock
from src.sync.checkpoint_manager import CheckpointManager
from src.storage.device_repository import DeviceRepository

class DivergenceError(Exception):
    """Base exception for divergence detection errors."""
    pass

class DivergenceDetector:
    """
    Compares local and remote sync manifests to identify divergent histories.
    """

    def __init__(self, db_manager: DatabaseManager, checkpoint_manager: CheckpointManager, 
                 device_repo: DeviceRepository, hlc: HybridLogicalClock):
        self.db = db_manager
        self.checkpoint_manager = checkpoint_manager
        self.device_repo = device_repo
        self.hlc = hlc

    def compute_local_manifest(self, until_hlc: Optional[str] = None) -> Dict[str, Any]:
        """
        Computes a cryptographic manifest of local vault state up to a certain HLC.
        Manifest includes HLC boundaries, number of entries, and a hash of entry IDs.
        """
        conn = self.db.connect()
        query = "SELECT id, hlc FROM entries"
        params = []
        
        if until_hlc:
            query += " WHERE hlc <= ?"
            params.append(until_hlc)

        cursor = conn.execute(query + " ORDER BY hlc, id", tuple(params))
        
        entry_hashes = []
        max_hlc = ""
        entry_count = 0
        
        for row in cursor.fetchall():
            entry_hlc = row['hlc']
            entry_id = row['id']
            entry_hashes.append(hashlib.sha256(f"{entry_id}:{entry_hlc}".encode()).hexdigest())
            
            if not max_hlc or HybridLogicalClock.compare(entry_hlc, max_hlc) > 0:
                max_hlc = entry_hlc
            entry_count += 1
            
        manifest_hash = hashlib.sha256("".join(entry_hashes).encode()).hexdigest() if entry_hashes else ""

        return {
            "last_hlc": max_hlc,
            "entry_count": entry_count,
            "entries_hash": manifest_hash,
            "protocol_version": "1.0"
        }

    def compare_peer_state(self, peer_id: str, remote_manifest: Dict[str, Any]) -> str:
        """
        Compares local manifest with a remote manifest to detect divergence.
        
        Returns:
            "IN_SYNC", "DIVERGED", "LOCAL_AHEAD", "REMOTE_AHEAD"
        """
        local_manifest = self.compute_local_manifest()
        
        # Check protocol version compatibility first
        if local_manifest["protocol_version"] != remote_manifest["protocol_version"]:
            raise DivergenceError("Incompatible protocol versions detected.")

        # If hashes match and HLCs match, we're in sync
        if (local_manifest["entries_hash"] == remote_manifest["entries_hash"] and
                local_manifest["last_hlc"] == remote_manifest["last_hlc"]):
            return "IN_SYNC"
        
        # Determine who is ahead by HLC
        hlc_comparison = HybridLogicalClock.compare(local_manifest["last_hlc"], remote_manifest["last_hlc"])
        
        if hlc_comparison > 0:
            # Local has newer HLC, but hashes differ -> possible divergence or remote is just behind
            return "LOCAL_AHEAD"
        elif hlc_comparison < 0:
            # Remote has newer HLC, but hashes differ -> possible divergence or local is just behind
            return "REMOTE_AHEAD"
        else:
            # HLCs are the same, but hashes differ. This indicates a divergence.
            # E.g., entries updated at same time, but different content.
            return "DIVERGED"

    def verify_manifest(self, manifest: Dict[str, Any]) -> bool:
        """Verify the integrity of a received manifest."""
        # This can be expanded to include digital signatures of the manifest
        # by the remote peer's identity key.
        return manifest.get("entries_hash") is not None and manifest.get("last_hlc") is not None

    def detect_missing_operations(self, peer_id: str, remote_hlc: str) -> bool:
        """
        Detects if local history has operations missing that are present in peer's history.
        This would be a complex comparison of actual operations in the journal, or reliance
        on explicit manifest hashes of operation ranges.
        For MVP, we use HLC difference. If remote_hlc is significantly ahead of our checkpoint,
        and our manifest is older than a previous sync, it's a strong indicator.
        """
        local_checkpoint = self.checkpoint_manager.get_peer_checkpoint(peer_id)
        if not local_checkpoint:
            return False # No previous sync, can't detect missing from a prior state
        
        # If remote HLC is very far ahead, and our local history has not advanced much
        # it *might* indicate missing operations from a previous sync.
        # This is a heuristic.
        return HybridLogicalClock.compare(remote_hlc, local_checkpoint) > 0 and \
               HybridLogicalClock.compare(self.hlc.tick(), remote_hlc) < 0

    def detect_conflicting_histories(self, peer_id: str, remote_manifest: Dict[str, Any]) -> bool:
        """
        Detects if two histories have diverged such that a simple fast-forward merge isn't possible.
        This happens when both sides have made changes based on different past states.
        """
        status = self.compare_peer_state(peer_id, remote_manifest)
        return status == "DIVERGED"
