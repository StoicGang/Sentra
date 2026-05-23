"""
Sentra Hybrid Logical Clock (HLC) Implementation
Provides causal ordering and monotonic guarantees in a distributed system.
Implements HLC as described in "Logical Physical Clocks and Consistent Snapshots in Distributed Systems".
"""
import time
import threading
from typing import Tuple, Optional


class HLCError(Exception):
    """Base exception for HLC errors."""
    pass


class ClockDriftError(HLCError):
    """Raised when remote clock is too far in the future."""
    pass


class ClockRollbackError(HLCError):
    """Raised when system clock jumped backward significantly."""
    pass


class HybridLogicalClock:
    """
    Hybrid Logical Clock
    Format: (wall_time, logical_count, node_id)
    - wall_time: 64-bit Unix timestamp (seconds)
    - logical_count: 16-bit counter for concurrent events
    - node_id: Unique device identifier (SHA256 hash or truncated version)
    """
    
    # Default drift limit: 60 minutes
    MAX_DRIFT_SECONDS = 3600

    def __init__(self, node_id: str, last_known_time: int = 0):
        self.node_id = node_id
        self.time = last_known_time
        self.count = 0
        self._lock = threading.Lock()

    def _get_system_time(self) -> int:
        return int(time.time())

    def tick(self) -> str:
        """
        Increment the clock for a local event.
        Returns the serialized HLC.
        """
        with self._lock:
            system_time = self._get_system_time()
            old_time = self.time
            
            # Ensure monotonicity: never move backward in physical time
            self.time = max(old_time, system_time)
            
            if self.time == old_time:
                self.count += 1
            else:
                self.count = 0
                
            return self.serialize()

    def merge(self, remote_hlc_str: str) -> str:
        """
        Merge local clock with a remote HLC from a received message.
        """
        remote_time, remote_count, remote_node = self.deserialize(remote_hlc_str)
        
        system_time = self._get_system_time()
        
        # 1. Drift Check: reject if remote is too far in the future
        if remote_time > system_time + self.MAX_DRIFT_SECONDS:
            raise ClockDriftError(
                f"Remote clock {remote_time} exceeds drift limit "
                f"(System: {system_time}, Limit: {self.MAX_DRIFT_SECONDS})"
            )

        with self._lock:
            old_time = self.time
            
            # l.time = max(l.time, remote.time, wall_time)
            self.time = max(old_time, remote_time, system_time)
            
            if self.time == old_time == remote_time:
                self.count = max(self.count, remote_count) + 1
            elif self.time == old_time:
                self.count += 1
            elif self.time == remote_time:
                self.count = remote_count + 1
            else:
                self.count = 0
                
            return self.serialize()

    @staticmethod
    def compare(hlc1_str: str, hlc2_str: str) -> int:
        """
        Compare two serialized HLCs.
        Returns:
            -1 if hlc1 < hlc2
             0 if hlc1 == hlc2
             1 if hlc1 > hlc2
        """
        t1, c1, n1 = HybridLogicalClock.deserialize(hlc1_str)
        t2, c2, n2 = HybridLogicalClock.deserialize(hlc2_str)
        
        if t1 < t2: return -1
        if t1 > t2: return 1
        
        if c1 < c2: return -1
        if c1 > c2: return 1
        
        if n1 < n2: return -1
        if n1 > n2: return 1
        
        return 0

    def serialize(self) -> str:
        """Format: <wall_time>:<count>:<node_id>"""
        return f"{self.time}:{self.count:04d}:{self.node_id}"

    @staticmethod
    def deserialize(hlc_str: str) -> Tuple[int, int, str]:
        """Parses a serialized HLC string."""
        try:
            parts = hlc_str.split(':')
            if len(parts) != 3:
                raise ValueError("Incorrect parts count")
            
            wall_time = int(parts[0])
            count = int(parts[1])
            node_id = parts[2]
            
            return wall_time, count, node_id
        except (ValueError, IndexError):
            raise HLCError(f"Malformed HLC: {hlc_str}")

    def update_from_storage(self, last_known_hlc: str):
        """
        Restore clock state from persistence.
        Ensures the clock doesn't reset to 0 after process restart.
        """
        t, c, n = self.deserialize(last_known_hlc)
        with self._lock:
            # We only adopt storage time if it's ahead
            if t > self.time:
                self.time = t
                self.count = c
            elif t == self.time:
                self.count = max(self.count, c)
