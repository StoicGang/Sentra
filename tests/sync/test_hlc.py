"""
Tests for Sentra Hybrid Logical Clock
Verifies monotonicity, causal ordering, and drift protection.
"""
import pytest
import time
from unittest.mock import patch
from src.sync.hlc import HybridLogicalClock, ClockDriftError, HLCError

def test_hlc_tick_monotonicity():
    hlc = HybridLogicalClock("node1")
    t1 = hlc.tick()
    t2 = hlc.tick()
    assert HybridLogicalClock.compare(t1, t2) == -1
    
    # Verify count increment if time is the same
    with patch.object(HybridLogicalClock, '_get_system_time', return_value=1000):
        hlc2 = HybridLogicalClock("node2", last_known_time=1000)
        c1 = hlc2.tick()
        c2 = hlc2.tick()
        assert c1 == "1000:0001:node2"
        assert c2 == "1000:0002:node2"

def test_hlc_merge_causality():
    hlc_a = HybridLogicalClock("nodeA")
    hlc_b = HybridLogicalClock("nodeB")
    
    # Event on A
    a1 = hlc_a.tick()
    
    # Send A -> B
    b1 = hlc_b.merge(a1)
    
    # B must be after A
    assert HybridLogicalClock.compare(b1, a1) == 1
    
    # Event on B after merge
    b2 = hlc_b.tick()
    assert HybridLogicalClock.compare(b2, b1) == 1

def test_hlc_drift_rejection():
    hlc = HybridLogicalClock("local")
    future_time = int(time.time()) + 5000 # Beyond 3600 limit
    future_hlc = f"{future_time}:0000:remote"
    
    with pytest.raises(ClockDriftError):
        hlc.merge(future_hlc)

def test_hlc_compare_logic():
    # Time comparison
    assert HybridLogicalClock.compare("100:0:A", "200:0:B") == -1
    assert HybridLogicalClock.compare("200:0:A", "100:0:B") == 1
    
    # Count comparison
    assert HybridLogicalClock.compare("100:1:A", "100:2:B") == -1
    assert HybridLogicalClock.compare("100:2:A", "100:1:B") == 1
    
    # Node ID comparison (tie-break)
    assert HybridLogicalClock.compare("100:0:A", "100:0:B") == -1
    assert HybridLogicalClock.compare("100:0:B", "100:0:A") == 1
    
    # Equality
    assert HybridLogicalClock.compare("100:0:A", "100:0:A") == 0

def test_hlc_serialization_roundtrip():
    hlc = HybridLogicalClock("nodeX")
    s1 = hlc.tick()
    t, c, n = HybridLogicalClock.deserialize(s1)
    assert n == "nodeX"
    assert s1 == f"{t}:{c:04d}:{n}"

def test_hlc_malformed_input():
    hlc = HybridLogicalClock("node")
    with pytest.raises(HLCError):
        hlc.merge("invalid-format")
    with pytest.raises(HLCError):
        hlc.merge("100:0") # Missing node_id

def test_hlc_rollback_protection_initialization():
    # Simulate a crash/restart where we restore from storage
    stored_hlc = "2000:0050:node1"
    
    # Current system time is 1000 (clock jumped back)
    with patch.object(HybridLogicalClock, '_get_system_time', return_value=1000):
        hlc = HybridLogicalClock("node1")
        hlc.update_from_storage(stored_hlc)
        
        # Next tick should be based on 2000, not 1000
        next_tick = hlc.tick()
        assert next_tick.startswith("2000:0051")

def test_hlc_concurrent_merge():
    # A and B both tick at the same physical time
    with patch.object(HybridLogicalClock, '_get_system_time', return_value=1000):
        hlc_a = HybridLogicalClock("nodeA", last_known_time=1000)
        hlc_b = HybridLogicalClock("nodeB", last_known_time=1000)
        
        a1 = hlc_a.tick() # 1000:0001:nodeA
        b1 = hlc_b.tick() # 1000:0001:nodeB
        
        # Merge B into A
        a2 = hlc_a.merge(b1)
        # Should be 1000:0002:nodeA (max count + 1)
        assert a2 == "1000:0002:nodeA"

def test_hlc_duplicate_merge():
    hlc = HybridLogicalClock("local")
    remote_event = "1000:0010:remote"
    
    # First merge
    m1 = hlc.merge(remote_event)
    
    # Second merge of same event
    # Since physical time might have advanced, we check causality
    m2 = hlc.merge(remote_event)
    assert HybridLogicalClock.compare(m2, m1) == 1
