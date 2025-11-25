"""
Unit tests for SecureMemory
"""
import pytest
import sys
from src.secure_memory import SecureMemory, SecureMemoryError


def test_platform_initialization():
    """Test platform detection and library loading"""
    sm = SecureMemory()
    
    if sys.platform.startswith('linux'):
        assert sm.libc is not None, "libc should be loaded on Linux"
        assert sm.kernel32 is None, "kernel32 should be None on Linux"
        assert hasattr(sm.libc, 'mlock'), "mlock should be available"
        assert hasattr(sm.libc, 'munlock'), "munlock should be available"
        print("Linux platform initialization passed!")
    
    elif sys.platform == 'win32':
        assert sm.kernel32 is not None, "kernel32 should be loaded on Windows"
        assert sm.libc is None, "libc should be None on Windows"
        assert hasattr(sm.kernel32, 'VirtualLock'), "VirtualLock should be available"
        assert hasattr(sm.kernel32, 'VirtualUnlock'), "VirtualUnlock should be available"
        print("Windows platform initialization passed!")
    
    elif sys.platform == 'darwin':
        assert sm.libc is not None, "libc should be loaded on macOS"
        assert sm.kernel32 is None, "kernel32 should be None on macOS"
        assert hasattr(sm.libc, 'mlock'), "mlock should be available"
        assert hasattr(sm.libc, 'munlock'), "munlock should be available"
        print("macOS platform initialization passed!")
    
    print(f"Platform initialization test passed on {sys.platform}!")

def test_zeroize_bytearray():
    """ Test secure zeroing of bytearray"""
    sm = SecureMemory()

    # Create mutable bytearray
    key = bytearray(b"sensitive_master_key_32_bytes!!")
    original_len = len(key)

    # Verify it is not zero
    assert key[0] != 0, "key should have non-zero bytes"

    #Zeroize 
    result = sm.zeroize(key)

    assert result == True, "Zeroize should succed"
    assert all(b == 0 for b in key), "All bytes should be zero"
    assert len(key) == original_len, "Length should not change"

    print("Zeroize() test passed!")

def test_zeroize_memoryview():
    """Test zeroing of memoryview"""
    sm = SecureMemory()

    data = bytearray(b"secret_data_here")
    mv = memoryview(data)

    # Zeroize through memoryview
    result = sm.zeroize(mv)

    assert result == True
    assert all(b==0 for b in data), "Original data should be zeroed"

    print("memoryview zeroize test passed!")

def test_protect_from_fork():
    """Test fork protection (Unix-only, no-op on windows)"""
    sm = SecureMemory()
    key = bytearray(b"Sensitive_key_for_fork_test!")

    # should return true (either protected on Unix or no-op on windows)
    result = sm.protect_from_fork(key)

    assert result == True, "protect from_frok should succeed"
    print ("protectd_from_fork() test passed!")

def test_cleanup_all():
    """Test cleanup of all locked regions"""
    sm = SecureMemory()

    # create and lock some data
    key1 = bytearray(b"first_key_to_clean!")
    key2 = bytearray(b"second_key_to_clean!")

    sm.lock_memory(key1)
    sm.lock_memory(key2)

    # Verify regions are tracked
    assert len(sm.locked_regions) >= 2, "Should have tracked regions"

    # cleanup 
    sm.cleanup_all()

    # Verify regions cleared
    assert len(sm.locked_regions) == 0, "Regions should be cleared"

    print(" Cleanup_all() test passed")

if __name__ == "__main__":
    test_platform_initialization()
    test_zeroize_bytearray()
    test_zeroize_memoryview()
    test_protect_from_fork()
    test_cleanup_all()
    print("\n Memory is secure")
