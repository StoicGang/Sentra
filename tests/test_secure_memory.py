import ctypes
import sys
import pytest
from unittest.mock import MagicMock, patch, ANY

import src.secure_memory as secure_mem_mod
from src.secure_memory import (
    SecureMemory,
    SecureMemoryHandle,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sm():
    """Returns a real SecureMemory instance (auto-detects platform)."""
    return SecureMemory()

@pytest.fixture
def sample_bytes():
    return b"super_secret_key_material"

@pytest.fixture
def sample_bytearray():
    return bytearray(b"mutable_secret_key_material")

# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------

def test_secure_memory_initializes(sm):
    assert isinstance(sm._handles, set)

def test_cleanup_registered_via_atexit():
    with patch("atexit.register") as reg:
        SecureMemory()
        reg.assert_called_once()

# ---------------------------------------------------------------------------
# Internal Address Handling (Platform Agnostic)
# ---------------------------------------------------------------------------

def test_address_and_length_bytes(sm, sample_bytes):
    addr, length, keeper = sm._address_and_length(sample_bytes)
    assert length == len(sample_bytes)
    assert isinstance(addr, int)
    assert keeper is not None
    # Ensure address points to the keeper buffer
    assert addr == ctypes.addressof(keeper)

def test_address_and_length_bytearray(sm, sample_bytearray):
    addr, length, keeper = sm._address_and_length(sample_bytearray)
    assert length == len(sample_bytearray)
    assert isinstance(addr, int)

def test_address_and_length_rejects_non_buffer(sm):
    with pytest.raises(TypeError):
        sm._address_and_length(123)

def test_address_and_length_non_contiguous_memoryview(sm):
    data = bytearray(b"abcdef")
    mv = memoryview(data)[::2]  # non-contiguous slice
    with pytest.raises(ValueError, match="contiguous"):
        sm._address_and_length(mv)

# ---------------------------------------------------------------------------
# lock_memory (General)
# ---------------------------------------------------------------------------

def test_lock_memory_invalid_type(sm):
    assert sm.lock_memory("not-bytes") is None

def test_lock_memory_zero_length(sm):
    assert sm.lock_memory(b"") is None

def test_lock_memory_returns_handle(sm, sample_bytes):
    handle = sm.lock_memory(sample_bytes)
    assert isinstance(handle, SecureMemoryHandle)
    assert handle in sm._handles
    assert handle.length == len(sample_bytes)

# ---------------------------------------------------------------------------
# Platform-Specific Logic (Mocked)
# ---------------------------------------------------------------------------

def test_linux_locking_flow():
    """Simulate Linux environment and ensure mlock is called."""
    with patch.multiple(secure_mem_mod, IS_LINUX=True, IS_WINDOWS=False, IS_MACOS=False):
        with patch("ctypes.CDLL") as mock_cdll:
            # Setup mock libc
            mock_libc = MagicMock()
            mock_cdll.return_value = mock_libc
            mock_libc.mlock.return_value = 0 # Success
            
            sm = SecureMemory()
            data = b"secret"
            
            handle = sm.lock_memory(data)
            
            assert handle.locked is True
            mock_libc.mlock.assert_called_once()
            
            # Check unlock
            mock_libc.munlock.return_value = 0
            sm.unlock_memory(handle)
            mock_libc.munlock.assert_called_once()

def test_windows_locking_flow():
    """Simulate Windows environment and ensure VirtualLock is called."""
    with patch.multiple(secure_mem_mod, IS_LINUX=False, IS_WINDOWS=True, IS_MACOS=False):
        with patch("ctypes.windll.kernel32") as mock_k32:
            # Setup mock kernel32
            mock_k32.VirtualLock.return_value = 1 # Non-zero is success on Windows
            mock_k32.VirtualUnlock.return_value = 1
            
            sm = SecureMemory()
            # Manually inject the mocked library if __init__ ran before patch
            sm.kernel32 = mock_k32 
            
            data = b"win_secret"
            handle = sm.lock_memory(data)
            
            assert handle.locked is True
            mock_k32.VirtualLock.assert_called_once()
            
            sm.unlock_memory(handle)
            mock_k32.VirtualUnlock.assert_called_once()

def test_lock_memory_failures_handled_gracefully():
    """If OS locking fails (e.g. permission denied), should return handle but locked=False."""
    with patch.multiple(secure_mem_mod, IS_LINUX=True, IS_WINDOWS=False):
        with patch("ctypes.CDLL") as mock_cdll:
            mock_libc = MagicMock()
            mock_cdll.return_value = mock_libc
            # mlock returns -1 on failure
            mock_libc.mlock.return_value = -1 
            
            sm = SecureMemory()
            with pytest.warns(UserWarning, match="memory lock attempt failed"):
                handle = sm.lock_memory(b"data")
            
            assert isinstance(handle, SecureMemoryHandle)
            assert handle.locked is False
            # Should still be tracked for zeroing
            assert handle in sm._handles

# ---------------------------------------------------------------------------
# Fork Protection
# ---------------------------------------------------------------------------

def test_protect_from_fork_linux():
    """Ensure madvise is called with MADV_DONTFORK (10)."""
    with patch.multiple(secure_mem_mod, IS_LINUX=True, IS_WINDOWS=False):
        with patch("ctypes.CDLL") as mock_cdll:
            mock_libc = MagicMock()
            mock_cdll.return_value = mock_libc
            mock_libc.madvise.return_value = 0
            
            sm = SecureMemory()
            handle = sm.lock_memory(b"fork_sensitive")
            
            res = sm.protect_from_fork(handle)
            assert res is True
            
            # Verify arg 3 is 10 (MADV_DONTFORK)
            args, _ = mock_libc.madvise.call_args
            assert args[2] == 10

def test_protect_from_fork_windows_noop():
    """Windows has no fork, so it should just return True."""
    with patch.multiple(secure_mem_mod, IS_WINDOWS=True, IS_LINUX=False):
        sm = SecureMemory()
        assert sm.protect_from_fork(b"data") is True

# ---------------------------------------------------------------------------
# Zeroing & Cleanup
# ---------------------------------------------------------------------------

def test_zeroize_zeros_memory(sm, sample_bytearray):
    """Verify memory is actually zeroed using ctypes."""
    handle = sm.lock_memory(sample_bytearray)
    
    # Pre-check: data exists
    assert sample_bytearray != bytes(len(sample_bytearray))
    
    ok = sm.zeroize(handle)
    assert ok is True
    
    # Check that underlying memory is zeroed
    assert all(b == 0 for b in sample_bytearray)

def test_zeroize_invalid_handle(sm):
    assert sm.zeroize("not-handle") is False

def test_cleanup_all_clears_handles(sm, sample_bytearray):
    handle = sm.lock_memory(sample_bytearray)
    assert handle in sm._handles

    sm.cleanup_all()
    assert len(sm._handles) == 0
    # Cleanup should also zeroize
    assert all(b == 0 for b in sample_bytearray)

# ---------------------------------------------------------------------------
# Error Messages
# ---------------------------------------------------------------------------

def test_get_last_error_message_unix():
    with patch.multiple(secure_mem_mod, IS_LINUX=True, IS_WINDOWS=False):
        with patch("ctypes.get_errno", return_value=12): # ENOMEM
            sm = SecureMemory()
            msg = sm._get_last_error_message()
            assert "errno 12" in msg

def test_get_last_error_message_windows():
    with patch.multiple(secure_mem_mod, IS_WINDOWS=True, IS_LINUX=False):
        with patch("ctypes.get_last_error", return_value=5): # Access Denied
            # Mock FormatMessageW to avoid complex ctypes setup for test
            with patch("ctypes.windll.kernel32.FormatMessageW") as mock_fmt:
                mock_fmt.return_value = 0 # Simulate failure to format message
                
                sm = SecureMemory()
                # Inject kernel32 mock
                sm.kernel32 = MagicMock()
                sm.kernel32.FormatMessageW = mock_fmt
                
                msg = sm._get_last_error_message()
                assert "WinError5" in msg