"""
Sentra Secure Memory Manager
Prevents sensitive keys from being swapped to disk and ensures forensic unrecoverability

Platform Support:
- Linux: mlock/munlock via libc
- Windows: VirtualLock/VirtualUnlock via kernel32
- Graceful degradation if privileges insufficient
"""

import os
import sys
import ctypes
import warnings
from typing import Optional, Tuple, Dict, Any
from datetime import datetime, timezone
import atexit

# Platform detection constants
IS_LINUX = sys.platform.startswith('linux')
IS_WINDOWS = sys.platform == 'win32'
IS_MACOS = sys.platform == 'darwin'

class SecureMemoryHandle:
    """
    Opaque handle for a locked memory region.
    Prevents ID-reuse vulnerabilities by avoiding id(obj) tracking.
    """
    def __init__(self, addr, length, keeper):
        self.addr = addr
        self.length = length
        self.keeper = keeper  # Keeps the ctypes object alive
        self.locked = False

class SecureMemoryError(Exception):
    """Base exception for secure memory operations"""
    pass

class MemoryLockError(SecureMemoryError):
    """Raised when memory locking fails"""
    pass

class SecureMemory:
    """
    Cross-platform secure memory manager
    
    Features:
    - Memory locking (prevents swap to disk)
    - Secure zeroing (compiler-resistant)
    - Fork protection (prevent child process inheritance)
    - Automatic cleanup on exit
    
    Usage: 
        sm = SecureMemory()
        key = b"sensitive_master_key_32_bytes!!"
        
        # Lock memory
        sm.lock_memory(key)

        # Use key...

        # Securely erase
        sm.zeroize(key)
        sm.unlock_memory(key)

    """
    def __init__(self):
        """Initialize secure memory manager and detect platform capabilities"""
        self._handles: set[SecureMemoryHandle] = set()
        self._initialize_platform()

        atexit.register(self.cleanup_all)

    def _initialize_platform(self):
        """
        Detect OS and load platform-specific system libraries
        
        TODO: Implement platform detection and library loading 
        HINTS:
        1. Check IS_LINUX, IS_WINDOWS, IS_MACOS flags
        2. For Linux/macOS : load libc using ctypes.CDLL('libc.so.6') or ('libc.dylib
        )
        3. For Windows: Load kernel32 using ctypes.windll.kernel32
        4. Store library refernces as instance variables
        5. Set up function signatures (argtypes, restype)
        
        Function Signatures Needed:
        Linux/macOS:
        - mlock(const void *addr, size_t len) -> int
        - munlock(const void *addr, size_t len) -> int
        
        Windows:
        - VirtualLock(LPVOID lpAddress, SIZE_T dwSize) -> BOOL
        - VirtualUnlock(LPVOID lpAddress, SIZE_T dwSize) -> BOOL
        """
        self.libc = None
        self.kernel32 = None
        
        try:
            if IS_LINUX:
                self.libc = ctypes.CDLL('libc.so.6')
                self.libc.mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                self.libc.mlock.restype = ctypes.c_int
                self.libc.munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                self.libc.munlock.restype = ctypes.c_int
                self.libc.madvise.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
                self.libc.madvise.restype = ctypes.c_int

            elif IS_MACOS:
                self.libc = ctypes.CDLL('libc.dylib')
                self.libc.mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                self.libc.mlock.restype = ctypes.c_int
                self.libc.munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                self.libc.munlock.restype = ctypes.c_int

            elif IS_WINDOWS:
                self.kernel32 = ctypes.windll.kernel32
                self.kernel32.VirtualLock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                self.kernel32.VirtualLock.restype = ctypes.c_bool
                self.kernel32.VirtualUnlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                self.kernel32.VirtualUnlock.restype = ctypes.c_bool

        except Exception as e:
            warnings.warn(f"SecureMemory init failed: {e}. Running in degraded mode.")
    
    # What if the Virtuallock/ VirtualUnlock fails

    def lock_memory(self, data: bytes) -> bool:
        """
        Lock memory region to prevent swapping to disk
        
        Args:
            data: Bytes object to lock in memory
            
        Returns:
            True if successfully locked
            False if degraded mode (warning issued, but continued)
            
        Security:
            - Prevents sensitive data from being written to disk
            - Graceful degradation if privileges insufficient 
            - Tracks locked regions for cleanup 
            
        Example:
            >>> key = b"sensitive_master_key_32_bytes!!!"
            >>> sm = SecureMemory()
            >>> success = sm.lock_memory(key)
            >>> if not success:
            ....    print("Running in degraded mode - no mlock protection")    
        """
        try:
            addr, length, keeper = self._address_and_length(data)
        except Exception as e:
            warnings.warn(f"SecureMemory: unable to get buffer address: {e}")
            return None
        
        if length == 0:
            return None
        
        locked_ok = False

        # Attempt OS-level locking
        if IS_WINDOWS and self.kernel32 is not None:
            ok = bool(self.kernel32.VirtualLock(ctypes.c_void_p(addr), ctypes.c_size_t(length)))
            locked_ok = ok
        elif (IS_LINUX or IS_MACOS) and self.libc is not None and hasattr(self.libc, "mlock"):
            rc = int(self.libc.mlock(ctypes.c_void_p(addr), ctypes.c_size_t(length)))
            locked_ok = (rc == 0)
        else:
            warnings.warn("SecureMemory: locking not supported; running in degraded mode.")
            # We still return a handle so zeroize() can work later
            locked_ok = False

        if not locked_ok and (IS_LINUX or IS_MACOS or IS_WINDOWS):
             warnings.warn(f"SecureMemory: memory lock attempt failed")

        # Create and register handle
        handle = SecureMemoryHandle(addr, length, keeper)
        handle.locked = locked_ok
        self._handles.add(handle)
        
        return handle
    
    def _address_and_length(self, data: bytes) -> Tuple[int, int, object]:
        """
        Get memory address and size of bytes object
        
        Args:
            data: Bytes object
        
        Returns:
            Tuple of (address, length)
        """
        if not isinstance(data, (bytes,bytearray, memoryview)):
            raise TypeError("lock_memory expects bytes/bytearray/memoryview")
        
        if isinstance(data, bytes):
            length = len(data)
            # create a dedicated native buffer copy;
            keeper = ctypes.create_string_buffer(data,length)
            addr = ctypes.addressof(keeper)
            return addr, length, keeper
        
        if isinstance(data, bytearray):
            mv = memoryview(data)
            if not mv.contiguous:
                raise ValueError("bytearray must be contiguous")
            length = len(mv)
            keeper = (ctypes.c_char * length).from_buffer(mv)
            addr = ctypes.addressof(keeper)
            return addr, length, keeper
        
        mv = data 
        if not mv.contiguous:
            raise ValueError("memoryview must be contiguous")
        length = len(mv)
        if mv.readonly:
            keeper = (ctypes.c_char * length).from_buffer_copy(mv)
        else:
            keeper = (ctypes.c_char * length).from_buffer(mv)
        addr = ctypes.addressof(keeper)
        return addr, length, keeper

    def unlock_memory(self, handle: SecureMemoryHandle) -> bool:
        """
        Unlock memory region to allow normal paging
        
        Args:
            data: Bytes object to unlock
            
        Returns:
            True if successfully unlocked
            False if unlock failed or region not tracked
            
        Security:
            - Called when key is no longger needed
            - Releases memory lock, allowing normal OS paging
            - Does NOT erase the data (use zeroize() for that)
            
        Example:
            >>> sm.unlock_memory(key)
        """
        if not isinstance(handle, SecureMemoryHandle) or handle not in self._handles:
            return False

        unlocked_ok = True 
        
        if handle.locked:
            unlocked_ok = False
            if IS_WINDOWS and self.kernel32 is not None:
                ret = self.kernel32.VirtualUnlock(ctypes.c_void_p(handle.addr), ctypes.c_size_t(handle.length))
                if ret:
                    unlocked_ok = True
                else:
                    err = ctypes.get_last_error()
                    if err in (158, 487, 0): unlocked_ok = True
            
            elif (IS_LINUX or IS_MACOS) and self.libc is not None and hasattr(self.libc, "munlock"):
                rc = int(self.libc.munlock(ctypes.c_void_p(handle.addr), ctypes.c_size_t(handle.length)))
                unlocked_ok = (rc == 0)

        if not unlocked_ok:
            msg = self._get_last_error_message()
            warnings.warn(f"SecureMemory: unlock failed: {msg}")
            return False

        # Unregister handle
        self._handles.discard(handle)
        return True
    
    def _get_last_error_message(self) -> str:
        """
        Get human-readable error message from OS
        
        Returns:
            Error message string
        
        Platform-specific:
            - Linux/macOS: errno via ctypes.get_errno()
            - Windows: GetLastError() via kernel32
        """
        # TODO: Implement error message retrieval
        # HINTS:
        # 1. On Windows: Use ctypes.GetLastError()
        # 2. On Unix: Use ctypes.get_errno()
        # 3. Common Windows errors:
        #    - 5: ERROR_ACCESS_DENIED (no privileges)
        #    - 8: ERROR_NOT_ENOUGH_MEMORY
        # 4. Return formatted message with error code
        if IS_WINDOWS and self.kernel32 is not None:
            # Expand GetLastError using FormatMessageW
            err = ctypes.get_last_error()
            if not err:
                return "No Error"
            buf = ctypes.create_unicode_buffer(1024)
            FORMAT_MESSAGE_FROM_SYSTEM  = 0x00001000
            FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200
            size = self.kernel32.FormatMessageW(
                FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                None, err, 0, buf, len(buf), None
            )
            return buf.value.strip() if size else f"WinError{err}"
        # Unix-like: use errno via ctypes.get_errno()
        err = ctypes.get_errno()
        try:
            # Resolve strerror via libc if available
            if getattr(self, "libc", None) is not None and hasattr(self.libc, "strerror"):
                cmsg = self.libc.strerror(err)
                return f"errno {err}: {ctypes.cast(cmsg, ctypes.c_char_p).value.decode()}"
        except Exception:
            pass
        return f"errno {err}" if err else "No Error"
    
    def zeroize(self, handle: SecureMemoryHandle) -> bool:
        """
        Securely erase sensitive data from memory
        
        Args:
            data: Bytes/bytearray/memoryview to zero out
        
        Returns:
            True if successfully zeroed
            False if zeroing may have failed
        
        Security:
            - Uses ctypes.memset (compiler-resistant)
            - Zeroes the actual memory location
            - Cannot prevent all copies (Python internals)
            - Best effort: zeros the primary buffer
        
        Example:
            >>> key = bytearray(b"sensitive_key_32_bytes_here!")
            >>> sm.zeroize(key)
            True
            >>> key
            bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00...')
        """
        if not isinstance(handle, SecureMemoryHandle):
            return False

        try:
            ctypes.memset(handle.addr, 0, handle.length)
            
            # Verify
            if handle.length > 0:
                first_byte = ctypes.cast(handle.addr, ctypes.POINTER(ctypes.c_ubyte))[0]
                if first_byte != 0:
                    warnings.warn("Zeroing Verification failed")
                    return False
            return True
        except Exception as e:
            warnings.warn(f"SecureMemory: zeroize failed: {e}")
            return False
        
    def protect_from_fork(self, data_or_handle) -> bool:
        """
         Prevent memory region from being copied to child processes on fork
    
        Args:
            data: Bytes object to protect
        
        Returns:
            True if protection applied
            False if not supported or failed
        
        Security:
            - Uses madvise(MADV_DONTFORK) on Unix
            - Prevents child processes from inheriting sensitive memory
            - Windows: Not applicable (no fork semantics)
        
        Example:
            >>> sm.protect_from_fork(master_key)
        """

        # Windows: No fork model, nothing to do
        if IS_WINDOWS:
            return True

        if self.libc is None:
            return False

        try:
            # 1. Preferred: Handle
            if hasattr(data_or_handle, "addr") and hasattr(data_or_handle, "length"):
                addr = data_or_handle.addr
                length = data_or_handle.length
            
            # 2. Backwards-compat: Raw buffer (Only safe for mutable types like bytearray)
            else:
                if isinstance(data_or_handle, bytes):
                    warnings.warn("SecureMemory: protect_from_fork called on immutable 'bytes'. "
                                  "This protects a temporary copy, not the original. Use a Handle.")
                
                # We intentionally discard the keeper (_) here because we assume
                # the caller is holding the object alive.
                addr, length, _ = self._address_and_length(data_or_handle)

            # MADV_DONTFORK = 10 on Linux
            MADV_DONTFORK = 10

            # Ensure madvise signature is set
            if not hasattr(self.libc, "madvise"):
                self.libc.madvise.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
                self.libc.madvise.restype = ctypes.c_int

            rc = self.libc.madvise(ctypes.c_void_p(addr), ctypes.c_size_t(length), MADV_DONTFORK)
            return rc == 0

        except Exception as e:
            warnings.warn(f"SecureMemory: fork protection failed: {e}")
            return False
        
    def cleanup_all(self) -> None:
        """
        Zero and unlock all tracked memory regions

        Security:
            - Called automatically on exit via atexit
            - Zeros all locked regions before unlocking
            - Best-effort cleanup (doesn't raise exceptions)

        Example:
            >>> sm = SecureMemory()
            >>> atexit.register(sm.cleanup_all)
        """

        active_handles = list(self._handles)
        
        for handle in active_handles:
            try:
                # 1. Zeroize
                if handle.addr and handle.length > 0:
                    ctypes.memset(handle.addr, 0, handle.length)

                # 2. Unlock
                if handle.locked:
                    if IS_WINDOWS and self.kernel32:
                        self.kernel32.VirtualUnlock(ctypes.c_void_p(handle.addr), ctypes.c_size_t(handle.length))
                    elif self.libc and hasattr(self.libc, 'munlock'):
                        self.libc.munlock(ctypes.c_void_p(handle.addr), ctypes.c_size_t(handle.length))
            except Exception:
                pass
        
        self._handles.clear()