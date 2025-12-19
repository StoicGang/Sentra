"""
Sentra Secure Memory Manager
Prevents sensitive keys from being swapped to disk and ensures forensic unrecoverability

Platform Support:
- Linux: mlock/munlock via libc
- Windows: VirtualLock/VirtualUnlock via kernel32
- Graceful degradation if privileges insufficient
"""

import sys
import ctypes
import warnings
from typing import Tuple, Union, Any, Optional, Dict
import atexit

def _detect_platform() -> str:
    p = sys.platform.lower()
    if p.startswith('linux'): return 'LINUX'
    if p.startswith('win32') or p.startswith('cygwin'): return 'WINDOWS'
    if p.startswith('darwin'): return 'MACOS'
    return 'UNKNOWN'

PLATFORM = _detect_platform()
IS_LINUX = (PLATFORM == 'LINUX')
IS_WINDOWS = (PLATFORM == 'WINDOWS')
IS_MACOS = (PLATFORM == 'MACOS')

FORMAT_MESSAGE_FROM_SYSTEM  = 0x00001000
FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200

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
    """

    def __init__(self):
        """Initialize secure memory manager and detect platform capabilities"""
        self._handles: set[SecureMemoryHandle] = set()
        self.libc: Any = None
        self.kernel32: Any = None
        self._initialize_platform()

        if PLATFORM == 'UNKNOWN':
            warnings.warn(
                "Secure Memory: Unsupported platform. Memory locking is DISABLED. "
                "Sensitive keys may be swapped to disk.",
                RuntimeWarning
            )

        atexit.register(self._cleanup_all_silent)

    def _initialize_platform(self):
        """
        Detect OS and load platform-specific system libraries

        Function Signatures Needed:
        Linux/macOS:
        - mlock(const void *addr, size_t len) -> int
        - munlock(const void *addr, size_t len) -> int

        Windows:
        - VirtualLock(LPVOID lpAddress, SIZE_T dwSize) -> BOOL
        - VirtualUnlock(LPVOID lpAddress, SIZE_T dwSize) -> BOOL
        """
        try:
            if IS_LINUX:
                self.libc = ctypes.CDLL('libc.so.6')
                self.libc.mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                self.libc.mlock.restype = ctypes.c_int
                self.libc.munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                self.libc.munlock.restype = ctypes.c_int
                # madvise is optional but good for security
                if hasattr(self.libc, 'madvise'):
                    self.libc.madvise.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
                    self.libc.madvise.restype = ctypes.c_int
                self.platform_supported = True

            elif IS_MACOS:
                self.libc = ctypes.CDLL('libc.dylib')
                self.libc.mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                self.libc.mlock.restype = ctypes.c_int
                self.libc.munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                self.libc.munlock.restype = ctypes.c_int
                self.platform_supported = True

            elif IS_WINDOWS:
                # Use Any to suppress static analysis errors on non-Windows dev machines
                self.kernel32 = ctypes.windll.kernel32

                # Dynamic attribute access to satisfy linters (cannot find reference 'VirtualLock')
                virtual_lock = getattr(self.kernel32, 'VirtualLock')
                virtual_lock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                virtual_lock.restype = ctypes.c_int  # BOOL is int

                virtual_unlock = getattr(self.kernel32, 'VirtualUnlock')
                virtual_unlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                virtual_unlock.restype = ctypes.c_int

                self.platform_supported = True

            else:
                self.platform_supported = False

        except Exception as e:
            self.platform_supported = False
            warnings.warn(f"SecureMemory init failed: {e}. Running in degraded mode.")

    def lock_memory(self, data: Union[bytearray, memoryview]) -> Optional[SecureMemoryHandle]:
        """
        Lock memory region to prevent swapping to disk

        Args:
            data: Bytes object to lock in memory

        Returns:
            SecureMemoryHandle if locking attempted (even in degraded mode)
            None if input is invalid or length is zero

        Security:
            - Prevents sensitive data from being written to disk
            - Graceful degradation if privileges insufficient
            - Tracks locked regions for cleanup
        """
        if not self.platform_supported:
            pass
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
            try:
                # VirtualLock returns non-zero on success
                res = self.kernel32.VirtualLock(ctypes.c_void_p(addr), ctypes.c_size_t(length))
                locked_ok = bool(res)
            except (OSError, AttributeError):
                locked_ok = False

        elif (IS_LINUX or IS_MACOS) and self.libc:
            try:
                # mlock returns 0 on success
                rc = self.libc.mlock(ctypes.c_void_p(addr), ctypes.c_size_t(length))
                locked_ok = (rc == 0)
            except (OSError, AttributeError):
                locked_ok = False

        if not locked_ok and self.platform_supported:
             warnings.warn(f"SecureMemory: memory lock attempt failed")

        # Create and register handle
        handle = SecureMemoryHandle(addr, length, keeper)
        handle.locked = locked_ok
        self._handles.add(handle)

        return handle

    @staticmethod
    def _address_and_length(data: Union[bytearray, memoryview]) -> Tuple[int, int, Any]:
        """
        Get memory address and size of bytes object

        Args:
            data: Bytes object

        Returns:
            Tuple of (address, length)
        """
        if not isinstance(data, (bytes,bytearray, memoryview)):
            raise TypeError("lock_memory expects bytearray or memoryview")

        if isinstance(data, bytes):
            raise TypeError(
                "secure_memory cannot lock immutable bytes objects. "
                "Use bytearray or a writable memoryview."
            )

        if isinstance(data, bytearray):
            mv = memoryview(data)
        else:
            mv = data

        if not mv.contiguous:
            raise ValueError("Buffer must be contiguous")
        if mv.readonly:
            raise TypeError(
                "secure_memory cannot lock readonly memoryview. "
                "Provide a writable buffer."
            )
        length = len(mv)
        keeper = (ctypes.c_char * length).from_buffer(mv)
        addr = ctypes.addressof(keeper)

        return addr, length, keeper

    def unlock_memory(self, handle: SecureMemoryHandle) -> bool:
        if not isinstance(handle, SecureMemoryHandle) or handle not in self._handles:
            return False

        if not handle.locked:
            self._handles.discard(handle)
            return True

        unlocked_ok = True
        try:
            if IS_WINDOWS and self.kernel32:
                ret = self.kernel32.VirtualUnlock(ctypes.c_void_p(handle.addr), ctypes.c_size_t(handle.length))
                if not ret:
                    # Error 158 (already unlocked) or 487 (invalid addr) are "ok" during cleanup
                    err = ctypes.get_last_error()
                    if err not in (158, 487, 0):
                        unlocked_ok = False

            elif (IS_LINUX or IS_MACOS) and self.libc:
                rc = self.libc.munlock(ctypes.c_void_p(handle.addr), ctypes.c_size_t(handle.length))
                if rc != 0:
                    unlocked_ok = False

        except Exception as e:
            warnings.warn(f"SecureMemory: exception during unlock: {e}")
            unlocked_ok = False

        if not unlocked_ok:
            warnings.warn(f"SecureMemory: unlock failed for handle at {handle.addr}")

        # Unregister handle regardless of OS error to prevent handle leaks
        self._handles.discard(handle)
        return unlocked_ok

    def _get_last_error_message(self) -> str:
        """
        Get human-readable error message from OS

        Returns:
            Error message string

        Platform-specific:
            - Linux/macOS: errno via ctypes.get_errno()
            - Windows: GetLastError() via kernel32
        """
        if IS_WINDOWS and self.kernel32 is not None:
            # Expand GetLastError using FormatMessageW
            err = ctypes.get_last_error()
            if not err:
                return "No Error"
            buf = ctypes.create_unicode_buffer(1024)
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

    @staticmethod
    def zeroize( handle: SecureMemoryHandle) -> bool:
        if not isinstance(handle, SecureMemoryHandle):
            return False

        if not handle.addr or handle.length <= 0:
            return False

        try:
            ctypes.memset(handle.addr, 0, handle.length)

            if handle.keeper:
                # Cast keeper to byte array for checking
                # We use the keeper directly rather than raw address pointer
                verified = True
                for i in range(handle.length):
                    if handle.keeper[i] != b'\x00':
                        verified = False
                        break

                if not verified:
                    warnings.warn("SecureMemory: zeroization verification failed!")
                    return False

            return True

        except Exception as e:
            warnings.warn(f"SecureMemory: zeroize failed: {e}")
            return False

    def protect_from_fork(self, data_or_handle) -> bool:

        # Windows: No fork model, nothing to do
        if IS_WINDOWS:
            return True

        if self.libc is None:
            return False

        try:
            # 1. Preferred: Handle
            if isinstance(data_or_handle, SecureMemoryHandle):
                addr = data_or_handle.addr
                length = data_or_handle.length
            elif hasattr(data_or_handle, "addr") and hasattr(data_or_handle, "length"):
                # Duck typing for handle-like objects
                addr = data_or_handle.addr
                length = data_or_handle.length
            else:
                # 2. Raw buffer (less safe, creates temporary handle)
                if isinstance(data_or_handle, bytes):
                    warnings.warn("SecureMemory: protect_from_fork called on immutable 'bytes'.")

                addr, length, _ = self._address_and_length(data_or_handle)

            # MADV_DONTFORK = 10 on Linux
            madv_dont_fork = 10

            # Ensure madvise signature is set (might be missing on some libcs)
            if not hasattr(self.libc, "madvise"):
                return False

            rc = self.libc.madvise(ctypes.c_void_p(addr), ctypes.c_size_t(length), madv_dont_fork)
            return rc == 0

        except Exception as e:
            warnings.warn(f"SecureMemory: fork protection failed: {e}")
            return False

    def cleanup_all(self) -> Dict[str, int]:
        """
        Zero and unlock all tracked memory regions

        Security:
            - Called automatically on exit via atexit
            - Zeros all locked regions before unlocking
            - Best-effort cleanup (doesn't raise exceptions)

        """
        result = {
            "total": 0,
            "zeroized": 0,
            "unlock_failed": 0,
            "zeroize_failed": 0
        }

        # Copy set to list to allow modification during iteration if needed
        active_handles = list(self._handles)
        result["total"] = len(active_handles)

        for handle in active_handles:
            # 1. Zeroize
            if self.zeroize(handle):
                result["zeroized"] += 1
            else:
                result["zeroize_failed"] += 1

            # 2. Unlock
            # (zeroize checks handle validity, unlock_memory handles logic)
            if not self.unlock_memory(handle):
                result["unlock_failed"] += 1

        self._handles.clear()
        return result

    def _cleanup_all_silent(self):
        try:
            self.cleanup_all()
        except Exception:
            pass
