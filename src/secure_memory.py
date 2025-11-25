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
from typing import Optional, Tuple
import atexit

# Platform detection constants
IS_LINUX = sys.platform.startswith('linux')
IS_WINDOWS = sys.platform == 'win32'
IS_MACOS = sys.platform == 'darwin'

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
        self.locked_regions = [] #track locked memory regions
        self._initialize_platform()
        pass

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

        # TODO: Platformmnh-specific initialization
        if IS_LINUX or IS_MACOS:
            try:
                # Load linux libc
                self.libc = ctypes.CDLL('libc.so.6')

                # Set up mlock signature: int mlock(const void *addr, size_t len)
                self.libc.mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                self.libc.mlock.restype = ctypes.c_int

                # Set up munlock signature: int munlock(const void *addr, size_t len)
                self.libc.munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                self.libc.munlock.restype = ctypes.c_int

                self.kernel32 = None

            except OSError as e:
                raise SecureMemoryError(f"Failed to load libc: {e}")

        elif IS_MACOS:
            try:
                # Load linux libc
                self.libc = ctypes.CDLL('libc.dylib')
                
                # Set up mlock signature: int mlock(const void *addr, size_t len)
                self.libc.mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                self.libc.mlock.restype = ctypes.c_int

                # Set up munlock signature: int munlock(const void *addr, size_t len)
                self.libc.munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                self.libc.munlock.restype = ctypes.c_int

                self.kernel32 = None

            except OSError as e:
                raise SecureMemoryError(f"Failed to load libc: {e}")

        elif IS_WINDOWS:
            try:
                # Load Windows kernel32
                self.kernel32 = ctypes.windll.kernel32
                
                # Set up VirtualLock signature: BOOL VirtualLock(LPVOID, SIZE_T)
                self.kernel32.VirtualLock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                self.kernel32.VirtualLock.restype = ctypes.c_bool
                
                # Set up VirtualUnlock signature: BOOL VirtualUnlock(LPVOID, SIZE_T)
                self.kernel32.VirtualUnlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]  # ✅ Fixed typo
                self.kernel32.VirtualUnlock.restype = ctypes.c_bool
                
                self.libc = None  # Linux/macOS only
                
            except Exception as e: 
                raise SecureMemoryError(f"Failed to load kernel32: {e}")

        else:
            warnings.warn(
                f"Secure memory not fully supported on {sys.platform}."
                "Keys will still be zeroed but may be swapped to disk.",
                RuntimeWarning
            )
            self.libc = None
            self.kernel32 = None
    
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

        # TODO: Implement memory locking
        # HINTS:
        # 1. Get memory address of data using id() and ctypes.addressof()
        # 2. Get data length using len(data)
        # 3. Call appropriate platform function (mlock on unix, VirtualLock on Windows)
        # 4. Check return value:
        #   - Unix: mlock returns 0 on success, -1 on failure
        #   - Windows: VirtualLock returns True on success, False on failure
        # 5. If failed, issue warning with get_last_error_message()
        # 6. Track region in self.locked_regions even if degraded
        # 7. Return True if locked, False if degraded

        try:
            addr, length, keeper = self._address_and_length(data)
        except Exception as e:
            warnings.warn(f"SecureMemory: unable to get buffer address: {e}")
            self.locked_regions.append({
                "addr": None, "length":len(data) if hasattr(data, "__len__") else None,
                "locked": False, "platfomr": sys.platform
            })
            return False
        
        if length == 0:
            # Nothing to lock : success
            self.locked_regions.append({
                "addr":addr, "length":0, "locked": True, "platform": sys.platform
            })
            return True
        
        locked_ok = False

        if IS_WINDOWS and self.kernel32 is not None:
            # Vituallock returns nonzero Bool on success
            ok = bool(self.kernel32.VirtualLock(ctypes.c_void_p(addr), ctypes.c_size_t(length)))
            locked_ok = ok
        elif (IS_LINUX or IS_MACOS) and self.libc is not None and hasattr(self.libc, "mlock"):
            # mlock returns 0 on success, -1 on failure
            rc = int(self.libc.mlock(ctypes.c_void_p(addr), ctypes.c_size_t(length)))
            locked_ok = (rc == 0)
        else:
            # Unsupported platform or missing symbols
            warnings.warn(
                "SecureMemory: locking not supported on this platform; running on degraded mode. "
            )
            locked_ok = False

        if not locked_ok:
            warnings.warn(f"SecureMemory: memory lock failed")

        if locked_ok and keeper is not None:
            setattr(self, f"_keeper_{addr}", keeper)

        self.locked_regions.append({
            "addr": addr, "length": length, "locked": bool(locked_ok),
            "platform": ("Windows" if IS_WINDOWS else "unix" if (IS_LINUX or IS_MACOS) else sys.platform)
        })

        return bool(locked_ok)
    
    def _get_memory_address(self, data: bytes) -> Tuple[int, int]:
        """
        Get memory address and size of bytes object
        
        Args:
            data: Bytes object
        
        Returns:
            Tuple of (address, length)
        """
        # TODO: Implement address extraction
        # HINTS:
        # 1. Use id(data) to get object ID
        # 2. Use ctypes.addressof() or ctypes.cast() to convert to memory address
        # 3. Return (address, len(data))
        # 
        # Note: In Python, bytes are immutable and stored contiguously,
        # so we can reliably get their memory address

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
        


    def unlock_memory(self, data: bytes) -> bool:
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

        # TODO: Implement memory unlocking
        # HINTS:
        # 1. Get memory address using id() and ctypes.addressof()
        # 2. Get data length using len(data)
        # 3. Call appropriate platform function (munlock on Unix, VirtualUnlock on Windows)
        # 4. Check return value (same as lock_memory)
        # 5. Remove region from self.locked_regions
        # 6. Handle cases where region not found (silently ignore)
        # 7. Return True if successful

        try:
            addr, length, keeper = self._address_and_length(data)
        except Exception as e:
            warnings.warn(f"SecureMemory: unable to get the buffer address for unlock: {e}")
            return False
        
        if length == 0:
            return True
        
        unlocked_ok = False

        if IS_WINDOWS and self.kernel32 is not None:
            ok = bool(self.kernel32.VirtualUnlock(ctypes.c_void_p(addr), ctypes.c_size_t(length)))
            unlocked_ok  = ok

        elif (IS_LINUX or IS_MACOS) and self.libc is not None and hasattr(self.libc, "munlock"):
            rc = int (self.libc.munlock(ctypes.c_void_p(addr), ctypes.c_size_t(length)))
            unlocked_ok = (rc == 0)
        else:
            warnings.warn("SecureMemory: unlocking not supported on the platfomr: degraded mode")
            unlocked_ok = False

        if not unlocked_ok:
            warnings.warn(f"SecureMemory: memory unlock failed")

        if hasattr(self, f"_keeper_{addr}"):
            delattr(self, f"__keeper_{addr}")

        self.locked_regions.append({
            "addr": addr, "length": length, "locked": False,
            "platform": ("windows" if IS_WINDOWS else "unix" if (IS_LINUX or IS_MACOS) else sys.platform)
        })

        return bool(unlocked_ok)
    
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
    
    def zeroize(self, data: bytes) -> bool:
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
        
        # TODO: Implement secure zeroing
        # HINTS:
        # 1. Get memory address using _get_memory_address() helper
        # 2. Get length of data
        # 3. Use ctypes.memset(address, 0, length) to zero
        # 4. ctypes.memset signature: memset(void *ptr, int value, size_t num)
        # 5. Return True if successful, False otherwise
        #
        # IMPORTANT: 
        # - For immutable bytes, create mutable buffer first
        # - For bytearray/memoryview, zero directly
        # - Verify zeroing by checking first few bytes
        try:
            addr, length, keeper = self._get_memory_address(data)
            ctypes.memset(addr, 0, length)
            # verify 
            first_byte = ctypes.cast(addr, ctypes.POINTER(ctypes.c_ubyte))[0]
            if first_byte != 0:
                warnings.warn("Zeroing Verification failed")
                return False
            return True
        except Exception as e:
            warnings.warn(f"SecureMemory: zeroize failed: {e}")
            return False

        
        
