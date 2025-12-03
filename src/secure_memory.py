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

        # TODO: Platformmnh-specific initialization
        if IS_LINUX:
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
                "locked": False, "platform": sys.platform
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
            setattr(self, f"_keeper_{id(data)}", keeper)

        self.locked_regions.append({
            "addr": addr, "length": length, "locked": bool(locked_ok), "id": id(data),
            "platform": ("Windows" if IS_WINDOWS else "unix" if (IS_LINUX or IS_MACOS) else sys.platform)
        })

        return bool(locked_ok)
    
    def _address_and_length(self, data: bytes) -> Tuple[int, int, object]:
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

        # 1. Check if we already have a locked keeper for this object ID
        keeper_name = f"_keeper_{id(data)}"
        if hasattr(self, keeper_name):
            keeper = getattr(self, keeper_name)
            addr = ctypes.addressof(keeper)
            length = len(keeper)
            return addr, length, keeper

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
            # 1. Capture the return value directly
            ret = self.kernel32.VirtualUnlock(ctypes.c_void_p(addr), ctypes.c_size_t(length))
            
            # 2. Check if it succeeded OR if the failure was harmless (Error 158)
            if ret:
                unlocked_ok = True
            else:
                err = ctypes.get_last_error()
                # Accept 158 (Already Unlocked), 487 (Invalid Address), and 0 (Success)
                if err in (158, 487, 0): 
                    unlocked_ok = True
                else:
                    unlocked_ok = False

        elif (IS_LINUX or IS_MACOS) and self.libc is not None and hasattr(self.libc, "munlock"):
            rc = int (self.libc.munlock(ctypes.c_void_p(addr), ctypes.c_size_t(length)))
            unlocked_ok = (rc == 0)
        else:
            warnings.warn("SecureMemory: unlocking not supported on the platform: degraded mode")
            unlocked_ok = False

        if unlocked_ok:
            for region in self.locked_regions:
                # Find the record matching this ID
                if region.get('id') == id(data):
                    region['locked'] = False # Mark as unlocked so cleanup_all skips it

        if not unlocked_ok:
            warnings.warn(f"SecureMemory: memory unlock failed")

        keeper_name = f"_keeper_{id(data)}"
        if hasattr(self, keeper_name):
            delattr(self, keeper_name)

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
        # 1. Get memory address using _address_and_length() helper
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
            addr, length, keeper = self._address_and_length(data)
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
        
    def protect_from_fork(self, data: bytes) -> bool:
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

        # TODO: Implement fork protection
        # HINTS:
        # 1. This is Unix-only (linux/macos) - return true on windows (no-op)
        # 2. Get memory address using _address_and_length()
        # 3. Use libc.madvice(MADV_DONTFORK) on Unix
        # 4. MADV_DONTFORK = 10 on Linux
        # 5. Return True if successful

        # Windows: No fork, so nothing to protect 
        if IS_WINDOWS:
            return True  # no-op here
        if self.libc is None:
            return False
        
        try:
            addr, length, keeper = self._address_and_length(data)

            # MADV_DONTFORK = 10 on Linux
            MADV_DONTFORK = 10

            # Set up madvise if not already done
            if not hasattr(self.libc, 'madvise'):
                self.libc.madvise.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
                self.libc.madvise.restype = ctypes.c_int

            result = self.libc.madvise(addr, length, MADV_DONTFORK)
            return result == 0
        
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
        # TODO: Implement cleanup
        # HINTS:
        # 1. Iterate over self.locked_regions
        # 2. For each region that is still "locked":
        #    a. Get the keeper object if stored
        #    b. Zero the memory using ctypes.memset
        #    c. Unlock the memory
        # 3. Clear the locked_regions list
        # 4. Don't raise exceptions (log warnings instead)

        for region in self.locked_regions:
            try: 
                addr = region.get('addr')
                length = region.get('length', 0)
                locked = region.get('locked', False)
                data_id = region.get('id')

                if addr is None or length ==0:
                    continue

                # Zero the memory first 
                try:
                    ctypes.memset(addr, 0, length)
                except Exception:
                    pass # Best efforts

                # Unlock if it was locked

                if locked:
                    if IS_WINDOWS and self.kernel32:
                        self.kernel32.VirtualUnlock(addr, length)
                    elif self.libc and hasattr(self.libc, 'munlock'):
                        self.libc.munlock(addr, length)

                # clean up keeper reference
                if data_id:
                    keeper_attr = f"_keeper_{data_id}"
                    if hasattr(self, keeper_attr):
                        delattr(self, keeper_attr)

            except Exception as e:
                pass # Best effort - Don't crash on cleanup

        # Clear the list
        self.locked_regions.clear()