from struct import pack

from win32api import *
from win32security import *

from .utils import get_system_info

__all__ = ()

SYSTEM_INFO = get_system_info()

# Prepare DLL loading shellcode for different architectures.
# Signature: unsigned long load_dll(const wchar_t* dll);
if SYSTEM_INFO.architecture == 0:  # x86
    POINTER_WIDTH = 32

    LoadLibraryW_START = 0x0004 + 1
    LoadLibraryW_END = LoadLibraryW_START + POINTER_WIDTH >> 3
    GetLastError_START = 0x0011 + 1
    GetLastError_END = GetLastError_START + POINTER_WIDTH >> 3

    DLL_LOADER = bytearray(
        b'\xFF\x74\x24\x04'      # 0000: push DWORD PTR [esp+4]
        b'\xE8\x00\x00\x00\x00'  # 0004: call LoadLibraryW@4
        b'\x85\xC0'              # 0009: test eax,eax
        b'\x74\x04'              # 000b: je 11 <error>
        b'\x31\xC0'              # 000d: xor eax,eax
        b'\xEB\x05'              # 000f: jmp 16 <success>
        b'\xE8\x00\x00\x00\x00'  # 0011 <error>: call GetLastError@0
        b'\xC2\x04\x00'          # 0016 <success>: ret 4
        b'\x90\x90\x90'          # 0019: nop nop nop
    )
elif SYSTEM_INFO.architecture == 5:  # ARM
    POINTER_WIDTH = 32
elif SYSTEM_INFO.architecture in (6, 9):  # x64
    POINTER_WIDTH = 64
elif SYSTEM_INFO.architecture == 12:  # AArch64
    POINTER_WIDTH = 64
else:  # Unknown architecture.
    raise RuntimeError('Unknown architecture')


def _prepare_shellcode() -> bytes:
    kernel32 = GetModuleHandle('kernel32')

    # Retrieve DLL addresses for functions called in the shellcode.
    LoadLibraryW_address = GetProcAddress(kernel32, 'LoadLibraryW')  # noqa
    GetLastError_address = GetProcAddress(kernel32, 'GetLastError')  # noqa

    # Replace the stubs in the shellcode with their real addresses.
    DLL_LOADER[LoadLibraryW_START:LoadLibraryW_END] = pack('L', LoadLibraryW_address)
    DLL_LOADER[GetLastError_START:GetLastError_END] = pack('L', GetLastError_address)

    return bytes(DLL_LOADER)


def _enable_process_privileges():
    # Retrieve the process access token.
    current_process = GetCurrentProcess()
    token = OpenProcessToken(current_process, TOKEN_ADJUST_PRIVILEGES)

    # Get process LUID.
    try:
        luid = LookupPrivilegeValue(None, SE_DEBUG_NAME)
    except error:
        CloseHandle(token)
        raise

    # Enable privileges for the access token.
    try:
        token_privileges = [(luid, SE_PRIVILEGE_ENABLED)]
        AdjustTokenPrivileges(token, False, token_privileges)
    except error:
        CloseHandle(token)
        raise

    # Finally clean up.
    CloseHandle(token)
