from .utils import get_system_info

__all__ = ()

SYSTEM_INFO = get_system_info()

if SYSTEM_INFO.architecture == 0:  # x86
    SHELLCODE = bytearray(
        b'\xFF\x74\x24\x04'      # 0000: push DWORD PTR [esp+4]
        b'\xE8\x00\x00\x00\x00'  # 0004: call LoadLibraryW@4
        b'\x85\xC0'              # 0009: test eax,eax
        b'\x74\x04'              # 000b: je 11 <error>
        b'\x31\xC0'              # 000d: xor eax,eax
        b'\xEB\x05'              # 000f: jmp 16 <success>
        b'\xE8\x00\x00\x00\x00'  # 0011 error: call GetLastError@0
        b'\xC2\x04\x00'          # 0016 success: ret 4
        b'\x90\x90\x90'          # 0019: nop nop nop
    )
elif SYSTEM_INFO.architecture == 5:  # ARM
    pass
elif SYSTEM_INFO.architecture in (6, 9):  # x64
    pass
elif SYSTEM_INFO.architecture == 12:  # AArch64
    pass
else:  # Unknown architecture.
    raise RuntimeError('Unknown architecture')

# TODO: Implement DLL injection for Windows systems.
