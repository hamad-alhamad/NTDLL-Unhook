# NTDLL Unhook

proper ntdll .text section unhooking via native api. x86/x64/wow64 supported.

## How It Works

The program walks the PEB to locate ntdll.dll base address and manually parses the PE export table to resolve NT API functions without touching the Import Address Table. It then uses NtOpenFile to open the clean ntdll.dll from disk, creates a section object with NtCreateSection, and maps it into the process with NtMapViewOfSection to get an unhook source without actually loading a second dll via LoadLibrary. The hooked .text section gets changed to PAGE_EXECUTE_READWRITE via NtProtectVirtualMemory, the clean .text is copied over the hooked one with a custom memcpy, and then protection is restored to original flags. After byte-by-byte verification that the unhook worked, the clean copy gets properly unmapped with NtUnmapViewOfSection so there's no second ntdll left loaded in memory.

## Why Most Unhooks Are Trash

Most public unhook code is literally copy-pasted from the same garbage source (like the ired.team example and basically almost every opensource unhooker on github) and has massive issues that make it useless against any real EDR. They use VirtualProtect instead of native APIs which defeats the entire point since you're calling hooked functions to unhook functions, they set RWX permissions on the .text section which is a massive IOC that EDRs flag immediately, and they don't actually unmap the clean copy because CloseHandle on a section mapping doesn't free the memory. You need UnmapViewOfFile or NtUnmapViewOfSection but everyone forgets this part, so they leave two copies of ntdll loaded in the process which is basically a giant neon sign saying "im malware". They also try to use FreeLibrary on the main ntdll which doesn't even work and causes handle leaks, plus they change protection to RWX twice unnecessarily when once is enough if you restore it properly.

## OPSEC Considerations

This implementation fixes the common bugs in public unhook code by using native APIs throughout (NtOpenFile, NtCreateSection, NtMapViewOfSection, NtProtectVirtualMemory), properly unmapping the clean copy with NtUnmapViewOfSection to avoid leaving two ntdll copies loaded, not using FreeLibrary on main ntdll, and verifying success via memory comparison. However it does NOT avoid the fundamental IOCs that modern EDRs detect. Using NtOpenFile on C:\Windows\System32\ntdll.dll is an IOC that gets logged, NtCreateSection with SEC_IMAGE pointing to ntdll.dll is tracked via ETW, modifying memory protection on ntdll's .text section is a huge red flag even with native APIs, and writing to .text is detectable via memory write callbacks. This technique is well-known and modern EDRs like CrowdStrike and SentinelOne have signatures for the entire pattern. Advanced EDRs like Microsoft Defender for Endpoint and Elastic don't even use usermode hooks anymore since they rely on kernel callbacks and ETW telemetry, so unhooking does literally nothing against them. This works against basic EDRs that only use inline hooks and older security products, but fails against anything with kernel-mode components or behavioral analysis. Better alternatives include direct syscalls where you never call hooked functions in the first place, heaven's gate for wow64 boundary crossing, manual syscall extraction from ntdll .text at runtime, or just avoiding suspicious APIs entirely since unhooking in 2024/2025 is generally a dead technique against real enterprise EDR.

## Architecture Support

Works on x64 native processes, x86 native processes, and wow64 processes (x86 on x64 windows). It automatically detects wow64 and uses the correct system directory (System32 vs SysWOW64) so you don't have to think about it.

## What Gets Unhooked

Only the .text section of ntdll.dll gets touched because that's where all the actual function code lives and where EDR hooks are placed as inline function hooks (jmp instructions at function prologues). Other sections like .data and .rdata are left alone because there's no reason to touch them and it just creates more IOCs for no benefit.

## Build

```
cl /EHsc /std:c++17 main.cpp /Fe:unhook.exe
```

or whatever, any modern c++ compiler works. needs windows.h and winternl.h.

## CFAA

unauthorized access to computer systems is illegal. use on systems you own or have authorization to test on. federal pound-me-in-the-ass prison is real.

## Technical Notes

The code uses CONTAINING_RECORD macro to walk LDR lists properly, accesses PEB via segment registers (gs on x64, fs on x86), does hardcoded .text section search via name comparison which could be more elegant but whatever it works, handles errors via NTSTATUS codes and NT_SUCCESS macro, and wraps memory operations in SEH try/except for safety. If you can't read c++ and understand PE format internals you probably shouldn't be using this anyway.
