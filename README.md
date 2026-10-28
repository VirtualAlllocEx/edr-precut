# Precut

---

[![Platform](https://img.shields.io/badge/Platform-Windows%20x64-blue.svg)](#build-requirements) [![Language](https://img.shields.io/badge/Language-C-brightgreen.svg)](precut.c) [![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE) [![Toolchain](https://img.shields.io/badge/Toolchain-MSVC%20v143-555555.svg)](#build-requirements) [![Type](https://img.shields.io/badge/Type-Security%20Research-red.svg)](#scope-and-limitations)

A proof-of-concept that prevents EDR user-mode hooking DLLs from initializing by exploiting a timing window in the Windows PE loader — TLS callbacks execute before `NtTestAlert` drains the kernel-queued APCs that deliver the hooking engine. Precut registers a DLL load notification from within that window and overwrites each target's entry point with a six-byte stub before `DllMain` ever runs.

> **Full Write-Up:** [EDR Analysis: TLS Callbacks and User-Mode Hook Initialization](https://redops.at/en/blog/edr-analysis-tls-callbacks-and-user-mode-hook-initialization)

## :warning: Disclaimer

**Educational and security research purposes only.** Use in controlled environments on systems you own or have explicit permission to test. The author accepts no responsibility for misuse.

---

## Codex

| File | What it is | When to use it |
|---|---|---|
| **`precut.c`** | Standalone PoC. All logic inline, builds via `PrecutCore.sln`. | Studying the technique or running it standalone on a lab VM. |
| **`precut.h`** | Single-header library (`#define PRECUT_IMPLEMENTATION`). | Integrating into an existing loader or toolchain. |

`precut.c` is the reference — the code the blog walks through. Compiles into its own binary, no external dependencies.

`precut.h` is what you `#include`. Exposes `precut_arm()` / `precut_disarm()`, compile-time target macros, a stub callback, and an atomic counter.

No `examples/` folder. `precut.c` is the example. Integration snippets for `precut.h` are below.

---

## How It Works

```
CreateProcessW
└─ LdrpInitializeProcess
   ├─ Map EXE + dependencies
   ├─ EXE TLS callbacks              ◄── Precut runs here
   ├─ NtTestAlert                    ◄── EDR's APC drains here
   │    └─ EDR DLLs mapped
   │         └─ LdrpSendDllNotifications  ◄── Precut's observer fires
   │              └─ LdrpCallInitRoutine   (DllMain — already stubbed)
   ├─ PE entry (mainCRTStartup)
   └─ main
```

`NtTestAlert` drains the thread's APC queue. EDR kernel drivers queue their hooking-engine injection as an APC. Until the loader reaches `NtTestAlert`, that APC sits undelivered — the hooking DLL does not exist in the process yet.

Precut lives in that gap. From a TLS callback:

**Write A** — PEB walk over `InMemoryOrderModuleList`. Stubs targets already mapped. Usually 0 hits (APC hasn't drained), but covers edge cases where an image lands before TLS.

**Write B** — Registers `LdrRegisterDllNotification`. When the loader maps a new image, the notification fires *after* the image is in memory but *before* `DllMain`. For each matching basename, Precut overwrites `AddressOfEntryPoint`:

```asm
B8 01 00 00 00    mov eax, 1
C3                ret
```

DllMain contract: nonzero = success. The loader calls the stub, gets TRUE, moves on. Real initialization never runs. No `E9` patches land on syscall stubs.

---

## Building the PoC

Open `PrecutCore.sln` in VS2022, build `Release|x64`. Or:

```
msbuild PrecutCore.sln /p:Configuration=Release /p:Platform=x64
```

Confirm TLS directory exists:

```
dumpbin /tls x64\Release\PrecutCore.exe
```

Non-zero callback address = TLS plumbing is live. If missing, verify `/INCLUDE:_tls_used` in Linker → Input → Force Symbol References.

---

## Integrating the Library (precut.h)

### Standalone binary

```c
#define PRECUT_IMPLEMENTATION
#define PRECUT_TLS_AUTO

#define PRECUT_TARGETS                  \
    PRECUT_PREFIX(L"edr_hook")          \
    PRECUT_PREFIX(L"edr_dev")           \
    PRECUT_EXACT(L"edrclient64.dll")

#include "precut.h"

int main(void)
{
    (void)g_precut_tls_sentinel;
    precut_disarm();
    return 0;
}
```

`PRECUT_TLS_AUTO` emits `.CRT$XLB` plumbing so `precut_arm()` fires at process attach.

### Loader with its own TLS callback

```c
#define PRECUT_IMPLEMENTATION

#define PRECUT_TARGETS                  \
    PRECUT_PREFIX(L"edr_hook")          \
    PRECUT_EXACT(L"edrclient64.dll")

#include "precut.h"

static void on_stub(const wchar_t *name, void *base, int ok)
{
    (void)name; (void)base; (void)ok;
}

static void NTAPI my_tls_callback(PVOID h, DWORD reason, PVOID r)
{
    (void)h; (void)r;
    if (reason != DLL_PROCESS_ATTACH) return;
    precut_set_callback(on_stub);
    precut_arm();
}

#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma section(".CRT$XLB", long, read)
__declspec(allocate(".CRT$XLB"))
    PIMAGE_TLS_CALLBACK g_my_tls = my_tls_callback;
__declspec(thread) static volatile int g_tls_keep = 0;

int main(void)
{
    (void)g_tls_keep;

    if (precut_stub_count() > 0) {
        /* EDR hooks neutralized */
    }

    precut_disarm();
    return 0;
}
```

### Target macros

| Macro | Behavior |
|---|---|
| `PRECUT_PREFIX(L"name")` | Case-insensitive prefix + `.dll` suffix guard. Matches `name12345.dll`, not `name.cfg`. |
| `PRECUT_EXACT(L"name.dll")` | Case-insensitive exact basename match. |

### API

| Function | Description |
|---|---|
| `precut_arm()` | PEB walk (Write A) + register notification (Write B). |
| `precut_disarm()` | Unregister notification. Reduces forensic surface. |
| `precut_set_callback(fn)` | `void fn(const wchar_t *name, void *base, int ok)` |
| `precut_stub_count()` | Entry points stubbed so far. |

### Compile-time options

| Define | Effect |
|---|---|
| `PRECUT_IMPLEMENTATION` | Include the implementation. Exactly one translation unit. |
| `PRECUT_TLS_AUTO` | Auto-register TLS callback that calls `precut_arm()`. Implies `PRECUT_STATIC`. |
| `PRECUT_STATIC` | All API functions `static`. |

---

## Configuring Target DLLs

All targets in this repo are non-functional placeholders (`edr_hook`, `edr_dev`, `edrclient64.dll`, `edrclient.dll`). Replace with real basenames before building. Use `lm` in WinDbg or break on `ntdll!LdrLoadDll` to identify injected modules.

### PREFIX vs EXACT

**`PRECUT_PREFIX`** — for versioned DLLs where the suffix (build number, hash) changes per agent update. Give only the stable leading part:

```c
PRECUT_PREFIX(L"hookengine")   /* hookengine.dll, hookengine8542.dll, ... */
```

**`PRECUT_EXACT`** — for fixed-name DLLs that never change across versions:

```c
PRECUT_EXACT(L"agentclient64.dll")   /* only this exact filename */
```

### Picking the wrong one

| Mistake | What happens |
|---|---|
| `EXACT` on a versioned DLL | Works until the agent updates and the suffix changes. Then silently stops matching — no crash, but EDR hooks load normally. |
| `PREFIX` on a fixed-name DLL | Works fine. Only risk: a generic prefix (e.g. `agent`) could collide with unrelated modules. Stubbing the wrong module crashes the process. |

`PREFIX` is the safer default for vendor-specific names. Use `EXACT` when the prefix is too generic to be collision-free. Add or remove entries freely — no fixed count.

### Example target lists

```c
/* Single-vendor, versioned DLLs */
#define PRECUT_TARGETS                          \
    PRECUT_PREFIX(L"edr_hook")                 \
    PRECUT_PREFIX(L"edr_dev")

/* Multi-vendor, mixed strategies */
#define PRECUT_TARGETS                          \
    PRECUT_PREFIX(L"vendorA_hook")             \
    PRECUT_PREFIX(L"vendorA_dev")              \
    PRECUT_EXACT(L"vendorBclient64.dll")
```

---

## Build Requirements

MSVC only. Four pieces of MSVC-specific machinery:

1. **`#pragma section(".CRT$XLB", long, read)`** — callback pointer into the CRT TLS array. MinGW does not guarantee the same section merge.
2. **`__declspec(allocate(".CRT$XLB"))`** — pins the pointer. No GCC equivalent.
3. **`__declspec(thread)`** — keeps the TLS directory alive.
4. **`/INCLUDE:_tls_used`** — forces emission of `IMAGE_TLS_DIRECTORY64`.

VS2022, v143 toolset, x64, `/MT` (static CRT).

---

## Verification

Run on a lab VM with the target EDR active. Attach WinDbg before launch.

**1. Confirm TLS ran before APC:**

```
bp ntdll!NtTestAlert
g
```

At the break, the notification is registered but EDR DLLs are not yet mapped.

**2. Continue and inspect targets:**

```
g
lm m edr_*
```

Replace `edr_*` with your target pattern. Modules appear mapped but entry points contain `B8 01 00 00 00 C3`.

**3. Verify syscall stubs are clean:**

```
db ntdll!NtProtectVirtualMemory L6
```

Clean: `4C 8B D1 B8 xx xx`. If byte +3 is `E9`, hooks landed — wrong target list or the product injects before TLS.

---

## Scope and Limitations

Precut targets one initialization order: EDR products that deliver their user-mode engine via a kernel APC draining at `NtTestAlert`, after EXE TLS. Common pattern, not the only one.

Products that map synchronously from a kernel image-load callback will have the module present before TLS runs. Write A partially covers this, but if `DllMain` also completes synchronously, hooks are installed before Precut acts. The blog post discusses this boundary.

Loader structures and the notification API have been stable across Win10/11 (tested through 10.0.26100). Win7/8 expose `LdrRegisterDllNotification` but are unverified. x64 only.

---

## References

- Microsoft, [PE Format — The TLS Section](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-tls-section). TLS directory and callback conventions.
- Microsoft, [CRT initialization](https://learn.microsoft.com/en-us/cpp/c-runtime-library/crt-initialization). Runtime init vs application entry.
- Microsoft, [DllMain entry point](https://learn.microsoft.com/en-us/windows/win32/dlls/dllmain) and [DLL Best Practices](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-best-practices). Attachment semantics.
- Hunt & Brubacher, [Detours: Binary Interception of Win32 Functions](https://www.microsoft.com/en-us/research/publication/detours-binary-interception-of-win32-functions/), 1999.
- MDSec, [Bypassing User-Mode Hooks and Direct Invocation of System Calls](https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/), 2020.
- Marcus Hutchins, [Bypassing EDRs With EDR-Preloading](https://malwaretech.com/2024/02/bypassing-edrs-with-edr-preload.html), 2024.
- Guido Miggelenbrink, [Early Cascade Injection](https://www.outflank.nl/blog/2024/10/15/introducing-early-cascade-injection-from-windows-process-creation-to-stealthy-injection/), 2024.

---

## Author

Daniel Feichter ([@VirtualAlllocEx](https://github.com/VirtualAlllocEx)) — [RedOps](https://redops.at)
