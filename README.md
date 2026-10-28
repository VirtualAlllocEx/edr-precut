# Precut

Stub EDR user-mode hooking DLLs before they initialize — from inside the PE loader's own TLS window.

Companion code for [EDR Analysis: TLS Callbacks and User-Mode Hook Initialization](https://redops.at/en/blog/edr-analysis-tls-callbacks-and-user-mode-hook-initialization).

---

## The Technique

When Windows creates a process, `ntdll!LdrpInitializeProcess` walks the PE's TLS directory and fires any registered callbacks early — before the CRT, before `main`, and before `NtTestAlert`. That last point matters. `NtTestAlert` drains the thread's APC queue, and an EDR kernel driver that wants to inject a hooking engine typically queues that injection as an APC from an image-load or process-creation callback. Until the loader reaches `NtTestAlert`, the APC sits undelivered. The hooking DLL does not exist in the process yet.

Precut lives in that window. From inside a TLS callback it does two things:

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

**Write A** walks the PEB's `InMemoryOrderModuleList` looking for targets that are already mapped. On a typical APC-based EDR this finds nothing — the hooking DLLs arrive later — but it covers edge cases where an image lands before TLS.

**Write B** registers a DLL load notification via `ntdll!LdrRegisterDllNotification`. When the loader maps a new image, it calls the notification *after* the image is in the address space but *before* `DllMain` runs. For each matching basename, Precut walks the PE headers to `AddressOfEntryPoint`, flips the page to `PAGE_EXECUTE_READWRITE`, and writes six bytes:

```asm
B8 01 00 00 00    mov eax, 1
C3                ret
```

The DllMain contract: return nonzero means "initialization succeeded." The loader calls what it thinks is `DllMain` and gets the stub. No hook-installation routines run. No `E9` jmp patches land on syscall stubs. The images stay mapped but inert.

---

## Repository Layout

```
precut.c                         Original standalone PoC (blog companion)
PrecutCore.sln / .vcxproj        VS2022 project for the standalone
precut.h                         Single-header library for loader integration
examples/
  standalone.c                   Minimal binary using precut.h
  loader_integration.c           Loader template with callback + stub gating
```

**`precut.c`** is the self-contained proof-of-concept the blog post walks through. Start here if you are reading the analysis or studying the technique for the first time.

**`precut.h`** packages the same mechanism as a drop-in single-header library. Define your targets, include the header, call `precut_arm()`. It adds a callback interface, an atomic stub counter, and `precut_disarm()` for cleanup.

**`examples/`** holds two integration templates — one for standalone binaries, one for loaders that already have their own TLS callback.

---

## Quick Start

Open `PrecutCore.sln` in Visual Studio 2022 and build `Release|x64`, or from a Developer Command Prompt:

```
msbuild PrecutCore.sln /p:Configuration=Release /p:Platform=x64
```

Confirm the TLS directory made it into the binary:

```
dumpbin /tls x64\Release\PrecutCore.exe
```

You should see a TLS directory entry with a non-zero callback address. If the section is missing, check that `/INCLUDE:_tls_used` is set in the project's Linker → Input → Force Symbol References.

---

## Header Library — precut.h

In exactly one `.c` file, define `PRECUT_IMPLEMENTATION`, set your target list, and include the header:

```c
#define PRECUT_IMPLEMENTATION

#define PRECUT_TARGETS                  \
    PRECUT_PREFIX(L"edr_hook")          \
    PRECUT_PREFIX(L"edr_dev")           \
    PRECUT_EXACT(L"edrclient64.dll")

#include "precut.h"
```

For standalone binaries, add `#define PRECUT_TLS_AUTO` before the include — this emits the MSVC `.CRT$XLB` plumbing so `precut_arm()` fires automatically at process attach. See `examples/standalone.c` for the minimal case and `examples/loader_integration.c` for a loader that calls `precut_arm()` from its own TLS callback.

### Target Macros

| Macro | Behavior |
|---|---|
| `PRECUT_PREFIX(L"name")` | Case-insensitive prefix match with `.dll` suffix guard. Catches versioned names like `name12345.dll` without matching `name.cfg`. |
| `PRECUT_EXACT(L"name.dll")` | Case-insensitive exact basename comparison. |

### API

| Function | Description |
|---|---|
| `precut_arm()` | Walk PEB for already-mapped targets (Write A), then register `LdrRegisterDllNotification` (Write B). Call from a TLS callback or any point before `NtTestAlert`. |
| `precut_disarm()` | Unregister the notification via `LdrUnregisterDllNotification`. Reduces forensic surface — the callback list in ntdll is walkable. |
| `precut_set_callback(fn)` | Register `void fn(const wchar_t *name, void *base, int ok)` — fires after each stub attempt. Use it to log hits or gate execution on a minimum count. |
| `precut_stub_count()` | Number of entry points successfully stubbed so far. Zero means no targets matched. |

### Compile-Time Options

| Define | Effect |
|---|---|
| `PRECUT_IMPLEMENTATION` | Include the implementation. Set this in exactly one translation unit. |
| `PRECUT_TLS_AUTO` | Emit MSVC TLS plumbing so `precut_arm()` runs at process attach. Implies `PRECUT_STATIC`. |
| `PRECUT_STATIC` | Make all API functions `static`. |

---

## Placeholder DLL Names

Every target list in this repository ships with non-functional placeholders — `edr_hook`, `edr_dev`, `edrclient64.dll`, `edrclient.dll` — that match nothing on a live system. Before building for a lab environment, replace them with the actual basenames of the hooking DLLs injected by your target EDR product. The blog post covers how to identify the correct names using a kernel debugger, `lm` output, and breakpoints on `ntdll!LdrLoadDll`.

---

## Build Requirements

MSVC only. The TLS callback registration depends on four pieces of MSVC-specific compiler and linker machinery:

1. **`#pragma section(".CRT$XLB", long, read)`** places the callback pointer into the CRT's TLS callback array. The linker merges `.CRT$XLA` through `.CRT$XLZ` alphabetically. MinGW's linker does not guarantee the same merge behavior.

2. **`__declspec(allocate(".CRT$XLB"))`** pins the pointer to that section. No GCC equivalent produces the same PE layout.

3. **`__declspec(thread)`** on the sentinel variable keeps the TLS directory alive. Without it, the linker may optimize away the entire TLS apparatus — the callback pointer exists in the binary but the loader never sees it.

4. **`/INCLUDE:_tls_used`** forces emission of the `IMAGE_TLS_DIRECTORY64` structure. This is what makes `dumpbin /tls` report the callback address.

Visual Studio 2022, v143 platform toolset, x64. The project uses `/MT` (static CRT) so the output has no runtime DLL dependencies.

---

## Verification

Run the binary on a lab VM with the target EDR active. Attach WinDbg before launch, or use `ntsd -G -g PrecutCore.exe`.

**1. Confirm the TLS callback ran before the APC:**

```
bp ntdll!NtTestAlert
g
```

At the breakpoint, the TLS callback has already fired and the notification is registered, but the EDR DLLs have not been mapped yet.

**2. Continue and inspect the target modules:**

```
g
lm m edr_*
```

(Replace `edr_*` with your target module pattern.)

The modules appear as mapped, but their entry points contain `B8 01 00 00 00 C3` instead of the real `DllMain` prologue.

**3. Verify syscall stubs are clean:**

```
db ntdll!NtProtectVirtualMemory L6
```

A clean stub reads `4C 8B D1 B8 xx xx` — the `mov r10, rcx` / `mov eax, <syscall_number>` sequence. If byte `+3` is `E9`, the EDR's inline hook landed — the target list was wrong or the product uses an injection path that completes before TLS.

---

## Scope and Limitations

Precut targets one specific initialization order: EDR products that deliver their user-mode engine via a kernel APC that drains at `NtTestAlert`, after EXE TLS callbacks have already executed. This is a common pattern, but not the only one.

Products that map their hooking DLL synchronously from a kernel image-load callback will have the module present before TLS runs. The PEB walk (Write A) partially covers this, but if the EDR's `DllMain` also completes synchronously during that callback, the hooks are installed before Precut acts. The blog post discusses this distinction in detail.

The undocumented loader structures and notification API used here have been stable across Windows 10 and 11 (tested through 10.0.26100). Older versions (7/8) expose the same `LdrRegisterDllNotification` export but have not been verified.

All code is x64 only. The PEB is read via `gs:[0x60]`, the NT headers layout assumes the 64-bit optional header, and the six-byte stub is an x64 instruction sequence.

---

## Disclaimer

This code is published for educational purposes and authorized security research only. It is intended to help defenders and researchers understand EDR initialization order on Windows. Do not use it against systems you do not own or do not have explicit written permission to test. The author assumes no liability for misuse.

## Author

Daniel Feichter ([@VirtualAlllocEx](https://github.com/VirtualAlllocEx)) — [RedOps](https://redops.at)
