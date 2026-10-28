# Precut

Precut is a minimal proof-of-concept that demonstrates a timing window in the Windows PE loader. The window sits between the execution of an EXE's TLS callbacks and the moment `NtTestAlert` drains the kernel-queued APCs that deliver EDR user-mode hooking DLLs into the process. Inside it, the hooking modules have not been mapped yet. Precut registers a DLL load notification from within the TLS callback, then uses that notification to overwrite each hooking DLL's entry point before the loader ever calls `DllMain`. The hooks are never planted. The syscall stubs in `ntdll` and `KERNELBASE` stay clean.

This repository is the companion code for the blog post [EDR Analysis: TLS Callbacks and User-Mode Hook Initialization](https://redops.at/en/blog/edr-analysis-tls-callbacks-and-user-mode-hook-initialization), which walks through the full analysis — from kernel callback to user-mode hook installation — and explains how the window was found, why it exists, and what its boundaries are.

## The timing window

When a new process starts on Windows, `ntdll!LdrpInitializeProcess` is responsible for bringing the image to life. Part of that work includes processing the PE's TLS directory: if the executable declares TLS callbacks, the loader invokes them early — before the C runtime initializes, before `main` runs, and critically, before `NtTestAlert` is called.

`NtTestAlert` is the gate. It checks the current thread's APC queue and drains any pending entries. EDR kernel drivers that want to inject a user-mode hooking engine typically queue an APC from an image-load or process-creation callback in the kernel. That APC carries the instructions to map the hooking DLL into the process, but it doesn't execute until the loader reaches `NtTestAlert`. Everything that happens before that call — including EXE TLS callbacks — runs in a process where the EDR's user-mode component does not yet exist.

That is the window Precut lives in.

## How Precut works

The entire mechanism is two functions and a six-byte stub.

**`tls_callback`** runs at `DLL_PROCESS_ATTACH` during `LdrpInitializeProcess`, before `NtTestAlert`. It does two things. First, it walks the PEB's `InMemoryOrderModuleList` looking for any matching EDR images that are somehow already mapped (Write A). On a typical APC-based EDR this walk finds nothing — the hooking DLLs aren't there yet — but it acts as a safety net for edge cases where the image arrives earlier than expected. Second, it resolves `ntdll!LdrRegisterDllNotification` by name and registers a DLL load notification callback. That registration writes zero bytes to any entry point; it simply tells the loader "call me whenever you map a new DLL."

**`on_dll_loaded`** fires for every DLL map after registration. The loader calls it with reason `LDR_DLL_NOTIFICATION_REASON_LOADED`, which means the image has been mapped into the address space and added to the loader's data structures, but `LdrpCallInitRoutine` has not yet invoked the DLL's `DllMain`. For each image whose basename matches the target list, Precut walks the PE headers to find `AddressOfEntryPoint`, flips the page to `PAGE_EXECUTE_READWRITE`, and writes six bytes:

```
B8 01 00 00 00 C3    mov eax, 1 / ret
```

This is the DllMain contract: return nonzero to tell the loader "initialization succeeded." The loader proceeds to call what it believes is `DllMain` at that address — and gets the stub instead. The real initialization code never executes. No hook-installation routines run, no ordinal exports are called, and no `E9` jmp patches land on syscall stubs. The images stay mapped in memory (they just never do anything), and `main` returns immediately because the method is already finished before it runs.

## Repository layout

The technique ships in three forms, each suited to a different integration scenario.

**`precut.c`** at the repository root is the original standalone proof-of-concept — the code the blog post walks through line by line. It is self-contained, heavily commented, and builds into its own executable via `PrecutCore.sln`. If you are reading the blog post or studying the technique for the first time, start here.

**`precut.h`** is a single-header library that packages the same mechanism for drop-in use in existing loaders and tooling. Define your target DLL names, include the header, and call `precut_arm()` from wherever you get early execution. It adds a callback interface, a stub counter, and a `precut_disarm()` function for cleaning up the notification after your payload is running.

**`shellcode/`** contains a position-independent variant of the technique. No CRT, no import table — every API is resolved at runtime via PEB walking and manual export-table parsing. This version is meant to be compiled, have its `.text` section extracted, and used as raw shellcode that runs from a TLS slot or any other early execution primitive.

**`examples/`** holds two integration templates: `standalone.c` shows a minimal binary built entirely from `precut.h` with automatic TLS registration, and `loader_integration.c` shows how to wire the header library into an existing loader that already has its own TLS callback or early-init path.

## Standalone PoC (precut.c)

The standalone binary is the simplest way to see the technique in action. It does everything itself — TLS registration, the PEB walk, the notification callback, the entry-point write — and returns immediately from `main`. No console output, no dependencies beyond the Windows API.

**Requirements:** Visual Studio 2022 with the v143 platform toolset, targeting x64. The project uses `/MT` (static CRT) so the output has no runtime DLL dependencies.

Open `PrecutCore.sln` in Visual Studio and build `Release|x64`, or from a VS2022 Developer Command Prompt:

```
MSBuild PrecutCore.sln /p:Configuration=Release /p:Platform=x64
```

Output: `x64\Release\PrecutCore.exe`. Confirm the TLS directory made it into the binary:

```
dumpbin /tls x64\Release\PrecutCore.exe
```

You should see a TLS directory entry with a non-zero callback address. If the section is missing, check that `/INCLUDE:_tls_used` is set under Linker → Input → Force Symbol References.

## Header library (precut.h)

The header library turns the technique into a reusable component. In exactly one `.c` file in your project, define `PRECUT_IMPLEMENTATION`, set your target list, and include the header:

```c
#define PRECUT_IMPLEMENTATION

#define PRECUT_TARGETS                  \
    PRECUT_PREFIX(L"edr_hook")          \
    PRECUT_PREFIX(L"edr_dev")           \
    PRECUT_EXACT(L"edrclient64.dll")

#include "precut.h"
```

Replace the placeholder names with the real basenames of the EDR hooking DLLs in your lab. `PRECUT_PREFIX` does a case-insensitive prefix match with a `.dll` suffix guard — it catches versioned names like `edr_hook12345.dll` without hitting `edr_hook.cfg`. `PRECUT_EXACT` does a full case-insensitive string comparison for fixed names.

The API is four functions:

- **`precut_arm()`** walks the PEB loader list to stub any matching images already mapped (Write A), then registers a DLL load notification via `LdrRegisterDllNotification` to catch everything mapped afterwards (Write B). Call it from a TLS callback, a reflective loader's early init, or anywhere else that runs before `NtTestAlert`.

- **`precut_disarm()`** unregisters the notification callback via `LdrUnregisterDllNotification`. Call it after your payload is initialized and running — it removes the notification from ntdll's internal callback list, which reduces the forensic surface left behind.

- **`precut_set_callback(fn)`** registers a function that fires after every stub attempt. The signature is `void fn(const wchar_t *name, void *base, int ok)` where `ok` is 1 on success and 0 on failure (e.g. `VirtualProtect` was denied). Use it to log which modules were hit or to gate payload execution on a minimum stub count.

- **`precut_stub_count()`** returns the total number of entry points successfully stubbed so far. A quick check in your loader's main path: if this returns zero, nothing matched and the hooks may still be live.

For standalone binaries that need their own TLS callback, define `PRECUT_TLS_AUTO` before including the header. This emits the MSVC `.CRT$XLB` plumbing so `precut_arm()` runs automatically at process attach — no manual TLS setup required. Define `PRECUT_STATIC` to make all API functions `static` (this is implied by `PRECUT_TLS_AUTO`).

See `examples/standalone.c` for the minimal standalone case and `examples/loader_integration.c` for a loader that calls `precut_arm()` from its own TLS callback, checks the stub count, runs a payload, and disarms afterwards.

## Shellcode variant (shellcode/)

The `shellcode/` directory contains a fully position-independent implementation of the Precut mechanism. It has no CRT dependency, no import table, and no relocations — every Windows API it needs is resolved at runtime by walking the PEB's module list to locate `ntdll.dll`, then parsing its export address table to find `LdrRegisterDllNotification` and `NtProtectVirtualMemory` by name. All string literals are built as stack-allocated character arrays so they live in the function's stack frame rather than a `.rdata` section, which keeps the code position-independent after extraction.

The kernel32 dependency that the other variants carry (`GetModuleHandleW`, `GetProcAddress`, `VirtualProtect`) is eliminated entirely. The PEB walk finds ntdll directly (it is always the first or second entry in the loader list), and page protection changes go through `NtProtectVirtualMemory` — the native syscall wrapper that `VirtualProtect` calls internally. This means the shellcode depends only on ntdll, which is always mapped before any user-mode code runs.

Build it with the included batch script:

```
cd shellcode
build.bat
```

The script compiles with MSVC, links a minimal PE, and extracts the raw `.text` section to a `.bin` file via PowerShell PE header parsing. The resulting shellcode is a function with no arguments — call it from a TLS slot, a loader's early init, or any context that executes before `NtTestAlert` drains the APC queue. The caller is responsible for arranging that early execution; the shellcode itself does not register a TLS callback (it has no PE headers to declare one in).

Target DLL names are compiled into the shellcode as stack strings. Edit them in `precut_pic.c` before building.

## Placeholder DLL names

**None of the three variants contain real EDR vendor module names.** Every target list ships with non-functional placeholders (`edr_hook`, `edr_dev`, `edrclient64.dll`, `edrclient.dll`) that match nothing on a live system. Before building for a lab environment, replace these with the actual basenames of the hooking DLLs injected by whatever EDR product you are analyzing. The blog post covers how to identify the correct module names using a kernel debugger, `lm` output, and breakpoints on `ntdll!LdrLoadDll`.

## Build requirements

The standalone PoC and the header library must be compiled with MSVC. The TLS callback registration depends on MSVC-specific compiler machinery that GCC and MinGW cannot reliably reproduce:

- `#pragma section(".CRT$XLB", long, read)` places the callback pointer into the CRT's TLS callback collection section. The linker merges `.CRT$XLA` through `.CRT$XLZ` in alphabetical order to build the callback array. MinGW's linker handles `.CRT$` sections differently and does not guarantee the same merge behavior.
- `__declspec(allocate(".CRT$XLB"))` assigns the callback pointer to that specific section. No GCC equivalent produces the same PE layout.
- `__declspec(thread)` on the sentinel variable keeps the TLS apparatus alive. Without it, the linker may optimize away the entire TLS directory and the callback never fires.
- `/INCLUDE:_tls_used` forces the linker to emit the `IMAGE_TLS_DIRECTORY64` structure. This is what makes `dumpbin /tls` show the callback address in the output binary.

A MinGW `.CRT$XLB` section without the corresponding TLS directory is not equivalent — the callback pointer exists in the binary but the loader never sees it.

The shellcode variant has its own `build.bat` and needs a VS2022 Developer Command Prompt (`cl.exe` and `link.exe`) with PowerShell available for the `.text` extraction step. It does not use TLS plumbing itself since the caller provides early execution.

## Verification

Run the standalone binary (or your loader with Precut integrated) on a lab VM where the target EDR sensor is active. Attach WinDbg before launch, or use `ntsd -G -g PrecutCore.exe`. Set a breakpoint on `ntdll!NtTestAlert` — at that point the TLS callback has already run and the notification is registered, but the EDR DLLs have not been mapped yet. Continue past the breakpoint and let the process finish. Then examine the modules:

```
lm m edr_*
```

(Replace `edr_*` with the actual module name pattern from your target EDR.)

The modules will appear as mapped but their entry points contain `B8 01 00 00 00 C3` instead of the real `DllMain` prologue. To verify the syscall stubs were not hooked:

```
db ntdll!NtProtectVirtualMemory L6
```

A clean result shows `4C 8B D1 B8 xx xx` — the `mov r10, rcx` / `mov eax, <syscall_number>` sequence of an unpatched syscall stub. If byte +3 is `E9`, the EDR's inline hook landed — either the target DLL names were wrong, or the product uses an injection path that completes before EXE TLS.

## Scope and limitations

Precut targets one specific initialization order: EDR products that deliver their user-mode hooking engine via a kernel APC that drains at `NtTestAlert`, after EXE TLS callbacks have already executed. This is a common pattern, but not the only one.

EDR products that map their hooking DLL synchronously from a kernel image-load callback — completing the map before control returns to user-mode loader code — will have their module present in the PEB loader list before TLS runs. The PEB walk (Write A) is a partial defense against this, but if the EDR's `DllMain` also runs synchronously during that callback's completion, the hooks are already installed before Precut gets a chance to act. The blog post discusses this distinction in detail.

The shellcode variant carries an additional constraint: it does not register its own TLS callback. The caller must arrange early execution — from a TLS slot in the host PE, a reflective loader's init path, or any other mechanism that runs before `NtTestAlert`. If the shellcode runs after the APC has already drained, the hooking DLLs are mapped with their real `DllMain` already called, and the technique has no effect.

The undocumented loader structures and notification API used here have been stable across Windows 10 and Windows 11 (tested through 10.0.26100). Older versions (Windows 7/8) expose the same `LdrRegisterDllNotification` export but have not been verified.

All code is x64 only. The PEB is read via `gs:[0x60]`, the `IMAGE_NT_HEADERS` layout assumes the 64-bit optional header, and the six-byte stub is an x64 instruction sequence. A 32-bit port would need `fs:[0x30]` and different register-width assumptions.

## Disclaimer

This code is published for educational purposes and authorized security research only. It is intended to help defenders and researchers understand EDR initialization order on Windows. Do not use it against systems you do not own or do not have explicit written permission to test. The author assumes no liability for misuse.

## Author

Daniel Feichter ([@VirtualAlllocEx](https://github.com/VirtualAlllocEx)) — [RedOps](https://redops.at)
