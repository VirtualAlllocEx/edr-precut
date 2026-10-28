# Precut

Precut is a minimal proof-of-concept that demonstrates a timing window in the Windows PE loader. The window sits between the execution of an EXE's TLS callbacks and the moment `NtTestAlert` drains the kernel-queued APCs that deliver EDR user-mode hooking DLLs into the process. Inside it, the hooking modules have not been mapped yet. Precut registers a DLL load notification from within the TLS callback, then uses that notification to overwrite each hooking DLL's entry point before the loader ever calls `DllMain`. The hooks are never planted. The syscall stubs in `ntdll` and `KERNELBASE` stay clean.

This repository is the companion code for the blog post [EDR Analysis: TLS Callbacks and User-Mode Hook Initialization](https://redops.at/en/blog/edr-analysis-tls-callbacks-and-user-mode-hook-initialization), which walks through the full analysis — from kernel callback to user-mode hook installation — and explains how the window was found, why it exists, and what its boundaries are.

## The timing window

When a new process starts on Windows, `ntdll!LdrpInitializeProcess` is responsible for bringing the image to life. Part of that work includes processing the PE's TLS directory: if the executable declares TLS callbacks, the loader invokes them early — before the C runtime initializes, before `main` runs, and critically, before `NtTestAlert` is called.

`NtTestAlert` is the gate. It checks the current thread's APC queue and drains any pending entries. EDR kernel drivers that want to inject a user-mode hooking engine typically queue an APC from an image-load or process-creation callback in the kernel. That APC carries the instructions to map the hooking DLL into the process, but it doesn't execute until the loader reaches `NtTestAlert`. Everything that happens before that call — including EXE TLS callbacks — runs in a process where the EDR's user-mode component does not yet exist.

That is the window Precut lives in.

## How Precut works

The entire mechanism is two functions and a six-byte stub.

**`tls_callback`** runs at `DLL_PROCESS_ATTACH` during `LdrpInitializeProcess`, before `NtTestAlert`. It does two things. First, it walks the PEB's `InMemoryOrderModuleList` looking for any matching EDR images that are somehow already mapped (Write A). On a typical APC-based EDR this walk finds nothing — the hooking DLLs aren't there yet — but it acts as a safety net for edge cases where the image arrives earlier than expected. Second, it resolves `ntdll!LdrRegisterDllNotification` by name and registers `on_dll_loaded` as a DLL load notification callback. That registration writes zero bytes to any entry point; it simply tells the loader "call me whenever you map a new DLL."

**`on_dll_loaded`** fires for every DLL map after registration. The loader calls it with reason `LDR_DLL_NOTIFICATION_REASON_LOADED`, which means the image has been mapped into the address space and added to the loader's data structures, but `LdrpCallInitRoutine` has not yet invoked the DLL's `DllMain`. For each image whose basename matches the target list, Precut walks the PE headers to find `AddressOfEntryPoint`, flips the page to `PAGE_EXECUTE_READWRITE`, and writes six bytes:

```
B8 01 00 00 00 C3    mov eax, 1 / ret
```

This is the DllMain contract: return nonzero to tell the loader "initialization succeeded." The loader proceeds to call what it believes is `DllMain` at that address — and gets the stub instead. The real initialization code never executes. No hook-installation routines run, no ordinal exports are called, and no `E9` jmp patches land on syscall stubs. The images stay mapped in memory (they just never do anything), and `main` returns immediately because the method is already finished before it runs.

## Placeholder DLL names

**This repository does not contain any real EDR vendor module names.** The `is_hooking_dll()` function ships with non-functional placeholders that match nothing on a live system:

```c
static int is_hooking_dll(const wchar_t *basename)
{
    if (prefix_dll(basename, L"edr_hook"))             return 1;
    if (prefix_dll(basename, L"edr_dev"))              return 1;
    if (wicmp(basename, L"edrclient64.dll") == 0)      return 1;
    if (wicmp(basename, L"edrclient.dll") == 0)        return 1;
    return 0;
}
```

Before you build this for a lab environment, you need to replace these entries with the actual basenames of the hooking DLLs injected by whatever EDR product you're analyzing. The matching supports two patterns: `prefix_dll()` does a case-insensitive prefix match followed by a `.dll` suffix check (useful for versioned module names like `edr_hook12345.dll`), and `wicmp()` does a full case-insensitive string comparison for exact names. The blog post covers how to identify the correct module names using a kernel debugger and `lm` output.

## Build

Precut must be compiled with MSVC. The TLS callback registration depends on MSVC-specific compiler machinery that GCC and MinGW cannot reliably reproduce:

- `#pragma section(".CRT$XLB", long, read)` places the callback pointer into the CRT's TLS callback collection section. The linker merges `.CRT$XLA` through `.CRT$XLZ` in alphabetical order to build the callback array that the loader walks. This is an MSVC/link.exe convention — MinGW's linker handles `.CRT$` sections differently and does not guarantee the same merge behavior.
- `__declspec(allocate(".CRT$XLB"))` assigns the callback pointer to that specific section. No GCC equivalent produces the same PE layout.
- `__declspec(thread)` on the sentinel variable keeps the TLS apparatus alive. Without a live TLS variable, the linker may optimize away the entire TLS directory, and the callback never fires.
- `/INCLUDE:_tls_used` forces the linker to emit the `IMAGE_TLS_DIRECTORY64` structure even when no code references `_tls_used` by name. This is what makes `dumpbin /tls` show the callback address in the output binary.

A MinGW `.CRT$XLB` section without the corresponding TLS directory is not equivalent — the callback pointer exists in the binary but the loader never sees it.

**Requirements:** Visual Studio 2022 with the v143 platform toolset, targeting x64. The project is configured for `/MT` (static CRT linkage) so the output binary has no CRT DLL dependencies.

Open `PrecutCore.sln` in Visual Studio and build `Release|x64`, or from a VS2022 Developer Command Prompt:

```
MSBuild PrecutCore.sln /p:Configuration=Release /p:Platform=x64
```

The output lands in `x64\Release\PrecutCore.exe`. To confirm the TLS directory made it into the binary:

```
dumpbin /tls x64\Release\PrecutCore.exe
```

You should see a TLS directory entry with a non-zero callback address. If the TLS section is missing or the callback array is empty, the linker dropped it — check that `/INCLUDE:_tls_used` is set in the project properties under Linker → Input → Force Symbol References.

## Verification

Run `PrecutCore.exe` on a lab VM where the target EDR sensor is active. The binary does nothing visible — `main` returns immediately — but the entry-point writes have already happened by the time it exits. To confirm:

Attach WinDbg to the process before launch (or use `ntsd -G -g PrecutCore.exe`). Set a breakpoint on `ntdll!NtTestAlert` and let execution reach it — at that point TLS has already run and the notification is registered, but the EDR DLLs haven't been mapped yet. Continue past the breakpoint and let the process finish. Then examine the EDR modules:

```
lm m edr_*
```

(Replace `edr_*` with the actual module name pattern from your target EDR.)

The modules will appear as mapped (they have a base address and image size) but their entry points contain `B8 01 00 00 00 C3` instead of the real `DllMain` prologue. To verify that the syscall stubs were not hooked, read six bytes from a known hook target:

```
db ntdll!NtProtectVirtualMemory L6
```

A clean result shows `4C 8B D1 B8 xx xx` — the `mov r10, rcx` / `mov eax, <syscall_number>` sequence of an unpatched syscall stub. If byte +3 is `E9` (a relative jmp), the EDR's inline hook landed, which means either the target DLL names in `is_hooking_dll()` were wrong, or the EDR uses an injection path that completes before EXE TLS.

## Scope and limitations

Precut targets one specific initialization order: EDR products that deliver their user-mode hooking engine via a kernel APC that drains at `NtTestAlert`, after EXE TLS callbacks have already executed. This is a common pattern, but not the only one.

EDR products that map their hooking DLL synchronously from a kernel image-load callback — completing the map before control returns to user-mode loader code — will have their module present in the PEB loader list before TLS runs. The PEB walk (Write A) is a partial defense against this, but if the EDR's `DllMain` also runs synchronously during that kernel callback's completion, the hooks are already installed before Precut gets a chance to act. The blog post discusses this distinction in detail and shows how to determine which path a given product uses.

The undocumented loader structures and notification API used here have been stable across Windows 10 and Windows 11 (tested through 10.0.26100). Older versions (Windows 7/8) expose the same `LdrRegisterDllNotification` export but have not been verified.

The code is x64 only. The PEB is read via `gs:[0x60]`, the `IMAGE_NT_HEADERS` layout assumes the 64-bit optional header, and the six-byte stub (`mov eax, 1` / `ret`) is an x64 instruction sequence. A 32-bit port would need different register-width assumptions and a `fs:[0x30]` PEB read.

Precut exists to teach EDR initialization order on Windows — not as an evasion framework, and not for production use or unauthorized testing.

## Disclaimer

This code is published for educational purposes and authorized security research only. It is intended to help defenders and researchers understand EDR initialization order on Windows. Do not use it against systems you do not own or do not have explicit written permission to test. The author assumes no liability for misuse.

## Author

Daniel Feichter ([@VirtualAlllocEx](https://github.com/VirtualAlllocEx)) — [RedOps](https://redops.at)
