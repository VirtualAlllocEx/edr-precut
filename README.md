# Precut

Proof-of-concept demonstrating a PE TLS callback timing window that prevents EDR user-mode hooking DLLs from initializing.

Companion code for the blog post: [EDR Analysis: TLS Callbacks and User-Mode Hook Initialization](https://redops.at/en/blog/edr-analysis-tls-callbacks-and-user-mode-hook-initialization)

## How it works

The Windows PE loader processes TLS callbacks during `LdrpInitializeProcess`, **before** it calls `NtTestAlert`. EDR products that deliver their user-mode hooking engines via queued APCs (kernel → `NtTestAlert` → DLL map → `DllMain` → hook installation) have a timing gap: the hooking DLLs are not yet mapped when the EXE's TLS callback runs.

Precut exploits this gap with two functions:

1. **`tls_callback`** — Executes at process attach, before `NtTestAlert` drains the APC queue. It walks the PEB loader list to stub any matching images that are somehow already mapped (Write A — normally zero hits), then registers `on_dll_loaded` via `ntdll!LdrRegisterDllNotification`.

2. **`on_dll_loaded`** — Fires for every subsequent DLL map (reason `LOADED`), after the image is mapped into memory but **before** the loader calls `DllMain`. For each matching EDR module it overwrites `AddressOfEntryPoint` with:
   ```
   B8 01 00 00 00 C3    ; mov eax, 1 / ret
   ```
   The loader calls this stub instead of the real `DllMain`. The hooking routines never execute. No inline hooks land in `ntdll` or `KERNELBASE`. The images remain mapped.

`main` returns immediately — the method is complete before it runs.

## Important: placeholder DLL names

**This repository ships with non-functional placeholder DLL names.** The `is_hooking_dll()` function in `precut.c` contains example prefixes (`edr_hook`, `edr_dev`) and example exact names (`edrclient64.dll`, `edrclient.dll`) that do not match any real product.

Before building for your lab, replace these placeholders with the actual module basenames of the EDR product you are analyzing:

```c
static int is_hooking_dll(const wchar_t *basename)
{
    /* Replace these with real DLL name prefixes/names from your target EDR */
    if (prefix_dll(basename, L"edr_hook"))             return 1;  // <-- your prefix here
    if (prefix_dll(basename, L"edr_dev"))              return 1;  // <-- your prefix here
    if (wicmp(basename, L"edrclient64.dll") == 0)      return 1;  // <-- your exact name here
    if (wicmp(basename, L"edrclient.dll") == 0)        return 1;  // <-- your exact name here
    return 0;
}
```

Identifying the correct module names is part of the analysis — the blog post walks through how to find them using a debugger.

## Build

**Requirements:** Visual Studio 2022 (v143 toolset), x64 only.

Open `PrecutCore.sln` and build `Release|x64`, or from a Developer Command Prompt:

```
MSBuild PrecutCore.sln /p:Configuration=Release /p:Platform=x64
```

Output: `x64\Release\PrecutCore.exe`

The project enforces `/MT` (static CRT) and `/INCLUDE:_tls_used` (forces the linker to emit a TLS directory). Verify with:

```
dumpbin /tls x64\Release\PrecutCore.exe
```

## Verification

On a lab VM with the target EDR sensor active:

1. Set a breakpoint on `ntdll!NtTestAlert` in WinDbg before launching the binary
2. Read `ntdll!NtProtectVirtualMemory` before and after — `4C 8B D1 B8` at byte +0 means the syscall stub was never patched with an inline hook (`E9` at byte +3 would indicate a hook was planted)
3. Check `lm` output — the EDR modules are mapped but their entry points contain the `B8 01 00 00 00 C3` stub

## Scope and limitations

- **x64 only** — PEB offsets, the `gs:[0x60]` read, and the stub bytes are x64-specific.
- **APC-delivered hooks only** — EDR products that map their hooking DLL before EXE TLS (e.g. via an image-load kernel callback that completes synchronously) are not affected by this timing window. The PEB walk (Write A) is a partial fallback for that case.
- **Lab/research use only** — This is a teaching tool for understanding EDR initialization order, not an evasion framework.

## License

This project is provided for educational and authorized security research purposes.

## Author

Daniel Feichter ([@VirtualAlllocEx](https://github.com/VirtualAlllocEx)) — [RedOps](https://redops.at)
