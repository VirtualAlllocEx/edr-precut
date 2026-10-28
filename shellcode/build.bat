@echo off
:: ========================================================================
::  build.bat — compile precut_pic.c and extract raw .text section
:: ========================================================================
::
::  Run from a VS2022 x64 Developer Command Prompt:
::    cd shellcode
::    build.bat
::
::  Output:
::    precut_pic.exe  — linked binary (entry: precut_pic_entry)
::    precut_pic.bin  — raw .text section, ready for embedding
::
::  The /NODEFAULTLIB and /ENTRY flags are set in the source via #pragma,
::  so cl.exe only needs the linker flags for merge and alignment.
:: ========================================================================

setlocal

set SRC=precut_pic.c
set OUT=precut_pic
set TEXTBIN=%OUT%.bin

echo [*] Compiling %SRC% ...
cl.exe /nologo /O1 /GS- /W4 /c %SRC% /Fo%OUT%.obj
if errorlevel 1 (
    echo [!] Compilation failed.
    exit /b 1
)

echo [*] Linking %OUT%.exe ...
link.exe /nologo /SUBSYSTEM:CONSOLE /MACHINE:X64 ^
    /MERGE:.rdata=.text /SECTION:.text,ERW ^
    /OUT:%OUT%.exe %OUT%.obj kernel32.lib
if errorlevel 1 (
    echo [!] Link failed.
    exit /b 1
)

echo [*] Extracting .text section to %TEXTBIN% ...

:: Use dumpbin to find .text section RVA and raw size, then extract
:: with certutil or PowerShell. We use a simpler approach: dump the
:: section info and parse it.

:: Get raw offset and raw size of .text via dumpbin /headers
for /f "tokens=1,2" %%a in (
    'dumpbin /headers %OUT%.exe ^| findstr /c:"size of code"'
) do set CODE_SIZE=%%a

:: Direct extraction via PowerShell (more reliable than parsing dumpbin)
powershell -NoProfile -Command ^
    "$pe = [System.IO.File]::ReadAllBytes('%OUT%.exe');" ^
    "$dosHdr = [System.BitConverter]::ToInt32($pe, 60);" ^
    "$numSections = [System.BitConverter]::ToUInt16($pe, $dosHdr + 6);" ^
    "$optHdrSize = [System.BitConverter]::ToUInt16($pe, $dosHdr + 20);" ^
    "$sectionStart = $dosHdr + 24 + $optHdrSize;" ^
    "for ($i = 0; $i -lt $numSections; $i++) {" ^
    "  $off = $sectionStart + $i * 40;" ^
    "  $name = [System.Text.Encoding]::ASCII.GetString($pe, $off, 8).TrimEnd([char]0);" ^
    "  if ($name -eq '.text') {" ^
    "    $rawSize = [System.BitConverter]::ToUInt32($pe, $off + 16);" ^
    "    $rawPtr  = [System.BitConverter]::ToUInt32($pe, $off + 20);" ^
    "    $bytes = New-Object byte[] $rawSize;" ^
    "    [Array]::Copy($pe, $rawPtr, $bytes, 0, $rawSize);" ^
    "    [System.IO.File]::WriteAllBytes('%TEXTBIN%', $bytes);" ^
    "    Write-Host \"[+] Wrote $rawSize bytes to %TEXTBIN%\";" ^
    "    break;" ^
    "  }" ^
    "}"

if not exist %TEXTBIN% (
    echo [!] Failed to extract .text section.
    exit /b 1
)

echo [+] Done. Shellcode: %TEXTBIN%
echo.
echo     Size:  & for %%f in (%TEXTBIN%) do echo     %%~zf bytes
echo     Entry: precut_pic_entry (offset 0 if first function)
echo.
echo     To verify, load %TEXTBIN% in a debugger or disassembler
echo     and confirm the first instructions match the entry point.

endlocal
