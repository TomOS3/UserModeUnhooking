@ECHO OFF

"c:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Tools\MSVC\14.28.29910\bin\Hostx86\x64\ml64.exe" /c /Cx Src\\syscalls64.asm
"c:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Tools\MSVC\14.28.29910\bin\Hostx86\x64\ml64.exe" /c /Cx Src\\sysc_sw1.asm
cl.exe /nologo /MT /GS- /Od /DNDEBUG /W4 /Tp Src\\dllmain.cpp /link syscalls64.obj sysc_sw1.obj Kernel32.lib ucrt.lib libvcruntime.lib libcmt.lib libcpmt.lib /NODEFAULTLIB /ENTRY:mainCRTStartup /OUT:Bin\\shellycoat_x64.exe /MACHINE:x64 /Brepro /RELEASE /MERGE:_RDATA=.text /EMITPOGOPHASEINFO

rem cd Python & python ConvertToShellcode.py -c -f "" -u "" -i ..\\Bin\shellycoat_x64.dll & cd ..
del dllmain.obj
del syscalls64.obj
del sysc_sw1.obj