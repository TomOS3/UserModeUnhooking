@ECHO OFF

"c:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\VC\Tools\MSVC\14.28.29910\bin\Hostx86\x64\ml64.exe" /c /Cx Src\\syscalls64.asm
cl.exe /nologo /MT /GS- /Od /DNDEBUG /W0 /Tp Src\\dllmain.cpp /link syscalls64.obj Kernel32.lib ucrt.lib libvcruntime.lib libcmt.lib libcpmt.lib /DLL /NODEFAULTLIB /ENTRY:DllMain /OUT:Bin\\shellycoat_x64.dll /MACHINE:x64 /STUB:Src\\stub.bin /Brepro /RELEASE /MERGE:_RDATA=.text /EMITPOGOPHASEINFO
cd Python & python ConvertToShellcode.py -c -f "" -u "" -i ..\\Bin\shellycoat_x64.dll & cd ..
del dllmain.obj
del syscalls64.obj