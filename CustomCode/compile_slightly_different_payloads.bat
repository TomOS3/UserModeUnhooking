@ECHO OFF

del %~dp0CFSR1.exe
del %~dp0CFSR2.exe
del %~dp0CFPR1.exe
del %~dp0CFPR2.exe
del %~dp0CFIF1.exe
del %~dp0CFIF2.exe
del %~dp0CFNO1.exe
del %~dp0CFNO2.exe
del %~dp0CFIS1.exe
del %~dp0CFIS2.exe
del %~dp0CFPF1.exe
del %~dp0CFPF2.exe

cl.exe /nologo /MT /GS- /Od /DNDEBUG /W4 /Tp %~dp0PaLoCF\PaLoCF.cpp /link Kernel32.lib ucrt.lib libvcruntime.lib libcmt.lib libcpmt.lib /NODEFAULTLIB /ENTRY:mainCRTStartup /OUT:%~dp0CFSR1.exe /MACHINE:x64 /Brepro /RELEASE /MERGE:_RDATA=.text /EMITPOGOPHASEINFO
timeout 2
cl.exe /nologo /MT /GS- /Od /DNDEBUG /W4 /Tp %~dp0PaLoCF\PaLoCF.cpp /link Kernel32.lib ucrt.lib libvcruntime.lib libcmt.lib libcpmt.lib /NODEFAULTLIB /ENTRY:mainCRTStartup /OUT:%~dp0CFSR2.exe /MACHINE:x64 /Brepro /RELEASE /MERGE:_RDATA=.text /EMITPOGOPHASEINFO
timeout 2
cl.exe /nologo /MT /GS- /Od /DNDEBUG /W4 /Tp %~dp0PaLoCF\PaLoCF.cpp /link Kernel32.lib ucrt.lib libvcruntime.lib libcmt.lib libcpmt.lib /NODEFAULTLIB /ENTRY:mainCRTStartup /OUT:%~dp0CFPR1.exe /MACHINE:x64 /Brepro /RELEASE /MERGE:_RDATA=.text /EMITPOGOPHASEINFO
timeout 2
cl.exe /nologo /MT /GS- /Od /DNDEBUG /W4 /Tp %~dp0PaLoCF\PaLoCF.cpp /link Kernel32.lib ucrt.lib libvcruntime.lib libcmt.lib libcpmt.lib /NODEFAULTLIB /ENTRY:mainCRTStartup /OUT:%~dp0CFPR2.exe /MACHINE:x64 /Brepro /RELEASE /MERGE:_RDATA=.text /EMITPOGOPHASEINFO
timeout 2
cl.exe /nologo /MT /GS- /Od /DNDEBUG /W4 /Tp %~dp0PaLoCF\PaLoCF.cpp /link Kernel32.lib ucrt.lib libvcruntime.lib libcmt.lib libcpmt.lib /NODEFAULTLIB /ENTRY:mainCRTStartup /OUT:%~dp0CFIF1.exe /MACHINE:x64 /Brepro /RELEASE /MERGE:_RDATA=.text /EMITPOGOPHASEINFO
timeout 2
cl.exe /nologo /MT /GS- /Od /DNDEBUG /W4 /Tp %~dp0PaLoCF\PaLoCF.cpp /link Kernel32.lib ucrt.lib libvcruntime.lib libcmt.lib libcpmt.lib /NODEFAULTLIB /ENTRY:mainCRTStartup /OUT:%~dp0CFIF2.exe /MACHINE:x64 /Brepro /RELEASE /MERGE:_RDATA=.text /EMITPOGOPHASEINFO
timeout 2
cl.exe /nologo /MT /GS- /Od /DNDEBUG /W4 /Tp %~dp0PaLoCF\PaLoCF.cpp /link Kernel32.lib ucrt.lib libvcruntime.lib libcmt.lib libcpmt.lib /NODEFAULTLIB /ENTRY:mainCRTStartup /OUT:%~dp0CFNO1.exe /MACHINE:x64 /Brepro /RELEASE /MERGE:_RDATA=.text /EMITPOGOPHASEINFO
timeout 2
cl.exe /nologo /MT /GS- /Od /DNDEBUG /W4 /Tp %~dp0PaLoCF\PaLoCF.cpp /link Kernel32.lib ucrt.lib libvcruntime.lib libcmt.lib libcpmt.lib /NODEFAULTLIB /ENTRY:mainCRTStartup /OUT:%~dp0CFNO2.exe /MACHINE:x64 /Brepro /RELEASE /MERGE:_RDATA=.text /EMITPOGOPHASEINFO
timeout 2
cl.exe /nologo /MT /GS- /Od /DNDEBUG /W4 /Tp %~dp0PaLoCF\PaLoCF.cpp /link Kernel32.lib ucrt.lib libvcruntime.lib libcmt.lib libcpmt.lib /NODEFAULTLIB /ENTRY:mainCRTStartup /OUT:%~dp0CFIS1.exe /MACHINE:x64 /Brepro /RELEASE /MERGE:_RDATA=.text /EMITPOGOPHASEINFO
timeout 2
cl.exe /nologo /MT /GS- /Od /DNDEBUG /W4 /Tp %~dp0PaLoCF\PaLoCF.cpp /link Kernel32.lib ucrt.lib libvcruntime.lib libcmt.lib libcpmt.lib /NODEFAULTLIB /ENTRY:mainCRTStartup /OUT:%~dp0CFIS2.exe /MACHINE:x64 /Brepro /RELEASE /MERGE:_RDATA=.text /EMITPOGOPHASEINFO
timeout 2
cl.exe /nologo /MT /GS- /Od /DNDEBUG /W4 /Tp %~dp0PaLoCF\PaLoCF.cpp /link Kernel32.lib ucrt.lib libvcruntime.lib libcmt.lib libcpmt.lib /NODEFAULTLIB /ENTRY:mainCRTStartup /OUT:%~dp0CFPF1.exe /MACHINE:x64 /Brepro /RELEASE /MERGE:_RDATA=.text /EMITPOGOPHASEINFO
timeout 2
cl.exe /nologo /MT /GS- /Od /DNDEBUG /W4 /Tp %~dp0PaLoCF\PaLoCF.cpp /link Kernel32.lib ucrt.lib libvcruntime.lib libcmt.lib libcpmt.lib /NODEFAULTLIB /ENTRY:mainCRTStartup /OUT:%~dp0CFPF2.exe /MACHINE:x64 /Brepro /RELEASE /MERGE:_RDATA=.text /EMITPOGOPHASEINFO
timeout 2


del %~dp0SISR1.exe
del %~dp0SISR2.exe
del %~dp0SIPR1.exe
del %~dp0SIPR2.exe
del %~dp0SIIF1.exe
del %~dp0SIIF2.exe
del %~dp0SINO1.exe
del %~dp0SINO2.exe
del %~dp0SIIS1.exe
del %~dp0SIIS2.exe
del %~dp0SIPF1.exe
del %~dp0SIPF2.exe

cl.exe /nologo /MT /GS- /Od /DNDEBUG /W4 /Tp %~dp0PaLoInj\PaLoInj.cpp /link Kernel32.lib ucrt.lib libvcruntime.lib libcmt.lib libcpmt.lib /NODEFAULTLIB /ENTRY:mainCRTStartup /OUT:%~dp0SISR1.exe /MACHINE:x64 /Brepro /RELEASE /MERGE:_RDATA=.text /EMITPOGOPHASEINFO
timeout 2
cl.exe /nologo /MT /GS- /Od /DNDEBUG /W4 /Tp %~dp0PaLoInj\PaLoInj.cpp /link Kernel32.lib ucrt.lib libvcruntime.lib libcmt.lib libcpmt.lib /NODEFAULTLIB /ENTRY:mainCRTStartup /OUT:%~dp0SISR2.exe /MACHINE:x64 /Brepro /RELEASE /MERGE:_RDATA=.text /EMITPOGOPHASEINFO
timeout 2
cl.exe /nologo /MT /GS- /Od /DNDEBUG /W4 /Tp %~dp0PaLoInj\PaLoInj.cpp /link Kernel32.lib ucrt.lib libvcruntime.lib libcmt.lib libcpmt.lib /NODEFAULTLIB /ENTRY:mainCRTStartup /OUT:%~dp0SIPR1.exe /MACHINE:x64 /Brepro /RELEASE /MERGE:_RDATA=.text /EMITPOGOPHASEINFO
timeout 2
cl.exe /nologo /MT /GS- /Od /DNDEBUG /W4 /Tp %~dp0PaLoInj\PaLoInj.cpp /link Kernel32.lib ucrt.lib libvcruntime.lib libcmt.lib libcpmt.lib /NODEFAULTLIB /ENTRY:mainCRTStartup /OUT:%~dp0SIPR2.exe /MACHINE:x64 /Brepro /RELEASE /MERGE:_RDATA=.text /EMITPOGOPHASEINFO
timeout 2
cl.exe /nologo /MT /GS- /Od /DNDEBUG /W4 /Tp %~dp0PaLoInj\PaLoInj.cpp /link Kernel32.lib ucrt.lib libvcruntime.lib libcmt.lib libcpmt.lib /NODEFAULTLIB /ENTRY:mainCRTStartup /OUT:%~dp0SIIF1.exe /MACHINE:x64 /Brepro /RELEASE /MERGE:_RDATA=.text /EMITPOGOPHASEINFO
timeout 2
cl.exe /nologo /MT /GS- /Od /DNDEBUG /W4 /Tp %~dp0PaLoInj\PaLoInj.cpp /link Kernel32.lib ucrt.lib libvcruntime.lib libcmt.lib libcpmt.lib /NODEFAULTLIB /ENTRY:mainCRTStartup /OUT:%~dp0SIIF2.exe /MACHINE:x64 /Brepro /RELEASE /MERGE:_RDATA=.text /EMITPOGOPHASEINFO
timeout 2
cl.exe /nologo /MT /GS- /Od /DNDEBUG /W4 /Tp %~dp0PaLoInj\PaLoInj.cpp /link Kernel32.lib ucrt.lib libvcruntime.lib libcmt.lib libcpmt.lib /NODEFAULTLIB /ENTRY:mainCRTStartup /OUT:%~dp0SINO1.exe /MACHINE:x64 /Brepro /RELEASE /MERGE:_RDATA=.text /EMITPOGOPHASEINFO
timeout 2
cl.exe /nologo /MT /GS- /Od /DNDEBUG /W4 /Tp %~dp0PaLoInj\PaLoInj.cpp /link Kernel32.lib ucrt.lib libvcruntime.lib libcmt.lib libcpmt.lib /NODEFAULTLIB /ENTRY:mainCRTStartup /OUT:%~dp0SINO2.exe /MACHINE:x64 /Brepro /RELEASE /MERGE:_RDATA=.text /EMITPOGOPHASEINFO
timeout 2
cl.exe /nologo /MT /GS- /Od /DNDEBUG /W4 /Tp %~dp0PaLoInj\PaLoInj.cpp /link Kernel32.lib ucrt.lib libvcruntime.lib libcmt.lib libcpmt.lib /NODEFAULTLIB /ENTRY:mainCRTStartup /OUT:%~dp0SIIS1.exe /MACHINE:x64 /Brepro /RELEASE /MERGE:_RDATA=.text /EMITPOGOPHASEINFO
timeout 2
cl.exe /nologo /MT /GS- /Od /DNDEBUG /W4 /Tp %~dp0PaLoInj\PaLoInj.cpp /link Kernel32.lib ucrt.lib libvcruntime.lib libcmt.lib libcpmt.lib /NODEFAULTLIB /ENTRY:mainCRTStartup /OUT:%~dp0SIIS2.exe /MACHINE:x64 /Brepro /RELEASE /MERGE:_RDATA=.text /EMITPOGOPHASEINFO
timeout 2
cl.exe /nologo /MT /GS- /Od /DNDEBUG /W4 /Tp %~dp0PaLoInj\PaLoInj.cpp /link Kernel32.lib ucrt.lib libvcruntime.lib libcmt.lib libcpmt.lib /NODEFAULTLIB /ENTRY:mainCRTStartup /OUT:%~dp0SIPF1.exe /MACHINE:x64 /Brepro /RELEASE /MERGE:_RDATA=.text /EMITPOGOPHASEINFO
timeout 2
cl.exe /nologo /MT /GS- /Od /DNDEBUG /W4 /Tp %~dp0PaLoInj\PaLoInj.cpp /link Kernel32.lib ucrt.lib libvcruntime.lib libcmt.lib libcpmt.lib /NODEFAULTLIB /ENTRY:mainCRTStartup /OUT:%~dp0SIPF2.exe /MACHINE:x64 /Brepro /RELEASE /MERGE:_RDATA=.text /EMITPOGOPHASEINFO
timeout 2

del %~dp0SSSR1.exe
del %~dp0SSSR2.exe
del %~dp0SSPR1.exe
del %~dp0SSPR2.exe
del %~dp0SSIF1.exe
del %~dp0SSIF2.exe
del %~dp0SSIS1.exe
del %~dp0SSIS2.exe
del %~dp0SSPF1.exe
del %~dp0SSPF2.exe

cl.exe /nologo /MT /GS- /Od /DNDEBUG /W4 /Tp %~dp0PaLoIns\PaLoIns.cpp /link Kernel32.lib ucrt.lib libvcruntime.lib libcmt.lib libcpmt.lib /NODEFAULTLIB /ENTRY:mainCRTStartup /OUT:%~dp0SSSR1.exe /MACHINE:x64 /Brepro /RELEASE /MERGE:_RDATA=.text /EMITPOGOPHASEINFO
timeout 2
cl.exe /nologo /MT /GS- /Od /DNDEBUG /W4 /Tp %~dp0PaLoIns\PaLoIns.cpp /link Kernel32.lib ucrt.lib libvcruntime.lib libcmt.lib libcpmt.lib /NODEFAULTLIB /ENTRY:mainCRTStartup /OUT:%~dp0SSSR2.exe /MACHINE:x64 /Brepro /RELEASE /MERGE:_RDATA=.text /EMITPOGOPHASEINFO
timeout 2
cl.exe /nologo /MT /GS- /Od /DNDEBUG /W4 /Tp %~dp0PaLoIns\PaLoIns.cpp /link Kernel32.lib ucrt.lib libvcruntime.lib libcmt.lib libcpmt.lib /NODEFAULTLIB /ENTRY:mainCRTStartup /OUT:%~dp0SSPR1.exe /MACHINE:x64 /Brepro /RELEASE /MERGE:_RDATA=.text /EMITPOGOPHASEINFO
timeout 2
cl.exe /nologo /MT /GS- /Od /DNDEBUG /W4 /Tp %~dp0PaLoIns\PaLoIns.cpp /link Kernel32.lib ucrt.lib libvcruntime.lib libcmt.lib libcpmt.lib /NODEFAULTLIB /ENTRY:mainCRTStartup /OUT:%~dp0SSPR2.exe /MACHINE:x64 /Brepro /RELEASE /MERGE:_RDATA=.text /EMITPOGOPHASEINFO
timeout 2
cl.exe /nologo /MT /GS- /Od /DNDEBUG /W4 /Tp %~dp0PaLoIns\PaLoIns.cpp /link Kernel32.lib ucrt.lib libvcruntime.lib libcmt.lib libcpmt.lib /NODEFAULTLIB /ENTRY:mainCRTStartup /OUT:%~dp0SSIF1.exe /MACHINE:x64 /Brepro /RELEASE /MERGE:_RDATA=.text /EMITPOGOPHASEINFO
timeout 2
cl.exe /nologo /MT /GS- /Od /DNDEBUG /W4 /Tp %~dp0PaLoIns\PaLoIns.cpp /link Kernel32.lib ucrt.lib libvcruntime.lib libcmt.lib libcpmt.lib /NODEFAULTLIB /ENTRY:mainCRTStartup /OUT:%~dp0SSIF2.exe /MACHINE:x64 /Brepro /RELEASE /MERGE:_RDATA=.text /EMITPOGOPHASEINFO
timeout 2
cl.exe /nologo /MT /GS- /Od /DNDEBUG /W4 /Tp %~dp0PaLoIns\PaLoIns.cpp /link Kernel32.lib ucrt.lib libvcruntime.lib libcmt.lib libcpmt.lib /NODEFAULTLIB /ENTRY:mainCRTStartup /OUT:%~dp0SSNO1.exe /MACHINE:x64 /Brepro /RELEASE /MERGE:_RDATA=.text /EMITPOGOPHASEINFO
timeout 2
cl.exe /nologo /MT /GS- /Od /DNDEBUG /W4 /Tp %~dp0PaLoIns\PaLoIns.cpp /link Kernel32.lib ucrt.lib libvcruntime.lib libcmt.lib libcpmt.lib /NODEFAULTLIB /ENTRY:mainCRTStartup /OUT:%~dp0SSNO2.exe /MACHINE:x64 /Brepro /RELEASE /MERGE:_RDATA=.text /EMITPOGOPHASEINFO
timeout 2
cl.exe /nologo /MT /GS- /Od /DNDEBUG /W4 /Tp %~dp0PaLoIns\PaLoIns.cpp /link Kernel32.lib ucrt.lib libvcruntime.lib libcmt.lib libcpmt.lib /NODEFAULTLIB /ENTRY:mainCRTStartup /OUT:%~dp0SSIS1.exe /MACHINE:x64 /Brepro /RELEASE /MERGE:_RDATA=.text /EMITPOGOPHASEINFO
timeout 2
cl.exe /nologo /MT /GS- /Od /DNDEBUG /W4 /Tp %~dp0PaLoIns\PaLoIns.cpp /link Kernel32.lib ucrt.lib libvcruntime.lib libcmt.lib libcpmt.lib /NODEFAULTLIB /ENTRY:mainCRTStartup /OUT:%~dp0SSIS2.exe /MACHINE:x64 /Brepro /RELEASE /MERGE:_RDATA=.text /EMITPOGOPHASEINFO
timeout 2
cl.exe /nologo /MT /GS- /Od /DNDEBUG /W4 /Tp %~dp0PaLoIns\PaLoIns.cpp /link Kernel32.lib ucrt.lib libvcruntime.lib libcmt.lib libcpmt.lib /NODEFAULTLIB /ENTRY:mainCRTStartup /OUT:%~dp0SSPF1.exe /MACHINE:x64 /Brepro /RELEASE /MERGE:_RDATA=.text /EMITPOGOPHASEINFO
timeout 2
cl.exe /nologo /MT /GS- /Od /DNDEBUG /W4 /Tp %~dp0PaLoIns\PaLoIns.cpp /link Kernel32.lib ucrt.lib libvcruntime.lib libcmt.lib libcpmt.lib /NODEFAULTLIB /ENTRY:mainCRTStartup /OUT:%~dp0SSPF2.exe /MACHINE:x64 /Brepro /RELEASE /MERGE:_RDATA=.text /EMITPOGOPHASEINFO
timeout 2
