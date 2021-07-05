@ECHO OFF

cl.exe /nologo /Od /MT /W0 /GS- /DNDEBUG /EHsc Loader.cpp /link /OUT:loader.exe /SUBSYSTEM:CONSOLE /RELEASE /MACHINE:x64 /MERGE:_RDATA=.text /EMITPOGOPHASEINFO
del *.obj