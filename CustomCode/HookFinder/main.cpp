#undef  _UNICODE
#define _UNICODE
#undef  UNICODE
#define UNICODE

using namespace std;

#include <Windows.h>
#include "HookDetector.h"
#include <DbgHelp.h>
#include "sysc_sw2.h"
#include <map>
#include <iostream>
#include <vector>
#include <algorithm>
#include <string>
#include <fstream>
#include <psapi.h>
#include <set>

#pragma comment (lib, "Dbghelp.lib")

#define MODE_WRITE 0
#define MODE_READ 1

#define SW2_SEED 0x874DD416
#define SW2_ROL8(v) (v << 8 | v >> 24)
#define SW2_ROR8(v) (v >> 8 | v << 24)
#define SW2_ROX8(v) ((SW2_SEED % 2) ? SW2_ROL8(v) : SW2_ROR8(v))
#define SW2_MAX_ENTRIES 6400 
#define SW2_RVA2VA(Type, DllBase, Rva) (Type)((ULONG_PTR) DllBase + Rva)

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

typedef struct FunctionEntry {
	string name;
	ULONG64 relativeAddress;
	char *code;
};

typedef std::map<string, vector<FunctionEntry>> DllFunctionMap;

typedef std::map<PCHAR, ULONG64> DllBaseMap;
typedef std::map<string, ULONG64> DllBaseMapStr;

const int BYTES_TO_CHECK = 16;

//There is some adapted code based on pieces of SysWhispers (https://github.com/jthuraisamy/SysWhispers2) used in this method 
int scanForModulesAndFunctions(DllFunctionMap& dllFunctionMap, DllBaseMap& dllBaseMap)
{
	PSW2_PEB Peb = (PSW2_PEB)__readgsqword(0x60);
	PSW2_PEB_LDR_DATA Ldr = Peb->Ldr;
	PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
	PVOID DllBase = NULL;

	PCHAR strDllName;
	vector<FunctionEntry> functionEntryList;

	// Get the DllBase address of NTDLL.dll. NTDLL is not guaranteed to be the second
	// in the list, so it's safer to loop through the full list and find it.
	PSW2_LDR_DATA_TABLE_ENTRY LdrEntry;
	printf("==============================================================\n");
	printf("Looping through loaded modules in process\n");
	printf("==============================================================\n");
	for (LdrEntry = (PSW2_LDR_DATA_TABLE_ENTRY)Ldr->Reserved2[1]; LdrEntry->DllBase != NULL; LdrEntry = (PSW2_LDR_DATA_TABLE_ENTRY)LdrEntry->Reserved1[0])
	{
		DllBase = LdrEntry->DllBase;
		PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)DllBase;
		PIMAGE_NT_HEADERS NtHeaders = SW2_RVA2VA(PIMAGE_NT_HEADERS, DllBase, DosHeader->e_lfanew);
		PIMAGE_DATA_DIRECTORY DataDirectory = (PIMAGE_DATA_DIRECTORY)NtHeaders->OptionalHeader.DataDirectory;
		DWORD VirtualAddress = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		if (VirtualAddress == 0) continue;

		ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)SW2_RVA2VA(ULONG_PTR, DllBase, VirtualAddress);

		PCHAR DllName = SW2_RVA2VA(PCHAR, DllBase, ExportDirectory->Name);
		
		strDllName = DllName;

		printf("--------------------\n");
		printf("DLL name: %s\n", DllName);
		printf("DLL Base: %p\n", (ULONG64)DllBase);
		DWORD NumberOfNames = ExportDirectory->NumberOfNames;
		DWORD NumberOfFunctions = ExportDirectory->NumberOfFunctions;
		//printf("Should have %d names\n", NumberOfNames);
		printf("%d functions found.\n", NumberOfFunctions);
		PDWORD Functions = SW2_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfFunctions);
		PDWORD Names = SW2_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfNames);
		PWORD Ordinals = SW2_RVA2VA(PWORD, DllBase, ExportDirectory->AddressOfNameOrdinals);
		// Populate SW2_SyscallList with unsorted Zw* entries.
		DWORD i = 0;
		PSW2_SYSCALL_ENTRY Entries = SW2_SyscallList.Entries;
		if (NumberOfNames > 0) 
		{
			do
			{
				PCHAR FunctionName = SW2_RVA2VA(PCHAR, DllBase, Names[NumberOfNames - 1]);
				struct FunctionEntry functionEntry;
				functionEntry.name = FunctionName;
				functionEntry.relativeAddress = (ULONG64)Functions[Ordinals[NumberOfNames - 1]];
				BYTE codeInMemory[BYTES_TO_CHECK]; //TODO: uitlezen hier al?
				functionEntryList.push_back(functionEntry);
				{
					Entries[i].Address = Functions[Ordinals[NumberOfNames - 1]];

					i++;
					if (i == SW2_MAX_ENTRIES) break;
				}
			} while (--NumberOfNames);
		}
		dllFunctionMap[strDllName] = functionEntryList;
		dllBaseMap[strDllName] = (ULONG64)DllBase;
		printf("Methods found: %d\n", i);
		SW2_SyscallList.Count = i;
	}

	return 0;
}

long GetFileSize(std::string filename)
{
	struct stat stat_buf;
	int rc = stat(filename.c_str(), &stat_buf);
	return rc == 0 ? stat_buf.st_size : -1;
}

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

#include "main.h"

string capitalizeString(string s)
{
	transform(s.begin(), s.end(), s.begin(),
		[](unsigned char c) { return toupper(c); });
	return s;
}

void LoadProloguesFromDisk(DllFunctionMap& expectedData)
{
	printf("==============================================================\n");
	printf(">>> Loading known code from disk...\n");
	printf("==============================================================\n");
	printf("Loading... ");
	ifstream infile("prologues.bin", ifstream::binary);
	while (!infile.eof()) {

		size_t size;
		infile.read((char*)&size, sizeof(size));
		char* readNameDll = (char*)malloc(size + 1);

		infile.read(readNameDll, size);
		readNameDll[size] = '\0';


		infile.read((char*)&size, sizeof(size));
		char* readNameFunction = (char*)malloc(size + 1);
		infile.read(readNameFunction, size);
		readNameFunction[size] = '\0';

		char* readBytes = (char*)malloc(BYTES_TO_CHECK + 1);
		infile.read(readBytes, BYTES_TO_CHECK);
		readBytes[BYTES_TO_CHECK] = '\0';

		struct FunctionEntry functionEntry;
		functionEntry.name = (PCHAR)readNameFunction;
		functionEntry.relativeAddress = 0;
		functionEntry.code = readBytes;
		string str(readNameDll);
		expectedData[str].push_back(functionEntry);

	}

	infile.close();
	printf("Done.\n");
}

void WriteProloguesToDisk(std::set<std::string>& dllsToProcess, DllFunctionMap& dllFunctionMap, DllBaseMap& dllBaseMap)
{
	printf("==============================================================\n");
	printf(">>> Dumping code to disk...\n");
	printf("==============================================================\n");
	std::ofstream outfile = std::ofstream("prologues.bin", std::ofstream::binary);
	for (const auto& any : dllBaseMap) {
		PCHAR dllName = any.first;
		ULONG64 dllAddr = any.second;
		string upper = capitalizeString((string)dllName);
		if (dllsToProcess.find(upper) == dllsToProcess.end())
		{
			printf("Skipping %s, not an interesting DLL.\n", dllName);
			continue;
		}
		printf("Checking methods of %s at base address %p\n", dllName, dllAddr);
		std::wstring stemp2 = s2ws((std::string(std::string("c:\\windows\\system32\\" + std::string(dllName)))));
		LPCWSTR normalDllName = stemp2.c_str();
		HMODULE libraryHandle = LoadLibrary(normalDllName); //Load original .dll, copy not possible for all Windows .dll's (!)
		MODULEINFO moduleInfo;
		GetModuleInformation(GetCurrentProcess(), libraryHandle, &moduleInfo, sizeof(MODULEINFO));
		ULONG64 dllBaseAddress = (ULONG64)moduleInfo.lpBaseOfDll;
		ULONG64 dllSize = (ULONG64)moduleInfo.SizeOfImage;


		vector<FunctionEntry> functions = dllFunctionMap[dllName];

		long entriesTotal = 0;
		long entriesNotExported = 0;
		long entriesForwarding = 0;
		for (FunctionEntry entry : functions)
		{
			entriesTotal++;

			BYTE functionCodeMemory[BYTES_TO_CHECK];
			BYTE functionCodeDisk[BYTES_TO_CHECK];

			//LPVOID totAddr = (LPVOID)(dllAddr + entry.relativeAddress); Onbetrouwbaar relativeaddress
			LPVOID lpProcAddress = 0;
			try
			{
				lpProcAddress = GetProcAddress(libraryHandle, (LPCSTR)entry.name.c_str()); //TEMP  (LPCSTR)entry.name.c_str()
			}
			catch (const std::exception& e)
			{
				printf("ERROR");
			}
			if (lpProcAddress == 0)
			{
				entriesNotExported++;
				//Skipping, not exported in .dll, so missing hooked unexported methods.
				//Test for exported methods using: dumpbin / exports c : \windows\system32\ucrtbased.dll > c:\RP2\out.txt
			}
			else
			{
				//To ignore forwarding functions (https://en.wikibooks.org/wiki/X86_Disassembly/Windows_Executable_Files#Forwarding)
				if (!(((ULONG64)lpProcAddress) >= dllBaseAddress && ((ULONG64)lpProcAddress) < dllBaseAddress + dllSize))
				{
					entriesForwarding++;
					continue;
				}

				SIZE_T noBytesRead;
				HANDLE processHandle;
				processHandle = GetCurrentProcess();

				SIZE_T uSize = BYTES_TO_CHECK;
				ULONG oldProtection, newProtection;
				NTSTATUS status;
				status = NtRVM(processHandle, lpProcAddress, &functionCodeMemory, sizeof(functionCodeMemory), &noBytesRead);
				if (noBytesRead == 0)
				{
					printf("ERROR: NoBytesRead!");
					printf("Line: [%d]" + __LINE__);
					exit(-1);
				}
				if (status != 0)
				{
					printf("NTStatus: %p", status);
					printf("Line: [%d]" + __LINE__);
					exit(-1);
				}

				std::string writeNameDll = (string)dllName;
				std::string writeNameFunction = (string)entry.name;
				//Write DLL name
				size_t sizeNameDll = writeNameDll.size();
				outfile.write((char*)&sizeNameDll, sizeof(sizeNameDll));
				outfile.write(writeNameDll.c_str(), sizeNameDll);
				//Write function name
				size_t sizeNameFunction = writeNameFunction.size();
				outfile.write((char*)&sizeNameFunction, sizeof(sizeNameFunction));
				outfile.write(writeNameFunction.c_str(), sizeNameFunction);
				//Write bytes
				outfile.write((char*)&functionCodeMemory, sizeof(functionCodeMemory));
			}
		}
		FreeLibrary(libraryHandle);

		printf("Done. Total of %lu methods - skipped: %lu (not exported), %lu (forwarding)\n", entriesTotal, entriesNotExported, entriesForwarding);
	}
	outfile.close();

}

int GetLoadedModulesForProcess(DWORD processID, DllBaseMapStr& dllBaseMapStr)
{
	HMODULE hMods[1024];
	HANDLE hProcess;
	DWORD cbNeeded;
	unsigned int i;

	// Print the process identifier.
	printf("\nTargeting process: %u\n\n", processID);

	// Get a handle to the process.
	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
		PROCESS_VM_READ,
		FALSE, processID);
	if (NULL == hProcess)
		return -1;

	// Get a list of all the modules in this process.

	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
	{
		for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			TCHAR szModName[MAX_PATH];

			// Get the full path to the module's file.

			if (GetModuleFileNameEx(hProcess, hMods[i], szModName,
				sizeof(szModName) / sizeof(TCHAR)))
			{
				// Print the module name and handle value.
				wstring modNameWStr(&szModName[0]); //convert to wstring
				string modNameStr(modNameWStr.begin(), modNameWStr.end()); //and convert to string.

				dllBaseMapStr[modNameStr] = (ULONG64)hMods[i];
			}
		}
	}

	// Release the handle to the process.
	CloseHandle(hProcess);

	return 0;
}


std::vector<std::string> alreadyProcessed;

void CompareDiskAndMemory(std::set<std::string>& dllsToProcess, int pid, DllFunctionMap& expectedData,string& specificFunction)
{
	printf("==============================================================\n");
	printf(">>> Comparing code in memory and on disk...\n");
	printf("==============================================================\n");
	DllBaseMapStr dllBaseMapStr;
	GetLoadedModulesForProcess(pid, dllBaseMapStr);

	
	//Loop through DLL's on disk
	for (const auto& any : expectedData) {
		string dllName = any.first;
		vector<FunctionEntry> functions = any.second;
		ULONG64 remoteDllBaseAddr;

		BOOL inDllBaseMapStr = FALSE;
		//Loop through DLL names loaded on target process
		for (const auto& any2 : dllBaseMapStr) {
			std::string base_filename = any2.first.substr(any2.first.find_last_of("/\\") + 1);
			string upperBaseFilename = capitalizeString(base_filename);
			string upperDllName = capitalizeString(dllName);

			if (upperBaseFilename == upperDllName)
			{
				inDllBaseMapStr = TRUE;
				remoteDllBaseAddr = (ULONG64)any2.second;
				break;
			}
		}
		if (inDllBaseMapStr)
		{
			//Dll on disk matches with dll loaded for remote process...
			printf("Checking %s... \n", dllName.c_str());
			MODULEINFO moduleInfo;

			//These line have no purpose, but wrong data is read without LoadLibrary.
			std::wstring stemp2 = s2ws((std::string(std::string("c:\\windows\\system32\\" + std::string(dllName)))));
			LPCWSTR fullDllName = stemp2.c_str();
			HMODULE libraryHandle = LoadLibrary(fullDllName);

			HANDLE remoteProcessHandle;
			NTSTATUS status;
			
			//Open process handle using direct syscalls
			CLIENT_ID uPid = { 0 };
			uPid.UniqueProcess = (HANDLE)pid;
			uPid.UniqueThread = (HANDLE)0;
			OBJECT_ATTRIBUTES oa;
			InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
			status = ZwOpenProcess10(&remoteProcessHandle, PROCESS_ALL_ACCESS, &oa, &uPid);
			if (status != 0)
			{
				printf("NTStatus: %p", status);
				printf("Line: [%d]" + __LINE__);
				exit(-1);
			}

			alreadyProcessed = {};

			for (FunctionEntry entry : functions)
			{
				//For demo purposes
				if (specificFunction != "" && specificFunction != entry.name.c_str())
				{
					continue;
				}
				
				//Skip duplicate results
				BOOL processed = FALSE;
				for (int i = 0; i < alreadyProcessed.size(); i++)
					if (alreadyProcessed[i] == entry.name.c_str())
					{
						processed = TRUE;
					}
				if (processed)
				{
					continue;
				}
				else
				{
					alreadyProcessed.push_back(entry.name.c_str());
				}				

				//Load module
				LPVOID lpProcAddress = GetProcAddress((HMODULE)remoteDllBaseAddr, (LPCSTR)entry.name.c_str());
				ULONG64 functionAddr = (ULONG64)lpProcAddress;

				SIZE_T uSize = BYTES_TO_CHECK;
				BYTE functionCodeMemory[BYTES_TO_CHECK];
				BYTE functionCodeDisk[BYTES_TO_CHECK];
				SIZE_T noBytesRead;

				ULONG oldProtection, newProtection;
				
				NTSTATUS status = NtRVM(remoteProcessHandle, lpProcAddress, &functionCodeMemory, sizeof(functionCodeMemory), &noBytesRead);
				if (noBytesRead == 0)
				{
					printf("ERROR: NoBytesRead!");
					printf("Line: [%d]"+__LINE__);
					exit(-1);
				}
				if (status != 0)
				{
					printf("NTStatus: %p", status);
					printf("Line: [%d]" + __LINE__);
					exit(-1);
				}
	
				//Fix signed/unsigned problem by copying and casting bytes individually 
				for (int i = 0; i < BYTES_TO_CHECK; i++)
				{
					functionCodeDisk[i] = static_cast<unsigned char>(entry.code[i]);
				}

				//Check for differences in the bytes
				BOOL same = TRUE;
				for (int i = 0; i < BYTES_TO_CHECK; i++)
					if (functionCodeDisk[i] != functionCodeMemory[i])
						same = FALSE;
				if (same)
					continue;

				printf("\n----------------------------------------------------------------\n");
				printf("Difference found in '%s' -> '%s':\n", dllName.c_str(), entry.name.c_str());
				printf("In memory: ");
				
				for (int i = 0; i < BYTES_TO_CHECK; i++)
					printf(" %02X", functionCodeMemory[i]);
				
				printf("\nOn disk:   ");
				for (int i = 0; i < BYTES_TO_CHECK; i++)
				{
					//Fix signed/unsigned problem
					printf(" %02X", functionCodeDisk[i]);
				}
				printf("\n----------------------------------------------------------------\n");
	

			}
		}
	}
}

void LoadInterestingLibraries(std::set<std::string>& dllsToProcess)
{
	printf("==============================================================\n");
	printf(">>> Loading interesting DLLs in memory before dumping code...\n");
	printf("==============================================================\n");

	//Load all libraries that should be stored for comparison
	for (auto dll : dllsToProcess) {
		std::wstring stemp = s2ws("c:\\windows\\system32\\" + dll);
		LPCWSTR fixedDllName = stemp.c_str();
		wcout << "Loading " << stemp << "...\n";
		HANDLE h = LoadLibrary(fixedDllName);
	}
}

int wmain(int argc, wchar_t* argv[]) {

	printf("==============================================================\n");
	printf("\nInline Hook Detector (OS3 demo version)\n\n");

	// your new String
	DllFunctionMap dllFunctionMap;
	DllBaseMap dllBaseMap;

	std::set<std::string> dllsToProcess = {"COMBASE.DLL", "GDI32.DLL","KERNEL32.DLL","KERNELBASE.DLL","NTDLL.DLL","RPCRT4.DLL","SECHOST.DLL","SHELL32.DLL","USER32.DLL","WIN32U.DLL" ,"FLTLIB.DLL","ADVAPI32.DLL" };
	//printf("Press Any Key to Continue\n"); getchar();

	DllFunctionMap expectedData;
	if (argc != 2 && argc != 3)
	{
		printf("Supply pid as argument or -1 to build code file (and optionally: specific function to show). \n");
		return -1;
	}

	int pid = _wtoi(argv[1]);
	string specificFunction = "";
	if (argc == 3)
	{
		wstring ws(argv[2]);
		string str(ws.begin(), ws.end());
		specificFunction = str;
	}

		
	if (pid == -1)
	{
		//Write mode
		LoadInterestingLibraries(dllsToProcess);
		scanForModulesAndFunctions(dllFunctionMap, dllBaseMap);
		WriteProloguesToDisk(dllsToProcess, dllFunctionMap, dllBaseMap);
	}
	else
	{
		//Compare mode
		HANDLE processHandleTarget = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
		if (processHandleTarget == 0)
		{
			printf("Process with PID supplied not found. \n");
			return -1;
		}
		LoadProloguesFromDisk(expectedData);
		CompareDiskAndMemory(dllsToProcess, pid, expectedData,specificFunction);

	}

	printf("\n");

	return 0;
}

