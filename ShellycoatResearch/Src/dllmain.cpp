#include "Structs.h"
#include "Syscalls.h"
#include "SectionRemap.h"

#include <cstdlib>
#include <cstdio>
//#include <stdio.h>
//#include <stdlib.h>

// Call after DLL is loaded
// ------------------------------------------------------------------------

int go(int pid, std::string dllToFix) {
	// [DEBUG]
	Sleep(50);
	printf("[DBG] Preparing to baptize tainted dll!\n");
		
    // Resolve the direct syscalls
	Sleep(50);
	if (!resolve_syscalls()) {
		printf("[DBG] Failed to resolve syscalls!\n");
		return -1;
	}
	Sleep(50);
	printf("[DBG] Syscalls resolved!\n");

	// Attempt to perform Section Remapping
	Sleep(50);
	if (!section_remap(pid, dllToFix)) {
		printf("[DBG] Failed to perform Section Remapping!\n");
		return -2;
	}
	Sleep(50);
	printf("[DBG] Section Remapping done!\n");
	return 0;
}

// DllMain
// ------------------------------------------------------------------------
//BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
//void main() {
//	go(10);
//}

int main(int argc, char *argv[]) {
	if (argc != 3)
	{
		printf("Supply pid and dll filename (without .dll) as argument. \n");
		return -1;
	}
	
	int pid = atoi(argv[1]);
	std::string dllToFix = argv[2];
	printf("Target pid: %d\n", pid);
	return go(pid,dllToFix);	
}