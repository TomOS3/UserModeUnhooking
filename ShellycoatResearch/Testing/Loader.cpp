// sRDI Loader
// Credits: Nick Landers(@monoxgas) and SBS Team

#include <Windows.h>
#include <string>

DWORD GetFileContents(LPCSTR filename, LPSTR *data, DWORD &size) {
	std::FILE *fp = std::fopen(filename, "rb");

	if (fp) {
		fseek(fp, 0, SEEK_END);
		size = ftell(fp);
		fseek(fp, 0, SEEK_SET);

		*data = (LPSTR)malloc(size + 1);
		fread(*data, size, 1, fp);
		fclose(fp);
		return true;
	}
	return false;
}

typedef UINT_PTR(WINAPI * RDI)();

int main(int argc, char *argv[], char *envp[]) {
	LPSTR finalShellcode = NULL, data = NULL;
	DWORD finalSize, dataSize;
	DWORD dwOldProtect1 = 0;
	SYSTEM_INFO sysInfo;

	// For any MessageBox testing in the blob
	HMODULE test = LoadLibraryA("User32.dll"); 

	if (argc < 2) {
		printf("\n[!] Usage:\n\n\tNativeLoader.exe <Shellcode Bin>\n");
		return 0;
	}

	if (!GetFileContents(argv[1], &data, dataSize)) {
		printf("\n[!] Failed to load file\n");
		return 0;
	}

	if (data[0] == 'M' && data[1] == 'Z') {
		printf("[+] File is a DLL, please convert first\n");
		return 0;
	}
	else {
		printf("[+] File is a shellcode, attempting to inline execute\n");
		finalShellcode = data;
		finalSize = dataSize;
	}

	// Wait for user interaction to fire payload
	printf("[!] Press any key to fire payload!\n");
	getchar();

	GetNativeSystemInfo(&sysInfo);

	// Only set the first page to RWX
	// This is should sufficiently cover the sRDI shellcode up top
	if (VirtualProtect(finalShellcode, sysInfo.dwPageSize, PAGE_EXECUTE_READWRITE, &dwOldProtect1)) {
		RDI rdi = (RDI)(finalShellcode);
 		UINT_PTR hLoadedDLL = rdi(); // Excute DLL

		free(finalShellcode); // Free the RDI blob. We no longer need it.
	}

    return 0;
}

