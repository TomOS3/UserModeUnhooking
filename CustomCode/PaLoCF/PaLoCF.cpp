#undef  _UNICODE
#define _UNICODE
#undef  UNICODE
#define UNICODE

#include <iostream>
#include <stdio.h>
#include <windows.h>
#include <direct.h>

void step(int line)
{
	printf("[%d]", line);
	Sleep(1000);
}

bool directoryExists(const std::string& directoryName)
{
	DWORD ftyp = GetFileAttributesA(directoryName.c_str());
	if (ftyp == INVALID_FILE_ATTRIBUTES)
		return false;  

	if (ftyp & FILE_ATTRIBUTE_DIRECTORY)
		return true;   

	return false;    
}

void copyFile(LPCWSTR fileSource, LPCWSTR fileDest, int& ret,BOOL expectError,DWORD expectedErrorCode)
{
	int res = CopyFileEx(fileSource, fileDest, NULL, NULL, NULL, COPY_FILE_NO_BUFFERING);
	if (res == 0)
	{
		if (expectError == FALSE)
		{
			std::wcout << "\nNo Error expected!\n";
			ret = -1;
		} 
		else
		if (GetLastError() != expectedErrorCode)
		{
			std::wcout << "\nCopying " << fileSource << " to " << fileDest << " failed with unexpected error " << GetLastError() << "\n";
			ret = -1;
		}
	}
	else
	{
		if (expectError == TRUE)
		{
			std::wcout << "\nError expected, none occured!\n";
			ret = -1;
		}
	}
}

int main(int argc, char* argv[])
{
	int ret = 0;
	printf("Compile time (for unique compilation): %s\n", __TIME__);
	printf("Waiting for some time to allow UH technique and detection of hooks...\n");
	Sleep(9000);
	Sleep(9000);
	Sleep(9000);
	Sleep(9000);
	Sleep(9000);
	Sleep(9000);
	Sleep(9000);
	Sleep(9000);
	Sleep(9000);
	Sleep(9000);

	printf("Copying files.... ");
	step(__LINE__);

	if (!directoryExists("c:\\tempdir"))
	{
		if (_mkdir("c:\\tempdir") != 0)
		{
			printf("make dir failed");
			ret = -1;
		}
	}
	step(__LINE__);
	copyFile(L"PaLoCF.exe", L"c:\\tempdir\\evil.exe", ret, FALSE, 0);
	step(__LINE__);
	copyFile(L"z:\\AV\\evil.txt", L"c:\\tempdir\\evil.exe",ret, FALSE, 0);
	step(__LINE__);
	copyFile(L"z:\\AV\\evil.txt", L"c:\\tempdir\\evil.exe", ret, FALSE, 0); //Twice, file exists
	step(__LINE__);
	copyFile(L"z:\\AV\\evil.txt", L"c:\\windows\\system32\\ntdll.dll", ret, TRUE, 5);
	step(__LINE__);
	copyFile(L"z:\\AV\\specialstring.txt", L"c:\\tempdir\\evil2.exe", ret, FALSE, 0);
	step(__LINE__);
	copyFile(L"z:\\AV\\specialstring.txt", L"c:\\windows\\system32\\ntdll2.dll", ret, TRUE, 5);
	step(__LINE__);
	copyFile(L"z:\\AV\\specialstring.txt", L"c:\\windows\\system32\\ntdll.dll", ret, TRUE, 5);
	step(__LINE__);
	copyFile(L"z:\\AV\\specialstring.txt", L"c:\\windows\\system32\\ntdll2.dll", ret, TRUE, 5);
	step(__LINE__);
	copyFile(L"z:\\AV\\specialstring.txt", L"c:\\windows\\system32\\lsass.exe", ret, TRUE, 5);
	step(__LINE__);
	copyFile(L"z:\\AV\\evil.txt", L"c:\\windows\\system32\\lsass.exe", ret, TRUE, 5);
	step(__LINE__);
	copyFile(L"\\\\VBoxSvr\\Shared\\AV\\specialstring.txt", L"c:\\tempdir\\test1.dll", ret, FALSE, 0);
	step(__LINE__);
	copyFile(L"\\\\VBoxSvr\\Shared\\AV\\specialstring.txt", L"c:\\tempdir\\test2.exe", ret, FALSE, 0);
	step(__LINE__);
	copyFile(L"\\\\VBoxSvr\\Shared\\AV\\specialstring.txt", L"c:\\tempdir\\test3.com", ret, FALSE, 0);
	step(__LINE__);
	copyFile(L"\\\\VBoxSvr\\Shared\\AV\\specialstring.txt", L"c:\\windows\\system32\\lsasss.exe", ret, TRUE, 5);
	step(__LINE__);
	copyFile(L"\\\\VBoxSvr\\Shared\\newsflash.dll", L"c:\\tempdir\\test.dll", ret, FALSE, 0);
	step(__LINE__);
	copyFile(L"\\\\VBoxSvr\\Shared\\newsflash.dll", L"c:\\tempdir\\lsass2.exe", ret, FALSE, 0);
	step(__LINE__);
	copyFile(L"\\\\VBoxSvr\\Shared\\newsflash.dll", L"c:\\windows\\system32\\lsass2.exe", ret, TRUE, 5);
	step(__LINE__);
	copyFile(L"\\\\VBoxSvr\\Shared\\newsflash.dll", L"c:\\windows\\system32\\lsass.exe", ret, TRUE, 5);
	step(__LINE__);
	copyFile(L"\\\\VBoxSvr\\Shared\\newsflash.dll", L"c:\\windows\\system32\\lsass.exe", ret, TRUE, 5);
	if (ret != 0)
	{
		printf("ERROR: return code not 0");
		return -1;
	}
	Sleep(9000);
	step(__LINE__);
	printf("Done.\n");
	return 0;
}

