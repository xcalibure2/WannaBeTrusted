#include <windows.h>
#include <stdio.h>
#include <TlHelp32.h>

// Function prototypes
BOOL MyDuplicateTokenEx(HANDLE hExistingToken, DWORD dwDesiredAccess, LPSECURITY_ATTRIBUTES lpTokenAttributes, 
                        SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, TOKEN_TYPE TokenType, PHANDLE phNewToken);
BOOL AmIAdmin();
BOOL SetMyPrivilege(HANDLE hToken, LPCWSTR lpszPrivilege, BOOL bEnablePrivilege);
BOOL EnableDebugPrivilege();
DWORD GetProcessID(const WCHAR* processName);
BOOL MyDuplicateToken(DWORD pid, HANDLE* token);
BOOL ImpersonateSystem(HANDLE* systemToken);
BOOL StartTrustedInstallerService();
BOOL GetTrustedInstallerToken(HANDLE* trustedInstallerToken);
BOOL CreateProcessWithToken(HANDLE token, const char* command);

// Function definitions

// Wrapper function for DuplicateTokenEx
BOOL MyDuplicateTokenEx(HANDLE hExistingToken, DWORD dwDesiredAccess, LPSECURITY_ATTRIBUTES lpTokenAttributes, 
                        SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, TOKEN_TYPE TokenType, PHANDLE phNewToken) {
    return DuplicateTokenEx(hExistingToken, dwDesiredAccess, lpTokenAttributes, ImpersonationLevel, TokenType, phNewToken);
}

// Check if the current process is running with administrative privileges
BOOL AmIAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }

    return isAdmin;
}

// Adjust the privileges for a given token
BOOL SetMyPrivilege(HANDLE hToken, LPCWSTR lpszPrivilege, BOOL bEnablePrivilege) {
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValueW(NULL, lpszPrivilege, &luid)) {
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = bEnablePrivilege ? SE_PRIVILEGE_ENABLED : 0;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        return FALSE;
    }

    return TRUE;
}

// Enable the debug privilege for the current process
BOOL EnableDebugPrivilege() {
    HANDLE hToken;
    BOOL result = FALSE;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        result = SetMyPrivilege(hToken, L"SeDebugPrivilege", TRUE);
        CloseHandle(hToken);
    }

    return result;
}

// Get the process ID by process name
DWORD GetProcessID(const WCHAR* processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    DWORD processID = 0;

    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W entry;
        entry.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(snapshot, &entry)) {
            do {
                if (_wcsicmp(entry.szExeFile, processName) == 0) {
                    processID = entry.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snapshot, &entry));
        }
        CloseHandle(snapshot);
    }

    return processID;
}

// Duplicate the token of a process by its PID
BOOL MyDuplicateToken(DWORD pid, HANDLE* token) {
    BOOL success = FALSE;
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, FALSE, pid);

    if (process) {
        HANDLE tokenHandle;
        if (OpenProcessToken(process, TOKEN_DUPLICATE, &tokenHandle)) {
            SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, FALSE };
            success = MyDuplicateTokenEx(tokenHandle, TOKEN_ALL_ACCESS, &sa, SecurityImpersonation, TokenPrimary, token);
            CloseHandle(tokenHandle);
        }
        CloseHandle(process);
    }

    return success;
}

// Impersonate the SYSTEM process
BOOL ImpersonateSystem(HANDLE* systemToken) {
    DWORD pid = GetProcessID(L"winlogon.exe");

    if (pid && MyDuplicateToken(pid, systemToken)) {
        wprintf(L"Successfully impersonated winlogon.exe - PID: %lu\n", pid);
        return TRUE;
    } else {
        wprintf(L"Failed to impersonate winlogon.exe. Trying services.exe...\n");
        pid = GetProcessID(L"services.exe");

        if (pid && MyDuplicateToken(pid, systemToken)) {
            wprintf(L"Successfully impersonated services.exe - PID: %lu\n", pid);
            return TRUE;
        } else {
            wprintf(L"Failed to impersonate services.exe.\n");
            return FALSE;
        }
    }
}

// Ensure the TrustedInstaller service is running
BOOL StartTrustedInstallerService() {
	
	// Trying to open it
    SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);

    if (schSCManager == NULL) {
        return FALSE;
    }
	// Open TI Service
    SC_HANDLE schService = OpenServiceW(schSCManager, L"TrustedInstaller", SERVICE_START | SERVICE_QUERY_STATUS);

    if (schService == NULL) {
        CloseServiceHandle(schSCManager);
        return FALSE;
    }
	// Status?
    SERVICE_STATUS_PROCESS ssStatus;
    DWORD dwBytesNeeded;

    if (!QueryServiceStatusEx(schService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssStatus, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded)) {
        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
        return FALSE;
    }
	
	// TI running?
    if (ssStatus.dwCurrentState != SERVICE_RUNNING) {
        if (!StartServiceW(schService, 0, NULL)) {
            CloseServiceHandle(schService);
            CloseServiceHandle(schSCManager);
            return FALSE;
        }
		// Trying to open TI with a loop
        wprintf(L"Starting TrustedInstaller service...\n");
        do {
            if (!QueryServiceStatusEx(schService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssStatus, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded)) {
                CloseServiceHandle(schService);
                CloseServiceHandle(schSCManager);
                return FALSE;
            }
            Sleep(500); // Wait a bit before retrying
        } while (ssStatus.dwCurrentState == SERVICE_START_PENDING);

        if (ssStatus.dwCurrentState != SERVICE_RUNNING) { // Last check
            wprintf(L"Failed to start TrustedInstaller service.\n");
            CloseServiceHandle(schService);
            CloseServiceHandle(schSCManager);
            return FALSE;
        }
    }

    wprintf(L"TrustedInstaller service is running.\n"); // There you go! TI is now running
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
    return TRUE;
}

// Impersonate the TrustedInstaller process
BOOL GetTrustedInstallerToken(HANDLE* trustedInstallerToken) {
    if (!StartTrustedInstallerService()) {
        return FALSE;
    }

    DWORD pid = GetProcessID(L"TrustedInstaller.exe");

    if (pid && MyDuplicateToken(pid, trustedInstallerToken)) {
        wprintf(L"Successfully impersonated TrustedInstaller - PID: %lu\n", pid);
        return TRUE;
    } else {
        wprintf(L"Failed to impersonate TrustedInstaller.\n");
        return FALSE;
    }
}

// Create a new process with a duplicated token
BOOL CreateProcessWithToken(HANDLE token, const char* command) {
    STARTUPINFOW si = { sizeof(STARTUPINFOW) };
    PROCESS_INFORMATION pi;
    WCHAR wCommand[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, command, -1, wCommand, MAX_PATH);

    BOOL result = CreateProcessWithTokenW(token, LOGON_WITH_PROFILE, NULL, wCommand, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);

    if (result) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        wprintf(L"CreateProcessWithTokenW failed.\n");
    }

    return result;
}

// Entry point of "WannaBeTrusted"
int main(int argc, char* argv[]) {
    wprintf(L"******************************************\n");
    wprintf(L"*                                        *\n");
    wprintf(L"*           WannaBeTrusted               *\n");
    wprintf(L"*                                        *\n");
    wprintf(L"*            Powered by                  *\n");
    wprintf(L"*             Luca Demers                *\n");
    wprintf(L"*                                        *\n");
    wprintf(L"*       https://lucademers.com/          *\n");
    wprintf(L"*                                        *\n");
    wprintf(L"******************************************\n");
    wprintf(L"This program attempts to obtain SYSTEM or TrustedInstaller privileges\n");
    wprintf(L"by duplicating the tokens of privileged processes. Typically, this requires two steps:\n");
    wprintf(L"1. Elevate the current process privileges to obtain a SYSTEM token.\n");
    wprintf(L"2. Use the SYSTEM token to duplicate tokens from other SYSTEM or TrustedInstaller processes.\n");

    if (!AmIAdmin()) {
        wprintf(L"This program must be run as an administrator.\n");
        return 1;
    }

    if (!EnableDebugPrivilege()) {
        wprintf(L"Failed to enable debug privilege.\n");
        return 1;
    }

    HANDLE systemToken = NULL;
    HANDLE trustedInstallerToken = NULL;

    if (ImpersonateSystem(&systemToken)) {
        wprintf(L"Obtained SYSTEM token.\n");

        // Set necessary privileges for SYSTEM token
        SetMyPrivilege(systemToken, L"SeTakeOwnershipPrivilege", TRUE);
        SetMyPrivilege(systemToken, L"SeLoadDriverPrivilege", TRUE);
        SetMyPrivilege(systemToken, L"SeBackupPrivilege", TRUE);
        SetMyPrivilege(systemToken, L"SeRestorePrivilege", TRUE);

        // Use SYSTEM token to get TrustedInstaller token
        if (ImpersonateLoggedOnUser(systemToken)) {
            wprintf(L"Impersonated SYSTEM token.\n");

            if (GetTrustedInstallerToken(&trustedInstallerToken)) {
                wprintf(L"Obtained TrustedInstaller token.\n");

                // Set necessary privileges for TrustedInstaller token
                SetMyPrivilege(trustedInstallerToken, L"SeTakeOwnershipPrivilege", TRUE);
                SetMyPrivilege(trustedInstallerToken, L"SeLoadDriverPrivilege", TRUE);
                SetMyPrivilege(trustedInstallerToken, L"SeBackupPrivilege", TRUE);
                SetMyPrivilege(trustedInstallerToken, L"SeRestorePrivilege", TRUE);

                // Create a new process with TrustedInstaller token
                if (CreateProcessWithToken(trustedInstallerToken, "cmd.exe")) {
                    wprintf(L"Created process with TrustedInstaller token.\n");
                } else {
                    wprintf(L"Failed to create process with TrustedInstaller token.\n");
                }

                CloseHandle(trustedInstallerToken);
            } else {
                wprintf(L"Failed to obtain TrustedInstaller token.\n");
            }

            RevertToSelf();
        } else {
            wprintf(L"Failed to impersonate SYSTEM token.\n");
        }

        CloseHandle(systemToken);
    } else {
        wprintf(L"Failed to obtain SYSTEM token.\n");
        return 1;
    }

    return 0;
}