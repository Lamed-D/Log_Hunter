#include "native.h"

/* Privilege state is restored even when export fails. No hive is mounted. */
LH_EXPORT DWORD __cdecl lh_save_registry(HKEY root, const wchar_t *subkey, const wchar_t *destination) {
    HANDLE token; HKEY key;
    TOKEN_PRIVILEGES requested, previous;
    DWORD size = sizeof(previous), error;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) return GetLastError();
    requested.PrivilegeCount = 1;
    requested.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!LookupPrivilegeValueW(NULL, SE_BACKUP_NAME, &requested.Privileges[0].Luid)) {
        error = GetLastError(); CloseHandle(token); return error;
    }
    SetLastError(ERROR_SUCCESS);
    if (!AdjustTokenPrivileges(token, FALSE, &requested, sizeof(previous), &previous, &size)) {
        error = GetLastError(); CloseHandle(token); return error;
    }
    error = GetLastError();
    if (error != ERROR_SUCCESS) { CloseHandle(token); return error; }
    error = RegOpenKeyExW(root, subkey, 0, KEY_READ, &key);
    if (!error) { error = RegSaveKeyExW(key, destination, NULL, REG_LATEST_FORMAT); RegCloseKey(key); }
    AdjustTokenPrivileges(token, FALSE, &previous, 0, NULL, NULL);
    CloseHandle(token);
    return error;
}
