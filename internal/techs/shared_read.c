#include "native.h"

/* CreateFile + ReadFile: sharing is requested, never forced on another handle. */
LH_EXPORT DWORD __cdecl lh_copy_shared(const wchar_t *source, const wchar_t *destination) {
    HANDLE input = CreateFileW(source, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    HANDLE output;
    BYTE buffer[65536];
    DWORD error = ERROR_SUCCESS, read, written, offset;
    if (input == INVALID_HANDLE_VALUE) return GetLastError();
    output = CreateFileW(destination, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (output == INVALID_HANDLE_VALUE) { error = GetLastError(); CloseHandle(input); return error; }
    for (;;) {
        if (!ReadFile(input, buffer, sizeof(buffer), &read, NULL)) { error = GetLastError(); break; }
        if (!read) break;
        offset = 0;
        while (offset < read) {
            if (!WriteFile(output, buffer + offset, read - offset, &written, NULL)) { error = GetLastError(); break; }
            if (!written) { error = ERROR_WRITE_FAULT; break; }
            offset += written;
        }
        if (error) break;
    }
    if (!error && !FlushFileBuffers(output)) error = GetLastError();
    CloseHandle(output); CloseHandle(input);
    if (error) DeleteFileW(destination); /* only our newly-created incomplete output */
    return error;
}
