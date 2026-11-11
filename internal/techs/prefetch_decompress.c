#include "native.h"

typedef LONG (WINAPI *GET_WORKSPACE)(USHORT, PULONG, PULONG);
typedef LONG (WINAPI *DECOMPRESS_EX)(USHORT, PUCHAR, ULONG, PUCHAR, ULONG, PULONG, PVOID);

/* XPRESS_HUFF (4). Python validates MAM header and bounds the output size. */
LH_EXPORT LONG __cdecl lh_decompress_prefetch(const BYTE *input, DWORD input_size, BYTE *output, DWORD capacity, DWORD *written) {
    HMODULE module = GetModuleHandleW(L"ntdll.dll");
    GET_WORKSPACE get_workspace;
    DECOMPRESS_EX decompress;
    ULONG workspace_size = 0, fragment_size = 0, final_size = 0;
    PVOID workspace;
    LONG result;
    if (!input || !output || !written || !capacity || !module) return (LONG)0xC000000DL;
    *written = 0;
    get_workspace = (GET_WORKSPACE)GetProcAddress(module, "RtlGetCompressionWorkSpaceSize");
    decompress = (DECOMPRESS_EX)GetProcAddress(module, "RtlDecompressBufferEx");
    if (!get_workspace || !decompress) return (LONG)0xC0000002L;
    result = get_workspace(4, &workspace_size, &fragment_size);
    if (result < 0) return result;
    workspace = HeapAlloc(GetProcessHeap(), 0, workspace_size);
    if (!workspace) return (LONG)0xC0000017L;
    result = decompress(4, output, capacity, (PUCHAR)input, input_size, &final_size, workspace);
    HeapFree(GetProcessHeap(), 0, workspace);
    if (result >= 0) *written = final_size;
    return result;
}
