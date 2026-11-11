#pragma once
#include <windows.h>
#ifdef __cplusplus
#define LH_EXPORT extern "C" __declspec(dllexport)
#else
#define LH_EXPORT __declspec(dllexport)
#endif
LH_EXPORT DWORD __cdecl lh_copy_shared(const wchar_t *source, const wchar_t *destination);
LH_EXPORT DWORD __cdecl lh_export_eventlog(const wchar_t *channel, const wchar_t *destination);
LH_EXPORT DWORD __cdecl lh_save_registry(HKEY root, const wchar_t *subkey, const wchar_t *destination);
LH_EXPORT HRESULT __cdecl lh_vss_create(const wchar_t *volume, void **context, wchar_t *device, DWORD capacity, LONGLONG *created);
LH_EXPORT HRESULT __cdecl lh_vss_close(void *context);
LH_EXPORT LONG __cdecl lh_decompress_prefetch(const BYTE *input, DWORD input_size, BYTE *output, DWORD capacity, DWORD *written);
