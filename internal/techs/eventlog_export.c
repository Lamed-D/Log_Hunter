#include "native.h"
#include <winevt.h>

LH_EXPORT DWORD __cdecl lh_export_eventlog(const wchar_t *channel, const wchar_t *destination) {
    if (!EvtExportLog(NULL, channel, L"*", destination, EvtExportLogChannelPath))
        return GetLastError();
    return ERROR_SUCCESS;
}
