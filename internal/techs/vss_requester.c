/* Windows SDK exposes IVssBackupComponents in C++. Compile this .c with /TP.
 * The exported ABI is C and is consumed by Python ctypes.CDLL (cdecl).
 * A dedicated Python thread owns creation, use and teardown of each COM context.
 */
#include "native.h"
#include <vss.h>
#include <vswriter.h>
#include <vsbackup.h>
#include <new>
#include <strsafe.h>

struct LH_VSS {
    IVssBackupComponents *backup;
    VSS_ID set, snapshot;
    DWORD thread;
    bool com, metadata, ready;
    LH_VSS() : backup(NULL), set(GUID_NULL), snapshot(GUID_NULL), thread(GetCurrentThreadId()), com(false), metadata(false), ready(false) {}
};

static HRESULT wait_async(IVssAsync *operation) {
    if (!operation) return E_POINTER;
    HRESULT hr = operation->Wait(120000), state = VSS_S_ASYNC_PENDING;
    if (SUCCEEDED(hr)) hr = operation->QueryStatus(&state, NULL);
    if (SUCCEEDED(hr)) {
        if (state == VSS_S_ASYNC_PENDING) { operation->Cancel(); hr = HRESULT_FROM_WIN32(ERROR_TIMEOUT); }
        else if (state == VSS_S_ASYNC_CANCELLED) hr = HRESULT_FROM_WIN32(ERROR_CANCELLED);
        else if (FAILED(state)) hr = state;
        else if (state != VSS_S_ASYNC_FINISHED) hr = E_UNEXPECTED;
    }
    if (FAILED(hr)) operation->Cancel();
    operation->Release();
    return hr;
}

static HRESULT check_writers(IVssBackupComponents *backup) {
    IVssAsync *async = NULL;
    HRESULT hr = backup->GatherWriterStatus(&async);
    if (FAILED(hr)) { if (async) async->Release(); return hr; }
    hr = wait_async(async);
    UINT count = 0;
    if (SUCCEEDED(hr)) hr = backup->GetWriterStatusCount(&count);
    for (UINT index = 0; SUCCEEDED(hr) && index < count; ++index) {
        VSS_ID instance, writer;
        BSTR name = NULL;
        VSS_WRITER_STATE state;
        HRESULT failure = S_OK;
        hr = backup->GetWriterStatus(index, &instance, &writer, &name, &state, &failure);
        if (name) SysFreeString(name);
        if (SUCCEEDED(hr) && FAILED(failure)) hr = failure;
        if (SUCCEEDED(hr) && state >= VSS_WS_FAILED_AT_IDENTIFY) hr = VSS_E_WRITERERROR_NONRETRYABLE;
    }
    backup->FreeWriterStatus();
    return hr;
}

LH_EXPORT HRESULT __cdecl lh_vss_close(void *context) {
    LH_VSS *v = static_cast<LH_VSS *>(context);
    if (!v) return S_OK;
    if (GetCurrentThreadId() != v->thread) return RPC_E_WRONG_THREAD;
    HRESULT result = S_OK;
    if (v->backup) {
        if (v->ready) {
            IVssAsync *async = NULL;
            HRESULT hr = v->backup->BackupComplete(&async);
            if (SUCCEEDED(hr)) hr = wait_async(async);
            else if (async) async->Release();
            if (FAILED(hr)) result = hr;
        } else v->backup->AbortBackup();
        if (!IsEqualGUID(v->set, GUID_NULL)) {
            LONG deleted = 0; VSS_ID remaining = GUID_NULL;
            HRESULT hr = v->backup->DeleteSnapshots(v->set, VSS_OBJECT_SNAPSHOT_SET, TRUE, &deleted, &remaining);
            if (FAILED(hr) && SUCCEEDED(result)) result = hr;
        }
        if (v->metadata) v->backup->FreeWriterMetadata();
        v->backup->Release();
    }
    if (v->com) CoUninitialize();
    delete v;
    return result;
}

LH_EXPORT HRESULT __cdecl lh_vss_create(const wchar_t *volume, void **context, wchar_t *device, DWORD capacity, LONGLONG *created) {
    if (!volume || !context || !device || !capacity || !created) return E_INVALIDARG;
    *context = NULL; device[0] = 0;
    LH_VSS *v = new(std::nothrow) LH_VSS();
    if (!v) return E_OUTOFMEMORY;
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) { delete v; return hr; }
    v->com = true;
    hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    if (hr == RPC_E_TOO_LATE) hr = S_OK;
    IVssAsync *async = NULL;
    VSS_SNAPSHOT_PROP properties = {};
    wchar_t volume_path[MAX_PATH];
    if (SUCCEEDED(hr) && !GetVolumeNameForVolumeMountPointW(volume, volume_path, MAX_PATH)) hr = HRESULT_FROM_WIN32(GetLastError());
    if (SUCCEEDED(hr)) hr = CreateVssBackupComponents(&v->backup);
    if (SUCCEEDED(hr)) hr = v->backup->InitializeForBackup();
    if (SUCCEEDED(hr)) hr = v->backup->SetContext(VSS_CTX_BACKUP);
    if (SUCCEEDED(hr)) hr = v->backup->SetBackupState(false, false, VSS_BT_COPY, false);
    if (SUCCEEDED(hr)) {
        BOOL supported = FALSE;
        hr = v->backup->IsVolumeSupported(GUID_NULL, volume_path, &supported);
        if (SUCCEEDED(hr) && !supported) hr = VSS_E_VOLUME_NOT_SUPPORTED;
    }
    if (SUCCEEDED(hr)) {
        hr = v->backup->GatherWriterMetadata(&async);
        if (SUCCEEDED(hr)) { hr = wait_async(async); async = NULL; v->metadata = SUCCEEDED(hr); }
    }
    if (SUCCEEDED(hr)) hr = v->backup->StartSnapshotSet(&v->set);
    if (SUCCEEDED(hr)) hr = v->backup->AddToSnapshotSet(volume_path, GUID_NULL, &v->snapshot);
    if (SUCCEEDED(hr)) {
        hr = v->backup->PrepareForBackup(&async);
        if (SUCCEEDED(hr)) { hr = wait_async(async); async = NULL; }
    }
    if (SUCCEEDED(hr)) hr = check_writers(v->backup);
    if (SUCCEEDED(hr)) {
        hr = v->backup->DoSnapshotSet(&async);
        if (SUCCEEDED(hr)) { hr = wait_async(async); async = NULL; }
    }
    if (SUCCEEDED(hr)) hr = check_writers(v->backup);
    if (SUCCEEDED(hr)) {
        v->ready = true;
        hr = v->backup->GetSnapshotProperties(v->snapshot, &properties);
        if (SUCCEEDED(hr)) {
            hr = StringCchCopyW(device, capacity, properties.m_pwszSnapshotDeviceObject);
            *created = properties.m_tsCreationTimestamp;
            VssFreeSnapshotProperties(&properties);
        }
    }
    if (async) async->Release();
    if (FAILED(hr)) { lh_vss_close(v); return hr; }
    *context = v;
    return S_OK;
}
