"""Windows collection through explicitly typed system APIs; no compiled extension."""
import ctypes
import ntpath
import os
import threading
from contextlib import contextmanager
from pathlib import Path


class LUID(ctypes.Structure):
    _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_int32)]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("count", ctypes.c_uint32), ("luid", LUID), ("attributes", ctypes.c_uint32)]


def _bind(library, name, result, arguments):
    function = getattr(library, name)
    function.argtypes, function.restype = arguments, result
    return function


class NativeAPI:
    _privilege_lock = threading.RLock()

    def __init__(self):
        if os.name != "nt":
            raise OSError("수집 기능은 Windows에서만 사용할 수 있습니다. 오프라인 분석을 사용하세요.")
        pointer, uint, boolean, wide = ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_wchar_p
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.security = ctypes.WinDLL("advapi32", use_last_error=True)
        self.events = ctypes.WinDLL("wevtapi", use_last_error=True)
        self.create_file = _bind(self.kernel, "CreateFileW", pointer, [wide, uint, uint, pointer, uint, uint, pointer])
        self.read_file = _bind(self.kernel, "ReadFile", boolean, [pointer, pointer, uint, ctypes.POINTER(uint), pointer])
        self.close_handle = _bind(self.kernel, "CloseHandle", boolean, [pointer])
        self.current_process = _bind(self.kernel, "GetCurrentProcess", pointer, [])
        self.open_token = _bind(self.security, "OpenProcessToken", boolean, [pointer, uint, ctypes.POINTER(pointer)])
        self.lookup_privilege = _bind(self.security, "LookupPrivilegeValueW", boolean, [wide, wide, ctypes.POINTER(LUID)])
        self.adjust_privilege = _bind(self.security, "AdjustTokenPrivileges", boolean,
                                      [pointer, boolean, ctypes.POINTER(TOKEN_PRIVILEGES), uint,
                                       ctypes.POINTER(TOKEN_PRIVILEGES), ctypes.POINTER(uint)])
        self.open_key = _bind(self.security, "RegOpenKeyExW", ctypes.c_int32, [pointer, wide, uint, uint, ctypes.POINTER(pointer)])
        self.save_key = _bind(self.security, "RegSaveKeyExW", ctypes.c_int32, [pointer, wide, pointer, uint])
        self.close_key = _bind(self.security, "RegCloseKey", ctypes.c_int32, [pointer])
        self.export_log = _bind(self.events, "EvtExportLog", boolean, [pointer, wide, wide, wide, uint])

    @staticmethod
    def _check(value):
        if not value:
            raise ctypes.WinError(ctypes.get_last_error())
        return value

    def copy_shared(self, source, destination):
        handle = self.create_file(str(source), 0x80000000, 7, None, 3, 0x0a000000, None)
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        created = False
        try:
            with Path(destination).open("xb") as output:
                created = True
                buffer, count = ctypes.create_string_buffer(1024 * 1024), ctypes.c_uint32()
                while True:
                    self._check(self.read_file(handle, buffer, len(buffer), ctypes.byref(count), None))
                    if not count.value:
                        break
                    output.write(buffer.raw[:count.value])
        except BaseException:
            if created:
                Path(destination).unlink(missing_ok=True)
            raise
        finally:
            self.close_handle(handle)

    @contextmanager
    def backup_privilege(self):
        from log_hunter.image.live import ADMIN_REQUIRED
        with self._privilege_lock:
            token = ctypes.c_void_p()
            self._check(self.open_token(self.current_process(), 0x28, ctypes.byref(token)))
            previous, changed = TOKEN_PRIVILEGES(), False
            try:
                desired = TOKEN_PRIVILEGES(count=1, attributes=2)
                self._check(self.lookup_privilege(None, "SeBackupPrivilege", ctypes.byref(desired.luid)))
                returned = ctypes.c_uint32()
                ctypes.set_last_error(0)
                self._check(self.adjust_privilege(token, False, ctypes.byref(desired), ctypes.sizeof(previous),
                                                   ctypes.byref(previous), ctypes.byref(returned)))
                changed = True
                if ctypes.get_last_error() == 1300:
                    raise PermissionError(ADMIN_REQUIRED)
                yield
            finally:
                try:
                    if changed:
                        self._check(self.adjust_privilege(token, False, ctypes.byref(previous), 0, None, None))
                finally:
                    self.close_handle(token)

    def save_registry(self, root, subkey, destination):
        if Path(destination).exists():
            raise FileExistsError(destination)
        with self.backup_privilege():
            key = ctypes.c_void_p()
            status = self.open_key(root, subkey, 0, 0x20019, ctypes.byref(key))
            if status:
                raise ctypes.WinError(status)
            try:
                status = self.save_key(key, str(Path(destination).resolve()), None, 2)
                if status:
                    raise ctypes.WinError(status)
            finally:
                self.close_key(key)

    def export_eventlog(self, channel, destination):
        if Path(destination).exists():
            raise FileExistsError(destination)
        self._check(self.export_log(None, channel, None, str(Path(destination).resolve()), 1))

    @contextmanager
    def volume_session(self, source):
        from log_hunter.image.live import LiveVolume
        from log_hunter.image.ntfs import NTFSVolume
        drive, relative = ntpath.splitdrive(str(Path(source).resolve()))
        if len(drive) != 2 or drive[1] != ":":
            raise ValueError("직접 읽기에는 로컬 드라이브의 절대 경로가 필요합니다")
        with LiveVolume(drive) as volume:
            yield NTFSVolume(volume), relative

    def copy_from_volume(self, source, destination):
        with self.volume_session(source) as (volume, relative):
            entry = volume.lookup(relative)
            if entry is None or entry.directory:
                raise FileNotFoundError(source)
            return volume.copy_file(entry, destination)

    def copy_browser(self, source, destination):
        copied = []
        with self.volume_session(source) as (volume, relative):
            for suffix in ("", "-wal", "-shm", "-journal"):
                entry = volume.lookup(relative + suffix)
                if entry is None:
                    if suffix:
                        continue
                    raise FileNotFoundError(source)
                target = Path(destination) / (Path(source).name + suffix)
                volume.copy_file(entry, target)
                copied.append((suffix, target))
        return copied
