"""Read the running PC's NTFS volume directly (\\\\.\\C:) so files Windows keeps locked
(registry hives, event logs, Amcache) can be copied without stopping the system."""
import ctypes
import os
import re
import struct
import subprocess
import sys
from pathlib import Path
from .ewf import DiskImage, ImageError

ALIGN = 4096
_DRIVE = re.compile(r"^(?:\\\\[.?]\\)?([A-Za-z]):?\\?$")
ADMIN_REQUIRED = ("실행 중인 PC를 직접 분석하려면 관리자 권한이 필요합니다. "
                  "Log Hunter를 '관리자 권한으로 실행'하거나 GUI의 '이 PC 직접 분석' 버튼을 사용하세요.")
LIVE_WARNING = ("실행 중인 PC에서 직접 읽었습니다. 읽는 도중에도 Windows가 파일을 계속 쓰기 때문에 "
                "몇 초 전 변경 내용이 빠지거나 일부 파일이 깨져 보일 수 있습니다")


def live_device(spec):
    """'C', 'C:', 'C:\\' or '\\\\.\\C:' -> '\\\\.\\C:'; None when spec is not a drive letter."""
    match = _DRIVE.match(str(spec).strip())
    return f"\\\\.\\{match[1].upper()}:" if match else None


def is_live_path(path):
    return str(path).startswith(("\\\\.\\", "\\\\?\\")) and live_device(path) is not None


def system_drive():
    return os.environ.get("SystemDrive", "C:")


def is_admin():
    if os.name != "nt":
        return hasattr(os, "geteuid") and os.geteuid() == 0
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def relaunch_as_admin(arguments):
    """Start `python <arguments>` through the Windows UAC prompt. True if the elevated process started."""
    if os.name != "nt":
        return False
    shell = ctypes.windll.shell32
    shell.ShellExecuteW.argtypes = (ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_wchar_p,
                                    ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_int)
    shell.ShellExecuteW.restype = ctypes.c_void_p
    package_root = str(Path(__file__).resolve().parents[2])
    code = shell.ShellExecuteW(None, "runas", sys.executable, subprocess.list2cmdline(arguments), package_root, 1)
    return (code or 0) > 32


def _open_device(device):
    return open(device, "rb", buffering=0)


class LiveVolume(DiskImage):
    """A mounted NTFS volume opened as a raw device. Reads are widened to 4KB boundaries
    because Windows rejects unaligned reads on volume handles."""
    format = "live"

    def __init__(self, device):
        self.device = live_device(device)
        if self.device is None:
            raise ImageError(f"드라이브 이름이 아닙니다: {device}")
        if not is_admin():
            raise PermissionError(ADMIN_REQUIRED)
        try:
            self.stream = _open_device(self.device)
        except PermissionError as exc:
            raise PermissionError(ADMIN_REQUIRED) from exc
        except OSError as exc:
            raise ImageError(f"{self.device[4:]} 드라이브를 열 수 없습니다 ({exc})") from exc
        self.size = None
        boot = self._aligned(0, 512)
        if boot[3:11] == b"-FVE-FS-":
            self.close()
            raise ImageError(f"{self.device[4:]} 드라이브가 BitLocker로 잠겨 있습니다. 잠금 해제 후 다시 시도하세요")
        if boot[3:11] != b"NTFS    ":
            self.close()
            raise ImageError(f"{self.device[4:]} 드라이브는 NTFS가 아닙니다")
        self.sector_size, = struct.unpack_from("<H", boot, 0x0B)
        total_sectors, = struct.unpack_from("<Q", boot, 0x28)
        self.size = (total_sectors + 1) * self.sector_size

    def _aligned(self, offset, length):
        start = offset - offset % ALIGN
        end = -(-(offset + length) // ALIGN) * ALIGN
        if self.size is not None:
            end = min(end, -(-self.size // self.sector_size) * self.sector_size)
        self.stream.seek(start)
        data = bytearray()
        while len(data) < end - start:
            piece = self.stream.read(end - start - len(data))
            if not piece:
                break
            data += piece
        return bytes(data[offset - start:offset - start + length])

    def read(self, offset, length):
        if offset < 0 or length < 0:
            raise ValueError("음수 오프셋/길이")
        length = max(0, min(length, self.size - offset))
        return self._aligned(offset, length) if length else b""

    def info(self):
        return {**super().info(), "device": self.device, "drive": self.device[4:]}

    def close(self):
        self.stream.close()
