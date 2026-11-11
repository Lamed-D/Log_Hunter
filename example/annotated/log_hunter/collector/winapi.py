# ▶ 원본: log_hunter/collector/winapi.py
# ▶ 이전 수집 코드가 현재 Windows API 구현을 가져올 수 있도록 공개 이름을 연결합니다.
# ▶ 실행 코드는 원본과 동일하며 이 접두어의 줄은 학습 해설입니다.
"""Compatibility imports for standard-library Windows collection and Prefetch decoding."""
import ctypes
import os
from .windows import NativeAPI
from log_hunter.parser.xpress import decompress_prefetch

__all__ = ["NativeAPI", "decompress_prefetch", "is_admin"]


def is_admin():
    if os.name != "nt":
        return False
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    shell.IsUserAnAdmin.argtypes = []
    shell.IsUserAnAdmin.restype = ctypes.c_int
    return bool(shell.IsUserAnAdmin())
