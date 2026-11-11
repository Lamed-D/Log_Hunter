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
