# ▶ 원본: log_hunter/collector/registry_collector.py
# ▶ 레지스트리 저장 API로 수집한 하이브를 증거 목록과 연결합니다.
# ▶ 실행 코드는 원본과 동일하며 이 접두어의 줄은 학습 해설입니다.
from pathlib import Path
from .live_collector import register_evidence
from .winapi import NativeAPI


def profile_list():
    import winreg
    result = {}
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList") as root:
        for index in range(winreg.QueryInfoKey(root)[0]):
            sid = winreg.EnumKey(root, index)
            with winreg.OpenKey(root, sid) as key:
                try:
                    result[sid] = winreg.QueryValueEx(key, "ProfileImagePath")[0]
                except FileNotFoundError:
                    pass
    return result


class RegistryCollector:
    def __init__(self, api=None):
        self.api = api or NativeAPI()

    def collect(self, source, destination):
        # Explicit root notation is required; arbitrary commands are never evaluated.
        root, _, subkey = source.partition("\\")
        roots = {"HKLM": 0xFFFFFFFF80000002, "HKU": 0xFFFFFFFF80000003}
        if root not in roots or not subkey:
            raise ValueError("HKLM\\SYSTEM 또는 HKU\\SID 형식이 필요합니다")
        destination = Path(destination).resolve()
        if destination.exists():
            raise FileExistsError(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        self.api.save_registry(roots[root], subkey, destination)
        return register_evidence(source, destination, "RegSaveKeyExW")
