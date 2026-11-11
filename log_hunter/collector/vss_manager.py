"""Compatibility context for callers migrating away from snapshots."""
from .winapi import NativeAPI


class VSSManager:
    def __init__(self, api=None):
        self.api = api or NativeAPI()

    def get_snapshot(self, volume="C:"):
        raise NotImplementedError("스냅샷 수집은 제거되었습니다. 공유 읽기 또는 직접 볼륨 읽기를 사용하세요.")

    def convert_path(self, original_path):
        return self.get_snapshot()

    def cleanup(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.cleanup()
