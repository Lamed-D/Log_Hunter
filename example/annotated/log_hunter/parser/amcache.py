# ▶ 원본: log_hunter/parser/amcache.py
# ▶ 기록 형식에 맞는 필드와 시각을 읽습니다. 범위 검사와 self.error 호출을 함께 확인하세요.
# ▶ 실행 코드는 원본과 동일하며 이 접두어의 줄은 학습 해설입니다.
from .base import ArtifactParser
from .registry import Hive, walk
from log_hunter.core.models import ForensicEvent
from log_hunter.core.timestamp import filetime


INVENTORY_FIELDS = {
    "LowerCaseLongPath": "path",
    "Name": "name",
    "Publisher": "publisher",
    "ProductName": "product",
    "ProductVersion": "product_version",
    "BinFileVersion": "file_version",
    "BinaryType": "binary_type",
    "Language": "language",
    "LinkDate": "link_date",
    "ProgramId": "program_id",
    "Size": "size",
    "Usn": "usn",
    "FileId": "file_id",
    "IsPeFile": "is_pe",
    "IsOsComponent": "is_os_component",
}

LEGACY_FIELDS = {
    "0":  "product_name",
    "1":  "company_name",
    "2":  "file_version_string",
    "3":  "language_code",
    "5":  "file_version",
    "6":  "file_size",
    "7":  "pe_header_hash",
    "c":  "program_description",
    "f":  "link_date_raw",
    "11": "last_modified_raw",
    "12": "created_raw",
    "15": "full_path",
    "17": "last_modified_2",
    "100": "program_id",
    "101": "sha1_hash",
}


class AmcacheParser(ArtifactParser):
    artifact = "amcache"

    def parse(self, path):
        hive = Hive(path, on_error=lambda offset, exc: self.error(path, offset, exc, "warning"))
        yield from self._parse_inventory(hive, path)
        yield from self._parse_legacy(hive, path)
        yield from self._parse_programs(hive, path)

    def _parse_inventory(self, hive, path):
        try:
            root = hive.open(r"Root\InventoryApplicationFile")
        except KeyError:
            return
        for suffix, key in walk(root):
            values = {v["name"]: v for v in key.values() if "error" not in v}
            target = values.get("LowerCaseLongPath", {}).get("value")
            if not isinstance(target, str):
                continue
            details = {"layout": "InventoryApplicationFile", "execution_confirmed": False}
            for reg_name, field_name in INVENTORY_FIELDS.items():
                val = values.get(reg_name, {}).get("value")
                if val is not None:
                    details[field_name] = val
            raw_hash = values.get("FileId", {}).get("value")
            if isinstance(raw_hash, str) and raw_hash.startswith("0000"):
                details["sha1"] = raw_hash[4:]
                details["hash_type"] = "SHA-1 (FileId prefix stripped)"
            else:
                details["hash_raw"] = raw_hash
                details["hash_type"] = "Amcache FileId (not full-file SHA-1)"
            details["all_values"] = {n: {"type": v["type"], "raw": v["raw"].hex()} for n, v in values.items()}
            yield ForensicEvent(self.artifact, str(path), "file_inventory", filetime(key.lastwrite),
                                "key_lastwrite", path=target, locator="Root\\InventoryApplicationFile" + suffix,
                                details=details)

    def _parse_legacy(self, hive, path):
        try:
            root = hive.open(r"Root\File")
        except KeyError:
            return
        for suffix, key in walk(root):
            values = {v["name"]: v for v in key.values() if "error" not in v}
            target = values.get("15", {}).get("value")
            if not isinstance(target, str):
                continue
            details = {"layout": "Root\\File (legacy)", "execution_confirmed": False}
            for reg_name, field_name in LEGACY_FIELDS.items():
                val = values.get(reg_name, {}).get("value")
                if val is not None:
                    details[field_name] = val
            raw_hash = values.get("101", {}).get("value")
            if isinstance(raw_hash, str) and raw_hash.startswith("0000"):
                details["sha1"] = raw_hash[4:]
                details["hash_type"] = "SHA-1 (legacy field 101)"
            else:
                details["hash_raw"] = raw_hash
                details["hash_type"] = "Amcache legacy hash"
            details["all_values"] = {n: {"type": v["type"], "raw": v["raw"].hex()} for n, v in values.items()}
            yield ForensicEvent(self.artifact, str(path), "file_inventory", filetime(key.lastwrite),
                                "key_lastwrite", path=target, locator="Root\\File" + suffix,
                                details=details)

    def _parse_programs(self, hive, path):
        try:
            root = hive.open(r"Root\InventoryApplication")
        except KeyError:
            try:
                root = hive.open(r"Root\Programs")
            except KeyError:
                return
        for suffix, key in walk(root):
            values = {v["name"]: v for v in key.values() if "error" not in v}
            name = values.get("Name", values.get("0", {})).get("value")
            if not isinstance(name, str):
                continue
            details = {
                "layout": "program_inventory",
                "program_name": name,
                "publisher": values.get("Publisher", values.get("1", {})).get("value"),
                "version": values.get("Version", values.get("2", {})).get("value"),
                "install_date": values.get("InstallDate", {}).get("value"),
                "uninstall_string": values.get("UninstallString", values.get("7", {})).get("value"),
                "install_source": values.get("InstallSource", values.get("d", {})).get("value"),
            }
            yield ForensicEvent(self.artifact, str(path), "program_inventory", filetime(key.lastwrite),
                                "key_lastwrite", path=name, locator="Root\\Programs" + suffix,
                                details={k: v for k, v in details.items() if v is not None})
