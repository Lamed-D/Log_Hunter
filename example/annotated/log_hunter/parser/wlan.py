# ▶ 원본: log_hunter/parser/wlan.py
# ▶ 기록 형식에 맞는 필드와 시각을 읽습니다. 범위 검사와 self.error 호출을 함께 확인하세요.
# ▶ 실행 코드는 원본과 동일하며 이 접두어의 줄은 학습 해설입니다.
"""Windows WLAN profile XML parser.

Parses Wi-Fi profile XML files from:
  C:\\ProgramData\\Microsoft\\Wlansvc\\Profiles\\Interfaces\\{GUID}\\*.xml
"""
import xml.etree.ElementTree as ET
from itertools import islice
from pathlib import Path
import uuid
from .base import ArtifactParser
from log_hunter.core.models import ForensicEvent

NS = "http://www.microsoft.com/networking/WLAN/profile/v1"
NS_MAP = {"w": NS}


def _text(element, tag, strip=True):
    child = element.find(f"w:{tag}", NS_MAP)
    if child is None:
        child = element.find(tag)
    if child is None or child.text is None:
        return None
    return child.text.strip() if strip else child.text


def _find(element, path):
    found=element.find("/".join(f"w:{p}" for p in path.split("/")), NS_MAP)
    return found if found is not None else element.find(path)


def parse_wlan_xml(data, source_path="", decrypt=False):
    if len(data)>1024*1024:
        return None
    declarations=data.replace(b'\0',b'').upper() if isinstance(data,bytes) else data.upper()
    markers=(b'<!DOCTYPE',b'<!ENTITY') if isinstance(declarations,bytes) else ('<!DOCTYPE','<!ENTITY')
    if any(marker in declarations for marker in markers):
        return None
    try:
        root = ET.fromstring(data)
    except (ET.ParseError, UnicodeError, ValueError, LookupError):
        return None
    tag = root.tag
    if tag not in ('{'+NS+'}WLANProfile','WLANProfile'):
        return None

    name = _text(root, "name", strip=False)
    ssid_config = _find(root, "SSIDConfig/SSID")
    ssid_hex = None
    ssid_name = None
    if ssid_config is not None:
        ssid_hex = _text(ssid_config, "hex")
        ssid_name = _text(ssid_config, "name", strip=False)

    conn_type = _text(root, "connectionType")
    conn_mode = _text(root, "connectionMode")

    auth_enc = _find(root, "MSM/security/authEncryption")
    authentication = None
    encryption = None
    if auth_enc is not None:
        authentication = _text(auth_enc, "authentication")
        encryption = _text(auth_enc, "encryption")

    shared_key = _find(root, "MSM/security/sharedKey")
    has_cleartext_password = False
    password=None;key_material=None;protected='';password_state='not_in_profile';decryption_error=None
    password_source=None
    if shared_key is not None:
        key_material = _text(shared_key, "keyMaterial", strip=False)
        protected = (_text(shared_key, "protected") or "").strip().lower()
        if key_material and protected in ("false", "0"):
            has_cleartext_password = True
            password=key_material
            password_state='plaintext_in_profile'
            password_source='input_xml'
            if len(password)>256:
                password=None;password_state='invalid_or_unsupported_key'
                decryption_error='공유키 문자열 크기 상한 초과'
        elif key_material and protected in ('true','1'):
            password_state='protected'
            if decrypt:
                from .wlan_keys import unprotect_key,decode_password
                try:
                    if len(key_material)>8192:
                        raise ValueError('보호 키 크기 상한 초과')
                    raw=bytes.fromhex(key_material)
                    password=decode_password(unprotect_key(raw))
                    password_state='decrypted'
                    password_source='dpapi_input_blob'
                except NotImplementedError:
                    password_state='platform_unavailable'
                    decryption_error='Windows DPAPI가 없는 환경이라 보호 키를 복호화하지 않았습니다'
                except OSError as exc:
                    password_state='context_unavailable'
                    decryption_error='복호화 불가: 대상 키·권한 문맥 또는 손상 여부 확인 필요 (Windows 오류 '+str(getattr(exc,'winerror',None) or exc.errno or '미상')+')'
                    # 동일 이름만으로 호스트 비밀번호를 대신 넣지 않습니다.
                    interface=None
                    for parent in Path(source_path).parents:
                        if parent.name.startswith('{') and parent.name.endswith('}'):
                            try: interface=str(uuid.UUID(parent.name.strip('{}')))
                            except ValueError: continue
                            break
                    if interface and name and ssid_name:
                        from .wlan_keys import verified_profile_candidate
                        try:
                            candidate=verified_profile_candidate(raw,interface,name,ssid_name)
                            if candidate is not None:
                                password=candidate;password_state='verified_live_candidate'
                                password_source='protected_blob_checked_before_after'
                                decryption_error=None
                        except (OSError,ValueError,NotImplementedError):
                            pass
                except (ValueError,UnicodeError):
                    password_state='invalid_or_unsupported_key'
                    decryption_error='보호 키 또는 복호화 결과 형식이 지원 범위를 벗어났습니다'
        elif key_material:
            password_state='unknown_protection'

    return {
        "profile_name": name or ssid_name,
        "ssid_name": ssid_name,
        "ssid_hex": ssid_hex,
        "connection_type": conn_type,
        "connection_mode": conn_mode,
        "automatic_connection": conn_mode == 'auto' if conn_mode in ('auto','manual') else None,
        "authentication": authentication,
        "encryption": encryption,
        "cleartext_password_found": has_cleartext_password,
        'password_stored_in_profile':bool(key_material),
        'password_protected':True if protected in ('true','1') else False if protected in ('false','0') else None,
        'wifi_password':password,
        'password_state':password_state,
        'password_source':password_source,
        'password_decryption_error':decryption_error,
    }


class WLANParser(ArtifactParser):
    artifact = "wlan"

    def parse(self, path):
        source = Path(path)
        if source.is_dir():
            files = sorted(islice((f for f in source.rglob("*.xml") if f.is_file()),8193))
        else:
            files = [source]

        for index,file in enumerate(files):
            if index>=8192:
                self.error(source,'profiles','WLAN 프로필 개수 상한 초과','warning')
                break
            try:
                data = file.read_bytes()
            except OSError as exc:
                self.error(file, "read", exc)
                continue

            if len(data)>1024*1024:
                self.error(file,'size','WLAN 프로필 크기 상한 초과','warning')
                continue
            if b"WLANProfile" not in data[:4096].replace(b'\0',b''):
                continue

            parsed = parse_wlan_xml(data, file, decrypt=True)
            if parsed is None:
                self.error(file, "xml", "WLAN 프로필 XML 파싱 실패", "warning")
                continue

            action = "wlan_profile"
            status = "ok"
            if parsed["cleartext_password_found"]:
                action = "cleartext_password"
                status = "warning"

            details = {k: v for k, v in parsed.items() if v is not None}
            if parsed.get('password_decryption_error'):
                self.error(file,'sharedKey',parsed['password_decryption_error'],'warning')
            if parsed["cleartext_password_found"]:
                details["cleartext_password_found"] = True
                details["risk_level"] = "high"

            interface_guid = None
            for parent in file.parents:
                name = parent.name
                if name.startswith("{") and name.endswith("}"):
                    interface_guid = name
                    break

            if interface_guid:
                details["interface_guid"] = interface_guid

            yield ForensicEvent(
                self.artifact, str(file), action,
                None, None,
                sid=self.sid,
                path=str(file),
                locator=str(file),
                status=status,
                details=details,
            )
