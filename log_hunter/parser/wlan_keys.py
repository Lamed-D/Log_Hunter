"""제공된 WLAN 키 원문에만 Windows DPAPI를 적용합니다. 호스트 프로필은 조회하지 않습니다."""
import ctypes
import os
import uuid
from ctypes import wintypes


class _Blob(ctypes.Structure):
    _fields_=[('cbData',wintypes.DWORD),('pbData',ctypes.POINTER(ctypes.c_ubyte))]


def unprotect_key(raw):
    if os.name!='nt':
        raise NotImplementedError('Windows 복호화 API가 없는 환경입니다')
    if not 0<len(raw)<=4096:
        raise ValueError('보호 키 크기 상한 초과')
    crypt=ctypes.WinDLL('crypt32',use_last_error=True)
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    crypt.CryptUnprotectData.argtypes=[ctypes.POINTER(_Blob),ctypes.c_void_p,ctypes.c_void_p,
                                     ctypes.c_void_p,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(_Blob)]
    crypt.CryptUnprotectData.restype=wintypes.BOOL
    kernel.LocalFree.argtypes=[ctypes.c_void_p];kernel.LocalFree.restype=ctypes.c_void_p
    buffer=(ctypes.c_ubyte*len(raw)).from_buffer_copy(raw)
    source=_Blob(len(raw),buffer);output=_Blob()
    if not crypt.CryptUnprotectData(ctypes.byref(source),None,None,None,None,1,ctypes.byref(output)):
        code=ctypes.get_last_error()
        raise OSError(code,'대상 키 또는 권한 문맥에서 복호화하지 못했습니다')
    try:
        if output.cbData>8192:
            raise ValueError('복호화 결과 크기 상한 초과')
        return ctypes.string_at(output.pbData,output.cbData)
    finally:
        if output.pbData:
            ctypes.memset(output.pbData,0,output.cbData)
            kernel.LocalFree(output.pbData)


def decode_password(raw):
    if raw.startswith((b'\xff\xfe',b'\xfe\xff')):
        value=raw.decode('utf-16')
    elif len(raw)%2==0 and (raw.endswith(b'\0\0') or raw[1::2].count(0)>len(raw)//4):
        value=raw.decode('utf-16-le')
    else:
        value=raw.decode('utf-8')
    value=value.rstrip('\0')
    if '\0' in value or len(value)>256 or any(ord(char)<32 for char in value):
        raise ValueError('지원하지 않는 공유키 문자열 형식입니다')
    return value


def _profile_xml(interface_guid, profile_name, plaintext=False):
    """지정된 로컬 프로필 하나만 읽습니다. 열거·네트워크 연결·프로필 변경은 하지 않습니다."""
    if os.name!='nt': raise NotImplementedError('Windows WLAN API가 없는 환경입니다')
    guid=(ctypes.c_ubyte*16).from_buffer_copy(uuid.UUID(interface_guid.strip('{}')).bytes_le)
    api=ctypes.WinDLL('wlanapi',use_last_error=True)
    api.WlanOpenHandle.argtypes=[wintypes.DWORD,ctypes.c_void_p,ctypes.POINTER(wintypes.DWORD),ctypes.POINTER(ctypes.c_void_p)]
    api.WlanOpenHandle.restype=wintypes.DWORD
    api.WlanCloseHandle.argtypes=[ctypes.c_void_p,ctypes.c_void_p];api.WlanCloseHandle.restype=wintypes.DWORD
    api.WlanGetProfile.argtypes=[ctypes.c_void_p,ctypes.c_void_p,wintypes.LPCWSTR,ctypes.c_void_p,
                                ctypes.POINTER(ctypes.c_void_p),ctypes.POINTER(wintypes.DWORD),ctypes.POINTER(wintypes.DWORD)]
    api.WlanGetProfile.restype=wintypes.DWORD
    api.WlanFreeMemory.argtypes=[ctypes.c_void_p];api.WlanFreeMemory.restype=None
    handle=ctypes.c_void_p();version=wintypes.DWORD()
    error=api.WlanOpenHandle(2,None,ctypes.byref(version),ctypes.byref(handle))
    if error: raise OSError(error,'로컬 WLAN 서비스에 접근하지 못했습니다')
    output=ctypes.c_void_p();flags=wintypes.DWORD(4 if plaintext else 0);access=wintypes.DWORD()
    try:
        error=api.WlanGetProfile(handle,ctypes.byref(guid),profile_name,None,ctypes.byref(output),ctypes.byref(flags),ctypes.byref(access))
        if error: raise OSError(error,'지정된 WLAN 프로필을 읽지 못했습니다')
        if not output: raise OSError('WLAN 서비스가 XML을 반환하지 않았습니다')
        xml=ctypes.wstring_at(output)
        if len(xml)>1024*1024: raise ValueError('WLAN XML 크기 상한 초과')
        if plaintext: ctypes.memset(output,0,(len(xml)+1)*ctypes.sizeof(ctypes.c_wchar))
        return xml
    finally:
        if output: api.WlanFreeMemory(output)
        api.WlanCloseHandle(handle,None)


def verified_profile_candidate(raw, interface_guid, profile_name, ssid):
    """보호 키·SSID의 전후 일치가 확인된 현재 프로필 후보만 반환합니다."""
    from .wlan import parse_wlan_xml,_find,_text
    import xml.etree.ElementTree as ET
    def fields(xml):
        parsed=parse_wlan_xml(xml,decrypt=False)
        if parsed is None: raise ValueError('로컬 WLAN XML 형식 오류')
        root=ET.fromstring(xml);key=_find(root,'MSM/security/sharedKey')
        return parsed,_text(key,'keyMaterial',strip=False) if key is not None else None
    before,protected=fields(_profile_xml(interface_guid,profile_name))
    if not before['password_protected'] or before['ssid_name']!=ssid or bytes.fromhex(protected or '')!=raw:
        return None
    plain,_=fields(_profile_xml(interface_guid,profile_name,plaintext=True))
    after,protected=fields(_profile_xml(interface_guid,profile_name))
    if after['ssid_name']!=ssid or not after['password_protected'] or bytes.fromhex(protected or '')!=raw:
        return None
    if plain['ssid_name']!=ssid or plain['password_protected'] is not False:
        return None
    return plain.get('wifi_password')
