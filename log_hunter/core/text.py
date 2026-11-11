"""대상 시스템 문자열을 해석하고 추정 여부와 손상 원시 바이트를 보존합니다."""
import codecs
import sys


def configure_console():
    """ANSI 코드 페이지 밖의 이름도 리디렉션 출력에 UTF-8로 보존합니다."""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            try:
                stream.reconfigure(encoding='utf-8', errors='backslashreplace')
            except (OSError, ValueError):
                pass


def target_acp(environment):
    value = (environment or {}).get('TARGET_ACP') or (environment or {}).get('ACP')
    try:
        number = int(value)
        if not 1 <= number <= 65535:
            return None
        name = 'utf-8' if number == 65001 else 'cp' + str(number)
        return codecs.lookup(name).name
    except (ValueError, TypeError, LookupError):
        return None


def decode_ansi(raw, codepage=None):
    raw = bytes(raw)
    if raw.isascii():
        return {'text': raw.decode('ascii'), 'encoding':'ascii', 'inferred':False, 'decode_error':False}
    encoding = target_acp({'ACP':codepage}) if str(codepage).isdigit() else codepage
    try:
        encoding = codecs.lookup(encoding).name if encoding else None
    except (LookupError, TypeError):
        encoding = None
    inferred = encoding is None
    encoding = encoding or 'cp949'
    failed = False
    try:
        text = raw.decode(encoding)
    except UnicodeDecodeError:
        text = raw.decode(encoding, errors='replace')
        failed = True
    result = {'text':text, 'encoding':encoding, 'inferred':inferred, 'decode_error':failed}
    if inferred or failed:
        result['raw_hex'] = raw.hex()
    return result


def decode_text(raw, codepage=None):
    """BOM·엄격한 UTF-8·UTF-16의 0 패턴·대상 ANSI 순으로 판별합니다."""
    raw = bytes(raw)
    encoding = None
    if raw.startswith((b'\xff\xfe', b'\xfe\xff')):
        encoding = 'utf-16'
    elif raw.startswith(b'\xef\xbb\xbf'):
        encoding = 'utf-8-sig'
    elif len(raw) >= 4 and len(raw) % 2 == 0 and raw[1::2].count(0) >= 2 and raw[1::2].count(0) > 2 * raw[::2].count(0):
        encoding = 'utf-16-le'
    elif len(raw) >= 4 and len(raw) % 2 == 0 and raw[::2].count(0) >= 2 and raw[::2].count(0) > 2 * raw[1::2].count(0):
        encoding = 'utf-16-be'
    if encoding is None:
        try:
            return {'text':raw.decode('utf-8'), 'encoding':'utf-8', 'inferred':False, 'decode_error':False}
        except UnicodeDecodeError:
            return decode_ansi(raw, codepage)
    try:
        text = raw.decode(encoding)
        failed = False
    except UnicodeDecodeError:
        text = raw.decode(encoding, errors='replace')
        failed = True
    result = {'text':text, 'encoding':encoding, 'inferred':not raw.startswith((b'\xff\xfe',b'\xfe\xff',b'\xef\xbb\xbf')), 'decode_error':failed}
    if failed or result['inferred']:
        result['raw_hex'] = raw.hex()
    return result
