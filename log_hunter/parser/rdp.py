"""Outgoing Remote Desktop client MRU, per-server hints, and .rdp settings."""
from itertools import islice
from pathlib import Path
import re
import struct

from .base import ArtifactParser
from .registry import Hive
from log_hunter.core.models import ForensicEvent
from log_hunter.core.timestamp import filetime


BASE = r'Software\Microsoft\Terminal Server Client'
MAX_TEXT = 1024 * 1024
MAX_SERVERS = 4096


def split_target(value):
    """Preserve the written host; do not resolve DNS or infer default ports."""
    value = value.strip()
    if not value or len(value) > 1024 or any(ord(char) < 32 or char == '\ufffd' for char in value):
        raise ValueError('원격 대상이 비어 있거나 길이/문자 범위가 잘못됐습니다')
    if value.startswith('['):
        match = re.fullmatch(r'\[([^\]]+)\](?::(\d+))?', value)
        if not match:
            raise ValueError('원격 대상 IPv6 괄호 형식 오류')
        host, port = match.groups()
    elif value.count(':') == 1:
        host, port = value.rsplit(':', 1)
        if not port.isascii() or not port.isdigit():
            raise ValueError('원격 대상 포트 형식 오류')
    else:
        host, port = value, None
    if not host or any(char.isspace() or char in '/\\@' for char in host) or port is not None and (
            not port.isascii() or not 1 <= int(port) <= 65535):
        raise ValueError('원격 대상 호스트/포트 범위 오류')
    return host, int(port) if port is not None else None


class RDPParser(ArtifactParser):
    artifact = 'rdp'

    def parse(self, path):
        path = Path(path)
        if path.is_dir():
            files = (file for file in path.rglob('*') if file.is_file() and file.suffix.lower() == '.rdp')
            for index, file in enumerate(files):
                if index >= MAX_SERVERS:
                    self.error(path, 'files', '원격 접속 설정 파일 개수 상한 초과', 'warning')
                    break
                yield from self._settings(file)
            return
        try:
            with path.open('rb') as stream:
                signature = stream.read(4)
        except OSError as exc:
            self.error(path, 'read', exc)
            return
        if signature == b'regf':
            try:
                yield from self._registry(path)
            except (ValueError, IndexError, struct.error) as exc:
                self.error(path, 'registry', exc, 'warning')
        else:
            yield from self._settings(path)

    def _registry(self, path):
        try:
            hive = Hive(path, on_error=lambda offset, exc: self.error(path, offset, exc, 'warning'))
        except (ValueError, OSError) as exc:
            self.error(path, 'hive', exc)
            return
        try:
            key = hive.open(BASE + r'\Default')
        except KeyError:
            key = None
        if key is not None:
            values = []
            for index, value in enumerate(key.values()):
                if index >= 1024:
                    self.error(path, BASE + r'\Default', '원격 대상 값 개수 상한 초과', 'warning')
                    break
                match = re.fullmatch(r'MRU([0-9])', value.get('name', ''), re.I)
                if match:
                    values.append((int(match[1]), value))
            for rank, value in sorted(values, key=lambda item: item[0]):
                locator = BASE + '\\Default\\' + value['name']
                if value.get('error') or value.get('type') != 1 or not isinstance(value.get('value'), str):
                    self.error(path, locator, '원격 대상 MRU 문자열 손상', 'warning')
                    continue
                try:
                    host, port = split_target(value['value'])
                except ValueError as exc:
                    self.error(path, locator, exc, 'warning')
                    continue
                yield ForensicEvent(self.artifact, str(path), 'rdp_mru', sid=self.sid, locator=locator,
                                    details={'rank': rank, 'remote_host': host, 'remote_port': port,
                                             'target_raw': value['value'], 'connection_confirmed': False})
        try:
            servers = hive.open(BASE + r'\Servers')
        except KeyError:
            return
        for index, server in enumerate(servers.subkeys()):
            if index >= MAX_SERVERS:
                self.error(path, BASE, '원격 서버 키 개수 상한 초과', 'warning')
                break
            locator = BASE + '\\Servers\\' + server.name
            try:
                host, port = split_target(server.name)
            except ValueError as exc:
                self.error(path, locator, exc, 'warning')
                continue
            hint = None
            for value in islice(server.values(), 1025):
                if value.get('name', '').lower() != 'usernamehint':
                    continue
                if value.get('error') or value.get('type') != 1 or not isinstance(value.get('value'), str):
                    self.error(path, locator, '원격 사용자 이름 힌트 손상', 'warning')
                else:
                    hint = value['value']
            yield ForensicEvent(self.artifact, str(path), 'rdp_server', filetime(server.lastwrite),
                                'key_lastwrite', self.sid, locator=locator,
                                details={'remote_host': host, 'remote_port': port, 'username_hint': hint,
                                         'time_is_connection_time': False, 'connection_confirmed': False})

    def _settings(self, path):
        try:
            with path.open('rb') as stream:
                data = stream.read(MAX_TEXT + 1)
            if len(data) > MAX_TEXT:
                raise ValueError('원격 접속 설정 파일 크기 상한 초과')
            if data.startswith((b'\xff\xfe', b'\xfe\xff')):
                text = data.decode('utf-16')
            elif b'\0' in data[:128]:
                text = data.decode('utf-16-le')
            else:
                text = data.decode('utf-8-sig')
        except (ValueError, OSError, UnicodeError) as exc:
            self.error(path, 'settings', exc, 'warning')
            return
        settings = {}
        allowed = {'full address', 'username', 'domain', 'gatewayhostname'}
        for number, line in enumerate(text.splitlines(), 1):
            parts = line.split(':', 2)
            if len(parts) != 3 or parts[0].strip().lower() not in allowed:
                continue
            name, kind, value = parts[0].strip().lower(), parts[1], parts[2].strip()
            if kind != 's' or name in settings and settings[name] != value:
                self.error(path, number, '원격 접속 설정 형식/중복값 충돌', 'warning')
                return
            settings[name] = value
        try:
            host, port = split_target(settings.get('full address', ''))
        except ValueError as exc:
            self.error(path, 'full address', exc, 'warning')
            return
        yield ForensicEvent(self.artifact, str(path), 'rdp_settings', sid=self.sid, locator='full address',
                            details={'remote_host': host, 'remote_port': port,
                                     'username_hint': settings.get('username'), 'domain': settings.get('domain'),
                                     'gateway_host': settings.get('gatewayhostname'),
                                     'connection_confirmed': False, 'target_raw': settings['full address']})
