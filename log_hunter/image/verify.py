"""Stream image media hashes and compare recorded E01 hashes or raw sidecars."""
import hashlib
from pathlib import Path
import re
import time

from .ewf import ImageError, open_image


MAX_SIDECAR = 65536
BLOCK_SIZE = 4 * 1024 * 1024


def _raw_hashes(path):
    """Read only bounded adjacent files; never follow filenames found inside them."""
    values, warnings, visited = [], [], set()
    for suffix in ('.md5', '.sha1', '.txt'):
        for candidate in (Path(str(path) + suffix), path.with_suffix(suffix)):
            if candidate in visited or candidate == path:
                continue
            visited.add(candidate)
            if not candidate.is_file():
                continue
            try:
                with candidate.open('rb') as stream:
                    raw = stream.read(MAX_SIDECAR + 1)
                if len(raw) > MAX_SIDECAR:
                    warnings.append(f'해시 보조 파일 크기 상한 초과: {candidate.name}')
                    continue
                text = raw.decode('utf-8-sig')
            except (OSError, UnicodeError) as exc:
                warnings.append(f'해시 보조 파일 읽기 실패: {candidate.name}: {exc}')
                continue
            for line in text.splitlines()[:1024]:
                line = line.strip()
                match = re.fullmatch(r'([a-fA-F0-9]{32}|[a-fA-F0-9]{40})(?:\s+\*?(.+))?', line)
                if match:
                    digest, filename = match.groups()
                    if filename and filename != path.name:
                        continue
                    algorithm = 'md5' if len(digest) == 32 else 'sha1'
                else:
                    match = re.fullmatch(r'(MD5|SHA1) \(([^)]+)\) = ([a-fA-F0-9]+)', line, re.I)
                    if not match or match[2] != path.name:
                        continue
                    algorithm, digest = match[1].lower(), match[3]
                    if len(digest) != {'md5': 32, 'sha1': 40}[algorithm]:
                        continue
                values.append({'algorithm': algorithm, 'value': digest.lower(), 'source': candidate.name})
    return values, warnings


def verify_open_image(image, path, progress=None, cancel=None, block_size=BLOCK_SIZE):
    """Hash an already opened image; progress(done,total), cancel() are optional callbacks."""
    if not isinstance(block_size, int) or not 1 <= block_size <= 16 * 1024 * 1024:
        raise ValueError('검증 읽기 블록은 1바이트~16MiB 범위여야 합니다')
    started = time.monotonic()
    stored, warnings = [], list(getattr(image, 'integrity_warnings', []))
    if image.format == 'ewf':
        for algorithm in ('md5', 'sha1'):
            value = getattr(image, 'stored_' + algorithm, None)
            if value and any(character != '0' for character in value):
                stored.append({'algorithm': algorithm, 'value': value, 'source': 'ewf'})
    elif image.format == 'raw':
        stored, sidecar_warnings = _raw_hashes(Path(path))
        warnings.extend(sidecar_warnings)
    hashes = {name: hashlib.new(name, usedforsecurity=False) for name in ('md5', 'sha1', 'sha256')}
    cache = getattr(image, 'cache', None)
    old_capacity = None
    if cache is not None:
        old_capacity = cache.capacity
        cache.capacity = 1  # Sequential verification must not retain dozens of large chunks.
        cache.items.clear()
    result = {'status': 'no_stored_hash', 'scope': 'image_media_stream', 'size': image.size,
              'bytes_read': 0, 'computed': {}, 'stored': stored, 'comparisons': [],
              'warnings': warnings, 'errors': []}
    try:
        if progress:
            progress(0, image.size)
        while result['bytes_read'] < image.size:
            if cancel and cancel():
                result['status'] = 'cancelled'
                return result
            offset = result['bytes_read']
            length = min(block_size, image.size - offset)
            try:
                data = image.read(offset, length)
            except (OSError, ImageError, ValueError) as exc:
                result['errors'].append({'offset': offset, 'length': length, 'message': str(exc)})
                result['status'] = 'read_error'
                return result
            if len(data) != length:
                result['errors'].append({'offset': offset, 'length': length, 'message': '이미지 데이터가 짧습니다'})
                result['status'] = 'read_error'
                return result
            for digest in hashes.values():
                digest.update(data)
            result['bytes_read'] += len(data)
            if progress:
                progress(result['bytes_read'], image.size)
        if cancel and cancel():
            result['status'] = 'cancelled'
            return result
        result['computed'] = {name: digest.hexdigest() for name, digest in hashes.items()}
        for item in stored:
            result['comparisons'].append({**item, 'matches': item['value'] == result['computed'][item['algorithm']]})
        if stored:
            result['status'] = 'match' if all(item['matches'] for item in result['comparisons']) else 'mismatch'
        if warnings and result['status'] in ('match', 'no_stored_hash'):
            result['status'] = 'metadata_error'
        return result
    finally:
        if cache is not None:
            cache.items.clear()
            cache.capacity = old_capacity
        result['elapsed_seconds'] = round(time.monotonic() - started, 6)


def verify_image(path, progress=None, cancel=None, block_size=BLOCK_SIZE):
    """Verify media bytes without modifying image/sidecars; partial hashes are never final hashes."""
    started = time.monotonic()
    try:
        with open_image(path) as image:
            return verify_open_image(image, path, progress, cancel, block_size)
    except (OSError, ImageError) as exc:
        return open_error(exc, time.monotonic() - started)


def open_error(exc, elapsed=0):
    return {'status': 'read_error', 'scope': 'image_media_stream', 'size': None, 'bytes_read': 0,
            'computed': {}, 'stored': [], 'comparisons': [], 'warnings': [],
            'errors': [{'offset': None, 'phase': 'open', 'message': str(exc)}],
            'elapsed_seconds': round(elapsed, 6)}
