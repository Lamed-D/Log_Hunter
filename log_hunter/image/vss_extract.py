"""명시적으로 선택한 VSS 부분 뷰에서 기존 NTFS 아티팩트 추출을 재사용합니다."""
import json
from log_hunter.core.labels import SNAPSHOT_VERIFY_LABELS
from pathlib import Path

from .ewf import DiskImage, ImageError, open_image
from .extract import ARTIFACT_SPECS, MFT_SPEC, ImageExtraction, _assign_sids, _extract_volume
from .live import is_live_path
from .ntfs import NTFSError, NTFSVolume
from .volumes import find_volumes
from .vss import read_catalog
from .vss_volume import prepare_mapped_volume


class _NTFSPartialView(DiskImage):
    """기존 NTFS 추출기의 오류 경계에 부분 뷰의 읽기 실패를 전달합니다."""
    def __init__(self, reader):
        self.reader = reader
        self.size = reader.size

    def read(self, offset, length):
        try:
            return self.reader.read(offset, length)
        except ImageError as exc:
            raise NTFSError(str(exc)) from exc


def extract_mapped_snapshot(image_path, output_dir, volume_index, store_id, include_mft=False, progress=None,
                            verification_progress=None, verification_cancel=None):
    """미매핑 영역은 진단으로 남기며, 전체 스냅숏을 추출했다고 주장하지 않습니다."""
    if is_live_path(image_path) or str(image_path).startswith(('\\\\.\\', '\\\\?\\')):
        raise ValueError('스냅숏 추출은 오프라인 이미지에서만 지원합니다')
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise FileExistsError(f'추출 폴더가 비어 있지 않습니다: {output}')
    result = ImageExtraction(str(Path(image_path).resolve()), str(output.resolve()))
    try:
        with open_image(image_path) as image:
            result.image = image.info()
            volumes = [v for v in find_volumes(image) if v.index == volume_index and v.filesystem == 'ntfs']
            if type(volume_index) is not int or len(volumes) != 1:
                raise ValueError('선택한 NTFS 볼륨을 이미지에서 찾을 수 없습니다')
            volume = volumes[0]
            result.volumes = [volume.to_dict()]
            catalog = read_catalog(image, volume, result.image_path)
            prepared = prepare_mapped_volume(image, volume, catalog, store_id, result.image_path)
            result.warnings.extend(f'{error.locator}: {error.message}' for error in prepared.errors)
            reader = prepared.reader
            if reader is not None:
                if not reader.verify_reconstruction(verification_progress, verification_cancel):
                    result.warnings.append('VSS 부분 뷰에서 확인된 저장 블록만 추출합니다. 전체 스냅숏 결과가 아닙니다')
                try:
                    if reader.verification['status'] == 'cancelled':
                        raise ValueError(SNAPSHOT_VERIFY_LABELS['cancelled'])
                    ntfs = NTFSVolume(_NTFSPartialView(reader), 0)
                    specs = ARTIFACT_SPECS + ([MFT_SPEC] if include_mft else [])
                    _extract_volume(ntfs, volume.index, output / 'snapshot', specs, result, progress)
                except (ImageError, NTFSError, ValueError, OSError) as exc:
                    result.warnings.append(f'스냅숏 NTFS 부분 추출: {exc}')
                result.image['snapshot'] = dict(reader.origin)
                result.image['snapshot_verification'] = dict(reader.verification)
                for item in result.files:
                    item['snapshot'] = dict(reader.origin)
                result.warnings.extend(f'{error.locator}: {error.message}' for error in reader.errors)
    except (ImageError, ValueError, OSError) as exc:
        result.warnings.append(f'스냅숏 추출 준비 실패: {exc}')
    if not result.files:
        result.warnings.append('선택한 스냅숏의 확인 가능한 범위에서 아티팩트를 찾지 못했습니다')
    _assign_sids(result)
    (output / 'image_manifest.json').write_text(json.dumps(result.to_dict(), ensure_ascii=False, indent=2), encoding='utf-8')
    return result
