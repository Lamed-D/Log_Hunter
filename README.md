# Log Hunter

**Windows에 남은 활동 기록을 모아 타임라인과 보고서로 정리하는 디지털 포렌식 도구입니다.**

프로그램 실행, 웹 방문·다운로드, 파일 사용·삭제, USB 연결 등의 흔적을 한곳에서 살펴볼 수 있습니다. 이런 흔적을 **아티팩트**라고 부릅니다. Log Hunter는 디스크 이미지나 수집한 파일을 읽고, 기록의 시각·사용자·출처를 정리해 관련 기록을 비교할 수 있도록 돕습니다.

예를 들어 파일을 내려받은 기록과 같은 이름의 프로그램 실행 관련 기록을 찾아, 어떤 근거로 연결되는지 확인할 수 있습니다. Windows 기록을 분석하는 실습과 프로젝트, 여러 자료의 활동 흔적 비교, 분석 결과 정리에 활용할 수 있습니다.

Python 3.11 이상에서 실행하며, GUI와 CLI을 모두 제공합니다.

## 목차

- [주요 기능](#주요-기능)
- [빠른 시작](#빠른-시작)
- [내 자료 분석하기](#내-자료-분석하기)
- [결과 읽기와 저장](#결과-읽기와-저장)
- [지원하는 기록](#지원하는-기록)
- [문제 해결](#문제-해결)
- [학습 자료와 개발 참여](#학습-자료와-개발-참여)

## 주요 기능

| 기능 | 할 수 있는 일 |
| --- | --- |
| 파일·이미지 분석 | 수집한 파일·폴더의 종류를 자동으로 인식하거나, 디스크 이미지에서 분석에 필요한 파일을 추출합니다. |
| 타임라인 탐색 | 기록을 시간순으로 보고, 검색어·기록 종류·기간·사용자로 범위를 좁힙니다. |
| 관련 기록 비교 | 경로·이름·URL·시각 등을 비교한 관계 후보와 판단 근거를 확인합니다. |
| 이미지 안 파일 탐색 | NTFS 폴더·파일을 탐색하고 파일 정보·텍스트·16진수 내용을 확인합니다. 선택한 파일과 확인된 휴지통 짝 파일을 별도 위치로 저장합니다. |
| 태그와 메모 | 관심 있는 기록에 태그·메모를 남기고, 저장한 분석을 다시 열어 검토를 이어갑니다. |
| 보고서와 데이터 저장 | HTML 보고서, CSV·JSON 타임라인, SQLite 분석 결과를 저장합니다. |

![합성 자료로 만든 화면 예시: 왼쪽의 기록 분류, 가운데 타임라인, 아래의 기록 상세 정보](docs/images/gui-main.png)

*합성 자료를 이용한 화면 예시입니다. 화면 구성과 버튼 배치는 버전에 따라 달라질 수 있습니다.*

## 빠른 시작

### 1. 실행 환경 준비

Python 3.11 이상을 준비합니다. GUI에는 Python의 화면 구성 모듈인 Tkinter와 Tcl/Tk가 필요합니다.

```powershell
python --version
python -m tkinter
```

두 번째 명령으로 작은 테스트 창이 열리면 GUI를 사용할 준비가 된 것입니다. 확인 후 창을 닫습니다.

| 실행 환경 | 사용 범위 |
| --- | --- |
| Windows | 수집한 파일·이미지 분석, GUI, 현재 PC의 드라이브 분석과 자료 수집 |
| Linux·macOS | 수집한 파일·이미지의 오프라인 분석. GUI에는 해당 환경의 Tkinter가 필요합니다. |

### 2. 소스 내려받기

Git이 설치되어 있다면 다음 명령을 실행합니다. GitHub의 **Code > Download ZIP**으로 받아 압축을 풀어도 됩니다.

```powershell
git clone https://github.com/Lamed-D/Log_Hunter.git
cd Log_Hunter
```

이후 명령은 `README.md`와 `log_hunter` 폴더가 있는 **저장소 루트**에서 실행합니다. 소스 폴더에서는 패키지 설치 없이 실행할 수 있습니다.

### 3. 합성 샘플로 결과 확인하기

분석할 자료가 없어도 다음 명령으로 체험할 수 있습니다.

```powershell
python example/samples/demo.py
```

생성된 `example/samples/output/report.html`을 브라우저로 엽니다. 가상 사용자의 웹 방문·다운로드, 프로그램 실행 관련 기록, 자동 실행 등록 등의 분석 결과가 나옵니다. 시각이 없는 기록은 미상으로 표시됩니다.

샘플 생성기는 `example/samples/evidence`와 `example/samples/output`을 다시 만듭니다. 두 폴더는 데모 전용으로 사용하고, 개인 자료는 별도 폴더에 보관합니다.

### 4. GUI 열기

```powershell
python -m log_hunter gui
```

Windows에서는 `run.bat`을 더블클릭해도 됩니다. 실제 자료를 선택하는 방법은 다음 절에서 설명합니다.

## 내 자료 분석하기

### GUI에서 분석하기

1. 아래 표에서 입력에 맞는 버튼을 선택합니다.
2. 파일·폴더를 추가하면 자동으로 분석합니다. 아래 상태 줄에서 진행 상황과 완료 여부를 확인합니다.
3. 왼쪽 **찾은 기록**이나 **사용자 계정**을 선택하고, 검색어·기간 필터로 필요한 기록을 찾습니다.
4. 기록을 선택해 아래 상세 정보를 읽습니다. **연관 분석**에서는 연결된 기록과 비교 근거를 확인합니다.
5. **분석 저장**으로 결과와 메모를 저장하거나, **보고서 저장**으로 보고서 파일을 만듭니다.

| 가지고 있는 자료 | 사용할 버튼 | 동작 |
| --- | --- | --- |
| E01·raw/dd·고정 VHD 이미지 | **디스크 이미지 열기 (E01)** | 이미지 안의 NTFS에서 지원하는 기록을 찾아 추출·분석합니다. |
| 레지스트리·로그·브라우저 DB 등 | **파일 추가** / **폴더 추가** | 종류를 자동으로 인식합니다. 직접 고른 파일의 종류를 찾지 못하면 선택한 기록 종류로 추가할지 확인합니다. |
| 현재 사용 중인 Windows 드라이브 | **이 PC 직접 분석 (관리자)** | 관리자 권한으로 드라이브를 직접 읽어 잠긴 파일까지 분석합니다. |

디스크 이미지는 저장장치의 내용을 파일로 복사해 둔 자료입니다. 이미지 분석과 현재 PC 분석에서는 왼쪽 **데이터 출처**에서 폴더와 파일도 탐색할 수 있습니다. [트리 보기와 파일 탐색](docs/features/tree-view.md)에 자세한 조작 방법이 있습니다.

현재 PC 분석은 Windows 관리자 권한이 필요합니다. 읽는 동안 원본이 바뀔 수 있어, 여러 파일이 서로 다른 시점의 상태를 담을 수 있습니다. 이 한계는 결과에도 기록됩니다.

### CLI에서 분석하기

다음은 PowerShell 예시입니다. `C:\Evidence`는 분석할 자료가 있는 경로로 바꾸고, 결과는 원본과 분리된 새 폴더에 저장합니다.

```powershell
# 디스크 이미지에서 기록 추출·분석
python -m log_hunter analyze --image "C:\Evidence\disk.E01" --output outputs/image-case

# 수집한 폴더의 기록 종류를 자동으로 인식해 분석
python -m log_hunter analyze --auto "C:\Evidence\collection" --output outputs/folder-case

# 입력 종류를 직접 지정해 분석
python -m log_hunter analyze --input history "C:\Evidence\History" --input prefetch "C:\Evidence\Prefetch" --output outputs/file-case

# 관리자 권한 PowerShell에서 현재 PC의 C: 드라이브 분석
python -m log_hunter analyze --live C: --output outputs/live-case
```

`--auto`, `--input`, `--image`, `--live` 중 한 가지 입력 방식을 선택합니다. `--input`은 여러 번 지정해 여러 종류의 파일을 함께 분석할 수 있습니다.

이미지의 파일 생성·수정 기록까지 포함하려면 `--with-mft`를 추가합니다. 전체 이미지 해시를 계산하고 저장된 값과 비교하려면 `--verify-image`를 추가합니다. 두 옵션은 처리 시간이 늘어날 수 있습니다.

```powershell
python -m log_hunter analyze --help
```

<details>
<summary>선택 사항: 자료 수집과 패키지 설치</summary>

`collect`는 Windows에서 지정한 자료를 별도 위치에 수집합니다. 레지스트리는 관리자·백업 권한, 이벤트 로그는 채널 접근 권한, 브라우저 수집은 관리자 권한이 필요합니다.

```powershell
python -m log_hunter collect registry HKLM\SYSTEM outputs/collected/SYSTEM
python -m log_hunter collect eventlog System outputs/collected/System.evtx
python -m log_hunter collect --help
```

파일 공유 읽기와 브라우저 DB 수집도 지원합니다. 수집 내역과 해시는 수집 파일 옆의 manifest에 기록합니다.

어느 폴더에서든 `log-hunter` 명령을 사용하려면 패키지로 설치합니다.

```powershell
python -m pip install .
log-hunter gui
```

단일 `.pyz` 파일로 묶어 배포하려면 `python tools/build_pyz.py`를 실행합니다. 생성된 파일도 실행할 PC에 Python 3.11 이상이 필요합니다.

</details>

## 결과 읽기와 저장

타임라인의 시각과 **시각의 의미**를 함께 확인합니다. 프로그램 실행 관련 시각, 레지스트리 키 수정 시각, 파일 삭제 시각은 각각 다른 정보를 나타냅니다. 확인할 수 없는 시각은 미상으로 유지합니다.

**연관 분석**은 같은 경로·이름·URL, 가까운 시각 등을 근거로 관계 후보를 제시합니다. 판단 규칙과 신뢰도, 양쪽에서 비교한 값을 함께 제공합니다. 이 결과를 바탕으로 원본 기록을 비교하며 실제 실행 여부와 행위의 관계를 검토할 수 있습니다.

**처리 결과/오류**에서 파일별로 읽은 기록 수와 진단을 확인합니다. 기록이 0건인 경우에도 빈 자료, 형식 미지원, 손상 등 원인을 구분해 살펴볼 수 있습니다.

### 저장되는 파일

CLI의 `--output`과 GUI의 **보고서 저장**은 아래 결과를 만듭니다. GUI의 **분석 저장**은 `case.sqlite`와 무결성 자료, HTML·JSON 보고서, CSV 타임라인을 저장합니다. 이전 결과와 이름이 겹치면 저장을 거부하므로 분석마다 새 폴더를 사용합니다.

| 파일 | 용도 |
| --- | --- |
| `report.html` | 웹 브라우저로 읽는 보고서. 결과를 처음 살펴볼 때 엽니다. |
| `case.sqlite` | 기록·관계·진단·태그·메모 등을 저장한 분석 DB. 나중에 다시 열 때 사용합니다. |
| `case.sqlite.integrity.json` | 저장한 DB의 SHA-256 해시와 표별 기록 수를 확인하는 자료입니다. |
| `timeline.csv`, `timeline.json` | 시간순 기록 목록. 스프레드시트나 코드에서 후속 분석할 때 사용합니다. |
| `report.json` | 증거 정보·기록·진단·관계·처리 요약을 담은 보고서 데이터입니다. |
| `timeline.bodyfile` | mactime 형식의 타임라인 데이터입니다. |
| `image_manifest.json` | 이미지·현재 PC 분석의 추출 출처, 원래 경로, 해시 등을 담습니다. |
| `extracted/` | CLI로 이미지·현재 PC를 분석할 때 생성하는 추출 사본입니다. |

GUI의 **보고서 저장**은 전체 분석 결과를 저장합니다. **타임라인 내보내기**와 **표를 CSV로 저장**은 현재 필터에 맞는 기록을 저장합니다.

### 저장한 분석 다시 열기

GUI에서 **저장한 분석 열기**를 눌러 `case.sqlite`를 선택하면 원본을 다시 분석하는 과정 없이 기록·태그·메모를 확인할 수 있습니다. 저장한 DB에는 원본 파일과 이미지 추출 사본이 포함되지 않으므로, 원본이 없는 상태에서는 내용 보기와 파일 추출이 제한됩니다.

**원본 위치 다시 지정**에서 저장할 때 사용한 디스크 이미지를 선택하면, 저장된 SHA-256과 일치하는지 확인한 뒤 연결합니다. 연결한 이미지의 파일 탐색을 이어갈 수 있습니다.

CLI에서는 저장된 분석의 요약을 확인하거나 보고서를 새 폴더에 다시 만들 수 있습니다.

```powershell
python -m log_hunter open outputs/image-case/case.sqlite --verify
python -m log_hunter report --from outputs/image-case/case.sqlite --output outputs/new-report --verify
```

`--verify`는 DB와 연결된 원본의 무결성을 추가로 확인합니다. 원본이 없거나 해시가 달라진 경우 경고를 남깁니다.

## 지원하는 기록

현재 26종의 입력 이름을 지원합니다. CLI의 `--input`에는 아래 이름을 사용합니다.

| 살펴볼 내용 | 입력 이름 | 주요 정보 |
| --- | --- | --- |
| 프로그램 실행 관련 흔적 | `prefetch`, `bam`, `userassist`, `amcache` | 프로그램 경로, 실행 관련 시각·횟수, 프로그램·파일 목록 |
| 자동 실행·예약 작업 | `run`, `startup`, `services`, `tasks`, `taskcache` | 로그인 시 실행 항목, 서비스, 예약 작업 파일과 레지스트리 등록 정보 |
| 명령어·보안 이벤트 | `psreadline`, `evtx`, `defender` | PowerShell 명령 이력, Windows 이벤트, Defender 탐지·조치 기록 |
| 파일·폴더 사용과 삭제 | `mru`, `lnk`, `jumplist`, `shellbag`, `recyclebin`, `mft`, `thumbcache` | 최근 항목, 바로가기, 폴더 기록, 휴지통, 파일 시각, 미리 보기 캐시 정보 |
| 웹 사용 기록 | `history`, `cache` | Chromium 계열 브라우저의 방문·다운로드와 지원하는 캐시 기록 |
| USB·외부 장치 | `usb` | 장치 등록 정보, 식별자, 설치·연결·분리 관련 속성 시각 |
| 네트워크·원격 접속 | `network`, `wlan`, `rdp`, `srum` | 네트워크·Wi-Fi 프로필, 원격 접속 관련 설정, SQLite로 내보낸 앱·네트워크 사용량 |

같은 자료에서도 Windows 버전과 파일 형식에 따라 읽을 수 있는 항목이 달라집니다. 각 기록의 출처·시각 의미·진단을 결과와 함께 확인합니다.

## 문제 해결

| 증상 | 확인할 내용 |
| --- | --- |
| `python` 명령을 찾지 못함 | Python 설치와 PATH 설정을 확인합니다. Windows에서 Python Launcher가 있다면 `py -3`로 실행할 수 있습니다. |
| Tkinter 오류 또는 GUI 실행 실패 | `python -m tkinter`로 확인하고, Python 설치 관리자의 Tcl/Tk 구성 요소나 운영체제의 Tkinter 패키지를 설치합니다. |
| 실행 중 PC의 파일에서 접근 거부 | Windows의 **이 PC 직접 분석 (관리자)**를 이용하거나, 별도로 수집한 파일·이미지를 분석합니다. |
| 이전 결과가 있다는 저장 오류 | 기존 결과와 분리된 새 출력 폴더를 선택합니다. |
| 기록이 없거나 일부만 표시됨 | **처리 결과/오류**에서 인식한 종류·지원 형식·손상 진단을 확인합니다. 종류를 아는 파일은 `--input`으로 지정할 수 있습니다. |

CLI 분석은 일부 입력에 오류가 생겨도 가능한 다음 입력을 처리하고 결과를 저장합니다. 오류 등급의 진단이 있으면 종료 코드 1을 반환하므로, 결과 파일과 진단을 함께 확인합니다.

## 학습 자료와 개발 참여

- [학습 자료](example/README.md): 기초 개념, 구조도, Python 코드 해설, 합성 샘플 실습
- [트리 보기와 파일 탐색](docs/features/tree-view.md): GUI에서 기록과 이미지 안 파일을 탐색하는 방법
- [기여 안내](CONTRIBUTING.md): 개발 환경, 브랜치와 PR 시작 방법
- [개발 문서](docs/README.md): 요구사항, 이슈·리뷰 규칙, AI 작업 가이드
- [버그 신고와 기능 요청](https://github.com/Lamed-D/Log_Hunter/issues): 실행 환경과 재현 절차를 공유하는 곳

테스트는 저장소 루트에서 다음 명령으로 실행합니다.

```powershell
python -m unittest discover -s tests
```

이슈와 PR에는 합성 자료를 이용한 재현 절차를 공유합니다. 실제 자료의 내용을 설명할 때는 사용자명·경로·식별 정보를 가린 요약을 사용합니다.
