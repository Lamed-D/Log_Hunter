# Teaching copy: source launchers preserve caller-relative arguments.
"""Source-tree Windows launch helpers; evidence arguments remain in caller cwd."""
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


def _explorer_launch():
    """Only pause for a cmd console opened directly by Explorer."""
    if os.name != 'nt' or not sys.stdin.isatty():
        return False
    # Query only process ancestry; do not interpolate arguments or evidence text.
    code = ("$p=Get-CimInstance Win32_Process -Filter ('ProcessId='+$PID);"
            "$p=Get-CimInstance Win32_Process -Filter ('ProcessId='+$p.ParentProcessId);"
            "for($i=0;$i -lt 5 -and $p;$i++){"
            "$parent=Get-CimInstance Win32_Process -Filter ('ProcessId='+$p.ParentProcessId);"
            "if($p.Name -eq 'cmd.exe' -and $parent.Name -eq 'explorer.exe'){exit 0};"
            "if($p.Name -notin @('python.exe','python3.exe','py.exe','cmd.exe')){exit 1};"
            "$p=$parent};exit 1")
    try:
        return subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-Command', code],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              timeout=10).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _gui_available():
    try:
        import tkinter  # noqa: F401 -- import check only, never creates a window
        return True
    except ImportError:
        print('GUI 실행에는 Tcl/Tk가 필요합니다. Python 설치 관리자의 Tcl/Tk 구성 요소를 설치하세요.',
              file=sys.stderr)
        return False


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    mode = args.pop(0) if args else 'run'
    if sys.version_info < (3, 11):
        print('Python 3.11 이상을 설치하고 다시 실행하세요.', file=sys.stderr)
        return 1
    if mode == 'test':
        temp = ROOT / 'outputs' / 'test-temp'
        temp.mkdir(parents=True, exist_ok=True)
        env = dict(os.environ, TEMP=str(temp), TMP=str(temp))
        return subprocess.call([sys.executable, '-m', 'unittest', 'discover', '-s', 'tests'],
                               cwd=ROOT, env=env)
    if mode == 'live':
        from .image.live import is_admin, live_device, relaunch_as_admin, system_drive
        if len(args) > 1:
            print('사용법: run-live.bat [드라이브 문자]', file=sys.stderr)
            return 1
        drive = args[0] if args else system_drive()
        device = live_device(drive)
        if device is None:
            print('드라이브 문자를 입력하세요. 예: run-live.bat C:', file=sys.stderr)
            return 1
        if not _gui_available():
            return 1
        drive = device[4:]
        if not is_admin():
            if relaunch_as_admin(['-m', 'log_hunter.launcher', 'live', drive]):
                return 0
            print('관리자 권한 실행이 취소되었거나 실패했습니다. 다시 실행해 UAC 요청을 확인하세요.',
                  file=sys.stderr)
            return 1
        args = ['gui', '--live', drive]
    elif mode == 'run':
        args = args or ['gui']
        if args[0] == 'gui' and not _gui_available():
            return 1
    else:
        print('알 수 없는 실행기 모드입니다.', file=sys.stderr)
        return 1
    from .main import main as application
    return application(args) or 0


def entrypoint():
    try:
        code = main()
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
    except Exception as exc:
        print('실행 실패: ' + str(exc), file=sys.stderr)
        code = 1
    if code and _explorer_launch():
        try:
            input('오류 내용을 확인한 뒤 Enter를 누르면 닫힙니다. ')
        except EOFError:
            pass
    return code


if __name__ == '__main__':
    sys.exit(entrypoint())
