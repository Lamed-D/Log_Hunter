"""Regenerate PNG previews from the SVG sources using an installed Chromium browser."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET


def main():
    candidates = [shutil.which(name) for name in ('chromium', 'google-chrome', 'msedge')]
    for variable in ('ProgramFiles', 'ProgramFiles(x86)'):
        folder = os.environ.get(variable)
        if folder:
            candidates.extend(str(Path(folder) / relative) for relative in (
                'Microsoft/Edge/Application/msedge.exe', 'Google/Chrome/Application/chrome.exe'))
    browser = next((path for path in candidates if path and Path(path).is_file()), None)
    if browser is None:
        raise SystemExit('No installed Chromium browser; SVG remains the source of truth.')
    root = Path(__file__).resolve().parent
    (root / 'png').mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='synthetic-diagram-browser-') as profile:
        for svg in sorted(root.glob('*.svg')):
            node = ET.parse(svg).getroot()
            width, height = int(node.attrib['width']), int(node.attrib['height'])
            destination = root / 'png' / (svg.stem + '.png')
            subprocess.run([browser, '--headless=new', '--disable-gpu', '--hide-scrollbars',
                            '--no-first-run', '--no-default-browser-check',
                            '--user-data-dir=' + profile, '--window-size=' + f'{width},{height}',
                            '--screenshot=' + str(destination), svg.as_uri()],
                           check=True, timeout=45, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(destination.name)


if __name__ == '__main__':
    main()
