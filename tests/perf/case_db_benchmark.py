"""Measure synthetic case persistence; output belongs in a new, ignored directory."""
import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from log_hunter.core.models import ForensicEvent
from log_hunter.core.pipeline import AnalysisResult
from log_hunter.database.case_db import save_case, load_case


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--events', type=int, default=100000)
    args = parser.parse_args()
    if not 1 <= args.events <= 1000000:
        parser.error('events must be between 1 and 1000000')
    result = AnalysisResult(events=[ForensicEvent('psreadline', r'C:\Evidence\generated.txt', 'command_history',
                                                locator=f'line:{i}', details={'command': f'Write-Output example-{i}'})
                                    for i in range(args.events)])
    started = time.perf_counter()
    save_case(args.output / 'case.sqlite', result)
    saved = time.perf_counter()
    restored, info = load_case(args.output / 'case.sqlite', verify=True)
    loaded = time.perf_counter()
    assert restored.events == result.events
    assert info.verification['database']['status'] == 'match'
    print(json.dumps({'events': len(restored.events), 'save_seconds': saved - started,
                      'load_seconds': loaded - saved, 'database_bytes': (args.output / 'case.sqlite').stat().st_size}))


if __name__ == '__main__':
    main()
