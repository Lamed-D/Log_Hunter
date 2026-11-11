"""Check that teaching copies differ from runtime sources only in comments/blank lines."""
import argparse
import io
from pathlib import Path
import tokenize


def code_tokens(path):
    ignored = {tokenize.COMMENT, tokenize.NL, tokenize.NEWLINE,
               tokenize.ENCODING, tokenize.ENDMARKER}
    return [(token.type, token.string) for token in
            tokenize.tokenize(io.BytesIO(path.read_bytes().replace(b'\r\n', b'\n').replace(b'\r', b'\n')).readline)
            if token.type not in ignored]


def check(root):
    source = root / 'log_hunter'
    annotated = root / 'example' / 'annotated' / 'log_hunter'
    originals = {p.relative_to(source): p for p in source.rglob('*.py')}
    copies = {p.relative_to(annotated): p for p in annotated.rglob('*.py')}
    errors = []
    for path in sorted(originals.keys() | copies.keys()):
        if path not in copies:
            errors.append(f'missing: {path}')
        elif path not in originals:
            errors.append(f'obsolete: {path}')
        elif code_tokens(originals[path]) != code_tokens(copies[path]):
            errors.append(f'code differs: {path}')
    return len(originals), errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    count, errors = check(args.root)
    for error in errors:
        print(error)
    print(f'{count} Python sources checked; {len(errors)} differences')
    return bool(errors)


if __name__ == '__main__':
    raise SystemExit(main())
