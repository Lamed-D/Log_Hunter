import ntpath
import re


def normalize_executable_path(path: str) -> str:
    return ntpath.normpath(path.strip().strip('"')).casefold()


def expand_environment_path(path: str, environment: dict | None = None) -> str:
    # Only evidence-supplied variables; never use the analyst's environment.
    mapping = {k.casefold(): v for k, v in (environment or {}).items()}
    return re.sub(r"%([^%]+)%", lambda m: mapping.get(m[1].casefold(), m[0]), path)


def split_windows_command(command: str) -> dict:
    text = command.strip()
    if not text:
        return {"executable": None, "arguments": "", "ambiguous": True}
    if text.startswith('"'):
        end = text.find('"', 1)
        if end < 0:
            return {"executable": None, "arguments": text, "ambiguous": True}
        return {"executable": text[1:end], "arguments": text[end + 1:].lstrip(), "ambiguous": False}
    match = re.match(r"(?i)^(.+?\.(?:exe|com|bat|cmd))(?=\s|$)", text)
    if match:
        exe = match[1]
        return {"executable": exe, "arguments": text[match.end():].lstrip(), "ambiguous": " " in exe}
    parts = text.split(None, 1)
    return {"executable": parts[0], "arguments": parts[1] if len(parts) > 1 else "", "ambiguous": True}
