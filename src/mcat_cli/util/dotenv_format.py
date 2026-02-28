from __future__ import annotations

import json
from pathlib import Path

from .atomic_files import write_text_atomic


def read_dotenv_file(path: str) -> dict[str, str]:
    file_path = Path(path)
    if not file_path.exists():
        return {}

    values: dict[str, str] = {}
    for raw_line in file_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not key:
            continue
        values[key] = _dotenv_unquote(value.strip())
    return values


def write_dotenv_var(path: str, name: str, value: str) -> None:
    file_path = Path(path)
    lines = (
        file_path.read_text(encoding="utf-8").splitlines(keepends=True)
        if file_path.exists()
        else []
    )
    encoded_value = _dotenv_quote(value)
    new_line = f"{name}={encoded_value}\n"
    replaced = False
    out_lines: list[str] = []
    for line in lines:
        stripped = line.strip()
        candidate = stripped
        if candidate.startswith("export "):
            candidate = candidate[len("export ") :].lstrip()
        if "=" in candidate:
            key, _ = candidate.split("=", 1)
            if key.strip() == name:
                out_lines.append(new_line)
                replaced = True
                continue
        out_lines.append(line if line.endswith("\n") else f"{line}\n")
    if not replaced:
        out_lines.append(new_line)
    write_text_atomic(file_path, "".join(out_lines))


def _dotenv_unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] == "'":
        return value[1:-1].replace("'\"'\"'", "'")
    if len(value) >= 2 and value[0] == value[-1] == '"':
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return value[1:-1]
        if isinstance(parsed, str):
            return parsed
        return value[1:-1]
    return value


def _dotenv_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"
