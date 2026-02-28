from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Callable


def parse_json_or_json5(text: str, *, source: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError as json_exc:
        json_msg = json_exc.msg

    try:
        import json5
    except ImportError:
        raise ValueError(
            f"invalid JSON in {source}: {json_msg} (install `json5` for JSON5 input)"
        ) from None

    try:
        return json5.loads(text)
    except Exception as exc:
        raise ValueError(f"invalid JSON/JSON5 in {source}: {exc}") from None


def parse_json_object_input(
    input_value: str,
    *,
    label: str,
    stdin_reader: Callable[[], str] | None = None,
) -> dict[str, Any]:
    spec = input_value.strip()
    if not spec:
        raise ValueError(f"{label} is required")

    source = label
    if spec == "@-":
        source = "stdin"
        text = (stdin_reader or sys.stdin.read)()
    elif spec.startswith("@"):
        path = spec[1:].strip()
        if not path:
            raise ValueError(
                f"invalid {label} reference: missing file path after @"
            )
        source = path
        try:
            text = Path(path).read_text(encoding="utf-8")
        except FileNotFoundError:
            raise ValueError(f"{label} file not found: {path}") from None
        except OSError as exc:
            raise ValueError(f"unable to read {label} file {path}: {exc}") from None
    else:
        text = input_value

    parsed = parse_json_or_json5(text, source=source)
    if not isinstance(parsed, dict):
        raise ValueError(f"{label} must be a JSON object")
    return parsed
