from __future__ import annotations

from pathlib import Path

from dotenv import dotenv_values, set_key


def read_env_file(path: str) -> dict[str, str]:
    file_path = Path(path)
    if not file_path.exists():
        return {}

    parsed = dotenv_values(dotenv_path=file_path, encoding="utf-8")
    return {
        key: value
        for key, value in parsed.items()
        if isinstance(key, str) and value is not None
    }


def write_env_var(path: str, name: str, value: str) -> None:
    set_key(
        dotenv_path=path,
        key_to_set=name,
        value_to_set=value,
        quote_mode="always",
        export=False,
        encoding="utf-8",
    )
