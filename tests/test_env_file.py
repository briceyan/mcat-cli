from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mcat_cli.util.env_file import read_env_file, write_env_var


class EnvFileTest(unittest.TestCase):
    def test_read_env_file_parses_export_comments_and_quotes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            env_path = Path(temp_dir) / ".env"
            env_path.write_text(
                "\n".join(
                    [
                        "# comment",
                        "export TOKEN='abc'",
                        'JSON_STRING="{\\"a\\":1}"',
                        "RAW=hello",
                        "IGNORED_LINE",
                        "",
                    ]
                ),
                encoding="utf-8",
            )

            values = read_env_file(str(env_path))

            self.assertEqual(
                values,
                {
                    "TOKEN": "abc",
                    "JSON_STRING": '{"a":1}',
                    "RAW": "hello",
                },
            )

    def test_write_env_var_replaces_existing_key(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            env_path = Path(temp_dir) / ".env"
            env_path.write_text("A='1'\nB='2'\n", encoding="utf-8")

            write_env_var(str(env_path), "A", "new'value")

            self.assertEqual(
                env_path.read_text(encoding="utf-8"),
                "A='new\\'value'\nB='2'\n",
            )

    def test_write_env_var_appends_missing_key(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            env_path = Path(temp_dir) / ".env"
            env_path.write_text("A='1'\n", encoding="utf-8")

            write_env_var(str(env_path), "B", "2")

            self.assertEqual(env_path.read_text(encoding="utf-8"), "A='1'\nB='2'\n")


if __name__ == "__main__":
    unittest.main()
