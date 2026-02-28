from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from mcat_cli.util.json_file import read_json_object, write_json_object_locked


class JsonFileTest(unittest.TestCase):
    def test_read_json_object_not_found(self) -> None:
        with self.assertRaisesRegex(ValueError, "auth state file not found: missing.json"):
            read_json_object(
                "missing.json",
                not_found_message="auth state file not found: missing.json",
                invalid_json_prefix="invalid auth state file JSON",
                expected_object_message="invalid auth state file: expected object",
            )

    def test_read_json_object_invalid_json(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "bad.json"
            path.write_text("{", encoding="utf-8")

            with self.assertRaisesRegex(
                ValueError,
                "invalid session info JSON: Expecting property name enclosed in double quotes",
            ):
                read_json_object(
                    str(path),
                    not_found_message=f"session info file not found: {path}",
                    invalid_json_prefix="invalid session info JSON",
                    expected_object_message="invalid session info file: expected JSON object",
                )

    def test_read_json_object_non_object(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "list.json"
            path.write_text("[]", encoding="utf-8")

            with self.assertRaisesRegex(
                ValueError,
                "invalid auth state file: expected object",
            ):
                read_json_object(
                    str(path),
                    not_found_message=f"auth state file not found: {path}",
                    invalid_json_prefix="invalid auth state file JSON",
                    expected_object_message="invalid auth state file: expected object",
                )

    def test_read_json_object_read_error_prefix(self) -> None:
        with mock.patch(
            "pathlib.Path.read_text", side_effect=OSError("permission denied")
        ):
            with self.assertRaisesRegex(
                ValueError, "unable to read session info file: permission denied"
            ):
                read_json_object(
                    "session.json",
                    not_found_message="session info file not found: session.json",
                    invalid_json_prefix="invalid session info JSON",
                    expected_object_message="invalid session info file: expected JSON object",
                    read_error_prefix="unable to read session info file",
                )

    def test_write_json_object_locked_writes_canonical_json(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "state.json"

            write_json_object_locked(
                str(path),
                {"b": 2, "a": 1},
                busy_message=f"auth state file is busy: {path}",
            )

            self.assertEqual(path.read_text(encoding="utf-8"), '{\n  "a": 1,\n  "b": 2\n}\n')

    def test_write_json_object_locked_busy(self) -> None:
        def raise_busy(_path: str):
            raise BlockingIOError

        with mock.patch("mcat_cli.util.json_file.locked_file", side_effect=raise_busy):
            with self.assertRaisesRegex(ValueError, "session info file is busy: session.json"):
                write_json_object_locked(
                    "session.json",
                    {"a": 1},
                    busy_message="session info file is busy: session.json",
                )


if __name__ == "__main__":
    unittest.main()
