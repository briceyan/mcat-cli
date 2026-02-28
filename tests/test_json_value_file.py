from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mcat_cli.util.json_value_file import (
    JsonValueFileNotFoundError,
    read_json_value,
    write_json_value,
)


class JsonValueFileTest(unittest.TestCase):
    def test_read_json_value_not_found(self) -> None:
        with self.assertRaisesRegex(
            JsonValueFileNotFoundError, "json key file not found: missing.json"
        ):
            read_json_value(
                "missing.json",
                not_found_message="json key file not found: missing.json",
                invalid_json_prefix="invalid JSON in missing.json",
            )

    def test_read_json_value_invalid_json(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "bad.json"
            path.write_text("{", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, rf"^invalid JSON in {path}: "):
                read_json_value(
                    str(path),
                    not_found_message=f"json key file not found: {path}",
                    invalid_json_prefix=f"invalid JSON in {path}",
                )

    def test_read_json_value_success(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "value.json"
            path.write_text('{"access_token":"abc"}', encoding="utf-8")

            value = read_json_value(
                str(path),
                not_found_message=f"json key file not found: {path}",
                invalid_json_prefix=f"invalid JSON in {path}",
            )

            self.assertEqual(value, {"access_token": "abc"})

    def test_write_json_value_exists_without_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "key.json"
            path.write_text("{}", encoding="utf-8")

            with self.assertRaisesRegex(
                ValueError,
                rf"json key file exists: {path} \(use --overwrite to replace\)",
            ):
                write_json_value(
                    str(path),
                    {"a": 1},
                    overwrite=False,
                    exists_message=f"json key file exists: {path} (use --overwrite to replace)",
                )

    def test_write_json_value_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "key.json"
            path.write_text("{}", encoding="utf-8")

            write_json_value(
                str(path),
                {"b": 2, "a": 1},
                overwrite=True,
                exists_message=f"json key file exists: {path} (use --overwrite to replace)",
            )

            self.assertEqual(path.read_text(encoding="utf-8"), '{\n  "a": 1,\n  "b": 2\n}\n')


if __name__ == "__main__":
    unittest.main()
