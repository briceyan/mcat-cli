from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from mcat_cli.util.json_input import parse_json_object_input


class JsonInputTest(unittest.TestCase):
    def test_parse_json_object_input_requires_value(self) -> None:
        with self.assertRaisesRegex(ValueError, "ARGS is required"):
            parse_json_object_input("   ", label="ARGS")

    def test_parse_json_object_input_invalid_file_reference(self) -> None:
        with self.assertRaisesRegex(
            ValueError, "invalid ARGS reference: missing file path after @"
        ):
            parse_json_object_input("@   ", label="ARGS")

    def test_parse_json_object_input_file_not_found(self) -> None:
        with self.assertRaisesRegex(ValueError, "ARGS file not found: missing.json"):
            parse_json_object_input("@missing.json", label="ARGS")

    def test_parse_json_object_input_file_read_error(self) -> None:
        with mock.patch("pathlib.Path.read_text", side_effect=OSError("permission denied")):
            with self.assertRaisesRegex(
                ValueError, "unable to read ARGS file data.json: permission denied"
            ):
                parse_json_object_input("@data.json", label="ARGS")

    def test_parse_json_object_input_from_stdin(self) -> None:
        parsed = parse_json_object_input(
            "@-",
            label="ARGS",
            stdin_reader=lambda: '{"a":1}',
        )
        self.assertEqual(parsed, {"a": 1})

    def test_parse_json_object_input_from_file_json5(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "args.json5"
            path.write_text("{a: 1,}", encoding="utf-8")

            parsed = parse_json_object_input(f"@{path}", label="ARGS")

            self.assertEqual(parsed, {"a": 1})

    def test_parse_json_object_input_must_be_object(self) -> None:
        with self.assertRaisesRegex(ValueError, "ARGS must be a JSON object"):
            parse_json_object_input("[]", label="ARGS")

    def test_parse_json_object_input_invalid_json(self) -> None:
        with self.assertRaisesRegex(ValueError, r"^invalid JSON/JSON5 in ARGS: "):
            parse_json_object_input("{", label="ARGS")


if __name__ == "__main__":
    unittest.main()
