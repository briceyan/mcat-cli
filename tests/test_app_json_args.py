from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from mcat_cli import app as app_mod


class AppJsonArgsTest(unittest.TestCase):
    def test_parse_cli_json_object_requires_value(self) -> None:
        with self.assertRaisesRegex(ValueError, "ARGS is required"):
            app_mod._parse_cli_json_object("   ", label="ARGS")

    def test_parse_cli_json_object_invalid_file_reference(self) -> None:
        with self.assertRaisesRegex(
            ValueError, "invalid ARGS reference: missing file path after @"
        ):
            app_mod._parse_cli_json_object("@   ", label="ARGS")

    def test_parse_cli_json_object_file_not_found(self) -> None:
        with self.assertRaisesRegex(ValueError, "ARGS file not found: missing.json"):
            app_mod._parse_cli_json_object("@missing.json", label="ARGS")

    def test_parse_cli_json_object_file_read_error(self) -> None:
        with mock.patch("pathlib.Path.read_text", side_effect=OSError("permission denied")):
            with self.assertRaisesRegex(
                ValueError, "unable to read ARGS file data.json: permission denied"
            ):
                app_mod._parse_cli_json_object("@data.json", label="ARGS")

    def test_parse_cli_json_object_from_file_json5(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "args.json5"
            path.write_text("{a: 1,}", encoding="utf-8")
            parsed = app_mod._parse_cli_json_object(f"@{path}", label="ARGS")
            self.assertEqual(parsed, {"a": 1})

    def test_parse_prompt_arguments_must_be_strings(self) -> None:
        with self.assertRaisesRegex(
            ValueError, "ARGS for prompts/get must be a JSON object of strings"
        ):
            app_mod._parse_prompt_arguments('{"a": 1}')


if __name__ == "__main__":
    unittest.main()
