from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mcat_cli import proxy


class ProxyLifecycleTest(unittest.TestCase):
    def test_proxy_up_status_down(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            socket_path = Path(temp_dir) / "proxy.sock"
            endpoint = f"unix://{socket_path}"

            up = proxy.proxy_up(endpoint=endpoint, command=["sleep", "60"])
            self.assertEqual(up["endpoint"], endpoint)
            self.assertTrue(Path(up["socket"]).exists())
            self.assertTrue(Path(up["proxy"]).exists())

            status = proxy.proxy_status(endpoint=endpoint)
            self.assertTrue(status["running"])
            self.assertTrue(status["socket_exists"])
            self.assertTrue(status["proxy_exists"])

            down = proxy.proxy_down(endpoint=endpoint)
            self.assertEqual(down["endpoint"], endpoint)
            self.assertTrue(down["stopped"])
            self.assertFalse(Path(up["socket"]).exists())
            self.assertFalse(Path(up["proxy"]).exists())

    def test_proxy_up_requires_command(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            endpoint = f"unix://{Path(temp_dir) / 'proxy.sock'}"
            with self.assertRaisesRegex(ValueError, "missing proxy command"):
                proxy.proxy_up(endpoint=endpoint, command=[])


if __name__ == "__main__":
    unittest.main()
