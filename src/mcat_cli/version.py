from __future__ import annotations

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _package_version

PACKAGE_NAME = "mcat-cli"

try:
    __version__ = _package_version(PACKAGE_NAME)
except PackageNotFoundError:
    __version__ = "0+unknown"

USER_AGENT = f"mcat-cli/{__version__}"
