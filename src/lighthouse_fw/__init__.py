"""lighthouse-fw package."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("lighthouse-fw")
except PackageNotFoundError:  # pragma: no cover - editable installs during local development
    __version__ = "0.1.0"

