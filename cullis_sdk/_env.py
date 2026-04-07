"""Environment variable helpers."""
import os
import sys
from pathlib import Path


def load_env_file(path: str, override: bool = False) -> None:
    """Load KEY=VALUE pairs from an env file into the current process."""
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if not value:
            continue
        if override or key not in os.environ:
            os.environ[key] = value


def cfg(key: str, default: str | None = None) -> str:
    """Get an environment variable, exit if required and missing."""
    value = os.environ.get(key, default)
    if value is None:
        print(f"[ERROR] missing required variable: {key}", flush=True)
        sys.exit(1)
    return value
