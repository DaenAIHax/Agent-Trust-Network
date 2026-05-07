"""``CULLIS_LOCAL_KMS_DIR`` env override for the local KMS state dir.

The local backend writes ``.admin_secret_hash`` /
``.admin_password_user_set`` / ``.admin_bootstrap_token`` to a
filesystem path. Historically this was hard-coded to ``certs/`` (CWD-
relative), which broke when the broker process ran with
``WorkingDirectory`` set to a read-only Nix store path: ``mkdir
certs/`` raised on first boot and the broker entered a restart loop.

Issue surfaced by the NixOS Tier 1 test fixture in
``tests/integration/cullis_network/lib/cullis-mastio.nix``. The fix is
to read the directory from ``CULLIS_LOCAL_KMS_DIR`` with the legacy
``certs`` default preserved for repo-root and Docker deploys.
"""
from __future__ import annotations

import importlib
import pathlib


def test_default_path_is_relative_certs(monkeypatch):
    """No env set → legacy ``certs/`` relative to cwd, as before."""
    monkeypatch.delenv("CULLIS_LOCAL_KMS_DIR", raising=False)
    from app.kms import admin_secret as mod
    importlib.reload(mod)
    assert mod._LOCAL_KMS_DIR == pathlib.Path("certs")
    assert mod._LOCAL_HASH_PATH == pathlib.Path("certs/.admin_secret_hash")
    assert mod._LOCAL_BOOTSTRAP_TOKEN_PATH == pathlib.Path(
        "certs/.admin_bootstrap_token"
    )


def test_env_override_redirects_all_three_files(monkeypatch, tmp_path):
    """All three local KMS files follow ``CULLIS_LOCAL_KMS_DIR``."""
    monkeypatch.setenv("CULLIS_LOCAL_KMS_DIR", str(tmp_path / "kms-state"))
    from app.kms import admin_secret as mod
    importlib.reload(mod)
    assert mod._LOCAL_KMS_DIR == tmp_path / "kms-state"
    assert mod._LOCAL_HASH_PATH == tmp_path / "kms-state" / ".admin_secret_hash"
    assert mod._LOCAL_USER_SET_PATH == (
        tmp_path / "kms-state" / ".admin_password_user_set"
    )
    assert mod._LOCAL_BOOTSTRAP_TOKEN_PATH == (
        tmp_path / "kms-state" / ".admin_bootstrap_token"
    )


def test_empty_env_falls_back_to_default(monkeypatch):
    """Empty string env behaves like unset (the ``or`` shortcut)."""
    monkeypatch.setenv("CULLIS_LOCAL_KMS_DIR", "")
    from app.kms import admin_secret as mod
    importlib.reload(mod)
    assert mod._LOCAL_KMS_DIR == pathlib.Path("certs")


def test_write_and_read_round_trip_under_override(monkeypatch, tmp_path):
    """Smoke check — with the override pointing at a writable dir,
    ``persist_admin_password_hash`` + ``load_admin_secret_hash`` round-
    trip without ever touching ``certs/`` in the cwd. Guards the
    NixOS read-only-cwd regression: under the old layout this test
    would have to ``cd`` into a writable dir to even run."""
    monkeypatch.setenv("CULLIS_LOCAL_KMS_DIR", str(tmp_path))
    monkeypatch.setenv("KMS_BACKEND", "local")
    monkeypatch.chdir("/")  # cwd intentionally not writable
    from app.config import get_settings
    get_settings.cache_clear()
    from app.kms import admin_secret as mod
    importlib.reload(mod)

    import asyncio

    async def _round_trip():
        await mod.set_admin_secret_hash("$2b$12$fakehashfortests")
        return await mod.get_admin_secret_hash()

    rehash = asyncio.run(_round_trip())
    assert rehash == "$2b$12$fakehashfortests"
    # ``certs/`` was never created on the read-only cwd
    assert not pathlib.Path("/certs").exists()
    # The override path holds the file
    assert (tmp_path / ".admin_secret_hash").exists()
