#!/usr/bin/env python3
"""Provider-free safety checks for the qualifier's hidden key writer."""

from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import crapi_runtime_qualifier as qualifier  # noqa: E402


def refused(action) -> None:
    try:
        action()
    except qualifier.Refusal:
        return
    raise AssertionError("unsafe answer-key path was accepted")


def test_new_key_is_private_and_not_overwritten() -> None:
    with tempfile.TemporaryDirectory() as name:
        root = Path(name) / "hidden"
        path = qualifier.write_private_answer_key(root, "RUN-1", {"password": "synthetic"})
        assert path.read_bytes() == qualifier.canonical_bytes({"password": "synthetic"})
        assert path.stat().st_mode & 0o777 == 0o600
        assert root.stat().st_mode & 0o777 == 0o700
        assert path.parent.stat().st_mode & 0o777 == 0o700
        refused(lambda: qualifier.write_private_answer_key(root, "RUN-1", {"password": "new"}))
        assert path.read_bytes() == qualifier.canonical_bytes({"password": "synthetic"})


def test_symlinks_and_untrusted_directory_are_refused() -> None:
    with tempfile.TemporaryDirectory() as name:
        base = Path(name)
        outside = base / "outside"
        outside.mkdir()
        root_link = base / "root-link"
        root_link.symlink_to(outside, target_is_directory=True)
        refused(lambda: qualifier.write_private_answer_key(root_link, "RUN-1", {"key": "secret"}))

        root = base / "hidden"
        root.mkdir(mode=0o700)
        run_link = root / "RUN-1"
        run_link.symlink_to(outside, target_is_directory=True)
        refused(lambda: qualifier.write_private_answer_key(root, "RUN-1", {"key": "secret"}))
        run_link.unlink()

        run = root / "RUN-1"
        run.mkdir(mode=0o700)
        target = base / "target"
        target.write_text("keep", encoding="utf-8")
        (run / "ANSWER_KEY.json").symlink_to(target)
        refused(lambda: qualifier.write_private_answer_key(root, "RUN-1", {"key": "secret"}))
        assert target.read_text(encoding="utf-8") == "keep"

        os.chmod(root, 0o755)
        refused(lambda: qualifier.write_private_answer_key(root, "RUN-2", {"key": "secret"}))
        assert not (root / "RUN-2").exists()


def test_run_id_cannot_escape_private_root() -> None:
    with tempfile.TemporaryDirectory() as name:
        root = Path(name) / "hidden"
        for run_id in ("", ".", "..", "../outside", "nested/run"):
            refused(lambda: qualifier.write_private_answer_key(root, run_id, {"key": "secret"}))
        assert not root.exists()


if __name__ == "__main__":
    test_new_key_is_private_and_not_overwritten()
    test_symlinks_and_untrusted_directory_are_refused()
    test_run_id_cannot_escape_private_root()
    print("PASS 3/3 private answer-key tests")
