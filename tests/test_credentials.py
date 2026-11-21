"""Credentials must never be written to the archive, diagnostics or tests."""

from __future__ import annotations

import json
from pathlib import Path

from imaparchive.cli import main


def test_password_absent_from_archive_and_outputs(harness, monkeypatch, capsys):
    password = harness.config.password
    (harness.layout.root / "messages").mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("IMAP_HOST", harness.config.host)
    monkeypatch.setenv("IMAP_PORT", str(harness.config.port))
    monkeypatch.setenv("IMAP_USER", harness.config.user)
    monkeypatch.setenv("IMAP_PASSWORD", password)
    monkeypatch.setenv("IMAP_TLS", "none")
    monkeypatch.setenv("IMAPARCHIVE_DATA", str(harness.config.data_dir))
    assert main(["check"]) == 0
    captured = capsys.readouterr()
    assert password not in captured.out
    assert password not in captured.err
    for path in Path(harness.layout.root).rglob("*"):
        if path.is_file():
            assert password.encode() not in path.read_bytes(), path


def test_config_redacted(harness):
    redacted = harness.config.redacted()
    assert "password" not in redacted
    assert harness.config.password not in json.dumps(redacted)
