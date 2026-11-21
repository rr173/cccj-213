from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


class ConfigError(Exception):
    pass


def _env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    if value is None:
        return default
    return value


@dataclass(frozen=True)
class Config:
    host: str
    port: int
    user: str
    password: str
    mailbox: str
    tls: str
    data_dir: Path
    chunk_size: int
    timeout: float
    verify_tls: bool = True

    @classmethod
    def from_env(cls) -> "Config":
        host = _env("IMAP_HOST")
        user = _env("IMAP_USER")
        password = _env("IMAP_PASSWORD")
        if not host:
            raise ConfigError("IMAP_HOST is required")
        if user is None:
            raise ConfigError("IMAP_USER is required")
        if password is None:
            raise ConfigError("IMAP_PASSWORD is required")

        tls = (_env("IMAP_TLS", "ssl") or "ssl").lower()
        if tls not in {"ssl", "starttls", "none"}:
            raise ConfigError("IMAP_TLS must be one of: ssl, starttls, none")
        default_port = "993" if tls == "ssl" else "143"
        try:
            port = int(_env("IMAP_PORT", default_port) or default_port)
        except ValueError as exc:
            raise ConfigError("IMAP_PORT must be an integer") from exc

        try:
            chunk_size = int(_env("IMAPARCHIVE_CHUNK_SIZE", "65536") or "65536")
        except ValueError as exc:
            raise ConfigError("IMAPARCHIVE_CHUNK_SIZE must be an integer") from exc
        if chunk_size < 1:
            raise ConfigError("IMAPARCHIVE_CHUNK_SIZE must be positive")

        try:
            timeout = float(_env("IMAPARCHIVE_TIMEOUT", "60") or "60")
        except ValueError as exc:
            raise ConfigError("IMAPARCHIVE_TIMEOUT must be a number") from exc

        verify = (_env("IMAP_TLS_VERIFY", "1") or "1").lower() not in {"0", "false", "no"}

        return cls(
            host=host,
            port=port,
            user=user,
            password=password,
            mailbox=_env("IMAP_MAILBOX", "INBOX") or "INBOX",
            tls=tls,
            data_dir=Path(_env("IMAPARCHIVE_DATA", "./archive") or "./archive"),
            chunk_size=chunk_size,
            timeout=timeout,
            verify_tls=verify,
        )

    @classmethod
    def offline_from_env(cls) -> "Config":
        """Configuration for commands that never contact a server."""
        return cls(
            host="",
            port=0,
            user="",
            password="",
            mailbox=_env("IMAP_MAILBOX", "INBOX") or "INBOX",
            tls="none",
            data_dir=Path(_env("IMAPARCHIVE_DATA", "./archive") or "./archive"),
            chunk_size=65536,
            timeout=60.0,
        )

    def redacted(self) -> dict:
        """Configuration description safe for diagnostics (no credential)."""
        return {
            "host": self.host,
            "port": self.port,
            "user": self.user,
            "mailbox": self.mailbox,
            "tls": self.tls,
            "data_dir": str(self.data_dir),
            "chunk_size": self.chunk_size,
            "timeout": self.timeout,
        }
