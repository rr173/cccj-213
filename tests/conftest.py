from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from imap_testserver import ImapServer, State  # noqa: E402

from imaparchive.archive import Layout  # noqa: E402
from imaparchive.config import Config  # noqa: E402
from support import Harness  # noqa: E402


@pytest.fixture
def server():
    srv = ImapServer(State()).start()
    try:
        yield srv
    finally:
        srv.stop()


@pytest.fixture
def state(server: ImapServer) -> State:
    return server.state


@pytest.fixture
def harness(tmp_path: Path, server: ImapServer) -> Harness:
    data = tmp_path / "archive"
    config = Config(
        host=server.host,
        port=server.port,
        user=server.state.user,
        password=server.state.password,
        mailbox="INBOX",
        tls="none",
        data_dir=data,
        chunk_size=256,
        timeout=10.0,
        verify_tls=False,
    )
    layout = Layout(data)
    layout.root.mkdir(parents=True, exist_ok=True)
    return Harness(root=tmp_path, config=config, layout=layout)
