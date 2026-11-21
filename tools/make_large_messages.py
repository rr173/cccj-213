#!/usr/bin/env python3
"""Generate large synthetic messages at runtime for the bounded-memory trial.

Nothing generated here is committed: the script writes to a caller-supplied
directory and prints a JSON manifest on stdout.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys


def build_message(index: int, body_bytes: int, block: int = 65536) -> bytes:
    message_id = f"<large-{index}@example.test>"
    header = (
        f"From: Bulk Sender <bulk{index}@example.test>\r\n"
        f"To: archive@example.test\r\n"
        f"Subject: synthetic large message {index}\r\n"
        f"Message-ID: {message_id}\r\n"
        f"Date: Mon, 01 Jan 2024 00:00:0{index % 10} +0000\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/plain; charset=us-ascii\r\n"
        "Content-Transfer-Encoding: 8bit\r\n"
        "\r\n"
    ).encode("ascii")
    out = bytearray()
    out.extend(header)
    written = 0
    pattern = (
        f"line {index:04d} "
        "0123456789abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ\r\n"
    ).encode("ascii")
    while written < body_bytes:
        take = min(len(pattern), body_bytes - written)
        out.extend(pattern[:take])
        written += take
    return bytes(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--count", type=int, default=3)
    parser.add_argument("--bytes", type=int, default=4 * 1024 * 1024)
    args = parser.parse_args(argv)
    os.makedirs(args.out, exist_ok=True)
    manifest = []
    for index in range(1, args.count + 1):
        data = build_message(index, args.bytes)
        path = os.path.join(args.out, f"large-{index}.eml")
        with open(path, "wb") as fh:
            fh.write(data)
        manifest.append(
            {
                "uid": index,
                "path": path,
                "length": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
        del data
    json.dump(manifest, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
