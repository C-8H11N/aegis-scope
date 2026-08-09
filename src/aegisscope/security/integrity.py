"""Canonical hashing and write-once helpers for manifests and evidence."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any


def canonical_json_bytes(payload: Any) -> bytes:
    """Return deterministic UTF-8 JSON suitable for hashing across platforms."""

    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_sha256(payload: Any) -> str:
    return sha256_bytes(canonical_json_bytes(payload))


def atomic_write_new(path: Path, content: bytes, *, mode: int = 0o600) -> None:
    """Create a file exclusively and fail closed instead of overwriting evidence."""

    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def atomic_write_new_text(path: Path, content: str, *, mode: int = 0o600) -> None:
    atomic_write_new(path, content.encode("utf-8"), mode=mode)
