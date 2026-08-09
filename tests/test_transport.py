from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from aegisscope.transport.ssh import DispatchCommands, OpenSshTransport


def test_transport_builds_argument_arrays(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}", encoding="utf-8")
    digest = tmp_path / "manifest.sha256"
    digest.write_text("0" * 64, encoding="ascii")
    transport = OpenSshTransport(alias="kali-src", remote_root="~/src-runner")
    commands = transport.build_commands(
        manifest_path=manifest,
        manifest_digest_path=digest,
        job_id="stage-demo-0001",
        local_output_dir=tmp_path / "output",
    )
    assert commands.upload_manifest[0] == "scp"
    assert commands.upload_digest[0] == "scp"
    assert commands.execute[:2] == ("ssh", "kali-src")
    assert "--manifest-sha256" in commands.execute
    assert "--execute" in commands.execute


def test_transport_rejects_unsafe_alias() -> None:
    with pytest.raises(ValueError):
        OpenSshTransport(alias="kali-src;whoami")


def test_transport_downloads_evidence_after_runner_failure(monkeypatch: Any) -> None:
    calls: list[tuple[str, ...]] = []

    def fake_run(command: tuple[str, ...], **_kwargs: Any) -> SimpleNamespace:
        calls.append(command)
        return SimpleNamespace(
            returncode=3 if command[0] == "ssh" else 0,
            stdout='{"event": "stage_started"}' if command[0] == "ssh" else "",
            stderr="runner stopped" if command[0] == "ssh" else "",
        )

    monkeypatch.setattr("aegisscope.transport.ssh.subprocess.run", fake_run)
    commands = DispatchCommands(
        upload_manifest=("scp", "manifest", "remote"),
        upload_digest=("scp", "digest", "remote"),
        execute=("ssh", "kali-src", "runner"),
        download=("scp", "-r", "remote", "local"),
    )
    result = OpenSshTransport.run(commands)

    assert not result.succeeded
    assert [command[0] for command in calls] == ["scp", "scp", "ssh", "scp"]
    assert result.steps[-1].name == "download"


def test_transport_does_not_download_stale_output_after_replay_denial(
    monkeypatch: Any,
) -> None:
    calls: list[tuple[str, ...]] = []

    def fake_run(command: tuple[str, ...], **_kwargs: Any) -> SimpleNamespace:
        calls.append(command)
        return SimpleNamespace(
            returncode=3 if command[0] == "ssh" else 0,
            stdout='{"event": "replay_denied"}' if command[0] == "ssh" else "",
            stderr="",
        )

    monkeypatch.setattr("aegisscope.transport.ssh.subprocess.run", fake_run)
    commands = DispatchCommands(
        upload_manifest=("scp", "manifest", "remote"),
        upload_digest=("scp", "digest", "remote"),
        execute=("ssh", "kali-src", "runner"),
        download=("scp", "-r", "remote", "local"),
    )
    result = OpenSshTransport.run(commands)

    assert not result.succeeded
    assert [command[0] for command in calls] == ["scp", "scp", "ssh"]
