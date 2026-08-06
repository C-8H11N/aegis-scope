from __future__ import annotations

from pathlib import Path

import pytest

from aegisscope.transport.ssh import OpenSshTransport


def test_transport_builds_argument_arrays(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}", encoding="utf-8")
    transport = OpenSshTransport(alias="kali-src", remote_root="~/src-runner")
    commands = transport.build_commands(
        manifest_path=manifest,
        job_id="stage-demo-0001",
        local_output_dir=tmp_path / "output",
    )
    assert commands.upload[0] == "scp"
    assert commands.execute[:2] == ("ssh", "kali-src")
    assert "--execute" in commands.execute


def test_transport_rejects_unsafe_alias() -> None:
    with pytest.raises(ValueError):
        OpenSshTransport(alias="kali-src;whoami")
