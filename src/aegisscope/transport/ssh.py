"""System OpenSSH transport with fixed commands and no shell interpolation."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from aegisscope.config import REMOTE_ROOT_RE, SSH_ALIAS_RE
from aegisscope.contracts.models import JOB_ID_RE


@dataclass(frozen=True, slots=True)
class DispatchCommands:
    upload: tuple[str, ...]
    execute: tuple[str, ...]
    download: tuple[str, ...]


class OpenSshTransport:
    def __init__(self, *, alias: str = "kali-src", remote_root: str = "~/src-runner") -> None:
        remote_root = remote_root.rstrip("/")
        if not SSH_ALIAS_RE.fullmatch(alias):
            raise ValueError("unsafe SSH alias")
        if not REMOTE_ROOT_RE.fullmatch(remote_root) or ".." in remote_root.split("/"):
            raise ValueError("unsafe remote root")
        self.alias = alias
        self.remote_root = remote_root

    def build_commands(
        self, *, manifest_path: Path, job_id: str, local_output_dir: Path
    ) -> DispatchCommands:
        if not manifest_path.is_file():
            raise FileNotFoundError(manifest_path)
        if not JOB_ID_RE.fullmatch(job_id):
            raise ValueError("unsafe job_id")
        remote_manifest = f"{self.remote_root}/input/{job_id}.json"
        remote_output = f"{self.remote_root}/output/{job_id}"
        remote_python = f"{self.remote_root}/venv/bin/python"
        return DispatchCommands(
            upload=("scp", str(manifest_path), f"{self.alias}:{remote_manifest}"),
            execute=(
                "ssh",
                self.alias,
                remote_python,
                "-m",
                "aegisscope.runner.cli",
                "--manifest",
                remote_manifest,
                "--output-dir",
                remote_output,
                "--execute",
            ),
            download=("scp", "-r", f"{self.alias}:{remote_output}", str(local_output_dir)),
        )

    @staticmethod
    def run(commands: DispatchCommands) -> None:
        for command in (commands.upload, commands.execute, commands.download):
            subprocess.run(command, check=True, shell=False, text=True)
