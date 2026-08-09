"""System OpenSSH transport with fixed commands and no shell interpolation."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from aegisscope.config import REMOTE_ROOT_RE, SSH_ALIAS_RE
from aegisscope.contracts.models import JOB_ID_RE
from aegisscope.security.redaction import redact_text


@dataclass(frozen=True, slots=True)
class DispatchCommands:
    upload_manifest: tuple[str, ...]
    upload_digest: tuple[str, ...]
    execute: tuple[str, ...]
    download: tuple[str, ...]

    def ordered(self) -> tuple[tuple[str, tuple[str, ...]], ...]:
        return (
            ("upload_manifest", self.upload_manifest),
            ("upload_digest", self.upload_digest),
            ("execute", self.execute),
            ("download", self.download),
        )


@dataclass(frozen=True, slots=True)
class TransportStepResult:
    name: str
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True, slots=True)
class DispatchResult:
    steps: tuple[TransportStepResult, ...]

    @property
    def succeeded(self) -> bool:
        return len(self.steps) == 4 and all(step.returncode == 0 for step in self.steps)


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
        self,
        *,
        manifest_path: Path,
        manifest_digest_path: Path,
        job_id: str,
        local_output_dir: Path,
    ) -> DispatchCommands:
        if not manifest_path.is_file():
            raise FileNotFoundError(manifest_path)
        if not manifest_digest_path.is_file():
            raise FileNotFoundError(manifest_digest_path)
        if not JOB_ID_RE.fullmatch(job_id):
            raise ValueError("unsafe job_id")
        remote_manifest = f"{self.remote_root}/input/{job_id}.json"
        remote_digest = f"{self.remote_root}/input/{job_id}.sha256"
        remote_output = f"{self.remote_root}/output/{job_id}"
        remote_python = f"{self.remote_root}/venv/bin/python"
        return DispatchCommands(
            upload_manifest=("scp", str(manifest_path), f"{self.alias}:{remote_manifest}"),
            upload_digest=(
                "scp",
                str(manifest_digest_path),
                f"{self.alias}:{remote_digest}",
            ),
            execute=(
                "ssh",
                self.alias,
                remote_python,
                "-m",
                "aegisscope.runner.cli",
                "--manifest",
                remote_manifest,
                "--manifest-sha256",
                remote_digest,
                "--output-dir",
                remote_output,
                "--execute",
            ),
            download=self.build_download_command(
                job_id=job_id, local_output_dir=local_output_dir
            ),
        )

    def build_download_command(
        self, *, job_id: str, local_output_dir: Path
    ) -> tuple[str, ...]:
        if not JOB_ID_RE.fullmatch(job_id):
            raise ValueError("unsafe job_id")
        remote_output = f"{self.remote_root}/output/{job_id}"
        return ("scp", "-r", f"{self.alias}:{remote_output}", str(local_output_dir))

    @staticmethod
    def _run_step(
        name: str, command: tuple[str, ...], *, timeout_seconds: float
    ) -> TransportStepResult:
        try:
            completed = subprocess.run(
                command,
                check=False,
                shell=False,
                text=True,
                capture_output=True,
                timeout=timeout_seconds,
            )
            safe_stdout = redact_text(completed.stdout)[0]
            safe_stderr = redact_text(completed.stderr)[0]
            return TransportStepResult(
                name=name,
                returncode=completed.returncode,
                stdout=safe_stdout,
                stderr=safe_stderr,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout if isinstance(exc.stdout, str) else ""
            stderr = exc.stderr if isinstance(exc.stderr, str) else ""
            return TransportStepResult(
                name=name,
                returncode=124,
                stdout=redact_text(stdout)[0],
                stderr=redact_text(f"{stderr}\ntransport step timed out")[0].strip(),
            )

    @classmethod
    def run(
        cls, commands: DispatchCommands, *, timeout_seconds: float = 180.0
    ) -> DispatchResult:
        results: list[TransportStepResult] = []
        for name, command in (
            ("upload_manifest", commands.upload_manifest),
            ("upload_digest", commands.upload_digest),
        ):
            result = cls._run_step(name, command, timeout_seconds=timeout_seconds)
            results.append(result)
            if result.returncode != 0:
                return DispatchResult(steps=tuple(results))

        execute_result = cls._run_step(
            "execute", commands.execute, timeout_seconds=timeout_seconds
        )
        results.append(execute_result)
        # Runner failures may still have useful evidence after stage_started. Policy,
        # digest, or replay denials never download a possibly stale remote directory.
        if execute_result.returncode == 0 or '"event": "stage_started"' in execute_result.stdout:
            results.append(
                cls._run_step("download", commands.download, timeout_seconds=timeout_seconds)
            )
        return DispatchResult(steps=tuple(results))

    @classmethod
    def recover_evidence(
        cls, command: tuple[str, ...], *, timeout_seconds: float = 180.0
    ) -> TransportStepResult:
        if not command or command[0] != "scp":
            raise ValueError("evidence recovery accepts only a fixed SCP command")
        return cls._run_step("download_recovery", command, timeout_seconds=timeout_seconds)
