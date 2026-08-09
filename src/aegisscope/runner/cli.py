"""CLI entry point installed on Kali."""

from __future__ import annotations

import argparse
import json
import os
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aegisscope.policy.engine import PolicyEngine
from aegisscope.runner.executor import EvidenceConflictError, StageExecutor
from aegisscope.security.integrity import atomic_write_new_text, canonical_sha256


def _within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _emit_jsonl(event: dict[str, Any]) -> None:
    print(json.dumps(event, ensure_ascii=False), flush=True)


def _claim_network_job(runner_root: Path, job_id: str, manifest_sha256: str) -> bool:
    claim_path = runner_root / "state" / "consumed" / f"{job_id}.json"
    try:
        atomic_write_new_text(
            claim_path,
            json.dumps(
                {
                    "job_id": job_id,
                    "manifest_sha256": manifest_sha256,
                    "claimed_at": datetime.now(timezone.utc).isoformat(),
                },
                ensure_ascii=False,
                indent=2,
            ),
        )
    except FileExistsError:
        return False
    return True


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AegisScope constrained Kali runner")
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--manifest-sha256", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Open the runner execution gate; manifest dry_run must also be false.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    runner_root = Path(os.getenv("AEGISSCOPE_RUNNER_ROOT", "~/src-runner")).expanduser().resolve()
    manifest_path = args.manifest.expanduser().resolve()
    digest_path = args.manifest_sha256.expanduser().resolve()
    output_dir = args.output_dir.expanduser().resolve()
    if (
        not _within(manifest_path, runner_root)
        or not _within(digest_path, runner_root)
        or not _within(output_dir, runner_root)
    ):
        _emit_jsonl({"event": "policy_denied", "errors": ["paths must remain in runner root"]})
        return 2

    try:
        if manifest_path.stat().st_size > 262_144:
            raise ValueError("manifest exceeds size limit")
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        _emit_jsonl({"event": "manifest_error", "error": exc.__class__.__name__})
        return 2
    if not isinstance(payload, dict):
        _emit_jsonl({"event": "manifest_error", "error": "root must be an object"})
        return 2

    try:
        if digest_path.stat().st_size > 128:
            raise ValueError("digest file exceeds size limit")
        expected_digest = digest_path.read_text(encoding="ascii").strip().lower()
    except (OSError, ValueError) as exc:
        _emit_jsonl({"event": "manifest_digest_error", "error": exc.__class__.__name__})
        return 2
    if len(expected_digest) != 64 or any(
        character not in "0123456789abcdef" for character in expected_digest
    ):
        _emit_jsonl({"event": "manifest_digest_error", "error": "invalid SHA-256"})
        return 2
    actual_digest = canonical_sha256(payload)
    if expected_digest != actual_digest:
        _emit_jsonl(
            {
                "event": "manifest_digest_mismatch",
                "expected": expected_digest,
                "actual": actual_digest,
            }
        )
        return 3

    decision = PolicyEngine.validate_payload(payload)
    if not decision.allowed or decision.manifest is None:
        _emit_jsonl({"event": "policy_denied", "errors": decision.errors})
        return 3

    if args.execute and not decision.manifest.dry_run:
        if not _claim_network_job(
            runner_root, decision.manifest.job_id, actual_digest
        ):
            _emit_jsonl(
                {
                    "event": "replay_denied",
                    "job_id": decision.manifest.job_id,
                    "error": "network-enabled job_id was already consumed",
                }
            )
            return 3

    executor = StageExecutor(
        output_dir=output_dir,
        network_gate=bool(args.execute),
        manifest_sha256=actual_digest,
        event_sink=_emit_jsonl,
    )
    try:
        summary = executor.run(decision.manifest)
    except EvidenceConflictError as exc:
        _emit_jsonl({"event": "evidence_conflict", "error": str(exc)})
        return 3
    except Exception as exc:  # fail closed without printing target-derived traceback data
        _emit_jsonl({"event": "stage_failed", "error": exc.__class__.__name__})
        return 4
    return 0 if summary.stage_status.value in {"dry_run", "completed", "stopped"} else 4


if __name__ == "__main__":
    raise SystemExit(main())
