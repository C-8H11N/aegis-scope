"""CLI entry point installed on Kali."""

from __future__ import annotations

import argparse
import json
import os
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from aegisscope.policy.engine import PolicyEngine
from aegisscope.runner.executor import StageExecutor


def _within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _emit_jsonl(event: dict[str, Any]) -> None:
    print(json.dumps(event, ensure_ascii=False), flush=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AegisScope constrained Kali runner")
    parser.add_argument("--manifest", required=True, type=Path)
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
    output_dir = args.output_dir.expanduser().resolve()
    if not _within(manifest_path, runner_root) or not _within(output_dir, runner_root):
        _emit_jsonl({"event": "policy_denied", "errors": ["paths must remain in runner root"]})
        return 2

    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _emit_jsonl({"event": "manifest_error", "error": exc.__class__.__name__})
        return 2
    if not isinstance(payload, dict):
        _emit_jsonl({"event": "manifest_error", "error": "root must be an object"})
        return 2

    decision = PolicyEngine.validate_payload(payload)
    if not decision.allowed or decision.manifest is None:
        _emit_jsonl({"event": "policy_denied", "errors": decision.errors})
        return 3

    executor = StageExecutor(
        output_dir=output_dir,
        network_gate=bool(args.execute),
        event_sink=_emit_jsonl,
    )
    summary = executor.run(decision.manifest)
    return 0 if summary.stage_status.value in {"dry_run", "completed", "stopped"} else 4


if __name__ == "__main__":
    raise SystemExit(main())
