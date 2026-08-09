#!/usr/bin/env bash
set -euo pipefail

runner_root="${AEGISSCOPE_RUNNER_ROOT:-$HOME/src-runner}"
python_path="$runner_root/venv/bin/python"

if [[ $# -lt 3 ]]; then
  echo "Usage: run-runner.sh MANIFEST MANIFEST_SHA256 OUTPUT_DIR [--execute]" >&2
  exit 2
fi

exec "$python_path" -m aegisscope.runner.cli \
  --manifest "$1" \
  --manifest-sha256 "$2" \
  --output-dir "$3" \
  "${@:4}"
