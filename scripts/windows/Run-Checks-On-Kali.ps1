[CmdletBinding()]
param(
    [string]$SshAlias = "kali-src",
    [switch]$Execute
)

$ErrorActionPreference = "Stop"
if ($SshAlias -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$') {
    throw "Unsafe SSH alias"
}

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).Path
$runId = Get-Date -Format "yyyyMMdd-HHmmss"
$remoteCheckRoot = "~/src-runner/temp/aegisscope-check-$runId"
$remoteLog = "$remoteCheckRoot/checks.txt"
$localCheckRoot = Join-Path $repoRoot "var\checks"
$localLog = Join-Path $localCheckRoot "$runId-kali-checks.txt"

Write-Host "Offline validation upload: $repoRoot"
Write-Host "Remote path: ${SshAlias}:$remoteCheckRoot"
Write-Host "This script does not access an SRC target."
Write-Host "Dependencies must already be available; this script does not install software."
Write-Host "Target access: none"
Write-Host "Local result: $localLog"

if (-not $Execute) {
    Write-Host "Preview only. Re-run with -Execute to upload and run checks."
    exit 0
}

& ssh $SshAlias "umask 077; mkdir -p $remoteCheckRoot"
if ($LASTEXITCODE -ne 0) { throw "Remote check directory initialization failed" }
& scp (Join-Path $repoRoot "pyproject.toml") "${SshAlias}:$remoteCheckRoot/pyproject.toml"
& scp -r (Join-Path $repoRoot "src") (Join-Path $repoRoot "tests") (Join-Path $repoRoot "examples") "${SshAlias}:$remoteCheckRoot/"
if ($LASTEXITCODE -ne 0) { throw "Check upload failed" }

$remoteCommand = "cd $remoteCheckRoot && { set -e; python3 -m compileall -q src tests; if ~/src-runner/venv/bin/python -c 'import pytest' >/dev/null 2>&1; then PYTHONPATH=src ~/src-runner/venv/bin/python -m pytest -q; else echo 'pytest: skipped (not available in existing runner venv)'; fi; } > $remoteLog 2>&1"
& ssh $SshAlias $remoteCommand
$checkExitCode = $LASTEXITCODE

New-Item -ItemType Directory -Force -Path $localCheckRoot | Out-Null
& scp "${SshAlias}:$remoteLog" $localLog
if ($LASTEXITCODE -ne 0) { throw "Check log download failed" }

Get-Content -LiteralPath $localLog
if ($checkExitCode -ne 0) { throw "Kali checks failed; review $localLog" }
Write-Host "Kali Python checks passed. Result: $localLog"
