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
$remoteCheckRoot = "~/src-runner/temp/aegisscope-check"

Write-Host "Offline validation upload: $repoRoot"
Write-Host "Remote path: ${SshAlias}:$remoteCheckRoot"
Write-Host "This script does not access an SRC target."
Write-Host "Dependencies must already be available; this script does not install software."

if (-not $Execute) {
    Write-Host "Preview only. Re-run with -Execute to upload and run checks."
    exit 0
}

& ssh $SshAlias "umask 077; mkdir -p $remoteCheckRoot"
if ($LASTEXITCODE -ne 0) { throw "Remote check directory initialization failed" }
& scp (Join-Path $repoRoot "pyproject.toml") "${SshAlias}:$remoteCheckRoot/pyproject.toml"
& scp -r (Join-Path $repoRoot "src") (Join-Path $repoRoot "tests") (Join-Path $repoRoot "examples") "${SshAlias}:$remoteCheckRoot/"
if ($LASTEXITCODE -ne 0) { throw "Check upload failed" }

& ssh $SshAlias "cd $remoteCheckRoot && python3 -m compileall -q src tests"
if ($LASTEXITCODE -ne 0) { throw "Python syntax validation failed" }
Write-Host "Kali Python syntax validation passed."
