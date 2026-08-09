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
$remoteApp = "~/src-runner/app/aegis-scope"
$remoteRoot = "~/src-runner"

Write-Host "AegisScope Kali runner deployment"
Write-Host "Source: $repoRoot"
Write-Host "Destination: ${SshAlias}:$remoteApp"
Write-Host "Uploads only pyproject.toml, README files, LICENSE, and src/."
Write-Host "Creates an isolated venv under ~/src-runner/venv."
Write-Host "No SRC target request is performed."

if (-not $Execute) {
    Write-Host "Preview only. Re-run with -Execute to deploy."
    exit 0
}

& ssh $SshAlias "umask 077; mkdir -p $remoteApp $remoteRoot/input $remoteRoot/output $remoteRoot/logs $remoteRoot/state/consumed; chmod 700 $remoteRoot $remoteRoot/state $remoteRoot/state/consumed"
if ($LASTEXITCODE -ne 0) { throw "Remote directory initialization failed" }

& scp (Join-Path $repoRoot "pyproject.toml") "${SshAlias}:$remoteApp/pyproject.toml"
if ($LASTEXITCODE -ne 0) { throw "pyproject.toml upload failed" }
& scp (Join-Path $repoRoot "README.md") (Join-Path $repoRoot "README.en.md") (Join-Path $repoRoot "LICENSE") "${SshAlias}:$remoteApp/"
if ($LASTEXITCODE -ne 0) { throw "Documentation upload failed" }
& scp -r (Join-Path $repoRoot "src") "${SshAlias}:$remoteApp/"
if ($LASTEXITCODE -ne 0) { throw "Source upload failed" }

& ssh $SshAlias "python3 -m venv $remoteRoot/venv && $remoteRoot/venv/bin/python -m pip install $remoteApp"
if ($LASTEXITCODE -ne 0) { throw "Runner virtual environment installation failed" }

Write-Host "Kali runner deployed successfully."
