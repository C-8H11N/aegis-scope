[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).Path
$venvPath = Join-Path $repoRoot ".venv"

Write-Host "Repository: $repoRoot"
Write-Host "Creating an isolated Windows development environment."

& python -m venv $venvPath
$pythonPath = Join-Path $venvPath "Scripts\python.exe"
& $pythonPath -m pip install -e "$repoRoot[dev]"

Write-Host "AegisScope development environment is ready."
Write-Host "Run: $venvPath\Scripts\aegisscope.exe init"
