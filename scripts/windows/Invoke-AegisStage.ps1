[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Manifest,
    [switch]$Execute
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).Path
$cli = Join-Path $repoRoot ".venv\Scripts\aegisscope.exe"
if (-not (Test-Path -LiteralPath $cli)) {
    throw "AegisScope is not installed in .venv. Run Install-Dev.ps1 first."
}

$resolvedManifest = (Resolve-Path -LiteralPath $Manifest).Path
if ($Execute) {
    & $cli dispatch $resolvedManifest --execute
} else {
    & $cli dispatch $resolvedManifest
}
exit $LASTEXITCODE
