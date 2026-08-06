[CmdletBinding()]
param(
    [ValidateRange(1024, 65535)]
    [int]$Port = 8765,

    [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..\..")).Path
$venvPath = Join-Path $repoRoot ".venv"
$pythonPath = Join-Path $venvPath "Scripts\python.exe"
$cliPath = Join-Path $venvPath "Scripts\aegisscope.exe"
$localUrl = "http://127.0.0.1:$Port"

function Write-Section {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host ""
    Write-Host "  $Message" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "  AEGISSCOPE" -ForegroundColor Cyan
Write-Host "  Authorization-first security orchestration" -ForegroundColor DarkGray
Write-Host "  Repository / 项目: $repoRoot" -ForegroundColor DarkGray

if (-not (Test-Path -LiteralPath $cliPath -PathType Leaf)) {
    Write-Section "First-run setup / 首次运行初始化"
    Write-Host "  An isolated .venv will be created inside this repository." -ForegroundColor Yellow
    Write-Host "  将在项目内创建独立 .venv，并安装项目依赖。不会修改系统 Python。" -ForegroundColor Yellow
    Write-Host "  This step may download Python packages from the configured package index." -ForegroundColor Yellow
    Write-Host "  此步骤可能从已配置的软件源下载 Python 包。" -ForegroundColor Yellow
    $answer = Read-Host "  Continue / 是否继续? [Y/N]"
    if ($answer -notmatch "^(?i:y|yes|是)$") {
        Write-Host "  Setup cancelled / 已取消初始化。" -ForegroundColor Yellow
        exit 2
    }

    $systemPython = Get-Command python -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -eq $systemPython) {
        Write-Host "  Python was not found in this terminal PATH." -ForegroundColor Red
        Write-Host "  当前终端 PATH 中未找到 Python。请从普通 PowerShell 启动本文件。" -ForegroundColor Red
        exit 3
    }

    Write-Host "  Creating virtual environment / 正在创建虚拟环境..." -ForegroundColor DarkGray
    & $systemPython.Source -m venv $venvPath
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $pythonPath -PathType Leaf)) {
        throw "Virtual environment creation failed / 虚拟环境创建失败。"
    }

    Write-Host "  Installing AegisScope / 正在安装 AegisScope..." -ForegroundColor DarkGray
    & $pythonPath -m pip install --disable-pip-version-check -e $repoRoot
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $cliPath -PathType Leaf)) {
        throw "AegisScope installation failed / AegisScope 安装失败。"
    }
}

Write-Section "Initializing local control plane / 初始化本地控制平面"
Push-Location $repoRoot
try {
    & $cliPath init
    if ($LASTEXITCODE -ne 0) {
        throw "AegisScope local initialization failed / 本地初始化失败。"
    }

    Write-Host ""
    Write-Host "  Dashboard / 控制台: $localUrl" -ForegroundColor Green
    Write-Host "  Stop / 停止服务: Ctrl+C" -ForegroundColor DarkGray
    Write-Host "  Network boundary / 网络边界: loopback only, no Kali or target dispatch" -ForegroundColor DarkGray
    Write-Host ""

    $browserJob = $null
    if (-not $NoBrowser) {
        $browserJob = Start-Job -ScriptBlock {
            param([string]$TargetUrl)
            for ($attempt = 0; $attempt -lt 40; $attempt++) {
                try {
                    Invoke-WebRequest -UseBasicParsing -Uri "$TargetUrl/health" -TimeoutSec 1 |
                        Out-Null
                    break
                }
                catch {
                    Start-Sleep -Milliseconds 250
                }
            }
            Start-Process $TargetUrl
        } -ArgumentList $localUrl
    }

    try {
        & $cliPath serve --host 127.0.0.1 --port $Port
    }
    finally {
        if ($null -ne $browserJob) {
            Stop-Job -Job $browserJob -ErrorAction SilentlyContinue
            Remove-Job -Job $browserJob -Force -ErrorAction SilentlyContinue
        }
    }
}
finally {
    Pop-Location
}
