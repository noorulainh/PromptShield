param(
    [switch]$InstallDeps,
    [switch]$Fresh
)

$ErrorActionPreference = "Stop"

$root = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $root

if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
}

if (-not (Test-Path "web/.env.local")) {
    Copy-Item "web/.env.example" "web/.env.local"
}

$venvPath = ".venv-py312"
$pythonExe = Join-Path $venvPath "Scripts/python.exe"

if ($Fresh -and (Test-Path $venvPath)) {
    Remove-Item $venvPath -Recurse -Force
}

if (-not (Test-Path $pythonExe)) {
    py -3.12 -m venv $venvPath
}

$pythonExeAbs = (Resolve-Path $pythonExe).Path

if ($InstallDeps -or -not (Test-Path (Join-Path $venvPath "Lib/site-packages/fastapi"))) {
    & $pythonExeAbs -m pip install -r api/requirements.txt
}

if (-not (Test-Path "web/node_modules")) {
    Push-Location web
    npm install
    Pop-Location
}

$apiWorkingDir = Join-Path $root.Path "api"
$webWorkingDir = Join-Path $root.Path "web"

Start-Process powershell -WorkingDirectory $apiWorkingDir -ArgumentList "-NoExit", "-Command", "& '$pythonExeAbs' -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000" | Out-Null
Start-Process powershell -WorkingDirectory $webWorkingDir -ArgumentList "-NoExit", "-Command", "npm run dev" | Out-Null

Write-Host "PromptShield started in two terminals:"
Write-Host "- API: http://127.0.0.1:8000/docs"
Write-Host "- Web: http://localhost:3000"
