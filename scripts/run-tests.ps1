 $root = Resolve-Path (Join-Path $PSScriptRoot "..")
 Set-Location $root
 $pythonExe = Join-Path $root.Path ".venv-py312/Scripts/python.exe"

 if (-not (Test-Path $pythonExe)) {
	 throw "Python environment not found. Run .\\scripts\\start-local.ps1 -InstallDeps first."
 }

Write-Host "Running backend tests..."
Push-Location api
& $pythonExe -m pytest
Pop-Location

Write-Host "Running frontend tests..."
Push-Location web
if (-not (Test-Path "node_modules")) {
	npm install
}
npm run test
Pop-Location
