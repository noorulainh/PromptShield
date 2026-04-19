 $root = Resolve-Path (Join-Path $PSScriptRoot "..")
 Set-Location $root
 $pythonExe = Join-Path $root.Path ".venv-py312/Scripts/python.exe"

 if (-not (Test-Path $pythonExe)) {
	 throw "Python environment not found. Run .\\scripts\\start-local.ps1 -InstallDeps first."
 }

Push-Location api
& $pythonExe -m scripts.run_evaluation --include-adversarial
Pop-Location
