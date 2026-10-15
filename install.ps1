#Requires -Version 5.1
$ErrorActionPreference = "Stop"

$kitDir = $PSScriptRoot
$venvPython = Join-Path $kitDir ".venv\Scripts\python.exe"
$venvVaptkit = Join-Path $kitDir ".venv\Scripts\vaptkit.exe"

if (-not (Test-Path $venvPython)) {
    $python = Get-Command python -ErrorAction SilentlyContinue
    if (-not $python) {
        Write-Host "Python 3.11+ is required. Install it from https://www.python.org/downloads/ first (check 'Add python.exe to PATH' during setup)."
        exit 2
    }
    Write-Host "First run: creating the toolkit's local Python environment."
    & python -m venv (Join-Path $kitDir ".venv")
}

$firstInstall = $false
& $venvPython -c "import rich, vaptkit.menu" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Installing the toolkit, terminal and PDF report dependencies (downloads Python packages)."
    & $venvPython -m pip install --quiet -e "$kitDir[report]"
    $firstInstall = $true
} else {
    & $venvPython -c "import playwright" 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Adding the PDF report tools (downloads Python packages)."
        & $venvPython -m pip install --quiet -e "$kitDir[report]"
    } else {
        # An editable install keeps running the latest code automatically, but its recorded
        # version/dependency metadata freezes at whatever it was on the last `pip install -e .` -
        # without this, a version bump that adds a new dependency would silently never install.
        $pyprojectVersion = (Select-String -Path (Join-Path $kitDir "pyproject.toml") -Pattern '^version = "(.*)"' | Select-Object -First 1).Matches.Groups[1].Value
        $installedVersion = & $venvPython -c "
from importlib.metadata import PackageNotFoundError, version
try:
    print(version('matt-vapt-kit'))
except PackageNotFoundError:
    print('')
" 2>$null
        if ($pyprojectVersion -ne $installedVersion) {
            Write-Host "Updating the toolkit to v$pyprojectVersion..."
            & $venvPython -m pip install --quiet -e "$kitDir[report]"
        }
    }
}

& $venvPython -c "from playwright.sync_api import sync_playwright as s; p = s().start(); b = p.chromium.launch(); b.close(); p.stop()" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Downloading the browser used to print PDF reports (about 150 MB, one time)."
    & $venvPython -m playwright install chromium
    if ($LASTEXITCODE -ne 0) { Write-Host "PDF browser download failed; reports will be saved as HTML until you re-run install.ps1." }
}

if ($firstInstall) {
    Write-Host "Installed. Protecting every Git project found under your home folder on every git push..."
    & $venvVaptkit --protect-all @args
} else {
    & $venvVaptkit @args
}
exit $LASTEXITCODE
