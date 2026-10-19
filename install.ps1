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

if ($firstInstall -and -not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host ""
    Write-Host "Docker was not found. It's needed for secret/dependency/static checks and local attack testing"
    Write-Host "(Nuclei/ZAP can also run natively without it - see 'vaptkit --help' for that path)."
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        $reply = Read-Host "Install Docker Desktop now via winget? (y/N)"
        if ($reply -eq "y" -or $reply -eq "Y") {
            Write-Host "Installing Docker Desktop (this may prompt for admin rights)..."
            & winget install -e --id Docker.DockerDesktop --accept-package-agreements --accept-source-agreements
            Write-Host "Docker Desktop installed. It needs WSL2 enabled and a sign-out/reboot to finish setup,"
            Write-Host "then launch Docker Desktop once before using checks that need it."
        } else {
            Write-Host "Skipped. Install Docker Desktop later from https://www.docker.com/products/docker-desktop/ if needed."
        }
    } else {
        Write-Host "winget isn't available to install it automatically. Get Docker Desktop from"
        Write-Host "https://www.docker.com/products/docker-desktop/ if you need checks that require it."
    }
}

if ($firstInstall) {
    Write-Host "Installed. Protecting every Git project found under your home folder on every git push..."
    & $venvVaptkit --protect-all @args
} else {
    & $venvVaptkit @args
}
exit $LASTEXITCODE
