# Build Windows exe via PyInstaller (works without Flutter)
# Usage: powershell -ExecutionPolicy Bypass -File build_windows.ps1

$ErrorActionPreference = "Stop"

Write-Host "Building CF Scanner Windows app (PyInstaller)..." -ForegroundColor Cyan

# Ensure deps
pip install -q flet rich httpx pyinstaller

# Clean
Remove-Item -Recurse -Force dist, build, __pycache__ -ErrorAction SilentlyContinue
Remove-Item -Force *.spec -ErrorAction SilentlyContinue

# PyInstaller command — bundles Flet + scanner backend
# --windowed = no console, --onefile = single exe. For debugging, remove --windowed
$args = @(
    "--name", "CF-Clean-IP-Scanner",
    "--windowed",
    "--onefile",
    "--icon", "assets/icon.png",
    "--add-data", "assets;assets",
    "--add-data", "config.json;.",
    "--hidden-import", "cf_scanner",
    "--hidden-import", "cf_scanner.fetch",
    "--hidden-import", "cf_scanner.sampler",
    "--hidden-import", "cf_scanner.prober",
    "--hidden-import", "cf_scanner.colo",
    "--hidden-import", "cf_scanner.speedtest",
    "--hidden-import", "cf_scanner.ranker",
    "--hidden-import", "cf_scanner.reporter",
    "--hidden-import", "cf_scanner.config",
    "--collect-all", "flet",
    "app.py"
)

# Use python -m PyInstaller
python -m PyInstaller @args

if ($LASTEXITCODE -eq 0) {
    Write-Host "Build OK: dist/CF-Clean-IP-Scanner.exe" -ForegroundColor Green
    Get-Item dist/CF-Clean-IP-Scanner.exe | Format-List Name, Length, LastWriteTime
} else {
    Write-Host "Build failed" -ForegroundColor Red
    exit 1
}
