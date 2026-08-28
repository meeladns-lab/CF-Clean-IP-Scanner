# Build Windows exe via PyInstaller (works without Flutter)
# Usage: powershell -ExecutionPolicy Bypass -File build_windows.ps1

$ErrorActionPreference = "Stop"

Write-Host "Building CF Scanner Windows app (PyInstaller)..." -ForegroundColor Cyan

# Ensure deps
pip install -q flet rich httpx pyinstaller

# Clean
Remove-Item -Recurse -Force dist, build, __pycache__ -ErrorAction SilentlyContinue
Remove-Item -Force *.spec -ErrorAction SilentlyContinue

# --- Tk version (recommended for Windows — no Flutter download, works offline in Iran) ---
Write-Host "Building Tk version (guaranteed)..." -ForegroundColor Yellow
$argsTk = @(
    "--name", "CF-Clean-IP-Scanner",
    "--windowed",
    "--onefile",
    "--icon", "assets/icon.png",
    "--add-data", "assets;assets",
    "--add-data", "config.json;.",
    "app_tk.py"
)
python -m PyInstaller @argsTk
if ($LASTEXITCODE -ne 0) { Write-Host "Tk build failed" -ForegroundColor Red; exit 1 }
Move-Item -Force "dist/CF-Clean-IP-Scanner.exe" "dist/CF-Clean-IP-Scanner-Tk.exe"
Write-Host "Tk OK: dist/CF-Clean-IP-Scanner-Tk.exe" -ForegroundColor Green
Copy-Item "dist/CF-Clean-IP-Scanner-Tk.exe" "dist/CF-Clean-IP-Scanner.exe" -Force
Write-Host "Primary exe = Tk version (CF-Clean-IP-Scanner.exe = Tk)" -ForegroundColor Cyan

# --- Flet version (modern UI, needs Flutter DL; fallback to WEB_BROWSER) ---
Write-Host "Building Flet version (modern)..." -ForegroundColor Yellow
$argsFlet = @(
    "--name", "CF-Clean-IP-Scanner-Flet",
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
    "--collect-all", "flet_desktop",
    "app.py"
)
python -m PyInstaller @argsFlet
if ($LASTEXITCODE -eq 0) {
    Write-Host "Flet OK: dist/CF-Clean-IP-Scanner-Flet.exe" -ForegroundColor Green
    Get-ChildItem dist/*.exe | Format-Table Name, Length, LastWriteTime -AutoSize
} else {
    Write-Host "Flet build failed (Tk exe still available)" -ForegroundColor Yellow
}
