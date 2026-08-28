@echo off
REM Ultra one-click — tries exe first, falls back to python
cd /d "%~dp0"
if exist "dist\CF-Clean-IP-Scanner\CF-Clean-IP-Scanner.exe" (
  echo Launching portable exe...
  start "" "dist\CF-Clean-IP-Scanner\CF-Clean-IP-Scanner.exe"
  exit /b
)
if exist "dist\CF-Clean-IP-Scanner.exe" (
  echo Launching exe...
  start "" "dist\CF-Clean-IP-Scanner.exe"
  exit /b
)
echo Exe not found, launching Python...
python app_tk.py
