@echo off
REM One-click launcher — no install, no exe extraction, works in Iran (Tk, no Flutter download)
REM Requires Python 3.10+ installed (you have 3.14)
title CF Clean IP Scanner
cd /d "%~dp0"
echo Starting CF Clean IP Scanner (Tk)...
echo If window doesn't appear, check Python is in PATH: python --version
python --version
if errorlevel 1 (
  echo Python not found! Install from https://www.python.org/downloads/ or use portable dist.
  pause
  exit /b 1
)
REM Install deps if missing (first run)
python -m pip show flet >nul 2>&1
if errorlevel 1 pip install -q flet rich httpx
pip show customtkinter >nul 2>&1
REM Run Tk UI (guaranteed to start, no browser)
python app_tk.py
if errorlevel 1 (
  echo.
  echo App crashed — trying fallback...
  python app_tk.py
  pause
)
