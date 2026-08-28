# Android APK — Flet Build

> Single Python codebase (`app.py` + `cf_scanner/`) builds to both Windows and Android via Flet (Flutter).

## Prereqs (local machine or CI)

1. **Flutter SDK** 3.22+
   ```bash
   # Windows
   # Download https://docs.flutter.dev/get-started/install/windows
   # Add flutter/bin to PATH, then:
   flutter doctor
   ```

2. **Android SDK + NDK** (via Android Studio)
   ```bash
   flutter doctor --android-licenses
   ```

3. **Python 3.10+ + Flet**
   ```bash
   pip install flet rich httpx
   ```

## Build APK (debug, for sideload testing)

From project root `D:\Vibe Coding\cf-scanner`:

```bash
# Via Flet (recommended) — builds Android APK using Flutter
flet build apk --verbose

# Output: build/apk/app-debug.apk  or  dist/*.apk
```

For **Play Store** release (AAB):

```bash
flet build aab --verbose
# or
flet build apk --release --verbose
# Sign with your keystore (configure in pyproject.toml or via --keystore)
```

### Alternative: `flet pack` for Windows (needs Flutter)

```bash
flet pack app.py --name "CF Clean IP Scanner" --icon assets/icon.png --distpath dist
# Output: dist/CF-Clean-IP-Scanner.exe (Windows) — uses Flutter wrapper
```

### PyInstaller alternative for Windows (no Flutter needed)

If Flutter not installed, use PyInstaller (works now, no Flutter):

```bash
powershell -ExecutionPolicy Bypass -File build_windows.ps1
# or
python -m PyInstaller --name CF-Clean-IP-Scanner --windowed --onefile --add-data "assets;assets" --add-data "config.json;." --collect-all flet app.py
```

## Notes

- **Inside Iran**: APK must be tested on Iranian IP for accurate `FRA/DXB/IST` colo and latency. Outside Iran results differ (as seen: `FRA 307ms` from test host).
- **Permissions**: APK needs `INTERNET` (auto-added by Flet) and `WRITE_EXTERNAL_STORAGE` for `clean_ips.txt` export to `Download/`.
- **File paths on Android**: `clean_ips.txt` defaults to app internal storage; use FilePicker to choose `Download/`.
- **Size**: Flet APK ~25-40 MB (Flutter engine).

## CI (GitHub Actions)

See `.github/workflows/build.yml` — builds Windows exe via PyInstaller and Android APK via Flet on push.
