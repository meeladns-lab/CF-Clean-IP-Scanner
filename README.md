# CF Clean IP Scanner — for Iran

Random-sample scanner for Cloudflare IP ranges, optimized for Iranian networks. Finds **clean / unfiltered** IPs with **colo tagging (FRA/DXB/IST...)**, measures **latency, jitter, loss**, then speed-tests the **Top 5** and exports `IP:PORT COLO latency jitter loss Upspeed/Downspeed`.

Single Python codebase → **CLI**, **Windows app**, **Android APK** via Flet (Flutter).

## Features

- **Live CIDR fetch** from `https://www.cloudflare.com/ips-v4` (fallback cached)
- **Weighted random sampling**: `--count 1000 | 2000 | 5000`
- **Multi-port**: `443`, `443,2053,8443`, or `all` (11 CF ports)
- **Inside-Iran optimized**: TCP/TLS timing (ICMP blocked), SNI `www.cloudflare.com`
- **Colo tagging**: `FRA` (Frankfurt), `DXB` (Dubai), `IST` (Istanbul), `AMS` etc via `/cdn-cgi/trace`
- **Jitter/loss**: 3 probes per `IP:port`
- **Speed test Top 5**: `10M` down / `5M` up via `speed.cloudflare.com` IP override
- **TXT export**: `104.18.1.1:2053 FRA 80ms 20ms(jitter) 0% loss Upspeed 20Mbps Downspeed 20Mbps`

## Quick Start — CLI

```bash
pip install -r requirements.txt
python main.py --count 1000 --ports 443 --threads 100
python main.py --count 2000 --ports 443,2053,8443
python main.py --count 5000 --ports all --output clean_ips.txt
```

## UI — Flet (Windows + Android)

```bash
pip install flet rich httpx
python app.py          # or: flet run app.py  (desktop window)
```

UI includes:
- Sample size `1000/2000/5000`, ports multi-select, probes/timeout/threads, Top N, DL/UL size
- Live progress + stage, `COLO` color badges, sortable table, jitter/loss/DL/UL
- TXT preview and `Copy` / `Export TXT` / `Stop`

## Build — Windows (.exe)

**No Flutter needed** (PyInstaller):
```bash
pip install pyinstaller flet
powershell -ExecutionPolicy Bypass -File build_windows.ps1
# or manually:
python -m PyInstaller --name CF-Clean-IP-Scanner --windowed --onefile --add-data "assets;assets" --add-data "config.json;." --collect-all flet app.py
# output: dist/CF-Clean-IP-Scanner.exe  (~15 MB)
```

`flet pack` alternative (needs Flutter):
```bash
flet pack app.py --name "CF Clean IP Scanner" --icon assets/icon.png --distpath dist
```

## Build — Android (APK)

Flet = Python + Flutter. Needs Flutter + Android SDK (heavy, Iran network slow — use CI or separate machine).

Local:
```bash
# Install Flutter https://docs.flutter.dev/get-started/install + Android Studio
flutter doctor
pip install flet
flet build apk --verbose          # debug APK for sideload
# flet build aab --verbose        # Play Store
# Output: build/apk/app-debug.apk (~30 MB)
```

**GitHub Actions** (recommended, no local Android SDK):
- Push to `main` → `.github/workflows/build.yml` builds Windows exe + Android APK automatically
- Download artifacts from Actions tab

See `build_android.md` for details.

## Ports

Cloudflare: `80, 443, 2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096, 8443, 8080`
- TLS: `443,2053,2083,2087,2096,8443`
- Plain: `80,2052,2082,2086,2095,8080`

## Pipeline

```
Fetch CIDRs -> Weighted sample 1k/2k/5k -> Probe 3x per IP:port (latency/jitter/loss + colo)
-> Rank (score = lat*(1+loss*0.02)+jitter*0.5) -> Top 5 -> DL/UL speed -> TXT/JSON/CSV
```

## Output

`clean_ips.txt`:
```
# CF Scanner Results - 2026-08-28T... - Top 5
104.18.1.1:2053 FRA 80ms 20ms(jitter) 0% loss Upspeed 20Mbps Downspeed 20Mbps
172.64.45.10:8443 DXB 42ms 3ms(jitter) 0% loss Upspeed 35Mbps Downspeed 88Mbps
```

## Notes for Iran

- Run **inside Iran** for accurate colo/latency. Outside Iran `FRA 307ms` is expected; inside Iran `DXB`/`IST` often faster.
- 0% loss + low jitter + low latency = best.

## Project Structure

```
cf-scanner/
  app.py               # Flet UI (Windows + Android)
  main.py              # CLI
  config.json
  pyproject.toml       # Flet build config
  build_windows.ps1    # Windows exe via PyInstaller
  build_android.md     # Android instructions
  .github/workflows/build.yml
  assets/icon.png
  cf_scanner/
    fetch.py  sampler.py  colo.py  prober.py  speedtest.py  ranker.py  reporter.py  config.py
```

## License

MIT
