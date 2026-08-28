# CF Clean IP Scanner — for Iran

Random-sample scanner for Cloudflare IP ranges, optimized for Iranian networks. Finds **clean / unfiltered** IPs with **colo tagging (FRA/DXB/IST...)**, measures **latency, jitter, loss**, then speed-tests the **Top 5** and exports `IP:PORT COLO latency jitter loss Upspeed/Downspeed`.

## Features

- **Live CIDR fetch** from `https://www.cloudflare.com/ips-v4` (fallback cached)
- **Weighted random sampling**: `--count 1000 | 2000 | 5000` (no full 1.5M expansion)
- **Multi-port**: `--ports 443`, `443,2053,8443`, or `all` (11 CF ports)
- **Inside-Iran optimized**: TCP/TLS timing (ICMP blocked), SNI `www.cloudflare.com`, DPI-aware
- **Colo tagging**: `FRA` (Frankfurt), `DXB` (Dubai), `IST` (Istanbul), `AMS` etc via `/cdn-cgi/trace` + `cf-ray` fallback
- **Jitter/loss**: 3 probes per `IP:port`, `loss=failed/total`, `jitter=stdev`
- **Speed test Top 5**: `10M` down / `5M` up via `speed.cloudflare.com` IP override (TLS SNI), Mbps
- **TXT export** exactly as: `104.18.1.1:2053 FRA 80ms 20ms(jitter) 0% loss Upspeed 20Mbps Downspeed 20Mbps`
- **Python CLI** with `rich` live table & progress

## Quick Start

```bash
pip install -r requirements.txt

# interactive port picker
python main.py --count 1000

# specific
python main.py --count 1000 --ports 443 --threads 100
python main.py --count 2000 --ports 443,2053,8443
python main.py --count 5000 --ports all --output clean_ips.txt

# custom sizes, no speed, CSV
python main.py --count 1000 --ports 443,2053 --probes 3 --top 5 --dl-size 10M --ul-size 5M --no-speed --csv results.csv --verbose
```

## Ports

Cloudflare official: `80, 443, 2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096, 8443, 8080`
- TLS: `443,2053,2083,2087,2096,8443` (SNI required)
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
# Format: IP:PORT COLO LAT JITTER LOSS Upspeed Downspeed
104.18.1.1:2053 FRA 80ms 20ms(jitter) 0% loss Upspeed 20Mbps Downspeed 20Mbps
172.64.45.10:8443 DXB 42ms 3ms(jitter) 0% loss Upspeed 35Mbps Downspeed 88Mbps
```

`results.json` contains full probed + top with meta.

## Notes for Iran

- Run **inside Iran** for accurate colo/latency. Many Iranian ISPs route to `FRA`/`IST`/`DXB`.
- 0% loss + low jitter + low latency = best. `DXB`/`IST` often better than `FRA` for Iran peering.
- Rate-limited to ~100 workers to avoid Cloudflare abuse flags.

## Project Structure

```
cf-scanner/
  main.py
  config.json
  requirements.txt
  cf_scanner/
    fetch.py      # CIDR fetch
    sampler.py    # weighted random
    colo.py       # FRA tag via /cdn-cgi/trace
    prober.py     # latency/jitter/loss
    speedtest.py  # DL/UL Mbps
    ranker.py
    reporter.py   # TXT/JSON export
    config.py
```

## License

MIT
