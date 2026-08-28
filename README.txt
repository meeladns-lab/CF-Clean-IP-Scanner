CF Scanner for Iran - Python CLI
================================

Pipeline:
 1) Fetch Cloudflare IP ranges (https://www.cloudflare.com/ips-v4)
 2) Random weighted sample 1000/2000/5000 IPs
 3) Probe each IP:port (3x) -> latency, jitter, loss + colo tag (FRA/DXB/IST etc via /cdn-cgi/trace)
 4) Rank -> Top 5
 5) Speed test Top5 -> DL/UL Mbps
 6) Export TXT as: 104.18.1.1:2053 FRA 80ms 20ms(jitter) 0% loss Upspeed 20Mbps Downspeed 20Mbps

Usage:

  pip install -r requirements.txt

  python main.py --count 1000 --ports 443
  python main.py --count 2000 --ports 443,2053,8443
  python main.py --count 5000 --ports all --threads 100 --output clean_ips.txt

  Interactive (no --ports): will prompt

Ports:
  Cloudflare: 80,443,2052,2053,2082,2083,2086,2087,2095,2096,8443,8080
  TLS ports: 443,2053,2083,2087,2096,8443 (SNI required)
  Plain ports: 80,2052,2082,2086,2095,8080

Outputs:
  clean_ips.txt  -> Top5 in requested format
  results.json   -> Full probed + top (with meta)
  results.csv    -> optional via --csv

Notes for Iran:
  Run inside Iran for accurate colo/latency. ICMP is blocked, so TCP/TLS timing used.
  Colo tag shows actual PoP: FRA=Frankfurt, AMS=Amsterdam, DXB=Dubai, IST=Istanbul, etc.
  Low latency + low jitter + 0% loss = best.
