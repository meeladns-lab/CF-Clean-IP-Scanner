import ipaddress
import json
import urllib.request
import urllib.error
from pathlib import Path

CONFIG_PATH = Path(__file__).parent.parent / "config.json"

def load_config():
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def _fetch_url(url: str, timeout: float = 10.0) -> list[str]:
    req = urllib.request.Request(url, headers={"User-Agent": "cf-scanner/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8", errors="ignore")
    lines = [l.strip() for l in body.splitlines() if l.strip()]
    # If JSON (api), parse
    if body.strip().startswith("{"):
        try:
            data = json.loads(body)
            cidrs = []
            # api format: {"result": {"ipv4_cidrs": [...], "ipv6_cidrs": [...]}}
            if "result" in data:
                cidrs.extend(data["result"].get("ipv4_cidrs", []))
                cidrs.extend(data["result"].get("ipv6_cidrs", []))
            return cidrs
        except Exception:
            pass
    return lines

def fetch_cloudflare_cidrs(include_ipv6: bool = False, timeout: float = 10.0) -> list[str]:
    cfg = load_config()
    cidrs: list[str] = []
    errors = []

    # Try v4 url
    for url in [cfg.get("cloudflare_ips_v4_url")]:
        try:
            cidrs.extend(_fetch_url(url, timeout=timeout))
            break
        except Exception as e:
            errors.append(f"{url}: {e}")

    # Try ipv6 if requested
    if include_ipv6:
        try:
            cidrs.extend(_fetch_url(cfg.get("cloudflare_ips_v6_url"), timeout=timeout))
        except Exception as e:
            errors.append(f"ipv6: {e}")

    # Validate cidrs are parseable
    valid = []
    for c in cidrs:
        try:
            ipaddress.ip_network(c, strict=False)
            valid.append(c)
        except ValueError:
            continue

    if valid:
        return valid

    # Fallback
    fallback = cfg.get("fallback_ipv4_cidrs", [])
    if include_ipv6:
        fallback = fallback + cfg.get("fallback_ipv6_cidrs", [])
    # Validate fallback too
    for c in fallback:
        try:
            ipaddress.ip_network(c, strict=False)
        except ValueError:
            fallback.remove(c)
    return fallback

def get_cidr_objects(cidrs: list[str]) -> list[ipaddress._BaseNetwork]:
    return [ipaddress.ip_network(c, strict=False) for c in cidrs]
