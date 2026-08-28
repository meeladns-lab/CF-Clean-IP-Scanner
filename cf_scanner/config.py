import json
from pathlib import Path

CONFIG_PATH = Path(__file__).parent.parent / "config.json"

_cache = None

def load_cfg():
    global _cache
    if _cache is None:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            _cache = json.load(f)
    return _cache

def is_tls_port(port: int) -> bool:
    cfg = load_cfg()
    return port in cfg.get("tls_ports", [443, 2053, 2083, 2087, 2096, 8443])

def all_ports() -> list[int]:
    return load_cfg().get("all_ports", [])

def default_ports() -> list[int]:
    return load_cfg().get("default_ports", [443])

def parse_ports(value: str) -> list[int]:
    """
    Parse --ports value.
    Examples: "443", "443,2053,8443", "all", "80, 443"
    """
    if not value:
        return default_ports()
    v = value.strip().lower()
    if v == "all":
        return all_ports()
    parts = [p.strip() for p in v.split(",") if p.strip()]
    ports = []
    for p in parts:
        try:
            port = int(p)
            if 1 <= port <= 65535:
                ports.append(port)
            else:
                raise ValueError(f"port out of range: {port}")
        except ValueError as e:
            raise ValueError(f"invalid port '{p}': {e}")
    if not ports:
        raise ValueError("no valid ports parsed")
    # dedupe preserve order
    seen = set()
    out = []
    for p in ports:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out
