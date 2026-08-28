import ipaddress
import random
import struct
import socket
from typing import List

def cidr_size(cidr: ipaddress._BaseNetwork) -> int:
    return cidr.num_addresses

def weighted_sample_cidrs(cidrs: List[ipaddress._BaseNetwork], count: int, rng: random.Random) -> List[ipaddress._BaseNetwork]:
    """Return list of `count` CIDRs sampled weighted by size (with replacement)."""
    weights = [c.num_addresses for c in cidrs]
    return rng.choices(cidrs, weights=weights, k=count)

def random_ip_from_cidr(cidr: ipaddress._BaseNetwork, rng: random.Random) -> str:
    # For IPv4: pick random host, avoid network/broadcast if feasible but include all for CF ranges
    # Cloudflare ranges are network ranges, any IP within is valid; we skip network/broadcast for /24+? Keep simple.
    if cidr.version == 4:
        # Use getrandbits for range
        nbits = 32 - cidr.prefixlen
        if nbits == 0:
            return str(cidr.network_address)
        # Generate random host bits
        rand_host = rng.getrandbits(nbits)
        # Special handling: avoid 0 and max? Not strictly needed, but avoid obvious network/broadcast for small subnets
        # We keep full range; CF IPs are all usable
        base = int(cidr.network_address)
        ip_int = base | rand_host
        # Ensure within cidr
        max_int = int(cidr.broadcast_address) if hasattr(cidr, 'broadcast_address') else base + cidr.num_addresses - 1
        ip_int = base + (rand_host % cidr.num_addresses)
        # Clamp
        if ip_int > max_int:
            ip_int = max_int
        if ip_int < base:
            ip_int = base
        return str(ipaddress.IPv4Address(ip_int))
    else:
        # IPv6: random 128-bit within prefix
        nbits = 128 - cidr.prefixlen
        base = int(cidr.network_address)
        if nbits == 0:
            return str(cidr.network_address)
        rand_host = rng.getrandbits(nbits)
        ip_int = base | rand_host
        # Ensure within range via modulo
        ip_int = base + (rand_host % cidr.num_addresses)
        return str(ipaddress.IPv6Address(ip_int))

def sample_ips(cidrs: List[ipaddress._BaseNetwork], count: int, seed: int | None = None) -> List[str]:
    """
    Weighted random sample of `count` IPs across CIDRs.
    Count can be 1000, 2000, 5000 etc. No expansion of full IP space.
    """
    rng = random.Random(seed)
    chosen_cidrs = weighted_sample_cidrs(cidrs, count, rng)
    ips = [random_ip_from_cidr(c, rng) for c in chosen_cidrs]
    return ips

def dedupe_preserve_order(ips: List[str]) -> List[str]:
    seen = set()
    out = []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out

def sample_unique_ips(cidrs: List[ipaddress._BaseNetwork], count: int, seed: int | None = None, max_attempts_multiplier: int = 5) -> List[str]:
    """Sample unique IPs; retry if duplicates (rare for large ranges)."""
    rng = random.Random(seed)
    seen = set()
    result = []
    attempts = 0
    max_attempts = count * max_attempts_multiplier
    while len(result) < count and attempts < max_attempts:
        cidr = rng.choices(cidrs, weights=[c.num_addresses for c in cidrs], k=1)[0]
        ip = random_ip_from_cidr(cidr, rng)
        if ip not in seen:
            seen.add(ip)
            result.append(ip)
        attempts += 1
    # If not enough unique (very small ranges), just return what we have + fill with retries
    while len(result) < count:
        cidr = rng.choices(cidrs, weights=[c.num_addresses for c in cidrs], k=1)[0]
        result.append(random_ip_from_cidr(cidr, rng))
    return result
