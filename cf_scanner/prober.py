import socket
import ssl
import time
import statistics
from typing import List, Dict, Any
from .colo import fetch_colo

def tcp_latency(ip: str, port: int, timeout: float = 3.0) -> float | None:
    """
    Single TCP connect latency in ms, or None on failure.
    """
    start = time.perf_counter()
    sock = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        latency = (time.perf_counter() - start) * 1000.0
        sock.close()
        return latency
    except Exception:
        return None
    finally:
        try:
            if sock:
                sock.close()
        except Exception:
            pass

def tls_latency(ip: str, port: int, timeout: float = 3.0, sni: str = "www.cloudflare.com") -> float | None:
    """
    TLS handshake latency (includes TCP). None on failure.
    """
    start = time.perf_counter()
    sock = None
    ssock = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        # Keep cert verification to ensure we hit real CF edge
        ssock = ctx.wrap_socket(sock, server_hostname=sni)
        latency = (time.perf_counter() - start) * 1000.0
        ssock.close()
        return latency
    except Exception:
        return None
    finally:
        try:
            if ssock is not None:
                ssock.close()
            elif sock is not None:
                sock.close()
        except Exception:
            pass

def probe_ip_port(ip: str, port: int, probes: int = 3, timeout: float = 3.0, sni: str = "www.cloudflare.com") -> Dict[str, Any]:
    """
    Probe single IP:port with `probes` attempts.
    Returns dict with latency, jitter, loss, colo, etc.
    """
    from .config import is_tls_port

    tls = is_tls_port(port)
    latencies: List[float] = []
    failures = 0

    for i in range(probes):
        if tls:
            lat = tls_latency(ip, port, timeout=timeout, sni=sni)
        else:
            lat = tcp_latency(ip, port, timeout=timeout)
        if lat is None:
            failures += 1
        else:
            latencies.append(lat)
        # small gap between probes to reduce burst
        if i < probes - 1:
            time.sleep(0.15)

    loss = (failures / probes) * 100.0

    if latencies:
        avg_lat = statistics.mean(latencies)
        # jitter: stddev if >=2 samples, else 0 ; alternative max-min
        if len(latencies) >= 2:
            try:
                jitter = statistics.stdev(latencies)
            except statistics.StatisticsError:
                jitter = 0.0
        else:
            jitter = 0.0
        # also consider max-min as jitter indicator for 2 samples; stdev already does
        best_lat = min(latencies)
        worst_lat = max(latencies)
    else:
        avg_lat = None
        jitter = None
        best_lat = None
        worst_lat = None

    # Fetch colo only if at least one success (to avoid wasting time)
    colo = None
    colo_latency = None
    colo_error = None
    if latencies:
        # Use same TLS decision, SNI
        colo, colo_latency, colo_error = fetch_colo(ip, port, timeout=timeout, sni=sni, use_tls=tls)
        # If colo fetch fails but TCP succeeded, keep TCP colo as None, still consider IP partially clean
        # We don't count colo failure as loss, just missing tag

    # Determine clean: at least 1 success and (if tls port, colo fetch either succeeded or tcp ok) - we consider clean if loss < 100%
    # But original spec wants "clean" meaning TCP+TLS+HTTP ok. For HTTP ports, colo is needed; for TLS ports, colo success strongly indicates clean
    # We'll define clean = loss < 100% and (colo is not None or not tls? but we try). For loss 0%, best. We'll mark clean if latency exists and (colo is not None or not tls) ?
    # Simpler: clean if loss < 100% and (colo is not None or not tls). For now, clean if at least one probe succeeded.
    # We'll add flag: http_ok = colo is not None
    http_ok = colo is not None
    # overall success: at least one probe
    overall_success = len(latencies) > 0

    # For jitter display, if jitter is None (all failed), keep None
    return {
        "ip": ip,
        "port": port,
        "tls": tls,
        "probes": probes,
        "success_count": len(latencies),
        "fail_count": failures,
        "loss": loss,
        "latencies": latencies,
        "avg_latency": avg_lat,
        "jitter": jitter,
        "best_latency": best_lat,
        "worst_latency": worst_lat,
        "colo": colo,
        "colo_latency": colo_latency,
        "colo_error": colo_error,
        "http_ok": http_ok,
        "overall_success": overall_success,
        # score: lower is better, penalize loss and jitter
        "score": (avg_lat * (1 + loss * 0.02) + (jitter or 0) * 0.5) if avg_lat is not None else float("inf"),
    }

def probe_many(ips: List[str], ports: List[int], probes: int = 3, timeout: float = 3.0, threads: int = 100, sni: str = "www.cloudflare.com", progress_callback=None) -> List[Dict[str, Any]]:
    """
    Probe many IP:port combos concurrently via ThreadPoolExecutor.
    Returns list of result dicts.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    tasks = [(ip, port) for ip in ips for port in ports]
    results = []

    def _probe(args):
        ip, port = args
        r = probe_ip_port(ip, port, probes=probes, timeout=timeout, sni=sni)
        return r

    total = len(tasks)
    done = 0
    with ThreadPoolExecutor(max_workers=threads) as ex:
        future_to_task = {ex.submit(_probe, t): t for t in tasks}
        for fut in as_completed(future_to_task):
            done += 1
            try:
                res = fut.result()
                results.append(res)
            except Exception as e:
                ip, port = future_to_task[fut]
                results.append({
                    "ip": ip,
                    "port": port,
                    "error": str(e),
                    "overall_success": False,
                    "loss": 100.0,
                    "avg_latency": None,
                    "jitter": None,
                    "colo": None,
                    "score": float("inf"),
                })
            if progress_callback:
                try:
                    progress_callback(done, total)
                except Exception:
                    pass
    return results
