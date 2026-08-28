import socket
import ssl
import time
import re

TRACE_PATH = "/cdn-cgi/trace"
DEFAULT_SNI = "www.cloudflare.com"
DEFAULT_HOST = "www.cloudflare.com"

def parse_colo_from_trace(body: str) -> str | None:
    """
    Parse colo=XXX from /cdn-cgi/trace body.
    Example body:
      fl=...
      colo=FRA
      loc=IR
    """
    for line in body.splitlines():
        line = line.strip()
        if line.startswith("colo="):
            return line.split("=", 1)[1].strip().upper()
    return None

def parse_colo_from_cf_ray(headers: dict | str) -> str | None:
    """
    Fallback: cf-ray: 9abc...-FRA
    """
    if isinstance(headers, dict):
        # case-insensitive
        for k, v in headers.items():
            if k.lower() == "cf-ray":
                headers = v
                break
        else:
            return None
    if isinstance(headers, str):
        # format XXXXX-FRA
        m = re.search(r"-([A-Z]{3})\s*$", headers.strip())
        if m:
            return m.group(1).upper()
    return None

def fetch_colo(ip: str, port: int, timeout: float = 3.0, sni: str = DEFAULT_SNI, use_tls: bool | None = None) -> tuple[str | None, float | None, str | None]:
    """
    Returns (colo, http_latency_ms, error). Tries /cdn-cgi/trace.
    use_tls: if None, auto-detect based on port (TLS ports).
    """
    from .config import is_tls_port
    if use_tls is None:
        use_tls = is_tls_port(port)

    start = time.perf_counter()
    sock = None
    ssock = None
    try:
        # Create TCP connection
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)

        if use_tls:
            ctx = ssl.create_default_context()
            # For IP direct connect, we still want SNI; don't verify hostname against IP, but verify cert chain
            # We set server_hostname=sni, but need to not check hostname match against IP
            ctx.check_hostname = False
            # Keep verify_mode CERT_REQUIRED to ensure we actually talk to Cloudflare; but allow if fails?
            # For colo detection we can allow any cert; but we try to verify
            ssock = ctx.wrap_socket(sock, server_hostname=sni)
            conn = ssock
        else:
            conn = sock
            ssock = None

        # Send HTTP GET
        host = sni  # use SNI as Host
        req = (
            f"GET {TRACE_PATH} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: cf-scanner/1.0\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        conn.sendall(req.encode())

        # Receive response
        conn.settimeout(timeout)
        data = b""
        # Read until close or timeout, but limit 16KB
        try:
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > 16384:
                    break
                # If we have headers + body and body contains colo, we can break early but keep simple
        except socket.timeout:
            pass

        latency_ms = (time.perf_counter() - start) * 1000

        if not data:
            return None, latency_ms, "empty response"

        try:
            text = data.decode("utf-8", errors="ignore")
        except Exception:
            text = ""

        # Split headers/body
        parts = text.split("\r\n\r\n", 1)
        header_part = parts[0] if parts else ""
        body_part = parts[1] if len(parts) > 1 else ""

        # Try body first
        colo = parse_colo_from_trace(body_part)
        if colo:
            return colo, latency_ms, None

        # Try body maybe without split if server used \n\n
        if not colo:
            colo = parse_colo_from_trace(text)
            if colo:
                return colo, latency_ms, None

        # Fallback to cf-ray header
        # Parse headers
        headers = {}
        for line in header_part.splitlines()[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
        colo2 = parse_colo_from_cf_ray(headers)
        if colo2:
            return colo2, latency_ms, None

        # Also check body for colo via regex fallback
        m = re.search(r"colo=([A-Z]{3})", text)
        if m:
            return m.group(1).upper(), latency_ms, None

        return None, latency_ms, "colo not found"

    except Exception as e:
        latency_ms = (time.perf_counter() - start) * 1000 if 'start' in locals() else None
        return None, latency_ms, str(e)
    finally:
        try:
            if ssock is not None:
                ssock.close()
            elif sock is not None:
                sock.close()
        except Exception:
            pass
