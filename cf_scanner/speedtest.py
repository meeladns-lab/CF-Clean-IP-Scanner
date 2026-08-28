import socket
import ssl
import time
import os
import random
from typing import Dict, Any

DEFAULT_SPEED_HOST = "speed.cloudflare.com"
DOWN_PATH_TEMPLATE = "/__down?bytes={bytes}"
UP_PATH = "/__up"

def _is_tls_port(port: int) -> bool:
    from .config import is_tls_port
    return is_tls_port(port)

def _create_connection(ip: str, port: int, timeout: float, sni: str, use_tls: bool):
    sock = socket.create_connection((ip, port), timeout=timeout)
    sock.settimeout(timeout)
    if use_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ssock = ctx.wrap_socket(sock, server_hostname=sni)
        return ssock
    return sock

def download_speed(ip: str, port: int, dl_bytes: int = 10_000_000, timeout: float = 15.0, sni: str = DEFAULT_SPEED_HOST) -> Dict[str, Any]:
    """
    Download test via direct IP:port with Host header.
    Returns dict with dl_mbps, dl_bytes, duration, error.
    """
    use_tls = _is_tls_port(port)
    # For down path, use same sni as Host; path depends on CF speed endpoint
    # If port is 80-type (plain), still use Host header for routing
    path = DOWN_PATH_TEMPLATE.format(bytes=dl_bytes)
    # Fallback: if CF speed endpoint not reachable via IP:port for plain http, we fallback to /cdn-cgi/trace? Might not be measurable
    # We'll try speed host first, if fails try www.cloudflare.com + larger download; but for now try speed host
    host = sni
    start = time.perf_counter()
    conn = None
    try:
        conn = _create_connection(ip, port, timeout=timeout, sni=host, use_tls=use_tls)

        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: cf-scanner/1.0\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        conn.sendall(req.encode())

        # Read response headers
        conn.settimeout(timeout)
        # Read until \r\n\r\n
        header_buf = b""
        header_found = False
        # We need to parse content-length and status
        while not header_found:
            chunk = conn.recv(4096)
            if not chunk:
                break
            header_buf += chunk
            if b"\r\n\r\n" in header_buf:
                header_found = True
                break
            if len(header_buf) > 16384:
                break

        if not header_found:
            return {"dl_mbps": None, "dl_bytes": 0, "duration": time.perf_counter() - start, "error": "no header response"}

        header_text, _, remaining = header_buf.partition(b"\r\n\r\n")
        header_str = header_text.decode(errors="ignore")
        # Check status
        first_line = header_str.splitlines()[0] if header_str else ""
        if "200" not in first_line:
            # If speed endpoint returns not 200 via IP (e.g., 404 or 403 due to host mismatch), try fallback to trace download?
            # Return error but also capture what we got
            return {"dl_mbps": None, "dl_bytes": 0, "duration": time.perf_counter() - start, "error": f"HTTP {first_line}"}

        # Determine content-length
        content_length = None
        for line in header_str.splitlines():
            if line.lower().startswith("content-length:"):
                try:
                    content_length = int(line.split(":", 1)[1].strip())
                except:
                    pass

        # Now read body
        body_bytes = len(remaining)  # already part of body
        # If content_length known, we expect that many; else read until close
        need = content_length if content_length is not None else dl_bytes
        # Already have remaining; subtract
        to_read = need - body_bytes if content_length is not None else None

        # Continue reading
        # For speed test, we want to read exactly dl_bytes if known
        read_bytes = body_bytes
        # If content_length is None, read until timeout/close
        deadline = time.perf_counter() + timeout
        while True:
            if content_length is not None:
                if read_bytes >= content_length:
                    break
            else:
                if read_bytes >= dl_bytes:
                    break
            if time.perf_counter() > deadline:
                break
            try:
                chunk = conn.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            read_bytes += len(chunk)
            # Prevent infinite if server sends more
            if read_bytes > dl_bytes + 1024*1024:
                break

        duration = time.perf_counter() - start
        if duration <= 0:
            duration = 0.001
        # Calculate Mbps: bytes *8 / duration /1e6
        mbps = (read_bytes * 8) / duration / 1_000_000
        # Also MB/s
        # If we got significantly less than expected, consider it partial failure but report
        error = None
        if content_length is not None and read_bytes < content_length * 0.9:
            error = f"partial download {read_bytes}/{content_length}"

        return {"dl_mbps": round(mbps, 2), "dl_bytes": read_bytes, "duration": round(duration, 2), "error": error}

    except Exception as e:
        duration = time.perf_counter() - start if 'start' in locals() else timeout
        return {"dl_mbps": None, "dl_bytes": 0, "duration": round(duration, 2), "error": str(e)}
    finally:
        try:
            if conn is not None:
                conn.close()
        except:
            pass

def upload_speed(ip: str, port: int, ul_bytes: int = 5_000_000, timeout: float = 15.0, sni: str = DEFAULT_SPEED_HOST) -> Dict[str, Any]:
    """
    Upload test via POST to /__up with random bytes.
    """
    use_tls = _is_tls_port(port)
    host = sni
    path = UP_PATH
    # Generate random payload
    # Use os.urandom for speed; fallback to random
    try:
        payload = os.urandom(ul_bytes)
    except Exception:
        payload = bytes(random.getrandbits(8) for _ in range(ul_bytes))

    start = time.perf_counter()
    conn = None
    try:
        conn = _create_connection(ip, port, timeout=timeout, sni=host, use_tls=use_tls)

        req_headers = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: cf-scanner/1.0\r\n"
            f"Content-Type: application/octet-stream\r\n"
            f"Content-Length: {ul_bytes}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        conn.sendall(req_headers.encode())
        # Send payload in chunks to measure upload time more accurately
        # But for Mbps we measure total time including send + response wait
        chunk_size = 65536
        sent = 0
        while sent < ul_bytes:
            end = min(sent + chunk_size, ul_bytes)
            conn.sendall(payload[sent:end])
            sent = end

        # Wait for response
        conn.settimeout(timeout)
        resp = b""
        try:
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                resp += chunk
                if len(resp) > 8192:
                    # Enough to get status
                    if b"\r\n\r\n" in resp:
                        # Check status
                        break
        except socket.timeout:
            pass

        duration = time.perf_counter() - start
        if duration <= 0:
            duration = 0.001
        mbps = (ul_bytes * 8) / duration / 1_000_000

        # Check response status
        error = None
        if resp:
            try:
                txt = resp.decode(errors="ignore")
                first = txt.splitlines()[0] if txt else ""
                if "200" not in first and "204" not in first:
                    # CF __up may return 200; if not, still count but note
                    if "400" in first or "404" in first:
                        error = f"HTTP {first}"
                        # If upload endpoint not available via this IP/host, mbps is still technically measured as sent, but mark error
            except:
                pass

        return {"ul_mbps": round(mbps, 2), "ul_bytes": ul_bytes, "duration": round(duration, 2), "error": error}

    except Exception as e:
        duration = time.perf_counter() - start if 'start' in locals() else timeout
        return {"ul_mbps": None, "ul_bytes": 0, "duration": round(duration, 2), "error": str(e)}
    finally:
        try:
            if conn is not None:
                conn.close()
        except:
            pass

def test_speed(ip: str, port: int, dl_bytes: int = 10_000_000, ul_bytes: int = 5_000_000, timeout: float = 15.0, sni: str = DEFAULT_SPEED_HOST) -> Dict[str, Any]:
    """
    Combined test: download then upload.
    """
    dl = download_speed(ip, port, dl_bytes=dl_bytes, timeout=timeout, sni=sni)
    # Small gap
    time.sleep(0.2)
    ul = upload_speed(ip, port, ul_bytes=ul_bytes, timeout=timeout, sni=sni)
    return {
        "ip": ip,
        "port": port,
        "dl_mbps": dl.get("dl_mbps"),
        "dl_bytes": dl.get("dl_bytes"),
        "dl_duration": dl.get("duration"),
        "dl_error": dl.get("error"),
        "ul_mbps": ul.get("ul_mbps"),
        "ul_bytes": ul.get("ul_bytes"),
        "ul_duration": ul.get("duration"),
        "ul_error": ul.get("error"),
    }
