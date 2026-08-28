import json
import csv
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime

def format_txt_line(entry: Dict[str, Any]) -> str:
    """
    Format per your spec: 104.18.1.1:2053 FRA 80ms 20ms(jitter) 0% loss Upspeed 20Mbps Downspeed 20Mbps
    entry must contain: ip, port, colo, avg_latency, jitter, loss, dl_mbps, ul_mbps
    """
    ip = entry.get("ip", "?")
    port = entry.get("port", "?")
    colo = entry.get("colo") or "UNK"
    lat = entry.get("avg_latency")
    jitter = entry.get("jitter")
    loss = entry.get("loss")
    dl = entry.get("dl_mbps")
    ul = entry.get("ul_mbps")

    # Format with defaults for missing
    lat_str = f"{int(round(lat))}ms" if isinstance(lat, (int, float)) else "NA"
    jitter_str = f"{int(round(jitter))}ms(jitter)" if isinstance(jitter, (int, float)) else "NA(jitter)"
    loss_str = f"{int(round(loss))}% loss" if isinstance(loss, (int, float)) else "NA% loss"
    # dl/ul may be None if speed not measured
    ul_str = f"Upspeed {ul}Mbps" if isinstance(ul, (int, float)) else "Upspeed NA"
    dl_str = f"Downspeed {dl}Mbps" if isinstance(dl, (int, float)) else "Downspeed NA"

    return f"{ip}:{port} {colo} {lat_str} {jitter_str} {loss_str} {ul_str} {dl_str}"

def export_txt(entries: List[Dict[str, Any]], path: str | Path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"# CF Scanner Results - {datetime.now().isoformat()} - Top {len(entries)}\n")
        f.write(f"# Format: IP:PORT COLO LAT JITTER LOSS Upspeed Downspeed\n")
        for e in entries:
            f.write(format_txt_line(e) + "\n")

def export_json(all_results: List[Dict[str, Any]], top_results: List[Dict[str, Any]], path: str | Path, meta: Dict[str, Any] | None = None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "meta": meta or {},
        "generated_at": datetime.now().isoformat(),
        "total_probed": len(all_results),
        "top_count": len(top_results),
        "top": top_results,
        "all": all_results,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def export_csv(entries: List[Dict[str, Any]], path: str | Path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Flatten
    fieldnames = ["ip", "port", "colo", "avg_latency", "jitter", "loss", "dl_mbps", "ul_mbps", "success_count", "fail_count", "score", "colo_error", "dl_error", "ul_error"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for e in entries:
            row = {k: e.get(k) for k in fieldnames}
            w.writerow(row)
