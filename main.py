#!/usr/bin/env python3
"""
Cloudflare IP Scanner for Iran — Random sample, multi-port, colo tagging, jitter/loss, speed test.
Pipeline: sample 1k/2k/5k -> probe latency/jitter/loss+colo -> Top5 -> speed -> TXT export
"""
import argparse
import sys
import time
from pathlib import Path
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
from rich.prompt import Prompt

from cf_scanner.fetch import fetch_cloudflare_cidrs, get_cidr_objects
from cf_scanner.sampler import sample_unique_ips
from cf_scanner.prober import probe_many
from cf_scanner.ranker import rank_results
from cf_scanner.speedtest import test_speed
from cf_scanner.reporter import export_txt, export_json, export_csv, format_txt_line
from cf_scanner.config import parse_ports, default_ports, all_ports
import json

console = Console()

def parse_args():
    p = argparse.ArgumentParser(
        description="Cloudflare IP Scanner for Iran — random sample, multi-port, colo tagging, speed test",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    p.add_argument("--count", type=int, choices=[1000, 2000, 5000], default=1000,
                   help="Random sample size from CF ranges (1000/2000/5000)")
    # also allow arbitrary int hidden? but spec says 1k 2k 5k
    p.add_argument("--custom-count", type=int, default=None, help=argparse.SUPPRESS)
    p.add_argument("--ports", type=str, default=None,
                   help='Comma-separated ports or "all". e.g., "443", "443,2053,8443", "all". If omitted, interactive prompt.')
    p.add_argument("--probes", type=int, default=3, help="Probes per IP:port for jitter/loss")
    p.add_argument("--timeout", type=float, default=3.0, help="Timeout per probe (seconds)")
    p.add_argument("--threads", type=int, default=100, help="Concurrent workers")
    p.add_argument("--top", type=int, default=5, help="Top N to speed-test")
    p.add_argument("--output", type=str, default="clean_ips.txt", help="Output TXT path")
    p.add_argument("--json", type=str, default="results.json", help="Output JSON path ('' to disable)")
    p.add_argument("--csv", type=str, default="", help="Output CSV path ('' to disable)")
    p.add_argument("--dl-size", type=str, default="10M", help="Download size: e.g., 10M, 5M, 10000000")
    p.add_argument("--ul-size", type=str, default="5M", help="Upload size: e.g., 5M")
    p.add_argument("--include-ipv6", action="store_true", help="Include IPv6 ranges")
    p.add_argument("--seed", type=int, default=None, help="RNG seed for reproducible sample")
    p.add_argument("--sni", type=str, default="www.cloudflare.com", help="SNI/Host for TLS/HTTP trace")
    p.add_argument("--speed-sni", type=str, default="speed.cloudflare.com", help="SNI/Host for speed test")
    p.add_argument("--speed-timeout", type=float, default=15.0, help="Timeout per speed test")
    p.add_argument("--no-speed", action="store_true", help="Skip speed test (only latency)")
    p.add_argument("--verbose", action="store_true", help="Verbose logging")
    return p.parse_args()

def parse_size(s: str) -> int:
    s = s.strip().upper()
    if s.endswith("M"):
        return int(float(s[:-1]) * 1_000_000)
    if s.endswith("K"):
        return int(float(s[:-1]) * 1_000)
    return int(s)

def interactive_ports():
    console.print("[bold cyan]Select ports to scan[/bold cyan] (Cloudflare ports)")
    cfg_all = all_ports()
    cfg_default = default_ports()
    console.print(f"All CF ports: {', '.join(map(str, cfg_all))}")
    console.print(f"Default: {', '.join(map(str, cfg_default))}")
    console.print("Enter comma-separated ports, or 'all', or press Enter for default (443,2053,2083,8443)")
    try:
        ans = Prompt.ask("Ports", default=",".join(map(str, cfg_default)))
    except Exception:
        ans = ",".join(map(str, cfg_default))
    try:
        ports = parse_ports(ans)
        return ports
    except Exception as e:
        console.print(f"[red]Invalid ports: {e}, using default[/red]")
        return cfg_default

def main():
    args = parse_args()
    # Handle custom-count override
    if args.custom_count is not None:
        args.count = args.custom_count

    # Ports handling
    if args.ports is None:
        # If stdin is tty, prompt; else use default
        if sys.stdin.isatty():
            ports = interactive_ports()
        else:
            ports = default_ports()
            console.print(f"[yellow]No --ports specified, using default: {ports}[/yellow]")
    else:
        try:
            ports = parse_ports(args.ports)
        except Exception as e:
            console.print(f"[red]Error parsing --ports: {e}[/red]")
            sys.exit(1)

    dl_bytes = parse_size(args.dl_size)
    ul_bytes = parse_size(args.ul_size)

    console.print("[bold green]CF Scanner for Iran[/bold green] — Random Sample Pipeline")
    console.print(f"  Sample: {args.count} IPs | Ports: {ports} | Probes: {args.probes} | Threads: {args.threads} | Timeout: {args.timeout}s")
    console.print(f"  SNI: {args.sni} | Speed SNI: {args.speed_sni} | DL {dl_bytes} bytes UL {ul_bytes} bytes")

    # Step 1: Fetch CIDRs
    console.print("\n[bold]Step 1: Fetching Cloudflare IP ranges...[/bold]")
    try:
        cidrs_str = fetch_cloudflare_cidrs(include_ipv6=args.include_ipv6)
        cidr_objs = get_cidr_objects(cidrs_str)
        total_ips = sum(c.num_addresses for c in cidr_objs)
        console.print(f"  Fetched {len(cidrs_str)} CIDRs, total ~{total_ips:,} IPs")
        if args.verbose:
            for c in cidrs_str[:10]:
                console.print(f"    {c}")
            if len(cidrs_str) > 10:
                console.print(f"    ... +{len(cidrs_str)-10} more")
    except Exception as e:
        console.print(f"[red]Failed to fetch CIDRs: {e}[/red]")
        sys.exit(1)

    # Step 2: Sample
    console.print(f"\n[bold]Step 2: Random sampling {args.count} IPs (weighted)...[/bold]")
    try:
        ips = sample_unique_ips(cidr_objs, args.count, seed=args.seed)
        console.print(f"  Sampled {len(ips)} unique IPs (seed={args.seed})")
        if args.verbose:
            for ip in ips[:5]:
                console.print(f"    {ip}")
    except Exception as e:
        console.print(f"[red]Sampling failed: {e}[/red]")
        sys.exit(1)

    total_tasks = len(ips) * len(ports)
    console.print(f"  Total probes: {total_tasks} IP:port combos x {args.probes} probes = {total_tasks * args.probes} connects")

    # Step 3: Probe latency/jitter/loss + colo
    console.print(f"\n[bold]Step 3: Probing latency/jitter/loss + colo tagging (this may take {total_tasks * args.probes * args.timeout / args.threads:.0f}-{total_tasks * 2:.0f}s)...[/bold]")

    results = []
    # Progress handling
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(f"Probing {total_tasks} IP:port...", total=total_tasks)

        def cb(done, total):
            progress.update(task, completed=done)

        start_probe = time.perf_counter()
        results = probe_many(ips, ports, probes=args.probes, timeout=args.timeout, threads=args.threads, sni=args.sni, progress_callback=cb)
        duration_probe = time.perf_counter() - start_probe
        progress.update(task, completed=total_tasks)

    # Summary table
    success_cnt = sum(1 for r in results if r.get("overall_success"))
    console.print(f"\n  Probed {len(results)} in {duration_probe:.1f}s | Success: {success_cnt} | Failed: {len(results)-success_cnt}")

    # Show interim table sorted by score
    sorted_results = sorted(results, key=lambda r: r.get("score", float("inf")))
    table = Table(title=f"Top 20 by latency/jitter/loss (all {len(results)} probed)", show_lines=False)
    table.add_column("Rank", style="dim")
    table.add_column("IP:PORT", style="bold")
    table.add_column("COLO", style="cyan")
    table.add_column("LAT", justify="right")
    table.add_column("JITTER", justify="right")
    table.add_column("LOSS", justify="right")
    table.add_column("Score", justify="right", style="dim")

    for i, r in enumerate(sorted_results[:20], 1):
        lat = f"{r['avg_latency']:.0f}ms" if r.get("avg_latency") is not None else "NA"
        jit = f"{r['jitter']:.0f}ms" if r.get("jitter") is not None else "NA"
        loss = f"{r.get('loss', 100):.0f}%"
        colo = r.get("colo") or "UNK"
        score = f"{r.get('score', 0):.0f}" if r.get("score") != float("inf") else "inf"
        # Color colo
        style = "green" if r.get("overall_success") and r.get("loss") == 0 else "yellow" if r.get("overall_success") else "red"
        table.add_row(str(i), f"{r['ip']}:{r['port']}", colo, lat, jit, loss, score, style=style)
    console.print(table)

    # Step 4: Rank Top N
    console.print(f"\n[bold]Step 4: Selecting Top {args.top} for speed test...[/bold]")
    top = rank_results(results, top=args.top)
    # Filter only successes for speed; if not enough, still try but will likely fail
    # Remove those with loss 100%
    top_success = [r for r in top if r.get("overall_success")]
    if not top_success:
        console.print("[yellow]No successful IPs to speed-test! Exporting what we have.[/yellow]")
        top = top_success  # empty
    else:
        top = top_success[:args.top]

    for i, r in enumerate(top, 1):
        console.print(f"  {i}. {r['ip']}:{r['port']} {r.get('colo') or 'UNK'} {r.get('avg_latency',0):.0f}ms {r.get('jitter',0):.0f}ms(jitter) {r.get('loss',0):.0f}% loss")

    # Step 5: Speed test
    if args.no_speed:
        console.print("\n[bold]Step 5: Skipping speed test (--no-speed)[/bold]")
        for r in top:
            r["dl_mbps"] = None
            r["ul_mbps"] = None
    elif top:
        console.print(f"\n[bold]Step 5: Speed testing Top {len(top)} (DL {dl_bytes/1e6:.0f}M / UL {ul_bytes/1e6:.0f}M each, timeout {args.speed_timeout}s)...[/bold]")
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Speed testing...", total=len(top))
            for idx, r in enumerate(top):
                progress.update(task, description=f"Speed {r['ip']}:{r['port']} {r.get('colo') or ''}")
                res = test_speed(r["ip"], r["port"], dl_bytes=dl_bytes, ul_bytes=ul_bytes, timeout=args.speed_timeout, sni=args.speed_sni)
                r.update(res)
                # Also keep colo if not already? Already have
                console.print(f"    [dim]{r['ip']}:{r['port']} -> DL {res.get('dl_mbps')} Mbps ({res.get('dl_error') or 'ok'}) UL {res.get('ul_mbps')} Mbps ({res.get('ul_error') or 'ok'})[/dim]")
                progress.update(task, completed=idx+1)
    else:
        console.print("[yellow]No candidates for speed test[/yellow]")

    # Final export
    console.print(f"\n[bold]Step 6: Exporting...[/bold]")
    # Prepare entries for TXT: ranking by dl_mbps desc if speed available, else by score
    if not args.no_speed and any(r.get("dl_mbps") is not None for r in top):
        # Sort by dl_mbps desc, fallback to score
        top_sorted = sorted(top, key=lambda r: (-(r.get("dl_mbps") or -1), r.get("score", float("inf"))))
    else:
        top_sorted = sorted(top, key=lambda r: r.get("score", float("inf")))

    # Ensure path is absolute or relative to cwd? Use Path(args.output)
    out_txt = Path(args.output)
    export_txt(top_sorted, out_txt)
    console.print(f"  TXT: {out_txt.resolve()} ({len(top_sorted)} lines)")

    # Show TXT preview
    console.print("\n[bold]TXT preview:[/bold]")
    for r in top_sorted:
        console.print(f"  {format_txt_line(r)}")

    if args.json:
        meta = {
            "count": args.count,
            "ports": ports,
            "probes": args.probes,
            "threads": args.threads,
            "timeout": args.timeout,
            "sni": args.sni,
            "speed_sni": args.speed_sni,
            "dl_bytes": dl_bytes,
            "ul_bytes": ul_bytes,
            "include_ipv6": args.include_ipv6,
            "seed": args.seed,
        }
        export_json(results, top_sorted, args.json, meta=meta)
        console.print(f"  JSON: {Path(args.json).resolve()} (full {len(results)} + top)")

    if args.csv:
        # Export all sorted results to CSV? Or just top? We'll export top_sorted for consistency + all if verbose
        export_csv(top_sorted, args.csv)
        console.print(f"  CSV: {Path(args.csv).resolve()}")

    console.print("\n[bold green]Done.[/bold green] Use clean_ips.txt for your proxy/WARP config.")
    console.print("[dim]Note: From Iran, colo will likely be FRA/IST/DXB/AMS. Lower latency + DXB/IST often better for Iran peering.[/dim]")

if __name__ == "__main__":
    main()
