#!/usr/bin/env python3
"""
CF Clean IP Scanner — Tkinter UI for Windows (no Flutter download, works offline in Iran)
Same backend as Flet UI, but uses tkinter/ttk for guaranteed PyInstaller bundling.
Flet app (app.py) remains for Android.
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import pathlib
import traceback
from datetime import datetime

from cf_scanner.fetch import fetch_cloudflare_cidrs, get_cidr_objects
from cf_scanner.sampler import sample_unique_ips
from cf_scanner.prober import probe_many
from cf_scanner.ranker import rank_results
from cf_scanner.speedtest import test_speed
from cf_scanner.reporter import export_txt, export_json, format_txt_line
from cf_scanner.config import all_ports as get_all_ports, default_ports as get_default_ports

APP_TITLE = "CF Clean IP Scanner — Iran (Tk)"
VERSION = "1.1.0"

COLO_COLORS = {
    "FRA": "#64B5F6",
    "DXB": "#FFD54F",
    "IST": "#FF8A65",
    "AMS": "#4DD0E1",
    "LHR": "#BA68C8",
    "CDG": "#81C784",
}

class AppTk:
    def __init__(self, root):
        self.root = root
        self.root.title(f"{APP_TITLE} v{VERSION}")
        self.root.geometry("1280x820")
        self.root.minsize(1100, 720)
        try:
            self.root.iconbitmap(default="")
        except:
            pass
        # Style
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except:
            pass
        style.configure("TButton", padding=6)
        style.configure("TLabel", font=("Segoe UI", 9))
        style.configure("Header.TLabel", font=("Segoe UI", 10, "bold"))

        self.cancel_event = threading.Event()
        self.is_scanning = False
        self.results_all = []
        self.top_results = []

        self.build_ui()

    def build_ui(self):
        # Header
        header = ttk.Frame(self.root, padding=8)
        header.pack(fill=tk.X)
        ttk.Label(header, text="🛡️  CF Clean IP Scanner — Iran", style="Header.TLabel").pack(side=tk.LEFT, padx=8)
        ttk.Label(header, text=f"v{VERSION}", foreground="#888").pack(side=tk.LEFT)
        ttk.Button(header, text="About", command=self.show_about).pack(side=tk.RIGHT, padx=4)
        ttk.Button(header, text="Open Output Folder", command=self.open_output_folder).pack(side=tk.RIGHT, padx=4)

        # Main paned
        paned = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)

        # Left controls
        left = ttk.Frame(paned, padding=8, width=380)
        paned.add(left, weight=1)
        # Right results
        right = ttk.Frame(paned, padding=8)
        paned.add(right, weight=3)

        # Left content
        ttk.Label(left, text="Scan Settings", style="Header.TLabel").pack(anchor=tk.W, pady=(0,6))

        # Count
        row1 = ttk.Frame(left)
        row1.pack(fill=tk.X, pady=2)
        ttk.Label(row1, text="Sample:").pack(side=tk.LEFT)
        self.count_var = tk.StringVar(value="1000")
        ttk.Combobox(row1, textvariable=self.count_var, values=["1000","2000","5000"], width=8, state="readonly").pack(side=tk.LEFT, padx=6)
        ttk.Label(row1, text="Probes:").pack(side=tk.LEFT, padx=(10,0))
        self.probes_var = tk.StringVar(value="3")
        ttk.Entry(row1, textvariable=self.probes_var, width=4).pack(side=tk.LEFT, padx=4)
        ttk.Label(row1, text="Top:").pack(side=tk.LEFT, padx=(6,0))
        self.top_var = tk.StringVar(value="5")
        ttk.Entry(row1, textvariable=self.top_var, width=4).pack(side=tk.LEFT, padx=4)

        row2 = ttk.Frame(left)
        row2.pack(fill=tk.X, pady=2)
        ttk.Label(row2, text="Timeout:").pack(side=tk.LEFT)
        self.timeout_var = tk.StringVar(value="3.0")
        ttk.Entry(row2, textvariable=self.timeout_var, width=6).pack(side=tk.LEFT, padx=4)
        ttk.Label(row2, text="Threads:").pack(side=tk.LEFT, padx=(8,0))
        self.threads_var = tk.StringVar(value="100")
        ttk.Entry(row2, textvariable=self.threads_var, width=6).pack(side=tk.LEFT, padx=4)
        ttk.Label(row2, text="DL:").pack(side=tk.LEFT, padx=(8,0))
        self.dl_var = tk.StringVar(value="10M")
        ttk.Combobox(row2, textvariable=self.dl_var, values=["1M","5M","10M","20M"], width=6, state="readonly").pack(side=tk.LEFT, padx=4)

        # Ports
        ttk.Separator(left, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=6)
        port_header = ttk.Frame(left)
        port_header.pack(fill=tk.X)
        ttk.Label(port_header, text="Ports (multi-select)", style="Header.TLabel").pack(side=tk.LEFT)
        ttk.Button(port_header, text="All", width=4, command=lambda: self.set_ports(get_all_ports())).pack(side=tk.RIGHT, padx=2)
        ttk.Button(port_header, text="Default", width=8, command=lambda: self.set_ports(get_default_ports())).pack(side=tk.RIGHT, padx=2)
        ttk.Button(port_header, text="None", width=5, command=lambda: self.set_ports([])).pack(side=tk.RIGHT, padx=2)

        self.port_vars = {}
        ports_frame = ttk.Frame(left)
        ports_frame.pack(fill=tk.X, pady=4)
        all_ports = get_all_ports()
        default_set = set(get_default_ports())
        # Grid 4 columns
        for idx, p in enumerate(all_ports):
            var = tk.BooleanVar(value=(p in default_set))
            self.port_vars[p] = var
            cb = ttk.Checkbutton(ports_frame, text=str(p), variable=var, command=self.update_ports_status)
            r, c = divmod(idx, 4)
            cb.grid(row=r, column=c, sticky=tk.W, padx=4, pady=1)
        self.ports_status = ttk.Label(left, text="", foreground="#666", font=("Segoe UI", 8))
        self.ports_status.pack(anchor=tk.W)
        self.update_ports_status()

        # Advanced
        ttk.Separator(left, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=6)
        self.adv_visible = False
        self.adv_btn = ttk.Button(left, text="Show Advanced ▼", command=self.toggle_advanced)
        self.adv_btn.pack(fill=tk.X, pady=2)
        self.adv_frame = ttk.Frame(left)
        # inside adv_frame
        r1 = ttk.Frame(self.adv_frame)
        r1.pack(fill=tk.X, pady=2)
        ttk.Label(r1, text="SNI:").pack(side=tk.LEFT)
        self.sni_var = tk.StringVar(value="www.cloudflare.com")
        ttk.Entry(r1, textvariable=self.sni_var, width=18).pack(side=tk.LEFT, padx=4)
        ttk.Label(r1, text="Speed SNI:").pack(side=tk.LEFT, padx=(6,0))
        self.speed_sni_var = tk.StringVar(value="speed.cloudflare.com")
        ttk.Entry(r1, textvariable=self.speed_sni_var, width=18).pack(side=tk.LEFT, padx=4)

        r2 = ttk.Frame(self.adv_frame)
        r2.pack(fill=tk.X, pady=2)
        self.ipv6_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(r2, text="Include IPv6", variable=self.ipv6_var).pack(side=tk.LEFT)
        ttk.Label(r2, text="Seed:").pack(side=tk.LEFT, padx=(12,0))
        self.seed_var = tk.StringVar(value="")
        ttk.Entry(r2, textvariable=self.seed_var, width=10).pack(side=tk.LEFT, padx=4)
        ttk.Label(r2, text="UL:").pack(side=tk.LEFT, padx=(8,0))
        self.ul_var = tk.StringVar(value="5M")
        ttk.Combobox(r2, textvariable=self.ul_var, values=["500K","1M","5M","10M"], width=6, state="readonly").pack(side=tk.LEFT, padx=4)

        r3 = ttk.Frame(self.adv_frame)
        r3.pack(fill=tk.X, pady=2)
        ttk.Label(r3, text="Output:").pack(side=tk.LEFT)
        self.output_var = tk.StringVar(value="clean_ips.txt")
        ttk.Entry(r3, textvariable=self.output_var, width=28).pack(side=tk.LEFT, padx=4)
        ttk.Button(r3, text="Browse", width=8, command=self.browse_output).pack(side=tk.LEFT, padx=4)

        # Action buttons
        ttk.Separator(left, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=8)
        btn_row = ttk.Frame(left)
        btn_row.pack(fill=tk.X, pady=4)
        self.start_btn = ttk.Button(btn_row, text="▶ Start Scan", command=self.start_scan)
        self.start_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        self.stop_btn = ttk.Button(btn_row, text="⏹ Stop", command=self.stop_scan, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)

        btn_row2 = ttk.Frame(left)
        btn_row2.pack(fill=tk.X, pady=2)
        self.export_btn = ttk.Button(btn_row2, text="💾 Export TXT", command=self.export_txt, state=tk.DISABLED)
        self.export_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        self.copy_btn = ttk.Button(btn_row2, text="📋 Copy", command=self.copy_txt, state=tk.DISABLED)
        self.copy_btn.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)

        # Status
        ttk.Separator(left, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=6)
        ttk.Label(left, text="Stage:", foreground="#666", font=("Segoe UI", 8)).pack(anchor=tk.W)
        self.stage_var = tk.StringVar(value="Idle")
        ttk.Label(left, textvariable=self.stage_var, foreground="#0ea5e9", font=("Segoe UI", 9, "bold")).pack(anchor=tk.W)
        self.progress = ttk.Progressbar(left, mode="determinate", maximum=100)
        self.progress.pack(fill=tk.X, pady=4)
        self.progress_text_var = tk.StringVar(value="0 / 0")
        ttk.Label(left, textvariable=self.progress_text_var, foreground="#888", font=("Segoe UI", 8)).pack(anchor=tk.W)
        self.log_text = tk.Text(left, height=6, wrap=tk.WORD, font=("Consolas", 8), bg="#1e1e1e", fg="#d4d4d4", relief=tk.FLAT)
        self.log_text.pack(fill=tk.BOTH, expand=False, pady=4)
        self.log_text.insert(tk.END, "Ready. Select sample/ports and Start.\n")
        self.log_text.configure(state=tk.DISABLED)

        # Right panel
        ttk.Label(right, text="Results (ranked by latency → speed)   COLO: FRA=Frankfurt DXB=Dubai IST=Istanbul AMS=Amsterdam", style="Header.TLabel").pack(anchor=tk.W)
        # Treeview
        cols = ("rank","ipport","colo","lat","jitter","loss","dl","ul")
        self.tree = ttk.Treeview(right, columns=cols, show="headings", height=18)
        self.tree.heading("rank", text="Rank")
        self.tree.heading("ipport", text="IP:PORT")
        self.tree.heading("colo", text="COLO")
        self.tree.heading("lat", text="LAT")
        self.tree.heading("jitter", text="JITTER")
        self.tree.heading("loss", text="LOSS")
        self.tree.heading("dl", text="DL")
        self.tree.heading("ul", text="UL")
        self.tree.column("rank", width=40, anchor=tk.CENTER)
        self.tree.column("ipport", width=150, anchor=tk.W)
        self.tree.column("colo", width=60, anchor=tk.CENTER)
        self.tree.column("lat", width=60, anchor=tk.E)
        self.tree.column("jitter", width=60, anchor=tk.E)
        self.tree.column("loss", width=50, anchor=tk.E)
        self.tree.column("dl", width=90, anchor=tk.E)
        self.tree.column("ul", width=90, anchor=tk.E)
        # Scrollbar
        sb = ttk.Scrollbar(right, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        tree_frame = ttk.Frame(right)
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=4)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, in_=tree_frame)
        sb.pack(side=tk.RIGHT, fill=tk.Y, in_=tree_frame)
        # Tag colors
        self.tree.tag_configure("top1", background="#1a3a1a")
        self.tree.tag_configure("top2", background="#1e2e1a")
        self.tree.tag_configure("fail", foreground="#888")

        ttk.Label(right, text="TXT Preview (Top 5: IP:PORT COLO LAT JITTER LOSS Upspeed Downspeed)", foreground="#666", font=("Segoe UI", 8)).pack(anchor=tk.W, pady=(6,0))
        self.txt_preview = tk.Text(right, height=6, wrap=tk.WORD, font=("Consolas", 9), bg="#1e1e1e", fg="#a5d6a7", relief=tk.FLAT)
        self.txt_preview.pack(fill=tk.BOTH, expand=False, pady=2)
        self.txt_preview.insert(tk.END, "")
        self.txt_preview.configure(state=tk.DISABLED)
        ttk.Label(right, text="Tip: Lower latency + 0% loss + low jitter = best. DXB/IST often better for Iran than FRA.", foreground="#888", font=("Segoe UI", 8)).pack(anchor=tk.W)

    def set_ports(self, ports):
        for p, var in self.port_vars.items():
            var.set(p in ports)
        self.update_ports_status()

    def update_ports_status(self):
        selected = [p for p, v in self.port_vars.items() if v.get()]
        txt = f"Selected: {sorted(selected)} ({len(selected)} ports)" if selected else "No ports selected!"
        self.ports_status.config(text=txt, foreground="red" if not selected else "#666")

    def toggle_advanced(self):
        self.adv_visible = not self.adv_visible
        if self.adv_visible:
            self.adv_frame.pack(fill=tk.X, pady=4)
            self.adv_btn.config(text="Hide Advanced ▲")
        else:
            self.adv_frame.pack_forget()
            self.adv_btn.config(text="Show Advanced ▼")

    def log(self, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.insert(tk.END, f"[{ts}] {msg}\n")
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)
        self.root.update_idletasks()

    def show_about(self):
        messagebox.showinfo("About", f"{APP_TITLE} v{VERSION}\n\nRandom 1k/2k/5k weighted sample from Cloudflare ranges.\nMeasures latency, jitter, loss + colo tag (FRA/DXB/IST...), speed-tests Top 5.\nExports: IP:PORT COLO LAT JITTER LOSS Upspeed Downspeed\n\nFor Iran networks — run inside Iran for accurate routing.\nGitHub: meeladns-lab/CF-Clean-IP-Scanner")

    def open_output_folder(self):
        p = pathlib.Path(self.output_var.get()).resolve().parent
        try:
            import os, subprocess, platform
            if platform.system() == "Windows":
                os.startfile(p)
            elif platform.system() == "Darwin":
                subprocess.Popen(["open", str(p)])
            else:
                subprocess.Popen(["xdg-open", str(p)])
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def browse_output(self):
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", "*.txt"), ("All", "*.*")], initialfile=self.output_var.get())
        if path:
            self.output_var.set(path)

    def start_scan(self):
        selected_ports = [p for p, v in self.port_vars.items() if v.get()]
        if not selected_ports:
            messagebox.showwarning("No ports", "Select at least one port!")
            return
        try:
            count = int(self.count_var.get())
            probes = int(self.probes_var.get())
            timeout = float(self.timeout_var.get())
            threads = int(self.threads_var.get())
            top = int(self.top_var.get())
        except Exception as e:
            messagebox.showerror("Invalid input", str(e))
            return
        if self.is_scanning:
            return
        self.cancel_event.clear()
        self.is_scanning = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.export_btn.config(state=tk.DISABLED)
        self.copy_btn.config(state=tk.DISABLED)
        self.results_all = []
        self.top_results = []
        for i in self.tree.get_children():
            self.tree.delete(i)
        self.txt_preview.configure(state=tk.NORMAL); self.txt_preview.delete("1.0", tk.END); self.txt_preview.configure(state=tk.DISABLED)
        self.progress["value"] = 0
        self.progress_text_var.set("Starting...")
        self.stage_var.set("Fetching Cloudflare ranges...")
        self.log_text.configure(state=tk.NORMAL); self.log_text.delete("1.0", tk.END); self.log_text.configure(state=tk.DISABLED)
        self.root.update()

        # Parse extra
        try:
            dl_bytes = self.parse_size(self.dl_var.get() or "10M")
            ul_bytes = self.parse_size(self.ul_var.get() or "5M")
        except:
            dl_bytes, ul_bytes = 10_000_000, 5_000_000
        seed = None
        try:
            if self.seed_var.get().strip():
                seed = int(self.seed_var.get().strip())
        except:
            seed=None
        sni = self.sni_var.get().strip() or "www.cloudflare.com"
        speed_sni = self.speed_sni_var.get().strip() or "speed.cloudflare.com"
        include_ipv6 = self.ipv6_var.get()
        output_path = self.output_var.get().strip() or "clean_ips.txt"

        threading.Thread(target=self.run_scan, args=(count, selected_ports, probes, timeout, threads, top, dl_bytes, ul_bytes, sni, speed_sni, include_ipv6, seed, output_path), daemon=True).start()

    def stop_scan(self):
        if self.is_scanning:
            self.cancel_event.set()
            self.stage_var.set("Cancelling...")
            self.log("Cancelling after current batch...")

    def run_scan(self, count, ports, probes, timeout, threads, top, dl_bytes, ul_bytes, sni, speed_sni, include_ipv6, seed, output_path):
        try:
            self.update_stage("Fetching Cloudflare CIDRs...", 5)
            if self.cancel_event.is_set():
                self.finish_scan(cancelled=True); return
            cidrs_str = fetch_cloudflare_cidrs(include_ipv6=include_ipv6)
            cidr_objs = get_cidr_objects(cidrs_str)
            total_ips = sum(c.num_addresses for c in cidr_objs)
            self.log(f"Fetched {len(cidrs_str)} CIDRs ~{total_ips:,} IPs")

            self.update_stage(f"Sampling {count} IPs (weighted)...", 10)
            if self.cancel_event.is_set():
                self.finish_scan(cancelled=True); return
            ips = sample_unique_ips(cidr_objs, count, seed=seed)
            self.log(f"Sampled {len(ips)} IPs")
            total_tasks = len(ips) * len(ports)
            self.log(f"Probing {total_tasks} IP:port x {probes} probes")

            self.update_stage(f"Probing {total_tasks} IP:port (latency/jitter/loss + colo)...", 15)
            if self.cancel_event.is_set():
                self.finish_scan(cancelled=True); return

            def progress_cb(done, total):
                if self.cancel_event.is_set():
                    return
                prog = 15 + (done/total)*60
                self.root.after(0, lambda: self.set_progress(prog, f"Probing {done}/{total}"))

            results = probe_many(ips, ports, probes=probes, timeout=timeout, threads=threads, sni=sni, progress_callback=progress_cb)
            if self.cancel_event.is_set():
                self.finish_scan(cancelled=True); return
            self.results_all = results
            success_cnt = sum(1 for r in results if r.get("overall_success"))
            self.log(f"Probed {len(results)}: {success_cnt} success, {len(results)-success_cnt} failed")
            self.root.after(0, lambda: self.set_progress(78, "Ranking..."))
            sorted_res = sorted(results, key=lambda r: r.get("score", float("inf")))
            self.root.after(0, lambda: self.update_table(sorted_res[:20], with_speed=False))

            top_candidates = rank_results(results, top=top)
            top_success = [r for r in top_candidates if r.get("overall_success")]
            if not top_success:
                self.log("No successful IPs for speed test")
                self.root.after(0, lambda: self.finish_scan(empty=True))
                return
            top_success = top_success[:top]
            self.log(f"Top {len(top_success)} selected for speed test")

            self.root.after(0, lambda: self.set_progress(80, f"Speed testing Top {len(top_success)}..."))
            for idx, r in enumerate(top_success):
                if self.cancel_event.is_set():
                    self.finish_scan(cancelled=True); return
                prog = 80 + (idx/len(top_success))*15
                self.root.after(0, lambda p=prog, i=idx, rr=r: self.set_progress(p, f"Speed {rr['ip']}:{rr['port']} {rr.get('colo') or ''}"))
                res = test_speed(r["ip"], r["port"], dl_bytes=dl_bytes, ul_bytes=ul_bytes, timeout=15.0, sni=speed_sni)
                r.update(res)
                self.log(f"  {r['ip']}:{r['port']} -> DL {res.get('dl_mbps')} Mbps UL {res.get('ul_mbps')} Mbps")
                self.root.after(0, lambda e=top_success: self.update_table(e, with_speed=True))

            if any(r.get("dl_mbps") is not None for r in top_success):
                self.top_results = sorted(top_success, key=lambda r: (-(r.get("dl_mbps") or -1), r.get("score", float("inf"))))
            else:
                self.top_results = sorted(top_success, key=lambda r: r.get("score", float("inf")))
            self.root.after(0, lambda: self.update_table(self.top_results, with_speed=True, highlight=True))

            self.root.after(0, lambda: self.set_progress(97, "Exporting TXT..."))
            try:
                out_path = pathlib.Path(output_path)
                export_txt(self.top_results, out_path)
                try:
                    export_json(results, self.top_results, "results.json", meta={"count":count,"ports":ports})
                except:
                    pass
                self.log(f"Exported {out_path.resolve()} ({len(self.top_results)} lines)")
            except Exception as e:
                self.log(f"Export failed: {e}")
            txt_lines = "\n".join(format_txt_line(r) for r in self.top_results)
            self.root.after(0, lambda: self.set_txt_preview(txt_lines))
            self.root.after(0, lambda: self.set_progress(100, f"Done — {len(self.top_results)} clean IPs"))
            self.log(f"Done. Best: {self.top_results[0]['ip']}:{self.top_results[0]['port']} {self.top_results[0].get('colo')} DL {self.top_results[0].get('dl_mbps')} Mbps" if self.top_results else "Done")
            self.root.after(0, lambda: self.finish_scan(success=True))
        except Exception as e:
            self.log(f"Error: {e}\n{traceback.format_exc()[:800]}")
            self.root.after(0, lambda: self.finish_scan(error=True, msg=str(e)))

    def set_progress(self, val, text):
        self.progress["value"] = val
        self.progress_text_var.set(text)
        self.stage_var.set(text)

    def update_stage(self, text, val):
        self.root.after(0, lambda: self.set_progress(val, text))

    def update_table(self, entries, with_speed=False, highlight=False):
        for i in self.tree.get_children():
            self.tree.delete(i)
        for i, r in enumerate(entries, 1):
            colo = r.get("colo") or "UNK"
            lat = f"{r.get('avg_latency',0):.0f}ms" if r.get("avg_latency") is not None else "—"
            jit = f"{r.get('jitter',0):.0f}ms" if r.get("jitter") is not None else "—"
            loss = f"{int(r.get('loss',100))}%"
            dl = f"{r.get('dl_mbps')} Mbps" if r.get('dl_mbps') is not None else ("—" if with_speed else "")
            ul = f"{r.get('ul_mbps')} Mbps" if r.get('ul_mbps') is not None else ("—" if with_speed else "")
            tag = ""
            if highlight and i==1:
                tag="top1"
            elif highlight and i<=3:
                tag="top2"
            elif r.get('loss',100)==100:
                tag="fail"
            self.tree.insert("", tk.END, values=(i, f"{r['ip']}:{r['port']}", colo, lat, jit, loss, dl, ul), tags=(tag,))

    def set_txt_preview(self, txt):
        self.txt_preview.configure(state=tk.NORMAL)
        self.txt_preview.delete("1.0", tk.END)
        self.txt_preview.insert(tk.END, txt)
        self.txt_preview.configure(state=tk.DISABLED)

    def finish_scan(self, success=False, cancelled=False, error=False, empty=False, msg=""):
        self.is_scanning=False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        if success and self.top_results:
            self.export_btn.config(state=tk.NORMAL)
            self.copy_btn.config(state=tk.NORMAL)
        if cancelled:
            self.progress["value"]=0
            self.stage_var.set("Cancelled")
            messagebox.showinfo("Cancelled","Scan cancelled")
        elif error:
            self.stage_var.set(f"Error: {msg}")
            messagebox.showerror("Error", msg)
        elif empty:
            self.stage_var.set("No clean IPs")
            messagebox.showwarning("No results","No clean IPs found")
        elif success:
            self.stage_var.set(f"Done — {len(self.top_results)} clean IPs")
            messagebox.showinfo("Done", f"Scan complete — {len(self.top_results)} IPs exported to {self.output_var.get()}")

    def parse_size(self, s):
        s=s.strip().upper()
        if s.endswith("M"):
            return int(float(s[:-1])*1_000_000)
        if s.endswith("K"):
            return int(float(s[:-1])*1_000)
        return int(s)

    def export_txt(self):
        if not self.top_results:
            messagebox.showwarning("No results","No results to export")
            return
        path=filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text","*.txt")], initialfile="clean_ips.txt")
        if path:
            try:
                export_txt(self.top_results, path)
                messagebox.showinfo("Saved", f"Saved to {path}")
            except Exception as e:
                messagebox.showerror("Save failed", str(e))

    def copy_txt(self):
        txt=self.txt_preview.get("1.0", tk.END).strip()
        if not txt:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(txt)
        messagebox.showinfo("Copied","Copied to clipboard")

    def set_progress(self, val, text):
        self.progress["value"]=val
        self.progress_text_var.set(text)
        self.stage_var.set(text)

def main():
    root=tk.Tk()
    AppTk(root)
    root.mainloop()

if __name__ == "__main__":
    main()
