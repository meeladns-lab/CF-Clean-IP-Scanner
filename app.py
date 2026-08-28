import flet as ft
import threading
import time
import pathlib
import json
import traceback
from datetime import datetime

# Import scanner backend
from cf_scanner.fetch import fetch_cloudflare_cidrs, get_cidr_objects
from cf_scanner.sampler import sample_unique_ips
from cf_scanner.prober import probe_many
from cf_scanner.ranker import rank_results
from cf_scanner.speedtest import test_speed
from cf_scanner.reporter import export_txt, export_json, format_txt_line
from cf_scanner.config import all_ports as get_all_ports, default_ports as get_default_ports, parse_ports

APP_TITLE = "CF Clean IP Scanner — Iran"
APP_VERSION = "1.1.0"

# Color mapping for colo badges
COLO_COLORS = {
    "FRA": ft.Colors.BLUE_300,
    "AMS": ft.Colors.CYAN_300,
    "DXB": ft.Colors.AMBER_300,
    "IST": ft.Colors.ORANGE_300,
    "LHR": ft.Colors.PURPLE_300,
    "CDG": ft.Colors.GREEN_300,
    "VIE": ft.Colors.TEAL_300,
    "MXP": ft.Colors.INDIGO_300,
    "MAD": ft.Colors.LIME_300,
    "ARN": ft.Colors.PINK_300,
    "UNK": ft.Colors.GREY_500,
}

def colo_color(colo: str):
    return COLO_COLORS.get((colo or "UNK").upper(), ft.Colors.GREY_400)

class ScannerUI:
    def __init__(self, page: ft.Page):
        self.page = page
        self.page.title = APP_TITLE
        self.page.theme_mode = ft.ThemeMode.DARK
        self.page.window_width = 1280
        self.page.window_height = 860
        self.page.window_min_width = 1100
        self.page.window_min_height = 720
        self.page.padding = 12
        self.page.scroll = ft.ScrollMode.AUTO

        self.cancel_event = threading.Event()
        self.is_scanning = False
        self.results_all = []
        self.top_results = []
        self.scan_thread = None

        # File picker
        self.file_picker = ft.FilePicker(on_result=self.on_file_picker_result)
        self.save_picker = ft.FilePicker(on_result=self.on_save_picker_result)
        self.page.overlay.extend([self.file_picker, self.save_picker])

        self.build_ui()

    def build_ui(self):
        # Header
        header = ft.Row([
            ft.Icon(ft.Icons.SHIELD_OUTLINED, size=28, color=ft.Colors.CYAN_300),
            ft.Text(APP_TITLE, size=20, weight=ft.FontWeight.BOLD),
            ft.Text(f"v{APP_VERSION}", size=12, color=ft.Colors.GREY_400),
            ft.Container(expand=True),
            ft.IconButton(icon=ft.Icons.DARK_MODE, tooltip="Toggle theme", on_click=self.toggle_theme),
            ft.IconButton(icon=ft.Icons.HELP_OUTLINE, tooltip="About", on_click=self.show_about),
        ], alignment=ft.MainAxisAlignment.START, vertical_alignment=ft.CrossAxisAlignment.CENTER)

        # Left controls
        self.count_dd = ft.Dropdown(
            label="Sample size",
            value="1000",
            options=[ft.dropdown.Option("1000"), ft.dropdown.Option("2000"), ft.dropdown.Option("5000")],
            width=140,
            dense=True,
        )
        self.probes_tf = ft.TextField(label="Probes", value="3", width=80, dense=True, keyboard_type=ft.KeyboardType.NUMBER, tooltip="Probes per IP:port for jitter/loss")
        self.timeout_tf = ft.TextField(label="Timeout (s)", value="3.0", width=100, dense=True, keyboard_type=ft.KeyboardType.NUMBER)
        self.threads_tf = ft.TextField(label="Threads", value="100", width=90, dense=True, keyboard_type=ft.KeyboardType.NUMBER)
        self.top_tf = ft.TextField(label="Top N", value="5", width=80, dense=True, keyboard_type=ft.KeyboardType.NUMBER)

        # Ports - chip style checkboxes
        self.port_checks = {}
        all_ports = get_all_ports()
        default_ports = set(get_default_ports())
        port_rows = []
        # Create wrap of checkboxes
        checks = []
        for p in all_ports:
            cb = ft.Checkbox(label=str(p), value=(p in default_ports), dense=True, width=70)
            self.port_checks[p] = cb
            checks.append(cb)
        ports_wrap = ft.Wrap(controls=checks, spacing=4, run_spacing=0)

        self.ports_status = ft.Text(f"Selected: {sorted(default_ports)}", size=11, color=ft.Colors.GREY_400)

        btn_all = ft.TextButton("All", on_click=lambda e: self.set_ports(all_ports))
        btn_default = ft.TextButton("Default", on_click=lambda e: self.set_ports(list(default_ports)))
        btn_none = ft.TextButton("None", on_click=lambda e: self.set_ports([]))

        # Advanced
        self.sni_tf = ft.TextField(label="SNI (trace)", value="www.cloudflare.com", dense=True, width=220, visible=False)
        self.speed_sni_tf = ft.TextField(label="Speed SNI", value="speed.cloudflare.com", dense=True, width=220, visible=False)
        self.ipv6_sw = ft.Switch(label="Include IPv6", value=False, visible=False)
        self.seed_tf = ft.TextField(label="Seed (optional)", value="", dense=True, width=120, visible=False, hint_text="random")
        self.dl_size_dd = ft.Dropdown(label="DL size", value="10M", options=[ft.dropdown.Option("1M"), ft.dropdown.Option("5M"), ft.dropdown.Option("10M"), ft.dropdown.Option("20M")], width=110, dense=True, visible=False)
        self.ul_size_dd = ft.Dropdown(label="UL size", value="5M", options=[ft.dropdown.Option("500K"), ft.dropdown.Option("1M"), ft.dropdown.Option("5M"), ft.dropdown.Option("10M")], width=110, dense=True, visible=False)
        self.output_tf = ft.TextField(label="Output TXT", value="clean_ips.txt", dense=True, width=220, visible=False, suffix=ft.IconButton(icon=ft.Icons.FOLDER_OPEN, tooltip="Choose file", on_click=lambda e: self.save_picker.save_file(dialog_title="Save TXT", file_name="clean_ips.txt", allowed_extensions=["txt"])))

        self.advanced_visible = False
        def toggle_advanced(e):
            self.advanced_visible = not self.advanced_visible
            for c in [self.sni_tf, self.speed_sni_tf, self.ipv6_sw, self.seed_tf, self.dl_size_dd, self.ul_size_dd, self.output_tf]:
                c.visible = self.advanced_visible
            self.advanced_btn.text = "Hide Advanced" if self.advanced_visible else "Show Advanced"
            self.advanced_btn.icon = ft.Icons.EXPAND_LESS if self.advanced_visible else ft.Icons.EXPAND_MORE
            self.page.update()
        self.advanced_btn = ft.TextButton("Show Advanced", icon=ft.Icons.EXPAND_MORE, on_click=toggle_advanced)

        # Action buttons
        self.start_btn = ft.ElevatedButton("Start Scan", icon=ft.Icons.PLAY_ARROW, bgcolor=ft.Colors.CYAN_700, color=ft.Colors.WHITE, on_click=self.start_scan, width=140, height=44)
        self.stop_btn = ft.ElevatedButton("Stop", icon=ft.Icons.STOP, bgcolor=ft.Colors.RED_700, color=ft.Colors.WHITE, on_click=self.stop_scan, disabled=True, width=100, height=44)
        self.export_btn = ft.ElevatedButton("Export TXT", icon=ft.Icons.DOWNLOAD, disabled=True, on_click=self.export_txt, width=130)
        self.copy_btn = ft.OutlinedButton("Copy", icon=ft.Icons.COPY, disabled=True, on_click=self.copy_txt, width=90)

        # Status
        self.stage_text = ft.Text("Idle", size=13, weight=ft.FontWeight.BOLD, color=ft.Colors.CYAN_300)
        self.progress = ft.ProgressBar(value=0, width=None, expand=True, color=ft.Colors.CYAN_400, bgcolor=ft.Colors.GREY_800)
        self.progress_text = ft.Text("0 / 0", size=11, color=ft.Colors.GREY_400)
        self.log_text = ft.Text("", size=11, color=ft.Colors.GREY_300, selectable=True, max_lines=4)

        # Results table
        self.results_table = ft.DataTable(
            columns=[
                ft.DataColumn(ft.Text("Rank", size=11, weight=ft.FontWeight.BOLD)),
                ft.DataColumn(ft.Text("IP:PORT", size=11, weight=ft.FontWeight.BOLD)),
                ft.DataColumn(ft.Text("COLO", size=11, weight=ft.FontWeight.BOLD)),
                ft.DataColumn(ft.Text("LAT", size=11, weight=ft.FontWeight.BOLD), numeric=True),
                ft.DataColumn(ft.Text("JITTER", size=11, weight=ft.FontWeight.BOLD), numeric=True),
                ft.DataColumn(ft.Text("LOSS", size=11, weight=ft.FontWeight.BOLD), numeric=True),
                ft.DataColumn(ft.Text("DL", size=11, weight=ft.FontWeight.BOLD), numeric=True),
                ft.DataColumn(ft.Text("UL", size=11, weight=ft.FontWeight.BOLD), numeric=True),
            ],
            rows=[],
            heading_row_color=ft.Colors.GREY_900,
            border=ft.border.all(1, ft.Colors.GREY_800),
            border_radius=8,
            column_spacing=14,
            data_row_min_height=32,
            data_row_max_height=36,
            expand=True,
        )
        self.table_scroll = ft.Column([ft.Row([self.results_table], scroll=ft.ScrollMode.AUTO, expand=True)], scroll=ft.ScrollMode.AUTO, expand=True, height=420)

        # TXT preview
        self.txt_preview = ft.TextField(
            label="TXT Preview (Top 5 format: IP:PORT COLO LAT JITTER LOSS Upspeed Downspeed)",
            value="",
            multiline=True,
            min_lines=4,
            max_lines=6,
            read_only=True,
            dense=True,
            text_size=11,
            expand=True,
        )

        # Left panel container
        left = ft.Container(
            content=ft.Column([
                ft.Text("Scan Settings", size=14, weight=ft.FontWeight.BOLD),
                ft.Row([self.count_dd, self.probes_tf, self.timeout_tf]),
                ft.Row([self.threads_tf, self.top_tf, ft.Container(width=10)]),
                ft.Divider(height=8, color=ft.Colors.GREY_800),
                ft.Row([ft.Text("Ports (multi-select)", size=12, weight=ft.FontWeight.BOLD), ft.Container(expand=True), btn_all, btn_default, btn_none]),
                ports_wrap,
                self.ports_status,
                ft.Divider(height=8, color=ft.Colors.GREY_800),
                self.advanced_btn,
                ft.Column([ft.Row([self.sni_tf, self.speed_sni_tf]), ft.Row([self.ipv6_sw, self.seed_tf]), ft.Row([self.dl_size_dd, self.ul_size_dd]), self.output_tf], spacing=6),
                ft.Divider(height=8, color=ft.Colors.GREY_800),
                ft.Row([self.start_btn, self.stop_btn], alignment=ft.MainAxisAlignment.CENTER),
                ft.Row([self.export_btn, self.copy_btn], alignment=ft.MainAxisAlignment.CENTER),
                ft.Divider(height=8, color=ft.Colors.GREY_800),
                ft.Text("Stage", size=11, color=ft.Colors.GREY_400),
                self.stage_text,
                self.progress,
                self.progress_text,
                self.log_text,
            ], spacing=8, scroll=ft.ScrollMode.AUTO),
            width=380,
            padding=12,
            bgcolor=ft.Colors.GREY_900,
            border_radius=12,
            border=ft.border.all(1, ft.Colors.GREY_800),
        )

        # Right panel
        right = ft.Container(
            content=ft.Column([
                ft.Row([ft.Icon(ft.Icons.TABLE_CHART, size=18), ft.Text("Results (ranked by latency → speed)", size=13, weight=ft.FontWeight.BOLD), ft.Container(expand=True), ft.Text("COLO: FRA=Frankfurt DXB=Dubai IST=Istanbul", size=10, color=ft.Colors.GREY_500)]),
                self.table_scroll,
                ft.Divider(height=6, color=ft.Colors.GREY_800),
                self.txt_preview,
                ft.Text("Tip: Lower latency + 0% loss + low jitter = best. DXB/IST often better for Iran peering than FRA.", size=10, color=ft.Colors.GREY_500),
            ], spacing=8, expand=True),
            expand=True,
            padding=12,
            bgcolor=ft.Colors.GREY_900,
            border_radius=12,
            border=ft.border.all(1, ft.Colors.GREY_800),
        )

        main_row = ft.Row([left, right], expand=True, vertical_alignment=ft.CrossAxisAlignment.START, spacing=12)

        self.page.add(header, ft.Divider(height=1, color=ft.Colors.GREY_800), main_row)

        # Update ports status live
        for cb in self.port_checks.values():
            cb.on_change = lambda e: self.update_ports_status()

        self.update_ports_status()

    def set_ports(self, ports):
        for p, cb in self.port_checks.items():
            cb.value = p in ports
        self.update_ports_status()
        self.page.update()

    def update_ports_status(self):
        selected = [p for p, cb in self.port_checks.items() if cb.value]
        self.ports_status.value = f"Selected: {sorted(selected)} ({len(selected)} ports)" if selected else "No ports selected!"
        self.ports_status.color = ft.Colors.RED_300 if not selected else ft.Colors.GREY_400
        self.page.update()

    def toggle_theme(self, e):
        self.page.theme_mode = ft.ThemeMode.LIGHT if self.page.theme_mode == ft.ThemeMode.DARK else ft.ThemeMode.DARK
        self.page.update()

    def show_about(self, e):
        dlg = ft.AlertDialog(
            title=ft.Text("About"),
            content=ft.Text(f"{APP_TITLE} v{APP_VERSION}\n\nRandom 1k/2k/5k weighted sample from Cloudflare ranges.\nMeasures latency, jitter, loss + colo tag (FRA/DXB/IST...), speed-tests Top 5.\nExports: IP:PORT COLO LAT JITTER LOSS Upspeed Downspeed\n\nFor Iran networks — run inside Iran for accurate routing.\nGitHub: meeladns-lab/CF-Clean-IP-Scanner", size=12),
            actions=[ft.TextButton("Close", on_click=lambda e: setattr(dlg, "open", False) or self.page.update())],
        )
        self.page.dialog = dlg
        dlg.open = True
        self.page.update()

    def on_file_picker_result(self, e: ft.FilePickerResultEvent):
        pass

    def on_save_picker_result(self, e: ft.FilePickerResultEvent):
        if e.path:
            self.output_tf.value = e.path
            self.page.update()

    def start_scan(self, e):
        selected_ports = [p for p, cb in self.port_checks.items() if cb.value]
        if not selected_ports:
            self.page.show_snack_bar(ft.SnackBar(ft.Text("Select at least one port!"), bgcolor=ft.Colors.RED_700))
            return
        try:
            count = int(self.count_dd.value)
            probes = int(self.probes_tf.value)
            timeout = float(self.timeout_tf.value)
            threads = int(self.threads_tf.value)
            top = int(self.top_tf.value)
        except Exception as ex:
            self.page.show_snack_bar(ft.SnackBar(ft.Text(f"Invalid numeric input: {ex}"), bgcolor=ft.Colors.RED_700))
            return

        if self.is_scanning:
            return
        self.cancel_event.clear()
        self.is_scanning = True
        self.start_btn.disabled = True
        self.stop_btn.disabled = False
        self.export_btn.disabled = True
        self.copy_btn.disabled = True
        self.results_all = []
        self.top_results = []
        self.results_table.rows.clear()
        self.txt_preview.value = ""
        self.progress.value = 0
        self.progress_text.value = "Starting..."
        self.stage_text.value = "Fetching Cloudflare ranges..."
        self.log_text.value = ""
        self.page.update()

        # Parse extra
        try:
            dl_bytes = self.parse_size(self.dl_size_dd.value or "10M")
            ul_bytes = self.parse_size(self.ul_size_dd.value or "5M")
        except:
            dl_bytes, ul_bytes = 10_000_000, 5_000_000
        seed = None
        try:
            if self.seed_tf.value.strip():
                seed = int(self.seed_tf.value.strip())
        except:
            seed = None

        sni = self.sni_tf.value.strip() or "www.cloudflare.com"
        speed_sni = self.speed_sni_tf.value.strip() or "speed.cloudflare.com"
        include_ipv6 = self.ipv6_sw.value
        output_path = self.output_tf.value.strip() or "clean_ips.txt"

        # Run in thread
        self.scan_thread = threading.Thread(target=self.run_scan, args=(count, selected_ports, probes, timeout, threads, top, dl_bytes, ul_bytes, sni, speed_sni, include_ipv6, seed, output_path), daemon=True)
        self.scan_thread.start()

    def stop_scan(self, e):
        if self.is_scanning:
            self.cancel_event.set()
            self.stage_text.value = "Cancelling..."
            self.log_text.value += "\nCancelling after current batch..."
            self.page.update()

    def run_scan(self, count, ports, probes, timeout, threads, top, dl_bytes, ul_bytes, sni, speed_sni, include_ipv6, seed, output_path):
        try:
            # Step 1 fetch
            self.update_stage("Fetching Cloudflare CIDRs...", 0.05)
            if self.cancel_event.is_set():
                self.finish_scan(cancelled=True)
                return
            cidrs_str = fetch_cloudflare_cidrs(include_ipv6=include_ipv6)
            cidr_objs = get_cidr_objects(cidrs_str)
            total_ips = sum(c.num_addresses for c in cidr_objs)
            self.log(f"Fetched {len(cidrs_str)} CIDRs ~{total_ips:,} IPs")

            # Step 2 sample
            self.update_stage(f"Sampling {count} IPs (weighted)...", 0.1)
            if self.cancel_event.is_set():
                self.finish_scan(cancelled=True)
                return
            ips = sample_unique_ips(cidr_objs, count, seed=seed)
            self.log(f"Sampled {len(ips)} IPs")

            total_tasks = len(ips) * len(ports)
            self.log(f"Probing {total_tasks} IP:port x {probes} probes")

            # Step 3 probe
            self.update_stage(f"Probing {total_tasks} IP:port (latency/jitter/loss + colo)...", 0.15)

            def progress_cb(done, total):
                if self.cancel_event.is_set():
                    return
                prog = 0.15 + (done / total) * 0.6  # 0.15-0.75
                self.progress.value = prog
                self.progress_text.value = f"Probing {done}/{total}"
                # Throttle UI updates
                if done % max(1, total // 20) == 0 or done == total:
                    self.page.update()

            # Check cancellation before heavy work
            if self.cancel_event.is_set():
                self.finish_scan(cancelled=True)
                return

            results = probe_many(ips, ports, probes=probes, timeout=timeout, threads=threads, sni=sni, progress_callback=progress_cb)

            if self.cancel_event.is_set():
                self.finish_scan(cancelled=True)
                return

            self.results_all = results
            success_cnt = sum(1 for r in results if r.get("overall_success"))
            self.log(f"Probed {len(results)}: {success_cnt} success, {len(results)-success_cnt} failed")
            self.update_stage("Ranking...", 0.78)

            # Update table interim (top 20 by score)
            sorted_res = sorted(results, key=lambda r: r.get("score", float("inf")))
            self.update_table(sorted_res[:20], with_speed=False)

            # Step 4 rank
            top_candidates = rank_results(results, top=top)
            top_success = [r for r in top_candidates if r.get("overall_success")]
            if not top_success:
                self.log("No successful IPs for speed test")
                self.top_results = []
                self.finish_scan(empty=True, output_path=output_path)
                return
            top_success = top_success[:top]
            self.log(f"Top {len(top_success)} selected for speed test")

            # Step 5 speed test
            self.update_stage(f"Speed testing Top {len(top_success)} (DL {dl_bytes//1_000_000}M / UL {ul_bytes//1_000_000}M)...", 0.8)
            for idx, r in enumerate(top_success):
                if self.cancel_event.is_set():
                    self.finish_scan(cancelled=True)
                    return
                self.progress.value = 0.8 + (idx / len(top_success)) * 0.15
                self.progress_text.value = f"Speed {idx+1}/{len(top_success)} {r['ip']}:{r['port']}"
                self.stage_text.value = f"Speed {r['ip']}:{r['port']} {r.get('colo') or ''}"
                self.page.update()
                res = test_speed(r["ip"], r["port"], dl_bytes=dl_bytes, ul_bytes=ul_bytes, timeout=15.0, sni=speed_sni)
                r.update(res)
                self.log(f"  {r['ip']}:{r['port']} -> DL {res.get('dl_mbps')} Mbps UL {res.get('ul_mbps')} Mbps")
                # Update table live
                self.update_table(top_success, with_speed=True, highlight_all=False)
                self.page.update()

            # Sort by dl_mbps desc else score
            if any(r.get("dl_mbps") is not None for r in top_success):
                self.top_results = sorted(top_success, key=lambda r: (-(r.get("dl_mbps") or -1), r.get("score", float("inf"))))
            else:
                self.top_results = sorted(top_success, key=lambda r: r.get("score", float("inf")))

            self.update_table(self.top_results, with_speed=True, highlight_all=True)

            # Step 6 export
            self.update_stage("Exporting TXT...", 0.97)
            try:
                out_path = pathlib.Path(output_path)
                # On Android, use app storage if needed
                export_txt(self.top_results, out_path)
                # Also try json
                try:
                    export_json(results, self.top_results, "results.json", meta={"count":count,"ports":ports,"probes":probes,"threads":threads,"timeout":timeout,"sni":sni})
                except:
                    pass
                self.log(f"Exported {out_path.resolve()} ({len(self.top_results)} lines)")
            except Exception as e:
                self.log(f"Export failed: {e}")

            # TXT preview
            txt_lines = "\n".join(format_txt_line(r) for r in self.top_results)
            self.txt_preview.value = txt_lines
            self.progress.value = 1.0
            self.progress_text.value = "Done"
            self.stage_text.value = f"Done — {len(self.top_results)} clean IPs"
            self.log(f"Done. Best: {self.top_results[0]['ip']}:{self.top_results[0]['port']} {self.top_results[0].get('colo')} DL {self.top_results[0].get('dl_mbps')} Mbps" if self.top_results else "Done")
            self.finish_scan(success=True)

        except Exception as e:
            self.log(f"Error: {e}\n{traceback.format_exc()[:800]}")
            self.stage_text.value = f"Error: {e}"
            self.finish_scan(error=True)

    def update_stage(self, text, progress_val):
        self.stage_text.value = text
        self.progress.value = progress_val
        self.page.update()

    def log(self, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_text.value = (self.log_text.value + f"\n[{ts}] {msg}")[-2000:]
        self.page.update()

    def update_table(self, entries, with_speed=False, highlight_all=False):
        self.results_table.rows.clear()
        for i, r in enumerate(entries, 1):
            colo = r.get("colo") or "UNK"
            lat = f"{r.get('avg_latency',0):.0f}ms" if r.get("avg_latency") is not None else "—"
            jit = f"{r.get('jitter',0):.0f}ms" if r.get("jitter") is not None else "—"
            loss = f"{int(r.get('loss',100))}%"
            dl = f"{r.get('dl_mbps')} Mbps" if r.get('dl_mbps') is not None else ("—" if with_speed else "")
            ul = f"{r.get('ul_mbps')} Mbps" if r.get('ul_mbps') is not None else ("—" if with_speed else "")
            # Rank or highlight
            rank_text = ft.Text(str(i), size=11, weight=ft.FontWeight.BOLD if highlight_all and i<=3 else ft.FontWeight.NORMAL, color=ft.Colors.AMBER_300 if i==1 and highlight_all else None)
            ip_port = ft.Text(f"{r['ip']}:{r['port']}", size=11, weight=ft.FontWeight.BOLD, selectable=True)
            colo_badge = ft.Container(
                content=ft.Text(colo, size=10, weight=ft.FontWeight.BOLD, color=ft.Colors.WHITE),
                bgcolor=colo_color(colo),
                padding=ft.padding.symmetric(horizontal=6, vertical=2),
                border_radius=6,
            )
            # Row color by loss
            loss_val = r.get('loss',100)
            if loss_val == 0:
                row_color = None
            elif loss_val < 100:
                row_color = ft.Colors.with_opacity(0.05, ft.Colors.AMBER_300)
            else:
                row_color = ft.Colors.with_opacity(0.08, ft.Colors.RED_400)

            self.results_table.rows.append(
                ft.DataRow(
                    cells=[
                        ft.DataCell(rank_text),
                        ft.DataCell(ip_port),
                        ft.DataCell(colo_badge),
                        ft.DataCell(ft.Text(lat, size=11)),
                        ft.DataCell(ft.Text(jit, size=11)),
                        ft.DataCell(ft.Text(loss, size=11, color=ft.Colors.RED_300 if loss_val>0 else ft.Colors.GREEN_300)),
                        ft.DataCell(ft.Text(dl, size=11, color=ft.Colors.CYAN_300)),
                        ft.DataCell(ft.Text(ul, size=11, color=ft.Colors.GREEN_300)),
                    ],
                    color=row_color,
                )
            )
        self.page.update()

    def finish_scan(self, success=False, cancelled=False, error=False, empty=False):
        self.is_scanning = False
        self.start_btn.disabled = False
        self.stop_btn.disabled = True
        if success and self.top_results:
            self.export_btn.disabled = False
            self.copy_btn.disabled = False
        if cancelled:
            self.progress.value = 0
            self.progress_text.value = "Cancelled"
            self.stage_text.value = "Cancelled"
            self.page.show_snack_bar(ft.SnackBar(ft.Text("Scan cancelled"), bgcolor=ft.Colors.AMBER_700))
        elif error:
            self.page.show_snack_bar(ft.SnackBar(ft.Text("Scan failed — check log"), bgcolor=ft.Colors.RED_700))
        elif empty:
            self.page.show_snack_bar(ft.SnackBar(ft.Text("No clean IPs found"), bgcolor=ft.Colors.AMBER_700))
        elif success:
            self.page.show_snack_bar(ft.SnackBar(ft.Text(f"Scan complete — {len(self.top_results)} IPs exported"), bgcolor=ft.Colors.GREEN_700))
        self.page.update()

    def parse_size(self, s: str) -> int:
        s = s.strip().upper()
        if s.endswith("M"):
            return int(float(s[:-1]) * 1_000_000)
        if s.endswith("K"):
            return int(float(s[:-1]) * 1_000)
        return int(s)

    def export_txt(self, e):
        if not self.top_results:
            self.page.show_snack_bar(ft.SnackBar(ft.Text("No results to export"), bgcolor=ft.Colors.RED_700))
            return
        self.save_picker.save_file(dialog_title="Save clean_ips.txt", file_name="clean_ips.txt", allowed_extensions=["txt"])

    def copy_txt(self, e):
        if not self.txt_preview.value:
            return
        self.page.set_clipboard(self.txt_preview.value)
        self.page.show_snack_bar(ft.SnackBar(ft.Text("Copied to clipboard"), bgcolor=ft.Colors.GREEN_700))

    def on_save_picker_result(self, e: ft.FilePickerResultEvent):
        if e.path and self.top_results:
            try:
                export_txt(self.top_results, e.path)
                self.page.show_snack_bar(ft.SnackBar(ft.Text(f"Saved to {e.path}"), bgcolor=ft.Colors.GREEN_700))
            except Exception as ex:
                self.page.show_snack_bar(ft.SnackBar(ft.Text(f"Save failed: {ex}"), bgcolor=ft.Colors.RED_700))

def main(page: ft.Page):
    ScannerUI(page)

if __name__ == "__main__":
    # Flet 0.86+: app() deprecated -> use run(); handle Iran throttling where flet_desktop binary download is slow/blocked
    import sys
    is_frozen = getattr(sys, 'frozen', False)
    # Prefer WEB_BROWSER in frozen exe (PyInstaller) to avoid needing flet_desktop download; native FLET_APP for dev
    view = ft.AppView.WEB_BROWSER if is_frozen else ft.AppView.FLET_APP
    assets = "assets"
    # Try ft.run if available (new API), else ft.app
    runner = getattr(ft, 'run', None) or getattr(ft, 'app')
    try:
        runner(target=main, view=view, assets_dir=assets, port=8599)
    except TypeError:
        # older signature without assets_dir/port
        try:
            runner(target=main, view=view)
        except Exception as e:
            print(f"Runner failed ({e}), trying fallback WEB_BROWSER...")
            runner(target=main, view=ft.AppView.WEB_BROWSER)
    except Exception as e:
        print(f"View {view} failed ({e}), falling back to WEB_BROWSER...")
        try:
            runner(target=main, view=ft.AppView.WEB_BROWSER, assets_dir=assets, port=8599)
        except Exception as e2:
            print(f"WEB_BROWSER also failed: {e2}")
            raise
