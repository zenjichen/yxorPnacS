import os, sys, csv, time, signal, threading, subprocess, re, ctypes, queue
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog

import requests
from requests.exceptions import RequestException

# =========================
# CẤU HÌNH & HẰNG SỐ
# =========================
BASE_DIR = Path(__file__).resolve().parent
MAIN_FILE = BASE_DIR / "main.py"

CANDIDATE_FILES = [
    BASE_DIR / "proxy-list" / "data.txt",
    BASE_DIR / "data.txt",
    BASE_DIR / "data" / "data.txt",
]

POLL_INTERVAL = 0.10
HTTP_TEST_URL = "https://httpbin.org/anything"
HTTP_TIMEOUT   = 7
MAX_WORKERS    = 64
COMMON_SCHEMES = ["http", "https", "socks5", "socks4"]

# Giao diện hiện đại
ACCENT      = "#4f46e5"
BG_DARK     = "#0f172a"
BG_PANEL    = "#111827"
BG_TABLE    = "#0b1220"
FG_TEXT     = "#e5e7eb"
FG_MUTED    = "#94a3b8"
ROW_HEIGHT  = 26


# =========================
# TIỆN ÍCH HỆ THỐNG
# =========================
def is_windows():
    return os.name == "nt"

def create_popen(cmd, cwd):
    if is_windows():
        CREATE_NEW_PROCESS_GROUP = 0x00000200
        return subprocess.Popen(
            cmd, cwd=str(cwd),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
            creationflags=CREATE_NEW_PROCESS_GROUP
        )
    else:
        return subprocess.Popen(
            cmd, cwd=str(cwd),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
            preexec_fn=os.setsid
        )

def kill_process_tree(proc: subprocess.Popen):
    if not proc: return
    try:
        if is_windows():
            subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except Exception:
                proc.terminate()
    except Exception:
        pass

def resolve_output_file():
    for p in CANDIDATE_FILES:
        if p.exists():
            return p
    return CANDIDATE_FILES[0]

# =========================
# XỬ LÝ PROXY
# =========================
def parse_proxy_line(line: str):
    s = line.strip()
    if not s or s.startswith("#"): return None
    if "://" in s:
        scheme, rest = s.split("://", 1)
        return scheme.lower(), rest
    return None, s

def extract_ip_host(address: str) -> str:
    if "@" in address:
        address = address.split("@", 1)[1]
    return address.split(":", 1)[0] if ":" in address else address

def build_requests_proxies(scheme: str, address: str):
    u = f"{scheme}://{address}"
    return {"http": u, "https": u}

def check_http_latency(scheme, address, stop_event: threading.Event):
    if stop_event.is_set(): return None
    schemes = [scheme] if scheme else COMMON_SCHEMES
    for sch in schemes:
        if stop_event.is_set(): return None
        proxies = build_requests_proxies(sch, address)
        t0 = time.time()
        try:
            r = requests.get(HTTP_TEST_URL, proxies=proxies, timeout=HTTP_TIMEOUT)
            if r.status_code == 200:
                return sch, round((time.time() - t0) * 1000)
        except RequestException:
            continue
    return None

def ping_host_once(host: str, stop_event: threading.Event):
    if stop_event.is_set(): return None
    try:
        if is_windows():
            p = subprocess.run(["ping", "-n", "1", "-w", "1000", host],
                               capture_output=True, text=True)
            out = p.stdout
            m = re.search(r"Average\s*=\s*(\d+)\s*ms", out)
            if not m: m = re.search(r"time[=<]\s*(\d+)\s*ms", out)
            return float(m.group(1)) if m else None
        else:
            p = subprocess.run(["ping", "-c", "1", "-W", "1", host],
                               capture_output=True, text=True)
            out = p.stdout
            m = re.search(r"time[=<]\s*([\d\.]+)\s*ms", out)
            return float(m.group(1)) if m else None
    except Exception:
        return None

def geo_lookup_ip(ip: str, stop_event: threading.Event):
    if stop_event.is_set(): return None
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,query"
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                return {
                    "country": data.get("country") or "",
                    "region": data.get("regionName") or "",
                    "city": data.get("city") or "",
                    "isp": data.get("isp") or data.get("org") or "",
                }
    except Exception:
        pass
    return None

# =========================
# ÁP DỤNG PROXY HỆ THỐNG (Windows)
# =========================
try:
    import winreg  # type: ignore
except Exception:
    winreg = None

INTERNET_OPTION_REFRESH = 37
INTERNET_OPTION_SETTINGS_CHANGED = 39

def _notify_internet_settings_change():
    if not is_windows(): return
    try:
        wininet = ctypes.WinDLL('Wininet', use_last_error=True)
        wininet.InternetSetOptionW(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
        wininet.InternetSetOptionW(0, INTERNET_OPTION_REFRESH, 0, 0)
    except Exception:
        pass

def _build_wininet_proxy_server(proxy_str: str):
    if "://" in proxy_str:
        scheme, addr = proxy_str.split("://", 1)
        scheme = scheme.lower()
    else:
        scheme, addr = "http", proxy_str
    if scheme.startswith("socks"):
        return f"socks={addr}"
    return f"http={addr};https={addr}"

def apply_system_proxy(proxy_full: str, winhttp=False, bypass="<local>"):
    if not is_windows():
        messagebox.showerror("Unsupported", "Áp dụng proxy hệ thống chỉ hỗ trợ Windows")
        return False
    if not winreg:
        messagebox.showerror("Thiếu winreg", "Môi trường không có winreg.")
        return False
    ps = _build_wininet_proxy_server(proxy_full)
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(k, "ProxyServer", 0, winreg.REG_SZ, ps)
        winreg.SetValueEx(k, "ProxyOverride", 0, winreg.REG_SZ, bypass or "<local>")
    _notify_internet_settings_change()
    if winhttp:
        try:
            subprocess.run(["netsh", "winhttp", "set", "proxy", f"proxy-server={ps}"],
                           check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        except Exception:
            pass
    return True

def stop_system_proxy(winhttp=False):
    if not is_windows(): return
    if not winreg: return
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 0)
    _notify_internet_settings_change()
    if winhttp:
        try:
            subprocess.run(["netsh", "winhttp", "reset", "proxy"],
                           check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        except Exception:
            pass

# =========================
# ỨNG DỤNG
# =========================
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ScanProxy Studio — v3")
        self.geometry("1180x760")
        self.configure(bg=BG_DARK)

        # Style hiện đại
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure(".", font=("Segoe UI", 10))
        # Notebook & Tab
        style.configure("TNotebook", background=BG_DARK, borderwidth=0)
        style.configure("TNotebook.Tab", background=BG_PANEL, foreground=FG_TEXT, padding=(14, 8))
        style.map("TNotebook.Tab",
                  background=[("selected", "#172036")],
                  foreground=[("selected", "#ffffff")])
        # Treeview
        style.configure("Treeview",
                        background=BG_TABLE, fieldbackground=BG_TABLE,
                        foreground=FG_TEXT, rowheight=ROW_HEIGHT,
                        bordercolor="#1f2937", borderwidth=0)
        style.map("Treeview",
                  background=[("selected", "#1d4ed8")],
                  foreground=[("selected", "#ffffff")])
        # Progressbar
        style.configure("Modern.Horizontal.TProgressbar",
                        troughcolor="#1f2937", background=ACCENT,
                        bordercolor="#1f2937", lightcolor=ACCENT, darkcolor=ACCENT)
        # Button
        style.configure("Accent.TButton", background=ACCENT, foreground="#ffffff")
        style.map("Accent.TButton", background=[("active", "#4338ca")])

        self.shared_crawler_list = []

        nb = ttk.Notebook(self); nb.pack(fill="both", expand=True, padx=8, pady=8)
        self.crawler_tab = CrawlerTab(nb, self)
        self.check_tab   = CheckListTab(nb, self)
        self.sources_tab = SourcesTab(nb, self)
        nb.add(self.crawler_tab, text="🕷️ Crawler (run main.py)")
        nb.add(self.sources_tab, text="📚 Nguồn (Pull lists)")
        nb.add(self.check_tab,   text="🧪 Check List (Ping + Geo)")

        # Ctrl+S để lưu trong tab Check
        self.bind_all("<Control-s>", lambda e: self.check_tab.save_results())

# =========================
# TAB: CRAWLER
# =========================
class CrawlerTab(ttk.Frame):
    def __init__(self, parent, app: App):
        super().__init__(parent, padding=(12,12,12,12))
        self.app = app
        self.proc = None
        self.stop_event = threading.Event()
        self.proxies = []
        self._seen = set()
        self.paused = False

        header = ttk.Frame(self); header.pack(fill="x", pady=(0,8))
        ttk.Label(header, text="Crawler main.py", foreground=FG_TEXT).pack(side="left")
        self.stats_var = tk.StringVar(value="Đã bắt: 0")
        ttk.Label(header, textvariable=self.stats_var, foreground=FG_MUTED).pack(side="right")

        ctrl = ttk.Frame(self); ctrl.pack(fill="x", pady=(0,4))
        ttk.Button(ctrl, text="▶ Bắt đầu crawl", command=self.start, style="Accent.TButton").pack(side="left")
        ttk.Button(ctrl, text="■ Dừng NGAY", command=self.stop).pack(side="left", padx=6)
        self.btn_pause = ttk.Button(ctrl, text="⏸ Tạm dừng", command=self.pause)
        self.btn_resume = ttk.Button(ctrl, text="▶ Tiếp tục", command=self.resume)
        self.btn_pause.pack(side="left", padx=6)
        self.btn_resume.pack(side="left", padx=4)
        ttk.Button(ctrl, text="⮕ Gửi sang tab Check", command=self.push_to_check).pack(side="left", padx=10)

        if is_windows():
            # Không có suspend/resume process gốc trên Windows
            self.btn_pause.configure(state="disabled")
            self.btn_resume.configure(state="disabled")

        pbf = ttk.Frame(self); pbf.pack(fill="x", pady=(4,8))
        self.pb = ttk.Progressbar(pbf, mode="indeterminate", style="Modern.Horizontal.TProgressbar")
        self.pb.pack(fill="x", expand=True)

        self.tree = ttk.Treeview(self, columns=("#","proxy"), show="headings", height=12)
        self.tree.heading("#", text="#"); self.tree.heading("proxy", text="Proxy (ip:port)")
        self.tree.column("#", width=60, anchor="center"); self.tree.column("proxy", width=840, anchor="w")
        self.tree.pack(fill="both", expand=True, pady=6)

        self.log = tk.Text(self, height=8, wrap="word", background=BG_TABLE, foreground=FG_TEXT, insertbackground=FG_TEXT)
        self.log.pack(fill="both", expand=False)

    def log_line(self, s:str):
        self.log.insert("end", s.rstrip()+"\n"); self.log.see("end")

    def _add_proxy(self, p: str):
        p = p.strip()
        if not p or p in self._seen: return
        self._seen.add(p)
        self.proxies.append(p)
        self.tree.insert("", "end", values=(len(self.proxies), p))
        self.stats_var.set(f"Đã bắt: {len(self.proxies)}")

    def start(self):
        if not MAIN_FILE.exists():
            messagebox.showerror("Lỗi", f"Không tìm thấy {MAIN_FILE}"); return
        self.stop_event.clear()
        for it in self.tree.get_children(): self.tree.delete(it)
        self.proxies.clear(); self._seen.clear()
        py = sys.executable or "python"
        self.proc = create_popen([py, "-u", str(MAIN_FILE)], cwd=BASE_DIR)
        self.log_line(f"• Running: {py} -u {MAIN_FILE.name}")
        self.pb.start(12)
        self.paused = False

        def reader():
            live_regex = re.compile(r"Live\s*[:\-]\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3}:\d+)")
            for line in self.proc.stdout:
                if self.stop_event.is_set(): break
                s = line.rstrip(); self.log_line(s)
                m = live_regex.search(s)
                if m: self._add_proxy(m.group(1))
            self.proc = None; self.stop_event.set()
            self.pb.stop()

        threading.Thread(target=reader, daemon=True).start()

    def pause(self):
        if not self.proc: return
        if is_windows():
            messagebox.showinfo("Tạm dừng", "Tạm dừng crawler chỉ khả dụng trên Linux/macOS. Trên Windows hãy dùng 'Dừng NGAY' rồi 'Bắt đầu' lại.")
            return
        try:
            os.killpg(os.getpgid(self.proc.pid), signal.SIGSTOP)
            self.paused = True
            self.pb.stop()
            self.log_line("• ĐÃ TẠM DỪNG crawler (SIGSTOP).")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể tạm dừng: {e}")

    def resume(self):
        if not self.proc: return
        if is_windows():
            return
        try:
            os.killpg(os.getpgid(self.proc.pid), signal.SIGCONT)
            self.paused = False
            self.pb.start(12)
            self.log_line("• ĐÃ TIẾP TỤC crawler (SIGCONT).")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể tiếp tục: {e}")

    def stop(self):
        self.stop_event.set()
        if self.proc and self.proc.poll() is None:
            kill_process_tree(self.proc)
        self.proc = None
        self.pb.stop()
        self.log_line("• ĐÃ DỪNG crawler.")

    def push_to_check(self):
        self.app.shared_crawler_list = list(self.proxies)
        self.app.check_tab.load_from_memory(self.app.shared_crawler_list)
        messagebox.showinfo("Đã gửi", f"Đã gửi {len(self.proxies)} proxy sang tab Check.")

# =========================
# TAB: SOURCES (PULL LISTS)
# =========================
DEFAULT_SOURCES = [
    # HTTP
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/http.txt",
    # HTTPS (thường trùng http list, vẫn hữu ích)
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/https.txt",
    # SOCKS4/5
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
]

class SourcesTab(ttk.Frame):
    def __init__(self, parent, app: App):
        super().__init__(parent, padding=(12,12,12,12))
        self.app = app
        self.stop_event = threading.Event()
        self._seen = set()
        self.proxies = []

        top = ttk.Frame(self); top.pack(fill="x")
        ttk.Label(top, text="Danh sách nguồn (mỗi dòng 1 URL hoặc đường dẫn file .txt):", foreground=FG_TEXT).pack(anchor="w")

        self.src_text = tk.Text(self, height=6, background=BG_TABLE, foreground=FG_TEXT, insertbackground=FG_TEXT)
        self.src_text.pack(fill="x", expand=False, pady=(6,8))

        btns = ttk.Frame(self); btns.pack(fill="x", pady=(0,4))
        ttk.Button(btns, text="➕ Thêm nguồn mặc định", command=self.add_defaults).pack(side="left")
        ttk.Button(btns, text="⬇ Tải về", command=self.fetch_all, style="Accent.TButton").pack(side="left", padx=6)
        ttk.Button(btns, text="■ Dừng tải", command=lambda: self.stop_event.set()).pack(side="left", padx=6)
        ttk.Button(btns, text="⮕ Gửi sang tab Check", command=self.push_to_check).pack(side="left", padx=10)

        pbf = ttk.Frame(self); pbf.pack(fill="x", pady=(4,8))
        self.pb = ttk.Progressbar(pbf, mode="determinate", style="Modern.Horizontal.TProgressbar")
        self.pb.pack(side="left", fill="x", expand=True)
        self.pb_label = tk.StringVar(value="0%")
        ttk.Label(pbf, textvariable=self.pb_label, width=6, anchor="e", foreground=FG_MUTED).pack(side="left", padx=8)

        self.tree = ttk.Treeview(self, columns=("#","proxy","source"), show="headings", height=14)
        for cid, text, w, anchor in [
            ("#", "#", 60, "center"),
            ("proxy", "Proxy (ip:port hoặc scheme://ip:port)", 520, "w"),
            ("source", "Nguồn", 520, "w"),
        ]:
            self.tree.heading(cid, text=text)
            self.tree.column(cid, width=w, anchor=anchor)
        self.tree.pack(fill="both", expand=True, pady=6)

    def add_defaults(self):
        cur = self.src_text.get("1.0","end").strip()
        lines = set([l.strip() for l in cur.splitlines() if l.strip()])
        for u in DEFAULT_SOURCES:
            lines.add(u)
        self.src_text.delete("1.0","end")
        self.src_text.insert("1.0", "\n".join(sorted(lines)))

    def _add_proxy(self, p: str, src: str):
        p = p.strip()
        if not p or p in self._seen: return
        self._seen.add(p)
        self.proxies.append(p)
        self.tree.insert("", "end", values=(len(self.proxies), p, src))

    def _iter_sources(self):
        raw = self.src_text.get("1.0","end")
        for line in raw.splitlines():
            u = line.strip()
            if not u: continue
            yield u

    def fetch_all(self):
        srcs = list(self._iter_sources())
        if not srcs:
            messagebox.showinfo("Nguồn", "Hãy nhập ít nhất 1 URL hoặc đường dẫn file .txt"); return
        # reset
        for it in self.tree.get_children(): self.tree.delete(it)
        self.proxies.clear(); self._seen.clear()
        self.stop_event.clear()
        self.pb.configure(value=0, maximum=len(srcs))
        self.pb_label.set("0%")

        def runner():
            done = 0
            for src in srcs:
                if self.stop_event.is_set(): break
                try:
                    if src.startswith("http://") or src.startswith("https://"):
                        r = requests.get(src, timeout=15)
                        if r.status_code == 200:
                            text = r.text
                            for line in text.splitlines():
                                pr = parse_proxy_line(line)
                                if pr:
                                    sch, addr = pr
                                    self._add_proxy(addr if sch is None else f"{sch}://{addr}", src)
                    else:
                        # đọc file cục bộ
                        p = Path(src)
                        if p.exists():
                            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                                for line in f:
                                    pr = parse_proxy_line(line)
                                    if pr:
                                        sch, addr = pr
                                        self._add_proxy(addr if sch is None else f"{sch}://{addr}", src)
                except Exception as e:
                    # ghi lỗi nhẹ, bỏ qua nguồn lỗi
                    pass
                finally:
                    done += 1
                    self.pb.configure(value=done)
                    pct = int(done * 100 / max(1, len(srcs)))
                    self.pb_label.set(f"{pct}%")
            messagebox.showinfo("Nguồn", f"Hoàn tất tải từ {done}/{len(srcs)} nguồn. Thu được {len(self.proxies)} proxy.")

        threading.Thread(target=runner, daemon=True).start()

    def push_to_check(self):
        self.app.shared_crawler_list = list(self.proxies)
        self.app.check_tab.load_from_memory(self.app.shared_crawler_list)
        messagebox.showinfo("Đã gửi", f"Đã gửi {len(self.proxies)} proxy sang tab Check.")

# =========================
# TAB: CHECK LIST
# =========================
class CheckListTab(ttk.Frame):
    def __init__(self, parent, app: App):
        super().__init__(parent, padding=(12,12,12,12))
        self.app = app
        self.stop_event = threading.Event()
        self.pause_event = threading.Event(); self.pause_event.set()  # set = đang chạy
        self.exec_thread = None

        self.entries = []
        self.results = []
        self.filtered = []

        self.filters = {}

        hdr = ttk.Frame(self); hdr.pack(fill="x")
        ttk.Label(hdr, text="Danh sách proxy (TXT):", foreground=FG_TEXT).pack(side="left")
        self.file_var = tk.StringVar(value="")
        ttk.Entry(hdr, textvariable=self.file_var).pack(side="left", fill="x", expand=True, padx=6)
        ttk.Button(hdr, text="Chọn…", command=self.choose_file).pack(side="left", padx=(0,6))
        ttk.Button(hdr, text="Nạp từ tab Crawler/Nguồn", command=self.load_from_crawler).pack(side="left")

        actions = ttk.Frame(self); actions.pack(fill="x", pady=(8,0))
        ttk.Button(actions, text="▶ Bắt đầu check", command=self.start_check, style="Accent.TButton").pack(side="left")
        self.btn_pause  = ttk.Button(actions, text="⏸ Tạm dừng", command=self.pause_check, state="disabled")
        self.btn_resume = ttk.Button(actions, text="▶ Tiếp tục", command=self.resume_check, state="disabled")
        self.btn_pause.pack(side="left", padx=6)
        self.btn_resume.pack(side="left", padx=4)
        ttk.Button(actions, text="■ Dừng NGAY", command=self.stop_check).pack(side="left", padx=6)
        ttk.Button(actions, text="🧹 Xóa FAIL", command=self.remove_fail).pack(side="left", padx=6)
        ttk.Button(actions, text="💾 Lưu…", command=self.save_results).pack(side="right")
        ttk.Button(actions, text="⨯ Xoá toàn bộ filter", command=self.clear_all_filters).pack(side="right", padx=10)

        pbf = ttk.Frame(self); pbf.pack(fill="x", pady=(8,6))
        self.pb = ttk.Progressbar(pbf, mode="determinate", style="Modern.Horizontal.TProgressbar")
        self.pb.pack(side="left", fill="x", expand=True)
        self.pb_label = tk.StringVar(value="0%")
        ttk.Label(pbf, textvariable=self.pb_label, width=6, anchor="e", foreground=FG_MUTED).pack(side="left", padx=8)

        tablef = ttk.Frame(self); tablef.pack(fill="both", expand=True, pady=(6,6))
        self.cols = ("#","proxy","ping_ms","http_ms","country","region","city","isp","status")
        self.tree = ttk.Treeview(tablef, columns=self.cols, show="headings", height=18, selectmode="browse")
        widths = {"#":50, "proxy":360, "ping_ms":90, "http_ms":90, "country":120, "region":120, "city":120, "isp":220, "status":110}
        anchors = {"#":"center","proxy":"w","ping_ms":"e","http_ms":"e","country":"w","region":"w","city":"w","isp":"w","status":"w"}
        for c in self.cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=widths[c], anchor=anchors[c])
        v = ttk.Scrollbar(tablef, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=v.set)
        self.tree.grid(row=0,column=0,sticky="nsew"); v.grid(row=0,column=1,sticky="ns")
        tablef.rowconfigure(0, weight=1); tablef.columnconfigure(0, weight=1)

        self.tree.bind("<Button-1>", self._on_left_click_header, add="+")
        self.tree.bind("<Button-3>", self._on_right_click_header, add="+")
        self.tree.bind("<<TreeviewSelect>>", self._on_row_select)

        prox = ttk.Frame(self); prox.pack(fill="x")
        self.apply_winhttp = tk.BooleanVar(value=False)
        self.btn_apply = ttk.Button(prox, text="▶ Áp dụng proxy đã chọn", command=self.apply_selected_proxy, state="disabled")
        self.btn_apply.pack(side="left")
        ttk.Button(prox, text="■ Dừng áp dụng proxy", command=self.stop_applying_proxy).pack(side="left", padx=6)
        ttk.Checkbutton(prox, text="Áp dụng cả WinHTTP (Admin)", variable=self.apply_winhttp).pack(side="right")

        self.sort_col = None
        self.sort_dir = 1

        self.status = tk.StringVar(value="Sẵn sàng.")
        ttk.Label(self, textvariable=self.status, anchor="w", foreground=FG_MUTED).pack(fill="x")

    def choose_file(self):
        p = filedialog.askopenfilename(title="Chọn file proxy (.txt)",
                                       filetypes=[("Text","*.txt"),("All","*.*")])
        if p: self.file_var.set(p)

    def load_from_crawler(self):
        self.load_from_memory(self.app.shared_crawler_list)

    def load_from_memory(self, lst):
        if not lst:
            messagebox.showinfo("Thông báo", "Tab Crawler/Nguồn chưa có danh sách."); return
        self.entries = []
        for raw in lst:
            p = parse_proxy_line(raw)
            if p: self.entries.append((p[0], p[1], raw))
        self._render_pending(lst)

    def _render_pending(self, lst):
        for it in self.tree.get_children(): self.tree.delete(it)
        self.results.clear(); self.filtered.clear()
        for i, raw in enumerate(lst, 1):
            self.tree.insert("", "end", values=(i, raw, "", "", "", "", "", "", "PENDING"))
        self.status.set(f"Đã nạp {len(lst)} proxy. Bấm 'Bắt đầu check'.")
        self.pb.configure(value=0, maximum=max(1,len(lst)))
        self.pb_label.set("0%")

    def start_check(self):
        infile = self.file_var.get().strip()
        if not self.entries and infile:
            if not os.path.isfile(infile):
                messagebox.showerror("Lỗi", f"Không tìm thấy file: {infile}"); return
            with open(infile, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    p = parse_proxy_line(line)
                    if p: self.entries.append((p[0], p[1], line.strip()))
        if not self.entries:
            messagebox.showinfo("Thông báo", "Chưa có danh sách proxy để check."); return

        self._render_pending([x[2] for x in self.entries])
        self.stop_event.clear()
        self.pause_event.set()
        self.status.set(f"Đang kiểm tra {len(self.entries)} proxy…")
        self.btn_pause.configure(state="normal")
        self.btn_resume.configure(state="disabled")
        self.exec_thread = threading.Thread(target=self._run_checks, daemon=True)
        self.exec_thread.start()

    def _run_checks(self):
        total = len(self.entries)

        def work(item):
            # Tạm dừng: chờ tới khi resume
            while not self.pause_event.is_set():
                if self.stop_event.is_set(): return None
                time.sleep(0.05)

            scheme, address, raw = item
            if self.stop_event.is_set(): return None
            host = extract_ip_host(address)

            # Cho phép dừng sớm giữa chừng
            if self.stop_event.is_set(): return None
            ping = ping_host_once(host, self.stop_event)

            if self.stop_event.is_set(): return None
            http = check_http_latency(scheme, address, self.stop_event)

            if self.stop_event.is_set(): return None
            geo  = geo_lookup_ip(host, self.stop_event)

            sch = http[0] if http else (scheme or "")
            http_ms = http[1] if http else None
            status = "OK" if http_ms is not None else "FAIL"
            return {
                "proxy": (f"{sch}://{address}" if sch else raw),
                "ping_ms": ping,
                "http_ms": http_ms,
                "country": (geo or {}).get("country",""),
                "region":  (geo or {}).get("region",""),
                "city":    (geo or {}).get("city",""),
                "isp":     (geo or {}).get("isp",""),
                "status":  status
            }

        try:
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
                futures = [ex.submit(work, it) for it in self.entries]
                for fut in as_completed(futures):
                    if self.stop_event.is_set(): break
                    row = fut.result()
                    if row is None: continue
                    self.results.append(row)
                    done = len(self.results)
                    self.status.set(f"Đã xử lý {done}/{total} proxy…")
                    self.pb.configure(value=done, maximum=max(1,total))
                    pct = int(done * 100 / max(1,total))
                    self.pb_label.set(f"{pct}%")
        finally:
            self.apply_filters_and_render()
            self.status.set(
                f"Hoàn tất. Có {len(self.results)} kết quả."
                if not self.stop_event.is_set() else
                f"Đã dừng. Có {len(self.results)} kết quả."
            )
            self.btn_pause.configure(state="disabled")
            self.btn_resume.configure(state="disabled")

    def pause_check(self):
        self.pause_event.clear()
        self.status.set("Đang TẠM DỪNG… Các request đang chạy sẽ kết thúc rồi dừng.")
        self.btn_pause.configure(state="disabled")
        self.btn_resume.configure(state="normal")

    def resume_check(self):
        self.pause_event.set()
        self.status.set("Tiếp tục kiểm tra…")
        self.btn_pause.configure(state="normal")
        self.btn_resume.configure(state="disabled")

    def stop_check(self):
        self.stop_event.set()
        self.status.set("Đang dừng NGAY…")
        self.btn_pause.configure(state="disabled")
        self.btn_resume.configure(state="disabled")

    def _row_pass(self, r):
        f = self.filters
        if f.get('ping_ms_max') is not None:
            if r['ping_ms'] is None or r['ping_ms'] > f['ping_ms_max']:
                return False
        if f.get('http_ms_max') is not None:
            if r['http_ms'] is None or r['http_ms'] > f['http_ms_max']:
                return False
        cin = f.get('country_in')
        if cin:
            if (r.get('country') or '') not in cin:
                return False
        if f.get('status_ok_only'):
            if r.get('status') != 'OK':
                return False
        return True

    def apply_filters_and_render(self):
        rows = [r for r in self.results if self._row_pass(r)]
        if self.sort_col:
            def key(r):
                if self.sort_col in ('ping_ms','http_ms'):
                    v = r[self.sort_col]
                    return float('inf') if v is None else v
                return (r.get(self.sort_col) or '').lower() if isinstance(r.get(self.sort_col), str) else r.get(self.sort_col)
            rows.sort(key=key, reverse=(self.sort_dir < 0))

        self.filtered = rows
        for it in self.tree.get_children(): self.tree.delete(it)
        for i, r in enumerate(self.filtered, 1):
            self.tree.insert("", "end", values=(
                i, r["proxy"],
                (r["ping_ms"] if r["ping_ms"] is not None else ""),
                (r["http_ms"] if r["http_ms"] is not None else ""),
                r["country"], r["region"], r["city"], r["isp"], r["status"]
            ))
        self.status.set(f"Đang hiển thị {len(self.filtered)}/{len(self.results)} (đã lọc).")
        self._refresh_headers_arrow()
        self._update_apply_button_state()

    def clear_all_filters(self):
        self.filters.clear()
        self.apply_filters_and_render()

    def _on_left_click_header(self, event):
        region = self.tree.identify("region", event.x, event.y)
        if region != "heading": return
        colid = self.tree.identify_column(event.x)
        idx = int(colid.replace("#","")) - 1
        col = self.cols[idx]
        if col == "#": return
        if getattr(self, "sort_col", None) == col:
            self.sort_dir *= -1
        else:
            self.sort_col = col; self.sort_dir = 1
        self.apply_filters_and_render()

    def _on_right_click_header(self, event):
        region = self.tree.identify("region", event.x, event.y)
        if region != "heading": return
        idx = int(self.tree.identify_column(event.x).replace("#","")) - 1
        col = self.cols[idx]
        if col == "ping_ms":
            val = simpledialog.askinteger("Filter Ping", "Giới hạn Ping ≤ (ms):", minvalue=1, maxvalue=10000, initialvalue=self.filters.get('ping_ms_max', 300))
            if val is not None:
                self.filters['ping_ms_max'] = int(val)
        elif col == "http_ms":
            val = simpledialog.askinteger("Filter HTTP", "Giới hạn HTTP ≤ (ms):", minvalue=1, maxvalue=60000, initialvalue=self.filters.get('http_ms_max', 3000))
            if val is not None:
                self.filters['http_ms_max'] = int(val)
        elif col == "country":
            countries = sorted({ (r["country"] or "") for r in self.results if r.get("country") })
            if not countries:
                messagebox.showinfo("Country", "Chưa có dữ liệu country."); return
            self._open_country_dialog(countries)
        elif col == "status":
            ok = messagebox.askyesno("Filter Status", "Chỉ giữ các proxy STATUS = OK?")
            self.filters['status_ok_only'] = ok
        else:
            messagebox.showinfo("Filter", f"Không có filter cho cột '{col}'.\nNhấn phải ở các cột: ping_ms, http_ms, country, status.")
        self.apply_filters_and_render()

    def _open_country_dialog(self, countries):
        top = tk.Toplevel(self); top.title("Chọn Country"); top.grab_set()
        tk.Label(top, text="Chọn 1 hoặc nhiều country (Ctrl/Shift):").pack(anchor="w", padx=8, pady=6)
        lb = tk.Listbox(top, selectmode="extended", height=min(12, max(4, len(countries))), exportselection=False)
        for c in countries: lb.insert("end", c)
        lb.pack(fill="both", expand=True, padx=8)
        all_var = tk.BooleanVar(value=False)
        tk.Checkbutton(top, text="Chọn tất cả", variable=all_var).pack(anchor="w", padx=8, pady=4)
        def on_ok():
            if all_var.get():
                self.filters['country_in'] = set(countries)
            else:
                sel = { lb.get(i) for i in lb.curselection() }
                self.filters['country_in'] = sel
            top.destroy()
        tk.Button(top, text="OK", command=on_ok).pack(pady=8)
        top.wait_window()

    def _refresh_headers_arrow(self):
        for c in self.cols:
            label = c
            if getattr(self, "sort_col", None) == c:
                label = f"{c} {'▲' if self.sort_dir>0 else '▼'}"
            self.tree.heading(c, text=label)

    def _on_row_select(self, evt):
        self._update_apply_button_state()

    def _get_selected_proxy(self):
        sel = self.tree.selection()
        if not sel: return None
        values = self.tree.item(sel[0], "values")
        return values[1] if len(values) >= 2 else None

    def _update_apply_button_state(self):
        self.btn_apply.configure(state=("normal" if self._get_selected_proxy() else "disabled"))

    def apply_selected_proxy(self):
        p = self._get_selected_proxy()
        if not p:
            messagebox.showinfo("Thông báo", "Hãy chọn một dòng trong bảng."); return
        ok = apply_system_proxy(p, winhttp=self.apply_winhttp.get(), bypass="<local>")
        if ok:
            messagebox.showinfo("OK", f"Đã áp dụng proxy:\n{p}")
        else:
            messagebox.showerror("Lỗi", "Không áp dụng được proxy.")

    def stop_applying_proxy(self):
        stop_system_proxy(winhttp=self.apply_winhttp.get())
        messagebox.showinfo("OK", "Đã dừng sử dụng proxy hệ thống.")

    def remove_fail(self):
        before = len(self.results)
        self.results = [r for r in self.results if r.get("status") != "FAIL"]
        self.apply_filters_and_render()
        messagebox.showinfo("Xóa FAIL", f"Đã xoá {before - len(self.results)} hàng FAIL.")

    def save_results(self):
        if not self.filtered and not self.results:
            messagebox.showinfo("Lưu", "Chưa có dữ liệu để lưu."); return
        data = self.filtered if self.filtered else self.results

        countries = sorted({ (r["country"] or "Unknown") for r in data }) or ["Unknown"]

        top = tk.Toplevel(self); top.title("Lưu kết quả"); top.grab_set()
        tk.Label(top, text="Chọn country để lưu (mặc định tất cả):").grid(row=0, column=0, sticky="w", padx=8, pady=(8,4))
        lb = tk.Listbox(top, selectmode="extended", height=min(10, max(4, len(countries))), exportselection=False)
        for c in countries: lb.insert("end", c)
        lb.grid(row=1, column=0, sticky="nsew", padx=8)
        all_var = tk.BooleanVar(value=True)
        tk.Checkbutton(top, text="Lưu TẤT CẢ country", variable=all_var).grid(row=2, column=0, sticky="w", padx=8, pady=(4,8))

        fmt_var = tk.StringVar(value="csv")
        tk.Label(top, text="Định dạng:").grid(row=0, column=1, sticky="w", padx=(12,4), pady=(8,4))
        ttk.Radiobutton(top, text="CSV", variable=fmt_var, value="csv").grid(row=1, column=1, sticky="w", padx=(12,4))
        ttk.Radiobutton(top, text="TXT", variable=fmt_var, value="txt").grid(row=2, column=1, sticky="w", padx=(12,4))

        folder_var = tk.StringVar(value=str(BASE_DIR))
        def pick_folder():
            d = filedialog.askdirectory(title="Chọn thư mục lưu", initialdir=folder_var.get())
            if d: folder_var.set(d)
        ttk.Button(top, text="Chọn thư mục…", command=pick_folder).grid(row=3, column=1, sticky="w", padx=(12,4), pady=4)
        tk.Entry(top, textvariable=folder_var, width=40).grid(row=3, column=0, sticky="we", padx=8)

        btnf = ttk.Frame(top); btnf.grid(row=4, column=0, columnspan=2, pady=8)
        done = {"ok": False, "sel": set()}
        def on_ok():
            if all_var.get():
                done["sel"] = set(countries)
            else:
                done["sel"] = { lb.get(i) for i in lb.curselection() } or set(countries)
            done["ok"] = True
            top.destroy()
        ttk.Button(btnf, text="Lưu", command=on_ok).pack(side="left", padx=6)
        ttk.Button(btnf, text="Huỷ", command=top.destroy).pack(side="left", padx=6)

        top.columnconfigure(0, weight=1)
        top.wait_window()
        if not done["ok"]: return

        groups = {}
        for r in data:
            c = r.get("country") or "Unknown"
            if c not in done["sel"]: continue
            groups.setdefault(c, []).append(r)

        if not groups:
            messagebox.showinfo("Lưu", "Không có dòng phù hợp để lưu."); return

        folder = Path(folder_var.get())
        folder.mkdir(parents=True, exist_ok=True)
        ext = fmt_var.get()

        def next_name(base_name: str):
            p = folder / base_name
            if not p.exists(): return p
            idx = 2
            while True:
                p2 = folder / f"{idx}_{base_name}"
                if not p2.exists(): return p2
                idx += 1

        saved_files = []
        for country, rows in groups.items():
            safe_country = re.sub(r'[^A-Za-z0-9_-]+', '_', country.strip() or "Unknown")
            base = f"proxy_{safe_country}.{ext}"
            out_path = next_name(base)
            try:
                if ext == "txt":
                    with open(out_path, "w", encoding="utf-8") as f:
                        for r in rows: f.write(r["proxy"] + "\n")
                else:
                    with open(out_path, "w", newline="", encoding="utf-8") as f:
                        w=csv.writer(f)
                        w.writerow(["proxy","ping_ms","http_ms","country","region","city","isp","status"])
                        for r in rows:
                            w.writerow([r["proxy"], r["ping_ms"] or "", r["http_ms"] or "",
                                        r["country"], r["region"], r["city"], r["isp"], r["status"]])
                saved_files.append(str(out_path))
            except Exception as e:
                messagebox.showerror("Lỗi", f"Không thể lưu {out_path}:\n{e}")
        messagebox.showinfo("OK", f"Đã lưu {len(saved_files)} file:\n" + "\n".join(saved_files))

# =========================
# MAIN
# =========================
if __name__ == "__main__":
    app = App()
    app.mainloop()
