
import os
import sys
import re
import ctypes
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox

try:
    import winreg  # type: ignore
except Exception:
    winreg = None

INTERNET_OPTION_REFRESH = 37
INTERNET_OPTION_SETTINGS_CHANGED = 39

def _notify_internet_settings_change():
    try:
        wininet = ctypes.WinDLL('Wininet', use_last_error=True)
        wininet.InternetSetOptionW(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
        wininet.InternetSetOptionW(0, INTERNET_OPTION_REFRESH, 0, 0)
    except Exception:
        pass

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

PROXY_RE = re.compile(
    r'^(?:(?P<scheme>http|https|socks4|socks5)://)?'
    r'(?:(?P<user>[^:@/\s]+)(?::(?P<pwd>[^@/\s]*))?@)?'
    r'(?P<host>\[[^\]]+\]|[^:/\s]+)'
    r'(?::(?P<port>\d{2,5}))?'
    r'/?$',
    re.IGNORECASE
)

def parse_proxy(s: str):
    s = (s or "").strip()
    s = re.sub(r'\s+', '', s)
    m = PROXY_RE.match(s)
    if not m:
        return None
    d = m.groupdict()
    scheme = (d.get('scheme') or '').lower() or None
    host = d.get('host')
    port = d.get('port')
    user = d.get('user')
    pwd  = d.get('pwd')
    if host and host.startswith('[') and host.endswith(']'):
        host = host[1:-1]
    if not port:
        if scheme in ('socks5', 'socks4'):
            port = '1080'
        elif scheme == 'https':
            port = '443'
        else:
            port = '8080'
    return {'scheme': scheme, 'host': host, 'port': port, 'user': user, 'pwd': pwd}

def build_proxyserver_string(info: dict):
    hostport = f"{info['host']}:{info['port']}"
    sch = (info.get('scheme') or '').lower()
    if sch in ('socks5', 'socks4'):
        return f"socks={hostport}"
    return f"http={hostport};https={hostport}"

def set_wininet_proxy(proxy_server: str, bypass_list: str = "<local>"):
    if winreg is None:
        raise RuntimeError("winreg is not available. This tool is for Windows.")
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(k, "ProxyServer", 0, winreg.REG_SZ, proxy_server)
        winreg.SetValueEx(k, "ProxyOverride", 0, winreg.REG_SZ, bypass_list)
    _notify_internet_settings_change()

def disable_wininet_proxy():
    if winreg is None:
        raise RuntimeError("winreg is not available. This tool is for Windows.")
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 0)
    _notify_internet_settings_change()

def set_winhttp_proxy(proxy_server: str):
    subprocess.run(["netsh", "winhttp", "set", "proxy", f"proxy-server={proxy_server}"],
                   check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

def reset_winhttp_proxy():
    subprocess.run(["netsh", "winhttp", "reset", "proxy"],
                   check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

def do_test_request(info: dict, output_callback):
    try:
        import requests
    except Exception:
        output_callback("Chưa cài 'requests'. Chạy: pip install requests")
        return
    sch = info.get('scheme') or 'http'
    user = info.get('user')
    pwd  = info.get('pwd')
    auth = ""
    if user:
        auth = f"{user}:{pwd or ''}@"
    proxy_url = f"{sch}://{auth}{info['host']}:{info['port']}"
    proxies = {"http": proxy_url, "https": proxy_url}
    output_callback(f"Đang test qua proxy: {proxy_url}")
    try:
        import json
        r = requests.get("https://httpbin.org/ip", proxies=proxies, timeout=10)
        output_callback(f"Kết quả HTTP {r.status_code}: {r.text.strip()}")
    except Exception as e:
        output_callback(f"Test lỗi: {e}")

class ProxyTool(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Proxy Toggle Tool (Windows) — Fixed Parser")
        self.geometry("640x400")
        self.resizable(False, False)

        frm = ttk.Frame(self, padding=12)
        frm.pack(fill="both", expand=True)

        ttk.Label(frm, text="Dán proxy (vd: 1.2.3.4:8080, http://1.2.3.4:8080, https://1.2.3.4, socks5://1.2.3.4:1080, user:pass@1.2.3.4:8080):").pack(anchor="w")
        self.proxy_var = tk.StringVar(value="http://167.99.171.156:443")
        ttk.Entry(frm, textvariable=self.proxy_var).pack(fill="x", pady=(4, 8))

        sub = ttk.Frame(frm); sub.pack(fill="x")
        ttk.Label(sub, text="Bypass (ProxyOverride):").pack(side="left")
        self.bypass_var = tk.StringVar(value="<local>")
        ttk.Entry(sub, textvariable=self.bypass_var, width=38).pack(side="left", padx=6)
        self.winhttp_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(sub, text="Áp dụng cả WinHTTP (yêu cầu Admin)", variable=self.winhttp_var).pack(side="right")

        btns = ttk.Frame(frm); btns.pack(fill="x", pady=(10, 0))
        ttk.Button(btns, text="Áp dụng Proxy", command=self.apply_proxy).pack(side="left")
        ttk.Button(btns, text="Dừng sử dụng Proxy", command=self.disable_proxy).pack(side="left", padx=8)
        ttk.Button(btns, text="Test qua httpbin", command=self.test_proxy).pack(side="left")

        self.status = tk.StringVar(value="Sẵn sàng.")
        ttk.Label(frm, textvariable=self.status).pack(anchor="w", pady=(10, 6))

        logf = ttk.LabelFrame(frm, text="Log"); logf.pack(fill="both", expand=True)
        self.log = tk.Text(logf, height=10, wrap="word")
        sb = ttk.Scrollbar(logf, orient="vertical", command=self.log.yview)
        self.log.configure(yscrollcommand=sb.set)
        self.log.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        if not winreg:
            messagebox.showerror("Unsupported", "Công cụ này chỉ dành cho Windows (cần winreg).")

    def write_log(self, s):
        self.log.insert("end", s.rstrip() + "\n"); self.log.see("end")

    def apply_proxy(self):
        raw = self.proxy_var.get().strip()
        info = parse_proxy(raw)
        if not info:
            messagebox.showerror("Sai định dạng", "Proxy không hợp lệ. Ví dụ hợp lệ:\n"
                                   "1.2.3.4:8080\nhttp://1.2.3.4:8080\nhttps://1.2.3.4\nsocks5://1.2.3.4:1080\nuser:pass@1.2.3.4:8080")
            return
        ps = build_proxyserver_string(info)
        try:
            set_wininet_proxy(ps, self.bypass_var.get().strip() or "<local>")
            self.status.set(f"Đã áp dụng WinINet: {ps}")
            self.write_log(f"[OK] WinINet ProxyServer = {ps}")
        except Exception as e:
            self.status.set("Lỗi áp dụng WinINet")
            self.write_log(f"[ERR] WinINet: {e}")

        if self.winhttp_var.get():
            if not is_admin():
                self.write_log("[WARN] WinHTTP cần quyền Admin. Thử chạy lại app bằng Run as administrator.")
            else:
                try:
                    set_winhttp_proxy(ps)
                    self.write_log("[OK] WinHTTP đã đặt proxy.")
                except Exception as e:
                    self.write_log(f"[ERR] WinHTTP: {e}")

    def disable_proxy(self):
        try:
            disable_wininet_proxy()
            self.status.set("Đã tắt WinINet proxy.")
            self.write_log("[OK] WinINet ProxyEnable = 0")
        except Exception as e:
            self.write_log(f"[ERR] WinINet disable: {e}")
        if self.winhttp_var.get():
            if not is_admin():
                self.write_log("[WARN] WinHTTP reset cần quyền Admin.")
            else:
                try:
                    reset_winhttp_proxy()
                    self.write_log("[OK] WinHTTP proxy reset.")
                except Exception as e:
                    self.write_log(f"[ERR] WinHTTP reset: {e}")

    def test_proxy(self):
        raw = self.proxy_var.get().strip()
        info = parse_proxy(raw)
        if not info:
            messagebox.showerror("Sai định dạng", "Không parse được proxy.")
            return
        do_test_request(info, self.write_log)

if __name__ == "__main__":
    app = ProxyTool()
    app.mainloop()
