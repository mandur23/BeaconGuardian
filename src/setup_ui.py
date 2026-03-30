import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import yaml
import os
import sys
import threading
import requests

from credential_store import encrypt_password, decrypt_password, is_encrypted

# 프로젝트 루트: 번들(frozen) 시 EXE 위치, 일반 실행 시 src/의 부모 폴더
if getattr(sys, 'frozen', False):
    ROOT_DIR = os.path.dirname(os.path.abspath(sys.executable))
else:
    ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CONFIG_PATH = os.path.join(ROOT_DIR, "config.yaml")

DEFAULT_CONFIG = {
    "beacon": {
        "server_url": "http://localhost:8080",
        "username": "admin",
        "password": "",
    },
    "agent": {
        "agent_name": "BeaconGuardian",
        "agent_version": "1.0.0",
        "heartbeat_interval_seconds": 60,
    },
    "monitoring": {
        "usb_check_interval": 5,
        "network_check_interval": 10,
        "process_check_interval": 5,
        "browser_check_interval": 30,
        "biometric_flush_interval": 2,
        "mouse_move_sample_ms": 120,
    },
    "paths": {
        "watch_dirs": [
            "C:\\Windows\\System32",
            f"C:\\Users\\{os.getenv('USERNAME', 'User')}\\Documents",
        ],
        "biometric_log_file": "logs/biometric_input.jsonl",
    },
    "logging": {
        "level": "INFO",
        "file": "agent.log",
        "max_bytes": 10485760,
        "backup_count": 5,
    },
    "collectors": {
        "usb": True,
        "network": True,
        "process": True,
        "filesystem": True,
        "browser_history": True,
        "input_biometric": True,
    },
}


def load_config():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or DEFAULT_CONFIG
    return DEFAULT_CONFIG


def save_config(cfg):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        yaml.dump(cfg, f, allow_unicode=True, default_flow_style=False)


class SetupApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("BeaconGuardian")
        self.resizable(False, False)
        self.config_data = load_config()
        self._setup_colors()
        self._setup_style()
        self._build_ui()
        self._center_window(780, 620)

    # ────────────────────────────── 색상 팔레트 ──────────────────────────

    def _setup_colors(self):
        self.BG = "#0b0e14"
        self.BG2 = "#10141c"
        self.CARD = "#151a25"
        self.CARD_HOVER = "#1a2030"
        self.ACCENT = "#3b82f6"
        self.ACCENT_HOVER = "#2563eb"
        self.ACCENT_GLOW = "#1d4ed8"
        self.ACCENT2 = "#8b5cf6"
        self.TEXT = "#e8ecf4"
        self.TEXT2 = "#c0c8d8"
        self.MUTED = "#5a6580"
        self.SUCCESS = "#10b981"
        self.SUCCESS_BG = "#052e16"
        self.ERROR = "#f43f5e"
        self.ERROR_BG = "#3b0a0a"
        self.WARNING = "#f59e0b"
        self.BORDER = "#1e2538"
        self.BORDER_FOCUS = "#3b82f6"
        self.ENTRY_BG = "#0f1320"
        self.ENTRY_BORDER = "#252d40"
        self.HEADER_BG = "#0d1220"
        self.HEADER_ACCENT = "#1e3a5f"

    # ────────────────────────────── 스타일 ──────────────────────────────

    def _setup_style(self):
        self.configure(bg=self.BG)

        style = ttk.Style(self)
        style.theme_use("clam")

        # Notebook
        style.configure("TNotebook", background=self.BG, borderwidth=0, padding=0)
        style.configure(
            "TNotebook.Tab",
            background=self.CARD,
            foreground=self.MUTED,
            padding=[22, 10],
            font=("Segoe UI Semibold", 9),
            borderwidth=0,
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", self.BG)],
            foreground=[("selected", self.ACCENT)],
        )

        # Frame
        style.configure("TFrame", background=self.BG)
        style.configure("Card.TFrame", background=self.CARD)

        # Label
        style.configure("TLabel", background=self.BG, foreground=self.TEXT, font=("Segoe UI", 10))
        style.configure("Muted.TLabel", background=self.BG, foreground=self.MUTED, font=("Segoe UI", 9))
        style.configure("Card.TLabel", background=self.CARD, foreground=self.TEXT, font=("Segoe UI", 10))

        # Entry
        style.configure(
            "TEntry",
            fieldbackground=self.ENTRY_BG,
            foreground=self.TEXT,
            insertcolor=self.ACCENT,
            borderwidth=1,
            relief="flat",
        )
        style.map("TEntry", bordercolor=[("focus", self.ACCENT)])

        # Combobox
        style.configure(
            "TCombobox",
            fieldbackground=self.ENTRY_BG,
            background=self.ENTRY_BG,
            foreground=self.TEXT,
            arrowcolor=self.MUTED,
            borderwidth=1,
        )

        # Spinbox
        style.configure(
            "TSpinbox",
            fieldbackground=self.ENTRY_BG,
            foreground=self.TEXT,
            arrowcolor=self.MUTED,
            borderwidth=1,
        )

        # Buttons
        style.configure(
            "Accent.TButton",
            background=self.ACCENT,
            foreground="#ffffff",
            font=("Segoe UI Semibold", 10),
            padding=[24, 10],
            borderwidth=0,
            relief="flat",
        )
        style.map("Accent.TButton", background=[("active", self.ACCENT_HOVER)])

        style.configure(
            "Ghost.TButton",
            background=self.CARD,
            foreground=self.TEXT2,
            font=("Segoe UI", 10),
            padding=[14, 8],
            borderwidth=1,
            relief="flat",
        )
        style.map("Ghost.TButton", background=[("active", self.CARD_HOVER)])

        style.configure(
            "Success.TButton",
            background="#065f46",
            foreground=self.SUCCESS,
            font=("Segoe UI", 9),
            padding=[12, 6],
            borderwidth=0,
            relief="flat",
        )
        style.map("Success.TButton", background=[("active", "#047857")])

        style.configure(
            "Danger.TButton",
            background=self.ERROR_BG,
            foreground=self.ERROR,
            font=("Segoe UI", 9),
            padding=[10, 6],
            borderwidth=0,
            relief="flat",
        )
        style.map("Danger.TButton", background=[("active", "#5a1010")])

    # ────────────────────────────── UI 구성 ──────────────────────────────

    def _build_ui(self):
        # ── 헤더 ──
        header = tk.Frame(self, bg=self.HEADER_BG, height=72)
        header.pack(fill="x")
        header.pack_propagate(False)

        # 왼쪽: 로고 + 타이틀
        left = tk.Frame(header, bg=self.HEADER_BG)
        left.pack(side="left", padx=28, pady=0)

        # 쉴드 아이콘 + 타이틀
        title_frame = tk.Frame(left, bg=self.HEADER_BG)
        title_frame.pack(anchor="w", pady=(14, 0))

        tk.Label(
            title_frame, text="\u25c6", bg=self.HEADER_BG, fg=self.ACCENT,
            font=("Segoe UI", 16),
        ).pack(side="left", padx=(0, 10))

        tk.Label(
            title_frame, text="BeaconGuardian", bg=self.HEADER_BG, fg=self.TEXT,
            font=("Segoe UI Semibold", 15),
        ).pack(side="left")

        # 버전 뱃지
        ver_frame = tk.Frame(title_frame, bg=self.HEADER_ACCENT, padx=8, pady=1)
        ver_frame.pack(side="left", padx=(12, 0))
        tk.Label(
            ver_frame, text="v1.0.0", bg=self.HEADER_ACCENT, fg=self.ACCENT,
            font=("Consolas", 8),
        ).pack()

        # 서브타이틀
        tk.Label(
            left, text="Security Monitoring Agent Configuration",
            bg=self.HEADER_BG, fg=self.MUTED, font=("Segoe UI", 9),
        ).pack(anchor="w", pady=(2, 0))

        # 오른쪽: 상태 인디케이터
        right = tk.Frame(header, bg=self.HEADER_BG)
        right.pack(side="right", padx=28)

        self.status_dot = tk.Canvas(right, width=10, height=10, bg=self.HEADER_BG, highlightthickness=0)
        self.status_dot.pack(side="left", padx=(0, 6), pady=0)
        self.status_dot.create_oval(1, 1, 9, 9, fill=self.MUTED, outline="")

        self.lbl_header_status = tk.Label(
            right, text="Not connected", bg=self.HEADER_BG, fg=self.MUTED,
            font=("Segoe UI", 9),
        )
        self.lbl_header_status.pack(side="left")

        # ── 구분선 ──
        tk.Frame(self, bg=self.BORDER, height=1).pack(fill="x")

        # ── 탭 ──
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=0, pady=0)

        self.tab_server = ttk.Frame(nb)
        self.tab_monitor = ttk.Frame(nb)
        self.tab_paths = ttk.Frame(nb)
        self.tab_logging = ttk.Frame(nb)

        nb.add(self.tab_server,  text="   Server   ")
        nb.add(self.tab_monitor, text="   Monitoring   ")
        nb.add(self.tab_paths,   text="   Watch Paths   ")
        nb.add(self.tab_logging, text="   Logging   ")

        self._build_server_tab()
        self._build_monitor_tab()
        self._build_paths_tab()
        self._build_logging_tab()

        # ── 하단 ──
        self._build_footer()

    # ── 탭 1: 서버 연결 ──

    def _build_server_tab(self):
        p = self.tab_server
        container = tk.Frame(p, bg=self.BG)
        container.pack(fill="both", expand=True, padx=32, pady=20)

        self._section_header(container, "Beacon Server", "Connect to your security monitoring server")

        # 카드
        card = self._card(container)

        bc = self.config_data.get("beacon", {})
        self.var_url = self._field(card, "Server URL", bc.get("server_url", "http://localhost:8080"), icon="\u2192")
        self.var_user = self._field(card, "Username", bc.get("username", "admin"), icon="\u2630")
        raw_pass = bc.get("password", "")
        self.var_pass = self._field(card, "Password", decrypt_password(raw_pass), show="\u2022", icon="\u26bf")

        # 연결 테스트
        test_row = tk.Frame(card, bg=self.CARD)
        test_row.pack(fill="x", padx=20, pady=(6, 16))

        ttk.Button(
            test_row, text="Test Connection", style="Success.TButton",
            command=self._test_connection,
        ).pack(side="left")

        self.lbl_conn = tk.Label(
            test_row, text="", bg=self.CARD, fg=self.MUTED, font=("Segoe UI", 9),
        )
        self.lbl_conn.pack(side="left", padx=14)

    # ── 탭 2: 모니터링 ──

    def _build_monitor_tab(self):
        p = self.tab_monitor
        container = tk.Frame(p, bg=self.BG)
        container.pack(fill="both", expand=True, padx=32, pady=20)

        self._section_header(container, "Monitoring Intervals", "Configure check frequency for each monitor (seconds)")

        card = self._card(container)

        mc = self.config_data.get("monitoring", {})
        self.var_usb = self._spin_field(card, "USB Detection", mc.get("usb_check_interval", 5), icon="\u2b24")
        self.var_net = self._spin_field(card, "Network Traffic", mc.get("network_check_interval", 10), icon="\u25ce")
        self.var_proc = self._spin_field(card, "Process Monitor", mc.get("process_check_interval", 5), icon="\u25a3")
        self.var_brow = self._spin_field(card, "Browser History", mc.get("browser_check_interval", 30), icon="\u25c9")

    # ── 탭 3: 감시 경로 ──

    def _build_paths_tab(self):
        p = self.tab_paths
        container = tk.Frame(p, bg=self.BG)
        container.pack(fill="both", expand=True, padx=32, pady=20)

        self._section_header(container, "Watch Directories", "File system paths to monitor for changes")

        card = self._card(container, expand=True)

        # 리스트
        list_frame = tk.Frame(card, bg=self.ENTRY_BG, highlightthickness=1, highlightbackground=self.ENTRY_BORDER)
        list_frame.pack(fill="both", expand=True, padx=20, pady=(16, 8))

        scrollbar = tk.Scrollbar(list_frame, bg=self.BG2, troughcolor=self.ENTRY_BG,
                                 activebackground=self.MUTED, width=8)
        scrollbar.pack(side="right", fill="y")

        self.path_listbox = tk.Listbox(
            list_frame,
            bg=self.ENTRY_BG,
            fg=self.TEXT2,
            selectbackground=self.ACCENT_GLOW,
            selectforeground="#ffffff",
            font=("Consolas", 10),
            borderwidth=0,
            highlightthickness=0,
            activestyle="none",
            yscrollcommand=scrollbar.set,
            relief="flat",
        )
        self.path_listbox.pack(fill="both", expand=True, padx=(8, 0), pady=6)
        scrollbar.config(command=self.path_listbox.yview)

        dirs = self.config_data.get("paths", {}).get("watch_dirs", [])
        for d in dirs:
            self.path_listbox.insert("end", f"  {d}")

        # 버튼 행
        btn_row = tk.Frame(card, bg=self.CARD)
        btn_row.pack(fill="x", padx=20, pady=(4, 16))

        ttk.Button(btn_row, text="+ Add Path", style="Ghost.TButton",
                   command=self._add_path).pack(side="left", padx=(0, 8))
        ttk.Button(btn_row, text="- Remove", style="Danger.TButton",
                   command=self._remove_path).pack(side="left")

        # 경로 수 표시
        self.lbl_path_count = tk.Label(
            btn_row, text=f"{len(dirs)} paths configured", bg=self.CARD, fg=self.MUTED,
            font=("Segoe UI", 9),
        )
        self.lbl_path_count.pack(side="right")

    # ── 탭 4: 로깅 ──

    def _build_logging_tab(self):
        p = self.tab_logging
        container = tk.Frame(p, bg=self.BG)
        container.pack(fill="both", expand=True, padx=32, pady=20)

        self._section_header(container, "Log Configuration", "Agent log file and verbosity settings")

        card = self._card(container)

        lc = self.config_data.get("logging", {})
        self.var_log_level = self._combo_field(
            card, "Log Level", ["DEBUG", "INFO", "WARNING", "ERROR"],
            lc.get("level", "INFO"), icon="\u25b6",
        )
        self.var_log_file = self._field(card, "Log File Path", lc.get("file", "agent.log"), icon="\u25a1")
        self.var_max_bytes = self._spin_field(
            card, "Max File Size (bytes)", lc.get("max_bytes", 10485760),
            from_=1048576, to=104857600, increment=1048576, icon="\u25c7",
        )
        self.var_backup_cnt = self._spin_field(
            card, "Backup Count", lc.get("backup_count", 5),
            from_=1, to=20, icon="\u25cb",
        )

    # ── 하단 푸터 ──

    def _build_footer(self):
        tk.Frame(self, bg=self.BORDER, height=1).pack(fill="x")

        footer = tk.Frame(self, bg=self.CARD, height=64)
        footer.pack(fill="x")
        footer.pack_propagate(False)

        # 좌측 상태 메시지
        self.lbl_status = tk.Label(
            footer, text="", bg=self.CARD, fg=self.MUTED, font=("Segoe UI", 9),
        )
        self.lbl_status.pack(side="left", padx=28, pady=0)

        # 우측 버튼
        ttk.Button(
            footer, text="Save & Start Agent", style="Accent.TButton",
            command=self._save_and_start,
        ).pack(side="right", padx=(8, 20), pady=14)

        ttk.Button(
            footer, text="Save", style="Ghost.TButton",
            command=self._save_only,
        ).pack(side="right", padx=0, pady=14)

    # ────────────────────────────── 위젯 헬퍼 ──────────────────────────────

    def _section_header(self, parent, title, subtitle=""):
        f = tk.Frame(parent, bg=self.BG)
        f.pack(fill="x", pady=(0, 12))

        tk.Label(
            f, text=title, bg=self.BG, fg=self.TEXT,
            font=("Segoe UI Semibold", 13),
        ).pack(anchor="w")

        if subtitle:
            tk.Label(
                f, text=subtitle, bg=self.BG, fg=self.MUTED,
                font=("Segoe UI", 9),
            ).pack(anchor="w", pady=(3, 0))

    def _card(self, parent, expand=False):
        outer = tk.Frame(parent, bg=self.BORDER, padx=1, pady=1)
        outer.pack(fill="both", expand=expand, pady=(0, 0))

        card = tk.Frame(outer, bg=self.CARD)
        card.pack(fill="both", expand=expand)
        return card

    def _field(self, parent, label, value="", show="", icon=""):
        row = tk.Frame(parent, bg=self.CARD)
        row.pack(fill="x", padx=20, pady=(14, 0))

        label_frame = tk.Frame(row, bg=self.CARD)
        label_frame.pack(fill="x")

        if icon:
            tk.Label(
                label_frame, text=icon, bg=self.CARD, fg=self.ACCENT,
                font=("Segoe UI", 8),
            ).pack(side="left", padx=(0, 6))

        tk.Label(
            label_frame, text=label, bg=self.CARD, fg=self.TEXT2,
            font=("Segoe UI", 9),
        ).pack(side="left")

        var = tk.StringVar(value=str(value))

        entry_frame = tk.Frame(row, bg=self.ENTRY_BORDER, padx=1, pady=1)
        entry_frame.pack(fill="x", pady=(6, 0))

        e = tk.Entry(
            entry_frame, textvariable=var, bg=self.ENTRY_BG, fg=self.TEXT,
            font=("Consolas", 10), insertbackground=self.ACCENT,
            relief="flat", borderwidth=6,
        )
        if show:
            e.config(show=show)
        e.pack(fill="x")

        # 포커스 시 보더 색상 변경
        e.bind("<FocusIn>", lambda ev, ef=entry_frame: ef.config(bg=self.ACCENT))
        e.bind("<FocusOut>", lambda ev, ef=entry_frame: ef.config(bg=self.ENTRY_BORDER))

        return var

    def _spin_field(self, parent, label, value=0, from_=1, to=3600, increment=1, icon=""):
        row = tk.Frame(parent, bg=self.CARD)
        row.pack(fill="x", padx=20, pady=(14, 0))

        label_frame = tk.Frame(row, bg=self.CARD)
        label_frame.pack(fill="x")

        if icon:
            tk.Label(
                label_frame, text=icon, bg=self.CARD, fg=self.ACCENT,
                font=("Segoe UI", 8),
            ).pack(side="left", padx=(0, 6))

        tk.Label(
            label_frame, text=label, bg=self.CARD, fg=self.TEXT2,
            font=("Segoe UI", 9),
        ).pack(side="left")

        var = tk.IntVar(value=int(value))

        spin_frame = tk.Frame(row, bg=self.ENTRY_BORDER, padx=1, pady=1)
        spin_frame.pack(anchor="w", pady=(6, 0))

        s = tk.Spinbox(
            spin_frame, textvariable=var, from_=from_, to=to, increment=increment,
            bg=self.ENTRY_BG, fg=self.TEXT, font=("Consolas", 10),
            insertbackground=self.ACCENT, relief="flat", borderwidth=4,
            width=12, buttonbackground=self.CARD, activebackground=self.ACCENT,
        )
        s.pack()

        s.bind("<FocusIn>", lambda ev, sf=spin_frame: sf.config(bg=self.ACCENT))
        s.bind("<FocusOut>", lambda ev, sf=spin_frame: sf.config(bg=self.ENTRY_BORDER))

        return var

    def _combo_field(self, parent, label, options, current, icon=""):
        row = tk.Frame(parent, bg=self.CARD)
        row.pack(fill="x", padx=20, pady=(14, 0))

        label_frame = tk.Frame(row, bg=self.CARD)
        label_frame.pack(fill="x")

        if icon:
            tk.Label(
                label_frame, text=icon, bg=self.CARD, fg=self.ACCENT,
                font=("Segoe UI", 8),
            ).pack(side="left", padx=(0, 6))

        tk.Label(
            label_frame, text=label, bg=self.CARD, fg=self.TEXT2,
            font=("Segoe UI", 9),
        ).pack(side="left")

        var = tk.StringVar(value=current)
        cb = ttk.Combobox(
            row, textvariable=var, values=options, state="readonly", width=18,
            style="TCombobox",
        )
        cb.pack(anchor="w", pady=(6, 0))
        return var

    # ────────────────────────────── 액션 ──────────────────────────────

    def _collect_config(self):
        # 경로 리스트에서 앞쪽 공백 제거
        paths = [p.strip() for p in self.path_listbox.get(0, "end")]

        cfg = {
            "beacon": {
                "server_url": self.var_url.get().strip(),
                "username":   self.var_user.get().strip(),
                "password":   encrypt_password(self.var_pass.get()),
            },
            "monitoring": {
                "usb_check_interval":     self.var_usb.get(),
                "network_check_interval": self.var_net.get(),
                "process_check_interval": self.var_proc.get(),
                "browser_check_interval": self.var_brow.get(),
            },
            "paths": {
                "watch_dirs": paths,
            },
            "logging": {
                "level":        self.var_log_level.get(),
                "file":         self.var_log_file.get().strip(),
                "max_bytes":    self.var_max_bytes.get(),
                "backup_count": self.var_backup_cnt.get(),
            },
        }
        if self.config_data.get("agent"):
            cfg["agent"] = self.config_data["agent"]
        if self.config_data.get("collectors"):
            cfg["collectors"] = self.config_data["collectors"]
        for k, v in self.config_data.get("beacon", {}).items():
            if k not in ("server_url", "username", "password"):
                cfg["beacon"][k] = v
        if self.config_data.get("monitoring"):
            for k, v in self.config_data["monitoring"].items():
                if k not in cfg["monitoring"]:
                    cfg["monitoring"][k] = v
        if self.config_data.get("paths"):
            for k, v in self.config_data["paths"].items():
                if k not in cfg["paths"]:
                    cfg["paths"][k] = v
        return cfg

    def _validate(self, cfg):
        if not cfg["beacon"]["server_url"]:
            messagebox.showerror("Input Error", "Server URL is required.")
            return False
        if not cfg["beacon"]["username"]:
            messagebox.showerror("Input Error", "Username is required.")
            return False
        if not cfg["logging"]["file"]:
            messagebox.showerror("Input Error", "Log file path is required.")
            return False
        return True

    def _save_only(self):
        cfg = self._collect_config()
        if not self._validate(cfg):
            return
        save_config(cfg)
        self.lbl_status.config(text="Settings saved successfully", fg=self.SUCCESS)
        self._flash_status()

    def _save_and_start(self):
        cfg = self._collect_config()
        if not self._validate(cfg):
            return
        save_config(cfg)
        self.lbl_status.config(text="Starting agent...", fg=self.ACCENT)
        self.update()
        self.destroy()
        _launch_agent()

    def _flash_status(self):
        """상태 메시지를 3초 후 자동으로 숨김."""
        def clear():
            try:
                self.lbl_status.config(text="")
            except tk.TclError:
                pass
        self.after(3000, clear)

    def _test_connection(self):
        url = self.var_url.get().strip().rstrip("/")
        user = self.var_user.get().strip()
        pwd = self.var_pass.get()

        self.lbl_conn.config(text="Connecting...", fg=self.WARNING)

        def do_test():
            try:
                r = requests.post(
                    f"{url}/api/auth/login",
                    json={"username": user, "password": pwd},
                    timeout=6,
                )
                if r.status_code == 200:
                    self.after(0, self._on_connect_success)
                else:
                    self.after(0, lambda sc=r.status_code: self._on_connect_fail(f"Failed ({sc})"))
            except Exception as e:
                self.after(0, lambda en=type(e).__name__: self._on_connect_fail(en))

        threading.Thread(target=do_test, daemon=True).start()

    def _on_connect_success(self):
        self.lbl_conn.config(text="Connected", fg=self.SUCCESS)
        self.status_dot.delete("all")
        self.status_dot.create_oval(1, 1, 9, 9, fill=self.SUCCESS, outline="")
        self.lbl_header_status.config(text="Connected", fg=self.SUCCESS)

    def _on_connect_fail(self, reason):
        self.lbl_conn.config(text=reason, fg=self.ERROR)
        self.status_dot.delete("all")
        self.status_dot.create_oval(1, 1, 9, 9, fill=self.ERROR, outline="")
        self.lbl_header_status.config(text="Connection failed", fg=self.ERROR)

    def _add_path(self):
        d = filedialog.askdirectory(title="Select directory to watch")
        if d:
            normalized = os.path.normpath(d)
            self.path_listbox.insert("end", f"  {normalized}")
            count = self.path_listbox.size()
            self.lbl_path_count.config(text=f"{count} paths configured")

    def _remove_path(self):
        sel = self.path_listbox.curselection()
        for idx in reversed(sel):
            self.path_listbox.delete(idx)
        count = self.path_listbox.size()
        self.lbl_path_count.config(text=f"{count} paths configured")

    # ────────────────────────────── 유틸 ──────────────────────────────

    def _center_window(self, w, h):
        self.update_idletasks()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        x = (sw - w) // 2
        y = (sh - h) // 2
        self.geometry(f"{w}x{h}+{x}+{y}")


# ────────────────────────────── 에이전트 실행 ──────────────────────────────

def _launch_agent():
    import subprocess

    if getattr(sys, "frozen", False):
        agent_exe = os.path.join(ROOT_DIR, "BeaconGuardianAgent.exe")
        cmd = [agent_exe, "--no-ui", "--config", CONFIG_PATH]
    else:
        agent_path = os.path.join(ROOT_DIR, "src", "agent.py")
        cmd = [sys.executable, agent_path, "--no-ui", "--config", CONFIG_PATH]

    subprocess.Popen(cmd, creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0))


def run_setup(force=False):
    """
    force=True  -> 항상 UI 표시
    force=False -> config.yaml 없을 때만 UI 표시 후 에이전트 실행,
                  있으면 바로 에이전트 실행
    """
    if force or not os.path.exists(CONFIG_PATH):
        app = SetupApp()
        app.mainloop()
    else:
        _launch_agent()


if __name__ == "__main__":
    run_setup(force=True)
