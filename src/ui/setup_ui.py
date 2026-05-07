import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import yaml
import os
import platform
import sys
import threading
import requests
from urllib.parse import urlparse
from datetime import datetime
import time

# [FIX] 모듈 임포트 전에 미리 경로를 설정해야 에러가 나지 않습니다.
if getattr(sys, 'frozen', False):
    ROOT_DIR = os.path.dirname(os.path.abspath(sys.executable))
else:
    # d:/다운로드/BeaconGuardian-master/src/ui/setup_ui.py -> src/ui -> src -> project root
    ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SRC_DIR = os.path.join(ROOT_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from core.app_context import AppContext
from core.credential_store import encrypt_password, decrypt_password, is_encrypted
from beacon.beacon_client import configure_tls_session

CONFIG_PATH = os.path.join(ROOT_DIR, "config.yaml")

DEFAULT_CONFIG = {
    "beacon": {
        "server_url": "http://localhost:8080",
        "username": "admin",
        "password": "",
        "tls": {
            "require_https": True,
        },
    },
    "agent": {
        "agent_name": "BeaconGuardian",
        "agent_version": "1.0.0",
        "heartbeat_interval_seconds": 10,
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
    "wazuh": {
        "enabled": False,
        "container_name": "single-node-wazuh.manager-1",
        "min_level": 5,
    },
    "collectors": {
        "usb": True,
        "network": True,
        "process": True,
        "filesystem": True,
        "browser_history": True,
        "input_biometric": True,
    },
    "ui": {
        "dark_mode": False,
        "skip_login": False,
        "default_role": "admin",
        "admin_usernames": [],
    },
    "suricata": {
        "enabled": False,
        "manage_process": True,
        "binary_path": "C:\\Program Files\\Suricata\\suricata.exe",
        "config_path": "C:\\Program Files\\Suricata\\suricata.yaml",
        "eve_log_path": "C:\\Program Files\\Suricata\\log\\eve.json",
        "interface": "any",
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
    def __init__(self, role="admin", login_prefill=None, token=None):
        super().__init__()
        self.title("BeaconGuardian Setup")
        self.minsize(920, 680)
        self.resizable(False, False)
        self.user_role = role if role in ("admin", "user") else "admin"
        self.token = token
        self.api_url = login_prefill[0].rstrip("/") if login_prefill else "https://localhost:8080"
        AppContext.set_role(self.user_role)
        self._tray_icon = None
        self._agent_launched_session = False
        self._agent_process = None

        self.config_data = load_config()
        self.current_step = 0
        self.total_steps = 9
        self._monitor_running = False
        self._monitor_filter_high_risk = False
        
        # [NEW] 전/후 비교 테스트용 메모리
        self._snapshot_memory = None
        self._diag_agent = None

        mon_cfg = self.config_data.get("monitoring", {})
        wz_cfg = self.config_data.get("wazuh", {})
        self.var_engine = tk.StringVar(value=mon_cfg.get("engine", "builtin"))
        self.var_wazuh_container = tk.StringVar(value=wz_cfg.get("container_name", "single-node-wazuh.manager-1"))
        self.var_wazuh_level = tk.IntVar(value=wz_cfg.get("min_level", 5))

        ui_cfg = self.config_data.get("ui", {})
        self.var_dark_mode = tk.BooleanVar(value=bool(ui_cfg.get("dark_mode", False)))

        self._set_theme(bool(self.var_dark_mode.get()))
        self._setup_style()
        self._build_ui()
        if login_prefill:
            u, n = login_prefill[0], login_prefill[1]
            if hasattr(self, "var_url"):
                self.var_url.set(u)
            if hasattr(self, "var_user"):
                self.var_user.set(n)
        self._apply_role_ui()
        self._center_window(940, 700)

    # ────────────────────────────── 테마/스타일 ──────────────────────────

    def _set_theme(self, dark):
        self.SP_1 = 8
        self.SP_2 = 16
        self.SP_3 = 24

        # 타이포 위계 4단계
        self.FONT_TITLE = ("Segoe UI Semibold", 17)
        self.FONT_SUBTITLE = ("Segoe UI Semibold", 12)
        self.FONT_BODY = ("Segoe UI", 10)
        self.FONT_HINT = ("Segoe UI", 9)

        # 포인트 컬러는 단일 블루만 사용
        self.ACCENT = "#2f6fed"
        self.ACCENT_HOVER = "#235bd1"

        if dark:
            self.BG = "#0f172a"
            self.BG2 = "#111b31"
            self.CARD = "#15223b"
            self.TEXT = "#e2e8f0"
            self.TEXT2 = "#cbd5e1"
            self.MUTED = "#94a3b8"
            self.BORDER = "#243453"
            self.SHADOW = "#0a1020"
            self.ACCENT_GLOW = "#1a2d52"
            self.ENTRY_BG = "#101a2f"
            self.ENTRY_BORDER = "#31456d"
            self.HEADER_BG = "#0f172a"
            self.HEADER_ACCENT = "#1a2b4f"
            self.SUCCESS = "#22c55e"
            self.SUCCESS_BG = "#11331f"
            self.ERROR = "#fb7185"
            self.ERROR_BG = "#3a1522"
            self.WARNING = "#f59e0b"
        else:
            self.BG = "#f4f6fb"
            self.BG2 = "#eef2f9"
            self.CARD = "#ffffff"
            self.TEXT = "#1f2937"
            self.TEXT2 = "#334155"
            self.MUTED = "#64748b"
            self.BORDER = "#dbe2ee"
            self.SHADOW = "#e8edf7"
            self.ACCENT_GLOW = "#dbe8ff"
            self.ENTRY_BG = "#f8fafd"
            self.ENTRY_BORDER = "#d7dfec"
            self.HEADER_BG = "#ffffff"
            self.HEADER_ACCENT = "#ecf3ff"
            self.SUCCESS = "#0f766e"
            self.SUCCESS_BG = "#dff7f3"
            self.ERROR = "#be123c"
            self.ERROR_BG = "#ffe4e8"
            self.WARNING = "#b45309"

    def _setup_style(self):
        self.configure(bg=self.BG)

        style = ttk.Style(self)
        style.theme_use("clam")

        style.configure("TFrame", background=self.BG)
        style.configure("TLabel", background=self.BG, foreground=self.TEXT, font=self.FONT_BODY)
        style.configure(
            "TCombobox",
            fieldbackground=self.ENTRY_BG,
            background=self.ENTRY_BG,
            foreground=self.TEXT2,
            arrowcolor=self.MUTED,
            borderwidth=1,
        )
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", self.ENTRY_BG)],
            selectbackground=[("readonly", self.ENTRY_BG)],
            selectforeground=[("readonly", self.TEXT2)],
        )
        style.configure("TNotebook", background=self.BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=self.BG2, foreground=self.MUTED, padding=[14, 8], borderwidth=0)
        style.map(
            "TNotebook.Tab",
            background=[("selected", self.CARD)],
            foreground=[("selected", self.ACCENT)],
        )
        style.configure(
            "Accent.TButton",
            background=self.ACCENT,
            foreground="#ffffff",
            font=("Segoe UI Semibold", 10),
            padding=[16, 8],
            borderwidth=0,
            relief="flat",
        )
        style.map("Accent.TButton", background=[("active", self.ACCENT_HOVER)])

        style.configure(
            "Ghost.TButton",
            background=self.CARD,
            foreground=self.TEXT2,
            font=self.FONT_BODY,
            padding=[12, 8],
            borderwidth=1,
            relief="flat",
        )
        style.map("Ghost.TButton", background=[("active", self.BG2)])

        style.configure(
            "Success.TButton",
            background=self.SUCCESS_BG,
            foreground=self.SUCCESS,
            font=self.FONT_HINT,
            padding=[10, 6],
            borderwidth=0,
            relief="flat",
        )
        style.map("Success.TButton", background=[("active", self.BG2)])

        style.configure(
            "Danger.TButton",
            background=self.ERROR_BG,
            foreground=self.ERROR,
            font=self.FONT_HINT,
            padding=[10, 6],
            borderwidth=0,
            relief="flat",
        )
        style.map("Danger.TButton", background=[("active", self.BG2)])

    # ────────────────────────────── UI 구성 ──────────────────────────────

    def _build_ui(self):
        header = tk.Frame(self, bg=self.HEADER_BG, height=80)
        header.pack(fill="x")
        header.pack_propagate(False)

        left = tk.Frame(header, bg=self.HEADER_BG)
        left.pack(side="left", padx=self.SP_3)
        tk.Label(
            left, text="BeaconGuardian", bg=self.HEADER_BG, fg=self.TEXT,
            font=self.FONT_TITLE,
        ).pack(anchor="w", pady=(self.SP_2 - 2, 0))
        tk.Label(
            left, text="단계별 설정 마법사",
            bg=self.HEADER_BG, fg=self.MUTED, font=self.FONT_HINT,
        ).pack(anchor="w", pady=(2, 0))

        right = tk.Frame(header, bg=self.HEADER_BG)
        right.pack(side="right", padx=self.SP_3)

        self.btn_header_quit = ttk.Button(
            right, text="종료", style="Ghost.TButton", command=self._on_admin_quit_request,
        )

        chip = tk.Frame(right, bg=self.HEADER_ACCENT, padx=10, pady=6)
        self.status_dot = tk.Canvas(chip, width=10, height=10, bg=self.HEADER_ACCENT, highlightthickness=0)
        self.status_dot.pack(side="left", padx=(0, 6))
        self.status_dot.create_oval(1, 1, 9, 9, fill=self.MUTED, outline="")

        self.lbl_header_status = tk.Label(
            chip, text="○ 연결 대기", bg=self.HEADER_ACCENT, fg=self.MUTED, font=self.FONT_HINT,
        )
        self.lbl_header_status.pack(side="left")

        self.btn_header_quit.pack(side="right", pady=self.SP_2)
        chip.pack(side="right", pady=self.SP_2, padx=(0, 12))

        tk.Frame(self, bg=self.BORDER, height=1).pack(fill="x")

        # 푸터(저장·연결 테스트 등)를 먼저 하단에 고정 — 노트북 탭 내용이 길어도 버튼이 잘리지 않음
        self._build_footer(self)

        body = tk.Frame(self, bg=self.BG)
        body.pack(fill="both", expand=True, padx=self.SP_3, pady=self.SP_2)

        scroll_inner = self._build_scrollable_body(body)
        self._build_step_indicator(scroll_inner)
        self._build_steps(scroll_inner)
        self._sync_step_ui()
        self.after_idle(self._refresh_body_scroll)

    def _build_scrollable_body(self, parent):
        """Canvas + 세로 스크롤바로 단계/탭 영역이 잘리지 않게 함."""
        container = tk.Frame(parent, bg=self.BG)
        container.pack(fill="both", expand=True)

        canvas = tk.Canvas(container, bg=self.BG, highlightthickness=0)
        vsb = tk.Scrollbar(
            container,
            orient="vertical",
            command=canvas.yview,
            bg=self.BG2,
            troughcolor=self.ENTRY_BG,
            activebackground=self.MUTED,
            width=10,
        )
        canvas.configure(yscrollcommand=vsb.set)

        vsb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        inner = tk.Frame(canvas, bg=self.BG)
        self._body_canvas = canvas
        self._body_inner = inner
        self._body_canvas_window = canvas.create_window((0, 0), window=inner, anchor="nw")

        def _on_inner_configure(_event=None):
            bbox = canvas.bbox("all")
            if bbox:
                canvas.configure(scrollregion=bbox)

        def _on_canvas_configure(event):
            canvas.itemconfig(self._body_canvas_window, width=event.width)

        inner.bind("<Configure>", _on_inner_configure)
        canvas.bind("<Configure>", _on_canvas_configure)

        self.bind_all("<MouseWheel>", self._on_body_mousewheel)
        return inner

    def _on_body_mousewheel(self, event):
        """바디 스크롤. Listbox/Spinbox 위에서는 내부 동작만 쓰도록 건너뜀."""
        if not getattr(self, "_body_canvas", None) or not self._body_canvas.winfo_ismapped():
            return
        try:
            x, y = self.winfo_pointerxy()
            w = self.winfo_containing(x, y)
        except tk.TclError:
            return
        while w and w != self:
            if isinstance(w, (tk.Listbox, tk.Spinbox, tk.Text)):
                return
            if w == self._body_inner:
                self._body_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
                return "break"
            w = getattr(w, "master", None)

    def _refresh_body_scroll(self):
        if not getattr(self, "_body_canvas", None):
            return
        try:
            self.update_idletasks()
            bbox = self._body_canvas.bbox("all")
            if bbox:
                self._body_canvas.configure(scrollregion=bbox)
            self._body_canvas.yview_moveto(0)
        except tk.TclError:
            pass

    def _apply_role_ui(self):
        if self.user_role == "admin":
            self.protocol("WM_DELETE_WINDOW", self._on_admin_quit_request)
        else:
            self.btn_header_quit.pack_forget()
            self.protocol("WM_DELETE_WINDOW", self._on_user_minimize_to_tray)
            if os.path.exists(CONFIG_PATH):
                self.after(400, self._enter_user_background)

    def _tray_show_window(self):
        self.deiconify()
        self.lift()
        self.after(0, lambda: self.focus_force())

    def _ensure_tray(self):
        if self._tray_icon is not None:
            return
        try:
            from ui.tray_icon import start_tray

            self._tray_icon = start_tray(
                self,
                on_open=self._tray_show_window,
                can_quit=False,
                on_quit=None,
            )
        except Exception:
            self.iconify()

    def _enter_user_background(self):
        if self.user_role != "user":
            return
        if not os.path.exists(CONFIG_PATH):
            return
        if self._agent_launched_session:
            return
        try:
            self._agent_process = _launch_agent()
            self._agent_launched_session = True
        except Exception:
            pass
        self._ensure_tray()
        self.withdraw()

    def _on_user_minimize_to_tray(self):
        self._ensure_tray()
        self.withdraw()

    def _on_admin_quit_request(self):
        if messagebox.askokcancel("종료", "BeaconGuardian 설정을 종료할까요?"):
            try:
                from ui.tray_icon import stop_tray

                stop_tray(self._tray_icon)
            except Exception:
                pass
            self.destroy()

    def destroy(self):
        try:
            from ui.tray_icon import stop_tray

            stop_tray(getattr(self, "_tray_icon", None))
        except Exception:
            pass
        try:
            self.unbind_all("<MouseWheel>")
        except tk.TclError:
            pass
        super().destroy()

    def _build_step_indicator(self, parent):
        top = tk.Frame(parent, bg=self.BG)
        top.pack(fill="x", pady=(0, self.SP_2))

        self.lbl_step_title = tk.Label(top, text="", bg=self.BG, fg=self.TEXT, font=self.FONT_SUBTITLE)
        self.lbl_step_title.pack(anchor="w")
        self.lbl_step_hint = tk.Label(top, text="", bg=self.BG, fg=self.MUTED, font=self.FONT_HINT)
        self.lbl_step_hint.pack(anchor="w", pady=(2, 0))

        self.progress = tk.Canvas(top, height=8, bg=self.BG, highlightthickness=0)
        self.progress.pack(fill="x", pady=(self.SP_1, 0))
        self.progress_bg = self.progress.create_rectangle(0, 0, 1, 8, fill=self.BORDER, outline="")
        self.progress_fg = self.progress.create_rectangle(0, 0, 1, 8, fill=self.ACCENT, outline="")
        self.progress.bind("<Configure>", self._draw_progress)

    def _draw_progress(self, event=None):
        w = self.progress.winfo_width()
        self.progress.coords(self.progress_bg, 0, 0, w, 8)
        fill_w = int((self.current_step + 1) / self.total_steps * w)
        self.progress.coords(self.progress_fg, 0, 0, fill_w, 8)

    def _build_steps(self, parent):
        self.nb = ttk.Notebook(parent)
        # 스크롤 바디 안에서는 세로 expand 금지 — 내용 높이만큼만 차지하고 Canvas가 스크롤
        self.nb.pack(fill="x", expand=False)
        self.nb.bind("<<NotebookTabChanged>>", self._on_tab_changed)

        self.step_frames = []
        tab_names = ("1. 서버", "2. 모니터링", "3. 경로/로그", "4. 고급/검토", "5. 시스템", "6. 실시간 로그", "7. 제로트러스트", "8. 위협 진단", "9. Wazuh 연동")
        for name in tab_names:
            f = tk.Frame(self.nb, bg=self.BG)
            self.nb.add(f, text=name)
            self.step_frames.append(f)

        self._build_step1(self.step_frames[0])
        self._build_step2(self.step_frames[1])
        self._build_step3(self.step_frames[2])
        self._build_step4(self.step_frames[3])
        self._build_step5(self.step_frames[4])
        self._build_step6(self.step_frames[5])
        self._build_step7(self.step_frames[6])
        self._build_step8(self.step_frames[7])
        self._build_step9_wazuh(self.step_frames[8])

    def _build_step1(self, parent):
        wrap = self._section(parent, "서버 및 에이전트", "기본 연결 정보와 에이전트 신원")
        card = self._card(wrap)
        bc = self.config_data.get("beacon", {})
        ag = self.config_data.get("agent", {})

        self.var_url = self._field(card, "Server URL", bc.get("server_url", "https://localhost:8080"))
        self.var_user = self._field(card, "Username", bc.get("username", "admin"))
        raw_pass = bc.get("password", "")
        self.var_pass = self._field(card, "Password", decrypt_password(raw_pass), show="\u2022")
        self.var_ip_selection = self._combo_field(
            card,
            "등록 IP 선택",
            ["outbound", "hostname"],
            bc.get("ip_selection", "outbound"),
        )
        self.var_jwt_refresh = self._spin_field(
            card,
            "JWT 갱신 여유 시간(초)",
            bc.get("jwt_refresh_before_exp_seconds", 90),
            from_=30,
            to=900,
            width=10,
        )

        test_row = tk.Frame(card, bg=self.CARD)
        test_row.pack(fill="x", padx=self.SP_2, pady=(self.SP_2, self.SP_2))

        ttk.Button(
            test_row, text="연결 테스트", style="Success.TButton",
            command=self._test_connection,
        ).pack(side="left")

        self.lbl_conn = tk.Label(
            test_row, text="○ 아직 테스트하지 않음", bg=self.CARD, fg=self.MUTED, font=self.FONT_HINT,
        )
        self.lbl_conn.pack(side="left", padx=12)

        wrap2 = self._section(parent, "에이전트 정보", "서버 등록명과 하트비트 주기")
        card2 = self._card(wrap2)
        self.var_agent_name = self._field(card2, "Agent Name", ag.get("agent_name", "BeaconGuardian"))
        self.var_agent_version = self._field(card2, "Agent Version", ag.get("agent_version", "1.0.0"))
        self.var_heartbeat = self._spin_field(
            card2,
            "Heartbeat Interval (sec)",
            ag.get("heartbeat_interval_seconds", 10),
            from_=10,
            to=299,
            width=10,
        )

    def _build_step2(self, parent):
        wrap_engine = self._section(parent, "보안 엔진 선택", "자체 감시(Built-in) 또는 Wazuh 하이브리드 엔진 선택")
        card_engine = self._card(wrap_engine)
        
        engine_frame = tk.Frame(card_engine, bg=self.CARD)
        engine_frame.pack(fill="x", padx=self.SP_2, pady=self.SP_2)
        
        tk.Radiobutton(
            engine_frame, text="기본 엔진 (Built-in)", variable=self.var_engine, value="builtin",
            bg=self.CARD, fg=self.TEXT, font=self.FONT_BODY, activebackground=self.CARD, selectcolor=self.ENTRY_BG,
            command=self._on_engine_change
        ).pack(side="left", padx=(0, 20))
        
        tk.Radiobutton(
            engine_frame, text="와주 하이브리드 (Wazuh Hybrid)", variable=self.var_engine, value="wazuh",
            bg=self.CARD, fg=self.TEXT, font=self.FONT_BODY, activebackground=self.CARD, selectcolor=self.ENTRY_BG,
            command=self._on_engine_change
        ).pack(side="left")

        wrap = self._section(parent, "수집 모듈", "활성화할 모듈과 체크 주기")
        card = self._card(wrap)
        cc = self.config_data.get("collectors", {})
        mc = self.config_data.get("monitoring", {})

        grid = tk.Frame(card, bg=self.CARD)
        grid.pack(fill="x", padx=self.SP_2, pady=(self.SP_2, self.SP_2))
        self.var_col_usb = tk.BooleanVar(value=bool(cc.get("usb", True)))
        self.var_col_network = tk.BooleanVar(value=bool(cc.get("network", True)))
        self.var_col_process = tk.BooleanVar(value=bool(cc.get("process", True)))
        self.var_col_filesystem = tk.BooleanVar(value=bool(cc.get("filesystem", True)))
        self.var_col_browser = tk.BooleanVar(value=bool(cc.get("browser_history", True)))
        self.var_col_biometric = tk.BooleanVar(value=bool(cc.get("input_biometric", True)))
        
        sc = self.config_data.get("suricata", {})
        self.var_col_suricata = tk.BooleanVar(value=bool(sc.get("enabled", False)))

        opts = [
            ("USB", self.var_col_usb),
            ("Network", self.var_col_network),
            ("Process", self.var_col_process),
            ("Filesystem", self.var_col_filesystem),
            ("Browser History", self.var_col_browser),
            ("Input Biometric", self.var_col_biometric),
            ("Suricata IDS", self.var_col_suricata),
        ]
        for idx, (name, var) in enumerate(opts):
            r = idx // 3
            c = idx % 3
            cb = tk.Checkbutton(
                grid,
                text=name,
                variable=var,
                bg=self.CARD,
                fg=self.TEXT2,
                activebackground=self.CARD,
                activeforeground=self.TEXT,
                selectcolor=self.ENTRY_BG,
                font=self.FONT_BODY,
                padx=6,
                pady=4,
            )
            cb.grid(row=r, column=c, sticky="w", padx=8, pady=4)

        wrap2 = self._section(parent, "모니터링 주기", "초 단위 주기를 지정하세요")
        card2 = self._card(wrap2)
        self.var_usb = self._spin_field(card2, "USB Check", mc.get("usb_check_interval", 5), from_=1, to=3600)
        self.var_net = self._spin_field(card2, "Network Check", mc.get("network_check_interval", 10), from_=1, to=3600)
        self.var_proc = self._spin_field(card2, "Process Check", mc.get("process_check_interval", 5), from_=1, to=3600)
        self.var_brow = self._spin_field(card2, "Browser Check", mc.get("browser_check_interval", 30), from_=1, to=3600)
        self.var_bio_flush = self._spin_field(
            card2, "Biometric Flush", mc.get("biometric_flush_interval", 2), from_=1, to=120
        )
        self.var_mouse_sample = self._spin_field(
            card2, "Mouse Sample (ms)", mc.get("mouse_move_sample_ms", 120), from_=20, to=2000
        )
        self.var_bio_target = self._spin_field(
            card2, "Bio Training Samples", mc.get("biometric_target_samples", 2000), from_=100, to=10000
        )
        self.var_bio_block = self._spin_field(
            card2, "Auto Block (1=On,0=Off)", 1 if mc.get("biometric_auto_block", True) else 0, from_=0, to=1
        )

    def _build_step3(self, parent):
        wrap = self._section(parent, "감시 경로", "파일 변경 감시 디렉터리")
        card = self._card(wrap, expand=False)
        list_frame = tk.Frame(card, bg=self.ENTRY_BG, highlightthickness=1, highlightbackground=self.ENTRY_BORDER, height=280)
        list_frame.pack(fill="x", expand=False, padx=self.SP_2, pady=(self.SP_2, self.SP_1))
        list_frame.pack_propagate(False)

        scrollbar = tk.Scrollbar(list_frame, bg=self.BG2, troughcolor=self.ENTRY_BG,
                                 activebackground=self.MUTED, width=8)
        scrollbar.pack(side="right", fill="y")

        self.path_listbox = tk.Listbox(
            list_frame,
            bg=self.ENTRY_BG,
            fg=self.TEXT2,
            selectbackground=self.ACCENT_GLOW,
            selectforeground=self.TEXT,
            font=("Segoe UI", 10),
            borderwidth=0,
            highlightthickness=0,
            activestyle="none",
            yscrollcommand=scrollbar.set,
            relief="flat",
        )
        self.path_listbox.pack(fill="both", expand=True, padx=(self.SP_1, 0), pady=6)
        scrollbar.config(command=self.path_listbox.yview)

        dirs = self.config_data.get("paths", {}).get("watch_dirs", [])
        for d in dirs:
            self.path_listbox.insert("end", d)

        btn_row = tk.Frame(card, bg=self.CARD)
        btn_row.pack(fill="x", padx=self.SP_2, pady=(4, self.SP_2))

        ttk.Button(btn_row, text="+ 경로 추가", style="Ghost.TButton",
                   command=self._add_path).pack(side="left", padx=(0, 8))
        ttk.Button(btn_row, text="- 선택 삭제", style="Danger.TButton",
                   command=self._remove_path).pack(side="left")
        ttk.Button(btn_row, text="중복 제거", style="Ghost.TButton",
                   command=self._dedupe_paths).pack(side="left", padx=(8, 0))

        self.lbl_path_count = tk.Label(
            btn_row, text=f"{len(dirs)}개 경로", bg=self.CARD, fg=self.MUTED,
            font=("Segoe UI", 9),
        )
        self.lbl_path_count.pack(side="right")

        wrap_suri = self._section(parent, "수리카타(Suricata) 설정", "NIDS 엔진 경로 및 인터페이스 설정")
        card_suri = self._card(wrap_suri)
        sc = self.config_data.get("suricata", {})
        self.var_suri_manage = tk.BooleanVar(value=bool(sc.get("manage_process", True)))
        
        suri_top = tk.Frame(card_suri, bg=self.CARD)
        suri_top.pack(fill="x", padx=self.SP_2, pady=(self.SP_2, 0))
        tk.Checkbutton(
            suri_top, text="에이전트가 프로세스 직접 관리", variable=self.var_suri_manage,
            bg=self.CARD, fg=self.TEXT2, activebackground=self.CARD, selectcolor=self.ENTRY_BG, font=self.FONT_BODY
        ).pack(side="left")

        self.var_suri_bin = self._field(card_suri, "Suricata Binary Path", sc.get("binary_path", ""))
        self.var_suri_cfg = self._field(card_suri, "Suricata Config(yaml) Path", sc.get("config_path", ""))
        self.var_suri_eve = self._field(card_suri, "EVE JSON Log Path", sc.get("eve_log_path", ""))
        self.var_suri_iface = self._field(card_suri, "Network Interface (-i)", sc.get("interface", "any"))

        wrap2 = self._section(parent, "로깅", "로그 레벨 및 파일 회전 설정")
        card2 = self._card(wrap2)
        lc = self.config_data.get("logging", {})
        self.var_log_level = self._combo_field(
            card2, "Log Level", ["DEBUG", "INFO", "WARNING", "ERROR"], lc.get("level", "INFO")
        )
        self.var_log_file = self._field(card2, "Log File Path", lc.get("file", "agent.log"))
        self.var_max_bytes = self._spin_field(
            card2, "Max File Size (bytes)", lc.get("max_bytes", 10485760),
            from_=1048576, to=104857600, increment=1048576, width=12,
        )
        self.var_backup_cnt = self._spin_field(
            card2, "Backup Count", lc.get("backup_count", 5),
            from_=1, to=20, width=10,
        )

    def _build_step4(self, parent):
        wrap = self._section(parent, "고급 옵션", "선택적 보안/저장 설정")
        card = self._card(wrap)
        mc = self.config_data.get("monitoring", {})
        pc = self.config_data.get("paths", {})
        bc = self.config_data.get("beacon", {})

        self.var_include_raw = tk.BooleanVar(value=bool(mc.get("include_traffic_raw_data", False)))
        self.var_biometric_log = tk.StringVar(value=pc.get("biometric_log_file", "logs/biometric_input.jsonl"))
        self.var_tls_https = tk.BooleanVar(value=bool(bc.get("tls", {}).get("require_https", True)))

        row1 = tk.Frame(card, bg=self.CARD)
        row1.pack(fill="x", padx=self.SP_2, pady=(self.SP_2, 4))
        tk.Checkbutton(
            row1,
            text="네트워크 이벤트에 rawData 포함",
            variable=self.var_include_raw,
            bg=self.CARD,
            fg=self.TEXT2,
            activebackground=self.CARD,
            selectcolor=self.ENTRY_BG,
            font=self.FONT_BODY,
        ).pack(side="left")

        row2 = tk.Frame(card, bg=self.CARD)
        row2.pack(fill="x", padx=self.SP_2, pady=(4, 4))
        tk.Checkbutton(
            row2,
            text="HTTPS 강제(require_https)",
            variable=self.var_tls_https,
            bg=self.CARD,
            fg=self.TEXT2,
            activebackground=self.CARD,
            selectcolor=self.ENTRY_BG,
            font=self.FONT_BODY,
        ).pack(side="left")

        row3 = tk.Frame(card, bg=self.CARD)
        row3.pack(fill="x", padx=self.SP_2, pady=(4, 4))
        tk.Checkbutton(
            row3,
            text="다크 모드(다음 실행 시 적용)",
            variable=self.var_dark_mode,
            bg=self.CARD,
            fg=self.TEXT2,
            activebackground=self.CARD,
            selectcolor=self.ENTRY_BG,
            font=self.FONT_BODY,
        ).pack(side="left")

        self._field(card, "Biometric Log File", self.var_biometric_log.get(), bind_var=self.var_biometric_log)

        review = self._section(parent, "검토", "저장 전에 주요 항목을 확인하세요")
        review_card = self._card(review)
        self.lbl_review = tk.Label(
            review_card,
            text="",
            justify="left",
            anchor="w",
            bg=self.CARD,
            fg=self.TEXT2,
            font=self.FONT_BODY,
            padx=self.SP_2,
            pady=self.SP_2,
        )
        self.lbl_review.pack(fill="x")
        self._update_review()

    def _build_step5(self, parent):
        wrap = self._section(parent, "시스템 · 개발", "런타임·경로·환경 확인 (지원·로그 첨부 시 활용)")
        card = self._card(wrap, expand=False)

        btn_row = tk.Frame(card, bg=self.CARD)
        btn_row.pack(fill="x", padx=self.SP_2, pady=(self.SP_2, self.SP_1))
        ttk.Button(
            btn_row, text="새로고침", style="Ghost.TButton", command=self._refresh_system_info,
        ).pack(side="left", padx=(0, 8))
        ttk.Button(
            btn_row, text="클립보드에 복사", style="Ghost.TButton", command=self._copy_system_info,
        ).pack(side="left")

        text_frame = tk.Frame(card, bg=self.ENTRY_BG, highlightthickness=1, highlightbackground=self.ENTRY_BORDER)
        text_frame.pack(fill="x", padx=self.SP_2, pady=(0, self.SP_2))
        sys_scroll = tk.Scrollbar(
            text_frame, bg=self.BG2, troughcolor=self.ENTRY_BG,
            activebackground=self.MUTED, width=8,
        )
        sys_scroll.pack(side="right", fill="y")
        self._system_info_text = tk.Text(
            text_frame,
            height=22,
            wrap="word",
            bg=self.ENTRY_BG,
            fg=self.TEXT2,
            font=("Consolas", 9),
            insertbackground=self.ACCENT,
            relief="flat",
            borderwidth=6,
            highlightthickness=0,
            yscrollcommand=sys_scroll.set,
        )
        self._system_info_text.pack(side="left", fill="both", expand=True)
        sys_scroll.config(command=self._system_info_text.yview)

        self._refresh_system_info()

    def _build_step6(self, parent):
        wrap = self._section(parent, "실시간 이벤트 모니터링", "서버로 전송된 최근 보안 탐지 로그를 확인합니다")
        card = self._card(wrap, expand=False)

        ctrl_row = tk.Frame(card, bg=self.CARD)
        ctrl_row.pack(fill="x", padx=self.SP_2, pady=self.SP_2)

        self.btn_mon_all = ttk.Button(
            ctrl_row, text="전체 이벤트", style="Accent.TButton" if not self._monitor_filter_high_risk else "Ghost.TButton",
            command=self._on_monitor_show_all
        )
        self.btn_mon_all.pack(side="left", padx=(0, 8))

        self.btn_mon_high = ttk.Button(
            ctrl_row, text="고위험(High-Risk)만", style="Accent.TButton" if self._monitor_filter_high_risk else "Ghost.TButton",
            command=self._on_monitor_show_high_risk
        )
        self.btn_mon_high.pack(side="left")

        ttk.Button(
            ctrl_row, text="지금 갱신 ↻", style="Ghost.TButton", command=self._fetch_monitor_data
        ).pack(side="right")

        tree_frame = tk.Frame(card, bg=self.ENTRY_BG, highlightthickness=1, highlightbackground=self.ENTRY_BORDER)
        tree_frame.pack(fill="x", padx=self.SP_2, pady=(0, self.SP_2))

        cols = ("Time", "Type", "Severity", "Summary")
        self.tree_events = ttk.Treeview(tree_frame, columns=cols, show="headings", height=15)
        
        self.tree_events.heading("Time", text="시간")
        self.tree_events.heading("Type", text="유형")
        self.tree_events.heading("Severity", text="심각도")
        self.tree_events.heading("Summary", text="설명")

        self.tree_events.column("Time", width=140, anchor="center")
        self.tree_events.column("Type", width=120, anchor="center")
        self.tree_events.column("Severity", width=90, anchor="center")
        self.tree_events.column("Summary", width=420, anchor="w")

        scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree_events.yview)
        self.tree_events.configure(yscrollcommand=scroll.set)

        self.tree_events.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        # 실시간 자동 갱신 시작 (현재 탭이 모니터링일 때만 동작하도록 나중에 보정)
        self._monitor_running = True
        self._monitor_loop()

    def _on_monitor_show_all(self):
        self._monitor_filter_high_risk = False
        self.btn_mon_all.config(style="Accent.TButton")
        self.btn_mon_high.config(style="Ghost.TButton")
        self._fetch_monitor_data()

    def _on_monitor_show_high_risk(self):
        self._monitor_filter_high_risk = True
        self.btn_mon_all.config(style="Ghost.TButton")
        self.btn_mon_high.config(style="Accent.TButton")
        self._fetch_monitor_data()

    def _monitor_loop(self):
        if not self._monitor_running:
            return
        # 현재 탭이 6번(인덱스 5)일 때만 자동 갱신 시도 (네트워크 절약)
        if self.current_step == 5:
            self._fetch_monitor_data()
        self.after(10000, self._monitor_loop) # 10초마다 갱신

    def _fetch_monitor_data(self):
        if not self.token:
            return

        def work():
            endpoint = "/api/security-events"
            if self._monitor_filter_high_risk:
                endpoint = "/api/security-events/high-risk"
            
            url = f"{self.api_url}{endpoint}"
            headers = {"Authorization": f"Bearer {self.token}"}
            
            try:
                session = requests.Session()
                configure_tls_session(session, {"verify": False})
                r = session.get(url, headers=headers, timeout=8)
                if r.status_code == 200:
                    data = r.json()
                    # Spring Data Page 객체 대비: 전체 리스트는 content 필드에 있음
                    events = data.get("content") if isinstance(data, dict) and "content" in data else data
                    if isinstance(events, list):
                        self.after(0, lambda e=events: self._update_event_table(e))
                session.close()
            except Exception:
                pass

        threading.Thread(target=work, daemon=True).start()

    def _update_event_table(self, events):
        # 기존 데이터 삭제
        for item in self.tree_events.get_children():
            self.tree_events.delete(item)
        
        # 새 데이터 삽입
        for ev in events:
            # entities: createdAt, eventType, severity, description 등
            # ISO 날짜 형식(2026-04-12T21:44:59) -> 21:44:59 형태나 줄여서 표시
            created = ev.get("createdAt", "")
            if "T" in created:
                created = created.split("T")[1].split(".")[0]
            
            self.tree_events.insert("", "end", values=(
                created,
                ev.get("eventType", "Unknown"),
                ev.get("severity", "LOW"),
                ev.get("description", "") or ev.get("summary", "")
            ))

    def _format_system_info(self):
        lines = [
            f"OS: {platform.system()} {platform.release()}",
            f"Version: {platform.version()}",
            f"Machine: {platform.machine()}",
            f"Processor: {platform.processor() or '—'}",
            f"Hostname: {platform.node()}",
            "",
            f"Python: {sys.version.splitlines()[0]}",
            f"Executable: {sys.executable}",
            f"Prefix: {sys.prefix}",
            "",
            f"frozen: {getattr(sys, 'frozen', False)}",
            f"ROOT_DIR: {ROOT_DIR}",
            f"CONFIG_PATH: {CONFIG_PATH}",
            f"CWD: {os.getcwd()}",
            "",
            f"Tk: {tk.TkVersion}  Tcl patchlevel: {self.tk.call('info', 'patchlevel')}",
        ]
        try:
            import psutil

            vm = psutil.virtual_memory()
            phys = psutil.cpu_count(logical=False)
            phys_s = str(phys) if phys is not None else "—"
            lines.extend(
                [
                    "",
                    f"Memory: {vm.percent}% used",
                    f"  available {vm.available // (1024 * 1024)} MiB / total {vm.total // (1024 * 1024)} MiB",
                    f"CPU: {psutil.cpu_count(logical=True)} logical, {phys_s} physical",
                ]
            )
        except Exception as e:
            lines.extend(["", f"psutil: 사용 불가 ({type(e).__name__}: {e})"])
        return "\n".join(lines)

    def _refresh_system_info(self):
        if not getattr(self, "_system_info_text", None):
            return
        self._system_info_text.delete("1.0", "end")
        self._system_info_text.insert("1.0", self._format_system_info())

    def _copy_system_info(self):
        if getattr(self, "_system_info_text", None):
            text = self._system_info_text.get("1.0", "end-1c")
        else:
            text = self._format_system_info()
        self.clipboard_clear()
        self.clipboard_append(text)
        self.lbl_status.config(text="시스템 정보를 클립보드에 복사했습니다.", fg=self.SUCCESS)
        self._flash_status()

    def _build_footer(self, parent):
        footer = tk.Frame(parent, bg=self.BG)
        footer.pack(side="bottom", fill="x", padx=self.SP_3, pady=(self.SP_2, self.SP_1))
        tk.Frame(footer, bg=self.BORDER, height=1).pack(fill="x", pady=(0, 12))
        row = tk.Frame(footer, bg=self.BG)
        row.pack(fill="x")
        self.lbl_status = tk.Label(
            row, text="", bg=self.BG, fg=self.MUTED, font=("Segoe UI", 9),
        )
        self.lbl_status.pack(side="left", padx=4)

        actions = tk.Frame(row, bg=self.BG)
        actions.pack(side="right")

        self.btn_prev = ttk.Button(actions, text="이전", style="Ghost.TButton", command=self._go_prev)
        self.btn_prev.pack(side="left")

        self.btn_next = ttk.Button(actions, text="다음", style="Ghost.TButton", command=self._go_next)
        self.btn_next.pack(side="left", padx=(self.SP_1, 0))

        ttk.Button(
            actions,
            text="연결 테스트",
            style="Accent.TButton",
            command=self._test_connection,
        ).pack(side="left", padx=(self.SP_1, 0))

        ttk.Button(
            actions, text="저장", style="Ghost.TButton", command=self._save_only,
        ).pack(side="left", padx=(self.SP_1, 0))

        ttk.Button(
            actions, text="저장 후 에이전트 시작", style="Accent.TButton", command=self._save_and_start,
        ).pack(side="left", padx=(self.SP_1, 0))

    def _go_prev(self):
        if self.current_step > 0:
            self.current_step -= 1
            self.nb.select(self.current_step)
            self._sync_step_ui()

    def _go_next(self):
        if self.current_step < self.total_steps - 1:
            self.current_step += 1
            self.nb.select(self.current_step)
            self._sync_step_ui()

    def _on_tab_changed(self, _event):
        self.current_step = self.nb.index(self.nb.select())
        self._sync_step_ui()
        self.after_idle(self._refresh_body_scroll)

    def _sync_step_ui(self):
        titles = [
            ("1단계 · 서버/에이전트", "인증과 기본 신원 정보를 입력하세요"),
            ("2단계 · 모니터링", "활성 모듈과 수집 주기를 설정하세요"),
            ("3단계 · 경로/로그", "감시 경로와 로그 저장 정책을 설정하세요"),
            ("4단계 · 고급/검토", "부가 옵션을 선택하고 최종 확인하세요"),
            ("5단계 · 시스템(개발)", "실행 환경을 확인합니다"),
            ("6단계 · 실시간 로그", "서버로 전송된 최근 보안 이벤트를 확인합니다"),
            ("7단계 · 제로트러스트", "생체 인증 상태 및 긴급 대응 시스템 제어"),
            ("8단계 · 통합 위협 진단", "가상/실기 시나리오를 통한 보안 모듈 수집 검증"),
            ("9단계 · Wazuh 전용 연동", "Wazuh 매니저 컨테이너 연동 및 알람 필터 설정")
        ]
        title, hint = titles[self.current_step]
        self.lbl_step_title.config(text=title)
        self.lbl_step_hint.config(text=hint)
        self._draw_progress()
        self.btn_prev.config(state=("normal" if self.current_step > 0 else "disabled"))
        self.btn_next.config(state=("normal" if self.current_step < self.total_steps - 1 else "disabled"))
        
        # 엔진 상태에 따른 필드 활성화 제어 (2단계 노출 시)
        if self.current_step == 1:
            self._on_engine_change()

        if self.current_step == 3:
            self._update_review()

    # ────────────────────────────── 위젯 헬퍼 ──────────────────────────────

    def _section(self, parent, title, subtitle=""):
        f = tk.Frame(parent, bg=self.BG)
        f.pack(fill="x", pady=(0, self.SP_2))

        tk.Label(
            f, text=title, bg=self.BG, fg=self.TEXT,
            font=self.FONT_SUBTITLE,
        ).pack(anchor="w")

        if subtitle:
            tk.Label(
                f, text=subtitle, bg=self.BG, fg=self.MUTED,
                font=self.FONT_HINT,
            ).pack(anchor="w", pady=(3, 0))
        return f

    def _card(self, parent, expand=False):
        shadow = tk.Frame(parent, bg=self.SHADOW)
        shadow.pack(fill="both", expand=expand, padx=2, pady=(2, 0))
        outer = tk.Frame(shadow, bg=self.BORDER, padx=1, pady=1)
        outer.pack(fill="both", expand=expand)
        card = tk.Frame(outer, bg=self.CARD)
        card.pack(fill="both", expand=expand, padx=0, pady=0)
        return card

    def _field(self, parent, label, value="", show="", bind_var=None):
        row = tk.Frame(parent, bg=self.CARD)
        row.pack(fill="x", padx=self.SP_2, pady=(self.SP_2, 0))

        tk.Label(
            row, text=label, bg=self.CARD, fg=self.TEXT2,
            font=self.FONT_HINT,
        ).pack(anchor="w")

        var = bind_var if bind_var is not None else tk.StringVar(value=str(value))
        if bind_var is not None:
            bind_var.set(str(value))

        entry_frame = tk.Frame(row, bg=self.ENTRY_BORDER, padx=1, pady=1)
        entry_frame.pack(fill="x", pady=(6, 0))

        e = tk.Entry(
            entry_frame, textvariable=var, bg=self.ENTRY_BG, fg=self.TEXT,
            font=self.FONT_BODY, insertbackground=self.ACCENT,
            relief="flat", borderwidth=6,
        )
        if show:
            e.config(show=show)
        e.pack(fill="x")

        # 포커스 시 보더 색상 변경
        e.bind("<FocusIn>", lambda ev, ef=entry_frame: ef.config(bg=self.ACCENT))
        e.bind("<FocusOut>", lambda ev, ef=entry_frame: ef.config(bg=self.ENTRY_BORDER))

        return var

    def _spin_field(self, parent, label, value=0, from_=1, to=3600, increment=1, width=12):
        row = tk.Frame(parent, bg=self.CARD)
        row.pack(fill="x", padx=self.SP_2, pady=(self.SP_2, 0))

        tk.Label(
            row, text=label, bg=self.CARD, fg=self.TEXT2,
            font=self.FONT_HINT,
        ).pack(anchor="w")

        var = tk.IntVar(value=int(value))

        spin_frame = tk.Frame(row, bg=self.ENTRY_BORDER, padx=1, pady=1)
        spin_frame.pack(anchor="w", pady=(6, 0))

        s = tk.Spinbox(
            spin_frame, textvariable=var, from_=from_, to=to, increment=increment,
            bg=self.ENTRY_BG, fg=self.TEXT, font=self.FONT_BODY,
            insertbackground=self.ACCENT, relief="flat", borderwidth=4,
            width=width, buttonbackground=self.CARD, activebackground=self.ACCENT,
        )
        s.pack()

        s.bind("<FocusIn>", lambda ev, sf=spin_frame: sf.config(bg=self.ACCENT))
        s.bind("<FocusOut>", lambda ev, sf=spin_frame: sf.config(bg=self.ENTRY_BORDER))

        return var

    def _combo_field(self, parent, label, options, current):
        row = tk.Frame(parent, bg=self.CARD)
        row.pack(fill="x", padx=self.SP_2, pady=(self.SP_2, 0))

        tk.Label(
            row, text=label, bg=self.CARD, fg=self.TEXT2,
            font=self.FONT_HINT,
        ).pack(anchor="w")

        var = tk.StringVar(value=current)
        cb = ttk.Combobox(
            row, textvariable=var, values=options, state="readonly", width=24,
            style="TCombobox",
        )
        cb.pack(anchor="w", pady=(6, 0))
        return var

    # ────────────────────────────── 액션 ──────────────────────────────

    def _update_review(self):
        engine_str = "와주 하이브리드" if self.var_engine.get() == "wazuh" else "자체 엔진(Built-in)"
        text = (
            f"• 모니터링 엔진: {engine_str}\n"
            f"• 서버: {self.var_url.get().strip() or '(미입력)'}\n"
            f"• 계정: {self.var_user.get().strip() or '(미입력)'}\n"
            f"• 하트비트: {self.var_heartbeat.get()}초\n"
            f"• 활성 모듈: "
            f"{sum([self.var_col_usb.get(), self.var_col_network.get(), self.var_col_process.get(), self.var_col_filesystem.get(), self.var_col_browser.get(), self.var_col_biometric.get()])}개\n"
            f"• 감시 경로: {self.path_listbox.size()}개\n"
            f"• 로깅 레벨: {self.var_log_level.get()}\n"
            f"• 수리카타 IDS: {'활성화' if self.var_col_suricata.get() else '비활성화'}\n"
            f"• 다크 모드: {'켜짐(다음 실행)' if self.var_dark_mode.get() else '꺼짐'}"
        )
        self.lbl_review.config(text=text)

    def _collect_config(self):
        paths = [p.strip() for p in self.path_listbox.get(0, "end")]
        beacon_existing = self.config_data.get("beacon", {})
        monitoring_existing = self.config_data.get("monitoring", {})
        paths_existing = self.config_data.get("paths", {})
        logging_existing = self.config_data.get("logging", {})
        agent_existing = self.config_data.get("agent", {})
        collectors_existing = self.config_data.get("collectors", {})
        tls_existing = beacon_existing.get("tls", {})

        cfg = {
            "beacon": {
                "server_url": self.var_url.get().strip(),
                "username":   self.var_user.get().strip(),
                "password":   encrypt_password(self.var_pass.get()),
                "ip_selection": self.var_ip_selection.get(),
                "jwt_refresh_before_exp_seconds": self.var_jwt_refresh.get(),
                "tls": {
                    "require_https": bool(self.var_tls_https.get()),
                },
                **{k: v for k, v in beacon_existing.items() if k not in (
                    "server_url", "username", "password", "ip_selection", "jwt_refresh_before_exp_seconds", "tls"
                )},
            },
            "agent": {
                "agent_name": self.var_agent_name.get().strip(),
                "agent_version": self.var_agent_version.get().strip(),
                "heartbeat_interval_seconds": self.var_heartbeat.get(),
                **{k: v for k, v in agent_existing.items() if k not in (
                    "agent_name", "agent_version", "heartbeat_interval_seconds"
                )},
            },
            "collectors": {
                "usb": bool(self.var_col_usb.get()),
                "network": bool(self.var_col_network.get()),
                "process": bool(self.var_col_process.get()),
                "filesystem": bool(self.var_col_filesystem.get()),
                "browser_history": bool(self.var_col_browser.get()),
                "input_biometric": bool(self.var_col_biometric.get()),
                **{k: v for k, v in collectors_existing.items() if k not in (
                    "usb", "network", "process", "filesystem", "browser_history", "input_biometric"
                )},
            },
            "monitoring": {
                "engine":                 self.var_engine.get(),
                "usb_check_interval":     self.var_usb.get(),
                "network_check_interval": self.var_net.get(),
                "process_check_interval": self.var_proc.get(),
                "browser_check_interval": self.var_brow.get(),
                "biometric_flush_interval": self.var_bio_flush.get(),
                "mouse_move_sample_ms": self.var_mouse_sample.get(),
                "biometric_target_samples": self.var_bio_target.get(),
                "biometric_auto_block": bool(self.var_bio_block.get()),
                "include_traffic_raw_data": bool(self.var_include_raw.get()),
                **{k: v for k, v in monitoring_existing.items() if k not in (
                    "engine", "usb_check_interval", "network_check_interval", "process_check_interval",
                    "browser_check_interval", "biometric_flush_interval", "mouse_move_sample_ms",
                    "include_traffic_raw_data"
                )},
            },
            "paths": {
                "watch_dirs": paths,
                "biometric_log_file": self.var_biometric_log.get().strip(),
                **{k: v for k, v in paths_existing.items() if k not in ("watch_dirs", "biometric_log_file")},
            },
            "logging": {
                "level":        self.var_log_level.get(),
                "file":         self.var_log_file.get().strip(),
                "max_bytes":    self.var_max_bytes.get(),
                "backup_count": self.var_backup_cnt.get(),
                **{k: v for k, v in logging_existing.items() if k not in ("level", "file", "max_bytes", "backup_count")},
            },
            "ui": {
                **self.config_data.get("ui", {}),
                "dark_mode": bool(self.var_dark_mode.get()),
            },
            "suricata": {
                "enabled": bool(self.var_col_suricata.get()),
                "manage_process": bool(self.var_suri_manage.get()),
                "binary_path": self.var_suri_bin.get().strip(),
                "config_path": self.var_suri_cfg.get().strip(),
                "eve_log_path": self.var_suri_eve.get().strip(),
                "interface": self.var_suri_iface.get().strip(),
            },
            "wazuh": {
                "enabled": (self.var_engine.get() == "wazuh"),
                "container_name": self.var_wazuh_container.get().strip(),
                "min_level": self.var_wazuh_level.get(),
            }
        }
        for k, v in tls_existing.items():
            if k not in cfg["beacon"]["tls"]:
                cfg["beacon"]["tls"][k] = v
        return cfg

    def _validate(self, cfg):
        if not cfg["beacon"]["server_url"]:
            messagebox.showerror("입력 오류", "Server URL은 필수입니다.")
            return False
        if not cfg["beacon"]["username"]:
            messagebox.showerror("입력 오류", "Username은 필수입니다.")
            return False
        if not cfg["logging"]["file"]:
            messagebox.showerror("입력 오류", "Log file path는 필수입니다.")
            return False
        parsed = urlparse(cfg["beacon"]["server_url"])
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            messagebox.showerror("입력 오류", "Server URL 형식이 올바르지 않습니다. 예: https://localhost:8080")
            return False
        if cfg["beacon"].get("tls", {}).get("require_https", False) and parsed.scheme != "https":
            messagebox.showerror("입력 오류", "HTTPS 강제 설정이 켜져 있어 Server URL은 https:// 이어야 합니다.")
            return False
        if cfg["agent"]["heartbeat_interval_seconds"] < 10 or cfg["agent"]["heartbeat_interval_seconds"] > 299:
            messagebox.showerror("입력 오류", "Heartbeat는 10~299초 사이여야 합니다.")
            return False
        if not cfg["paths"]["watch_dirs"]:
            messagebox.showerror("입력 오류", "감시 경로를 최소 1개 이상 추가하세요.")
            return False
        return True

    def _save_only(self):
        cfg = self._collect_config()
        if not self._validate(cfg):
            return
        save_config(cfg)
        self._update_review()
        self.lbl_status.config(text="설정이 저장되었습니다. (다크 모드는 다음 실행 시 적용)", fg=self.SUCCESS)
        self._flash_status()

    def _save_and_start(self):
        cfg = self._collect_config()
        if not self._validate(cfg):
            return
        save_config(cfg)
        self.lbl_status.config(text="에이전트를 시작합니다...", fg=self.ACCENT)
        self.update()
        try:
            self._agent_process = _launch_agent()
        except Exception:
            self._agent_process = None
        if self.user_role == "user":
            self._agent_launched_session = True
            self._ensure_tray()
            self.withdraw()
        else:
            self.destroy()

    def _flash_status(self):
        """상태 메시지를 3초 후 자동으로 숨김."""
        def clear():
            try:
                self.lbl_status.config(text="")
            except tk.TclError:
                pass
        self.after(3000, clear)

    def _beacon_tls_merged(self):
        """저장 시와 동일하게 UI의 require_https 와 config.yaml 의 ca_bundle 등을 합칩니다."""
        beacon_existing = self.config_data.get("beacon", {})
        tls_existing = dict(beacon_existing.get("tls") or {})
        tls = {
            "require_https": bool(self.var_tls_https.get()),
            "verify": tls_existing.get("verify", True)
        }
        for k, v in tls_existing.items():
            if k not in tls:
                tls[k] = v
        return tls

    def _test_connection(self):
        url = self.var_url.get().strip().rstrip("/")
        user = self.var_user.get().strip()
        pwd = self.var_pass.get()
        tls = self._beacon_tls_merged()

        self.lbl_conn.config(text="◔ 연결 중...", fg=self.WARNING)

        parsed = urlparse(url)
        if tls.get("require_https") and parsed.scheme != "https":
            self._on_connect_fail("HTTPS 강제와 URL이 맞지 않습니다.")
            return

        def do_test():
            session = requests.Session()
            session.headers.update({"User-Agent": "BeaconGuardian-setup/connection-test"})
            try:
                configure_tls_session(session, tls)
                r = session.post(
                    f"{url}/api/auth/login",
                    json={"username": user, "password": pwd},
                    timeout=10,
                )
                if r.status_code == 200:
                    self.after(0, self._on_connect_success)
                else:
                    self.after(0, lambda sc=r.status_code: self._on_connect_fail(f"실패 (HTTP {sc})"))
            except Exception as e:
                self.after(0, lambda en=type(e).__name__: self._on_connect_fail(f"오류: {en}"))
            finally:
                session.close()

        threading.Thread(target=do_test, daemon=True).start()

    def _on_connect_success(self):
        self.lbl_conn.config(text="✓ 연결 성공 · 인증 토큰 수신 가능", fg=self.SUCCESS)
        self.status_dot.delete("all")
        self.status_dot.create_oval(1, 1, 9, 9, fill=self.SUCCESS, outline="")
        self.lbl_header_status.config(text="● 연결됨", fg=self.SUCCESS)

    def _on_connect_fail(self, reason):
        self.lbl_conn.config(text=f"✕ 연결 실패 · {reason}", fg=self.ERROR)
        self.status_dot.delete("all")
        self.status_dot.create_oval(1, 1, 9, 9, fill=self.ERROR, outline="")
        self.lbl_header_status.config(text="● 연결 실패", fg=self.ERROR)

    def _add_path(self):
        d = filedialog.askdirectory(title="감시할 디렉터리 선택")
        if d:
            normalized = os.path.normpath(d)
            existing = {self.path_listbox.get(i).strip().lower() for i in range(self.path_listbox.size())}
            if normalized.lower() in existing:
                self.lbl_status.config(text="이미 등록된 경로입니다.", fg=self.WARNING)
                self._flash_status()
                return
            self.path_listbox.insert("end", normalized)
            self._refresh_path_count()
            self._update_review()

    def _remove_path(self):
        sel = self.path_listbox.curselection()
        for idx in reversed(sel):
            self.path_listbox.delete(idx)
        self._refresh_path_count()
        self._update_review()

    def _dedupe_paths(self):
        seen = set()
        unique = []
        for i in range(self.path_listbox.size()):
            p = self.path_listbox.get(i).strip()
            key = p.lower()
            if key not in seen:
                seen.add(key)
                unique.append(p)
        self.path_listbox.delete(0, "end")
        for p in unique:
            self.path_listbox.insert("end", p)
        self._refresh_path_count()
        self._update_review()

    def _refresh_path_count(self):
        self.lbl_path_count.config(text=f"{self.path_listbox.size()}개 경로")

    # ────────────────────────────── 유틸 ──────────────────────────────

    def _center_window(self, w, h):
        self.update_idletasks()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        x = (sw - w) // 2
        y = (sh - h) // 2
        self.geometry(f"{w}x{h}+{x}+{y}")

    def _on_scan_connections(self):
        """백그라운드에서 연결 목록 및 호스트명 조회"""
        import psutil
        import socket
        
        for item in self.tree_conn.get_children():
            self.tree_conn.delete(item)

        self.lbl_status.config(text="네트워크 연결 스캔 중...", fg=self.WARNING)

        def _scan_worker():
            from concurrent.futures import ThreadPoolExecutor
            import psutil
            import socket

            def _get_hostname(ip):
                try:
                    return socket.gethostbyaddr(ip)[0]
                except:
                    return "(알 수 없음)"

            try:
                connections = psutil.net_connections(kind="inet")
                established = [c for c in connections if c.status == "ESTABLISHED" and c.raddr]
                count = 0
                
                # 병렬 처리를 위한 Executor (최대 20개 동시 조회)
                with ThreadPoolExecutor(max_workers=20) as executor:
                    futures = []
                    for conn in established:
                        proto = "TCP" if conn.type == 1 else "UDP"
                        l_addr = f"{conn.laddr.ip}:{conn.laddr.port}"
                        r_ip = conn.raddr.ip
                        r_port = conn.raddr.port
                        
                        if r_ip in ("127.0.0.1", "::1"): continue
                        
                        # 도메인 조회를 별도 작업으로 제출
                        futures.append((proto, l_addr, r_ip, r_port, executor.submit(_get_hostname, r_ip)))
                    
                    # 결과가 나오는 대로 UI 업데이트
                    for proto, l_addr, r_ip, r_port, future in futures:
                        hostname = future.result()
                        self.after(0, lambda p=proto, l=l_addr, ri=r_ip, h=hostname, rp=r_port: 
                                   self.tree_conn.insert("", "end", values=(p, l, ri, h, rp)))
                        count += 1
                
                self.after(0, lambda c=count: self.lbl_status.config(text=f"{c}개의 연결을 찾았습니다.", fg=self.SUCCESS))
            except Exception as e:
                self.after(0, lambda msg=str(e): messagebox.showerror("오류", f"스캔 실패: {msg}"))

        threading.Thread(target=_scan_worker, daemon=True).start()

    def _on_select_active_ip(self, event):
        """테이블에서 선택한 IP를 차단 입력란에 자동 입력"""
        selected_item = self.tree_conn.selection()
        if not selected_item:
            return
            
        values = self.tree_conn.item(selected_item[0], "values")
        if values:
            selected_ip = values[2] # RemoteIP column
            self.var_target_ip.set(selected_ip)
            self.lbl_status.config(text=f"차단 대상으로 {selected_ip}가 선택되었습니다.", fg=self.ACCENT)
            self._flash_status()

    def _on_double_click_active_ip(self, event):
        """더블클릭 시 해당 IP의 보안 정보를 브라우저에서 열기 (VirusTotal)"""
        import webbrowser
        selected_item = self.tree_conn.selection()
        if not selected_item:
            return
            
        values = self.tree_conn.item(selected_item[0], "values")
        if values:
            selected_ip = values[2] # RemoteIP column
            url = f"https://www.virustotal.com/gui/ip-address/{selected_ip}"
            
            # 사용자에게 안내 후 브라우저 열기
            self.lbl_status.config(text=f"상세 정보 조회 중: {selected_ip}...", fg=self.ACCENT)
            self._flash_status()
            webbrowser.open(url)

    def _build_step7(self, parent):
        wrap = self._section(parent, "제로트러스트 및 긴급 대응", "생체 인증 모델 상태 관리 및 방화벽 긴급 제어")
        
        # 1. 생체 인증 엔진 상태
        card1 = self._card(wrap)
        tk.Label(card1, text="마우스 생체 인증 맞춤 학습 상태", font=self.FONT_SUBTITLE, bg=self.CARD, fg=self.ACCENT).pack(anchor="w", pady=(0, 10))
        
        self.lbl_bio_mode = tk.Label(card1, text="상태: 확인 중...", font=self.FONT_BODY, bg=self.CARD, fg=self.TEXT)
        self.lbl_bio_mode.pack(anchor="w")
        
        self.bio_progress = ttk.Progressbar(card1, orient="horizontal", length=400, mode="determinate")
        self.bio_progress.pack(fill="x", pady=10)
        
        self.lbl_bio_progress = tk.Label(card1, text="진행률: 0%", font=self.FONT_HINT, bg=self.CARD, fg=self.MUTED)
        self.lbl_bio_progress.pack(anchor="w")

        btn_row = tk.Frame(card1, bg=self.CARD)
        btn_row.pack(fill="x", pady=(10, 0))
        ttk.Button(btn_row, text="모델 최신화/재학습", style="Ghost.TButton", command=self._on_reset_bio_model).pack(side="left")

        # 2. 긴급 조치
        card2 = self._card(wrap)
        tk.Label(card2, text="네트워크 긴급 대응", font=self.FONT_SUBTITLE, bg=self.CARD, fg=self.ERROR).pack(anchor="w", pady=(0, 10))
        
        # 관리자 권한 체크 경고 추가
        import ctypes
        def is_admin():
            try: return ctypes.windll.shell32.IsUserAnAdmin()
            except: return False
        
        if not is_admin():
            tk.Label(card2, text="⚠️ 관리자 권한이 필요합니다. (방화벽 제어 불가)", font=self.FONT_HINT, bg=self.ERROR_BG, fg=self.ERROR, padx=5, pady=2).pack(anchor="w", pady=(0, 10))

        self.lbl_net_status = tk.Label(card2, text="네트워크 상태: 정상", font=self.FONT_BODY, bg=self.CARD, fg=self.TEXT)
        self.lbl_net_status.pack(anchor="w")

        # 특정 IP 입력 필드
        ip_row = tk.Frame(card2, bg=self.CARD)
        ip_row.pack(fill="x", pady=(10, 0))
        tk.Label(ip_row, text="차단 대상 IP:", bg=self.CARD, fg=self.TEXT2, font=self.FONT_HINT).pack(side="left")
        self.var_target_ip = tk.StringVar(value="8.8.8.8")
        ip_entry = tk.Entry(ip_row, textvariable=self.var_target_ip, width=15, font=self.FONT_BODY, bg=self.ENTRY_BG, fg=self.TEXT, relief="flat", highlightthickness=1, highlightbackground=self.ENTRY_BORDER)
        ip_entry.pack(side="left", padx=5)

        btn_row2 = tk.Frame(card2, bg=self.CARD)
        btn_row2.pack(fill="x", pady=(10, 0))
        ttk.Button(btn_row2, text="전체 네트워크 차단 (테스트)", style="Danger.TButton", command=lambda: self._on_manual_block_network(all_net=True)).pack(side="left", padx=(0, 10))
        ttk.Button(btn_row2, text="특정 IP 차단", style="Ghost.TButton", command=lambda: self._on_manual_block_network(all_net=False)).pack(side="left", padx=(0, 10))
        ttk.Button(btn_row2, text="모든 차단 해제", style="Success.TButton", command=self._on_unblock_network).pack(side="left")
        
        # 3. 현재 활성 연결 모니터링
        card3 = self._card(wrap)
        tk.Label(card3, text="실시간 활성 연결 (Established)", font=self.FONT_SUBTITLE, bg=self.CARD, fg=self.ACCENT).pack(anchor="w", pady=(0, 5))
        
        tree_frame = tk.Frame(card3, bg=self.ENTRY_BG, highlightthickness=1, highlightbackground=self.ENTRY_BORDER)
        tree_frame.pack(fill="x", pady=5)
        
        cols = ("Proto", "Local", "RemoteIP", "Hostname", "RemotePort")
        self.tree_conn = ttk.Treeview(tree_frame, columns=cols, show="headings", height=10)
        self.tree_conn.heading("Proto", text="프로토콜")
        self.tree_conn.heading("Local", text="로컬 주소")
        self.tree_conn.heading("RemoteIP", text="외부 IP")
        self.tree_conn.heading("Hostname", text="도메인(호스트명)")
        self.tree_conn.heading("RemotePort", text="포트")
        
        self.tree_conn.column("Proto", width=60, anchor="center")
        self.tree_conn.column("Local", width=150, anchor="w")
        self.tree_conn.column("RemoteIP", width=130, anchor="w")
        self.tree_conn.column("Hostname", width=220, anchor="w")
        self.tree_conn.column("RemotePort", width=60, anchor="center")
        
        self.tree_conn.pack(side="left", fill="x", expand=True)
        scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree_conn.yview)
        self.tree_conn.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        
        self.tree_conn.bind("<<TreeviewSelect>>", self._on_select_active_ip)
        self.tree_conn.bind("<Double-1>", self._on_double_click_active_ip)

        btn_row3 = tk.Frame(card3, bg=self.CARD)
        btn_row3.pack(fill="x", pady=(5, 0))
        ttk.Button(btn_row3, text="현재 연결 스캔 ↻", style="Ghost.TButton", command=self._on_scan_connections).pack(side="left")
        tk.Label(btn_row3, text="* 목록에서 IP를 클릭하면 차단 대상으로 자동 입력됩니다.", font=self.FONT_HINT, bg=self.CARD, fg=self.MUTED).pack(side="left", padx=10)

        # 주기적 업데이트 시작
        self._update_zt_status()

    def _update_zt_status(self):
        """생체 인증 상태 및 차단 상태 업데이트 (성능을 위해 백그라운드 실행)"""
        if not self.winfo_exists():
            return

        def _worker():
            try:
                # 1. 네트워크 차단 여부 확인 (PowerShell 실행 - 느림)
                from firewall.local_block_controller import LocalBlockController
                lbc = LocalBlockController()
                is_blocked = lbc.is_blocked()

                # 2. 생체 인증 엔진 모드/진행률 확인
                mode = "UNKNOWN"
                prog = 0.0
                
                log_path = self.config_data.get("paths", {}).get("biometric_log_file", "logs/biometric_input.jsonl")
                if not os.path.isabs(log_path):
                    from agent import ROOT_DIR
                    log_path = os.path.join(ROOT_DIR, log_path)
                
                if os.path.exists(log_path):
                    with open(log_path, 'rb') as f:
                        f.seek(0, os.SEEK_END)
                        pos = f.tell()
                        f.seek(max(0, pos - 4096))
                        lines = f.readlines()
                        if lines:
                            for line in reversed(lines):
                                try:
                                    data = json.loads(line.decode('utf-8', errors='ignore'))
                                    if "engine_mode" in data:
                                        mode = data.get("engine_mode", "UNKNOWN")
                                        prog = float(data.get("progress", 0.0))
                                        break
                                except: continue
                
                # UI 업데이트는 다시 메인 스레드에서 호출
                self.after(0, lambda m=mode, p=prog, b=is_blocked: self._apply_zt_updates(m, p, b))
            except Exception:
                pass

        threading.Thread(target=_worker, daemon=True).start()
        # 다음 체크는 3초 후 (부하 경감)
        self.after(3000, self._update_zt_status)

    def _apply_zt_updates(self, mode, prog, is_blocked):
        if not self.winfo_exists():
            return
            
        # 1. 방화벽 상태 표시
        if is_blocked:
            self.lbl_net_status.config(text="네트워크 상태: 차단됨 (이상 탐지)", fg=self.ERROR)
        else:
            self.lbl_net_status.config(text="네트워크 상태: 정상", fg=self.SUCCESS)

        # 2. 생체 인증 엔진 상태 표시
        mode_map = {
            "COLLECTING": "학습 데이터 수집 중 (마우스를 움직이세요)",
            "TRAINING": "패턴 학습 중 (잠시만 기다려 주세요)", 
            "GUARDING": "사용자 보호 중 (실시간 모니터링)"
        }
        self.lbl_bio_mode.config(text=f"상태: {mode_map.get(mode, mode)}")
        self.bio_progress["value"] = prog
        self.lbl_bio_progress.config(text=f"진행률: {prog:.1f}%")

    def _build_step8(self, parent):
        wrap = self._section(parent, "통합 위협 진단 및 시뮬레이션", "버튼을 클릭하여 각 보안 모듈의 수집 성능을 테스트하세요.")
        
        # 1. 시뮬레이션 (Virtual)
        card1 = self._card(wrap)
        tk.Label(card1, text="가상 위협 시뮬레이션 (Injection)", font=self.FONT_SUBTITLE, bg=self.CARD, fg=self.ACCENT).pack(anchor="w", pady=(0, 10))
        
        btn_row1 = tk.Frame(card1, bg=self.CARD)
        btn_row1.pack(fill="x", pady=5)
        ttk.Button(btn_row1, text="IDS 경보 주입 (Suricata)", style="Ghost.TButton", 
                   command=lambda: self._run_gui_test("ids-v")).pack(side="left", padx=(0, 10))
        ttk.Button(btn_row1, text="행위 이상 주입 (Biometric)", style="Ghost.TButton", 
                   command=lambda: self._run_gui_test("bio")).pack(side="left")

        # 2. 실기 테스트 (Direct)
        card2 = self._card(wrap)
        tk.Label(card2, text="실제 위협 트리거 테스트 (Direct)", font=self.FONT_SUBTITLE, bg=self.CARD, fg=self.WARNING).pack(anchor="w", pady=(0, 10))
        
        btn_row2 = tk.Frame(card2, bg=self.CARD)
        btn_row2.pack(fill="x", pady=5)
        ttk.Button(btn_row2, text="파일 감시 테스트 (File)", style="Ghost.TButton", 
                   command=lambda: self._run_gui_test("file")).pack(side="left", padx=(0, 10))
        ttk.Button(btn_row2, text="네트워크 IDS 트리거 (Real)", style="Ghost.TButton", 
                   command=lambda: self._run_gui_test("ids-r")).pack(side="left")

        # 3. 인터랙티브 수집 테스트 (전/후 비교 Diff) - [NEW]
        card_diff = self._card(wrap)
        tk.Label(card_diff, text="인터랙티브 수집 테스트 (전/후 비교)", font=self.FONT_SUBTITLE, bg=self.CARD, fg="#8b5cf6").pack(anchor="w", pady=(0, 5))
        tk.Label(card_diff, text="실제 환경 변화(USB 연결, 프로세스 실행 등) 전후의 상태를 비교하여 감증합니다.", font=self.FONT_HINT, bg=self.CARD, fg=self.MUTED).pack(anchor="w", pady=(0, 10))
        
        btn_row_diff = tk.Frame(card_diff, bg=self.CARD)
        btn_row_diff.pack(fill="x", pady=5)
        
        self.btn_capture = ttk.Button(btn_row_diff, text="[1] 현재 상태 캡처 (Before)", style="Accent.TButton", 
                                      command=self._on_capture_snapshot)
        self.btn_capture.pack(side="left", padx=(0, 10))
        
        self.btn_diff_proc = ttk.Button(btn_row_diff, text="[2] 프로세스 변동 확인 (After)", state="disabled",
                                        command=lambda: self._on_check_diff_test("process"))
        self.btn_diff_proc.pack(side="left", padx=(0, 5))
        
        self.btn_diff_usb = ttk.Button(btn_row_diff, text="[2] USB 변동 확인 (After)", state="disabled",
                                       command=lambda: self._on_check_diff_test("usb"))
        self.btn_diff_usb.pack(side="left")

        # 4. 진단 콘솔
        tk.Label(wrap, text="진단 로그 콘솔", font=self.FONT_SUBTITLE, bg=self.BG, fg=self.TEXT).pack(anchor="w", pady=(10, 5))
        
        console_frame = tk.Frame(wrap, bg=self.ENTRY_BG, highlightthickness=1, highlightbackground=self.ENTRY_BORDER)
        console_frame.pack(fill="both", expand=True)
        
        scroll = tk.Scrollbar(console_frame, bg=self.BG2, troughcolor=self.ENTRY_BG)
        scroll.pack(side="right", fill="y")
        
        self.diag_console = tk.Text(
            console_frame, height=12, bg=self.ENTRY_BG, fg=self.TEXT2, 
            font=("Consolas", 10), relief="flat", padx=10, pady=10,
            yscrollcommand=scroll.set
        )
        self.diag_console.pack(fill="both", expand=True)
        scroll.config(command=self.diag_console.yview)
        
        self._diag_log("진단 시스템 준비 완료. 테스트할 항목을 선택하세요.")

    def _diag_log(self, msg, level="INFO"):
        if not hasattr(self, "diag_console"): return
        time_str = datetime.now().strftime("%H:%M:%S")
        color = self.TEXT2
        if "[SUCCESS]" in msg or level == "SUCCESS": color = self.SUCCESS
        elif "[ERROR]" in msg or level == "ERROR": color = self.ERROR
        elif "[INFO]" in msg: color = self.ACCENT
        
        self.diag_console.insert("end", f"[{time_str}] ", self.MUTED)
        tag_name = f"tag_{level}_{time.time()}"
        self.diag_console.tag_configure(tag_name, foreground=color)
        self.diag_console.insert("end", f"{msg}\n", tag_name)
        self.diag_console.see("end")

    def _run_gui_test(self, scenario):
        self._diag_log(f"시나리오 '{scenario}' 실행 시도 중...", "INFO")
        
        # Circular import 방지를 위해 메서드 내부에서 임포트
        try:
            from agent import SecurityAgent
            cfg = self._collect_config()
            # 임무 대리 수행을 위한 임시 에이전트 객체 (네트워크 전송 등은 실제 설정 기반)
            agent_temp = SecurityAgent(config_path=None) 
            agent_temp.config = cfg # 현재 UI의 설정을 주입
            
            # [ADD] 현재 로그인된 세션 토큰 주입 (재로그인 방지 및 즉시 전송 가능)
            if hasattr(self, 'token') and self.token:
                agent_temp.client._set_token(self.token)
            
            # 수동으로 로직 호출 (이전 agent.py 수정 시 추가한 메서드)
            agent_temp.run_test_scenario(scenario)
            self._diag_log(f"시나리오 '{scenario}' 실행 명령 전송 완료.", "SUCCESS")
            self._diag_log("웹 대시보드(Threats)에서 결과를 확인하세요.")
        except Exception as e:
            self._diag_log(f"테스트 실행 중 오류 발생: {e}", "ERROR")

    def _on_capture_snapshot(self):
        self.btn_capture.config(state="disabled")
        self._diag_log("현재 시스템 상태를 분석 중입니다 (수초 소요)...", "INFO")
        
        def _task():
            try:
                from agent import SecurityAgent
                if not self._diag_agent:
                    self._diag_agent = SecurityAgent(config_path=None)
                    self._diag_agent.config = self._collect_config()
                    if hasattr(self, 'token') and self.token:
                        self._diag_agent.client._set_token(self.token)
                
                self._snapshot_memory = self._diag_agent.get_system_snapshot()
                
                u_cnt = len(self._snapshot_memory.get("usb", {}))
                p_cnt = len(self._snapshot_memory.get("processes", {}))
                
                self.after(0, lambda: self._diag_log(f"[캡처 완료] USB: {u_cnt}개, 프로세스: {p_cnt}개", "SUCCESS"))
                self.after(0, lambda: self._diag_log("이제 환경 변화를 일으킨 후 [After] 버튼을 누르세요."))
                self.after(0, self._enable_after_buttons)
            except Exception as e:
                self.after(0, lambda: self._diag_log(f"캡처 실패: {e}", "ERROR"))
                self.after(0, lambda: self.btn_capture.config(state="normal"))

        threading.Thread(target=_task, daemon=True).start()

    def _enable_after_buttons(self):
        self.btn_capture.config(state="normal")
        self.btn_diff_proc.config(state="normal")
        self.btn_diff_usb.config(state="normal")

    def _on_check_diff_test(self, scenario):
        if not self._snapshot_memory:
            self._diag_log("기준 스냅샷이 없습니다. [1]단계를 먼저 수행하세요.", "WARNING")
            return
            
        btn = self.btn_diff_proc if scenario == "process" else self.btn_diff_usb
        old_state = btn['state']
        btn.config(state="disabled")
        self._diag_log(f"'{scenario}' 변동 사항 정밀 분석 중...", "INFO")
        
        def _task():
            try:
                diff = self._diag_agent.run_diff_test(self._snapshot_memory, scenario)
                def _report():
                    if not diff:
                        self._diag_log("변동 사항이 감지되지 않았습니다.", "WARNING")
                    else:
                        for line in diff:
                            self._diag_log(line, "SUCCESS")
                        self._diag_log("발견된 변동 사항이 서버 대시보드로 전송되었습니다.")
                    btn.config(state=old_state)
                
                self.after(0, _report)
            except Exception as e:
                self.after(0, lambda: self._diag_log(f"비교 테스트 실패: {e}", "ERROR"))
                self.after(0, lambda: btn.config(state=old_state))

        threading.Thread(target=_task, daemon=True).start()

    def _on_reset_bio_model(self):
        if messagebox.askyesno("확인", "기존 학습된 생체 인증 모델을 삭제하고 처음부터 다시 학습할까요?"):
            from agent import ROOT_DIR
            m_dir = os.path.join(ROOT_DIR, "models", "biometric")
            try:
                import shutil
                if os.path.exists(m_dir):
                    shutil.rmtree(m_dir)
                messagebox.showinfo("성공", "모델이 초기화되었습니다. 에이전트 재시작 시 새로운 학습이 시작됩니다.")
            except Exception as e:
                messagebox.showerror("오류", f"초기화 실패: {e}")

    def _on_unblock_network(self):
        try:
            from firewall.local_block_controller import LocalBlockController
            lbc = LocalBlockController()
            if lbc.unblock_network():
                messagebox.showinfo("성공", "네트워크 차단이 해제되었습니다.")
                self._update_zt_status()
            else:
                messagebox.showerror("오류", f"차단 해제 실패. 관리자 권한을 확인하세요.")
        except Exception as e:
            messagebox.showerror("오류", f"차단 해제 중 오류: {e}")

    def _on_manual_block_network(self, all_net=True):
        target = "Any" if all_net else self.var_target_ip.get().strip()
        msg = "전체 네트워크를 차단할까요?" if all_net else f"특정 IP ({target})를 차단할까요?"
        
        if not target and not all_net:
            messagebox.showwarning("경고", "차단할 IP 주소를 입력해 주세요.")
            return

        if messagebox.askyesno("확인", f"테스트를 위해 {msg}\n(해제 전까지 해당 통신이 중단됩니다.)"):
            try:
                from firewall.local_block_controller import LocalBlockController
                lbc = LocalBlockController()
                if lbc.block_network(remote_ip=target, reason="Manual block from UI"):
                    messagebox.showwarning("주의", f"{target} 차단이 완료되었습니다.")
                    self._update_zt_status()
                else:
                    messagebox.showerror("오류", "차단 실패. 관리자 권한을 확인하세요.")
            except Exception as e:
                messagebox.showerror("오류", f"차단 연동 중 오류: {e}")

    def _on_engine_change(self):
        """엔진 선택에 따라 수집 주기 등 관련 필드의 활성 상태를 변경합니다."""
        is_wazuh = (self.var_engine.get() == "wazuh")
        # Wazuh가 관리하는 영역은 에이전트 내 수집 주기 설정을 비활성화하여 혼선 방지 로직 (필요시 추가)
        pass

    def _build_step9_wazuh(self, parent):
        wrap = self._section(parent, "Wazuh 하이브리드 연동 설정", "도커 환경의 Wazuh 매니저와 연합 보안 체계를 구성합니다.")
        
        # 1. 컨테이너 연동 정보
        card1 = self._card(wrap)
        tk.Label(card1, text="Wazuh 매니저(Docker) 정보", font=self.FONT_SUBTITLE, bg=self.CARD, fg=self.ACCENT).pack(anchor="w", pady=(0, 10))
        
        self._field(card1, "Wazuh Manager Container Name", self.var_wazuh_container.get(), bind_var=self.var_wazuh_container)
        
        status_row = tk.Frame(card1, bg=self.CARD)
        status_row.pack(fill="x", padx=self.SP_2, pady=(self.SP_2, 0))
        
        ttk.Button(status_row, text="Wazuh 상태 체크", style="Success.TButton", command=self._test_wazuh_connection).pack(side="left")
        self.lbl_wazuh_status = tk.Label(status_row, text="○ 도커 연결 확인 전", bg=self.CARD, fg=self.MUTED, font=self.FONT_HINT)
        self.lbl_wazuh_status.pack(side="left", padx=12)

        # 2. 알람 정책 (최소 레벨)
        card2 = self._card(wrap)
        tk.Label(card2, text="알람 전송 정책 (Noise Reduction)", font=self.FONT_SUBTITLE, bg=self.CARD, fg=self.WARNING).pack(anchor="w", pady=(0, 10))
        
        tk.Label(card2, text="비콘 서버로 전송할 최소 Wazuh 레벨 (추천: 5)", bg=self.CARD, fg=self.TEXT2, font=self.FONT_BODY).pack(anchor="w", padx=self.SP_2)
        
        lvl_frame = tk.Frame(card2, bg=self.CARD)
        lvl_frame.pack(fill="x", padx=self.SP_2, pady=(5, 15))
        
        scale = tk.Scale(
            lvl_frame, variable=self.var_wazuh_level, from_=1, to=15, 
            orient="horizontal", bg=self.CARD, highlightthickness=0,
            fg=self.ACCENT, font=self.FONT_HINT, length=500
        )
        scale.pack(side="left")

        # 3. 안내 문구
        note_card = self._card(wrap)
        note_text = (
            "💡 [Wazuh Hybrid Mode 안내]\n"
            "- 이 모드에서는 프로세스 미세 감시 및 파일 무결성 체크(FIM)를 Wazuh가 담당합니다.\n"
            "- 에이전트의 생체 인증(Mouse Bio) 및 USB DLP 기능은 별도로 동작하며 결과가 통합됩니다.\n"
            "- 도커 컨테이너가 로컬에서 실행 중이어야 실시간 로그 수집이 가능합니다."
        )
        tk.Label(note_card, text=note_text, justify="left", bg=self.CARD, fg=self.MUTED, font=self.FONT_HINT, padx=15, pady=15).pack(fill="both")

    def _test_wazuh_connection(self):
        container = self.var_wazuh_container.get().strip()
        self.lbl_wazuh_status.config(text="◔ 체크 중...", fg=self.WARNING)
        
        def _check():
            try:
                import subprocess
                cmd = ["docker", "exec", container, "ls", "/var/ossec/logs/alerts/alerts.json"]
                creationflags = 0
                if sys.platform == "win32":
                    creationflags = 0x08000000 
                
                result = subprocess.run(cmd, capture_output=True, creationflags=creationflags, timeout=5)
                if result.returncode == 0:
                    self.after(0, lambda: self.lbl_wazuh_status.config(text="✓ 연결 성공 (alerts.json 확인됨)", fg=self.SUCCESS))
                else:
                    self.after(0, lambda: self.lbl_wazuh_status.config(text="✕ 연결 실패 (컨테이너/파일 없음)", fg=self.ERROR))
            except Exception as e:
                self.after(0, lambda: self.lbl_wazuh_status.config(text=f"✕ 오류: {str(e)[:20]}", fg=self.ERROR))

        threading.Thread(target=_check, daemon=True).start()


# ────────────────────────────── 에이전트 실행 ──────────────────────────────

def _launch_agent():
    import subprocess

    if getattr(sys, "frozen", False):
        agent_exe = os.path.join(ROOT_DIR, "BeaconGuardianAgent.exe")
        cmd = [agent_exe, "--no-ui", "--config", CONFIG_PATH]
    else:
        agent_path = os.path.join(ROOT_DIR, "src", "agent.py")
        cmd = [sys.executable, agent_path, "--no-ui", "--config", CONFIG_PATH]

    # Windows: 새 콘솔 창을 띄우지 않음(백그라운드 에이전트는 GUI와 동일하게 무콘솔 권장)
    if sys.platform == "win32":
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    else:
        creationflags = 0
    return subprocess.Popen(cmd, creationflags=creationflags)


def _run_user_background_shell():
    """유저 로그인(백그라운드): 관리자가 저장한 config로 에이전트만 기동 + 트레이. 설정 마법사는 띄우지 않음."""
    import tkinter as tk
    from tkinter import ttk

    AppContext.set_role("user")
    root = tk.Tk()
    root.title("BeaconGuardian")
    root.withdraw()
    root.minsize(380, 130)
    root.resizable(False, False)

    frm = ttk.Frame(root, padding=20)
    ttk.Label(
        frm,
        text="에이전트가 백그라운드에서 실행 중입니다.\n(관리자가 저장한 설정·config.yaml)",
        justify="center",
    ).pack()
    ttk.Button(frm, text="트레이로 숨기기", command=root.withdraw).pack(pady=(14, 0))
    frm.pack(fill="both", expand=True)

    tray_ref = [None]

    def show():
        root.deiconify()
        root.lift()
        root.update_idletasks()
        w, h = 460, 160
        sw = root.winfo_screenwidth()
        sh = root.winfo_screenheight()
        root.geometry(f"{w}x{h}+{(sw - w) // 2}+{(sh - h) // 2}")

    def _start_tray():
        try:
            from ui.tray_icon import start_tray

            tray_ref[0] = start_tray(
                root,
                on_open=show,
                can_quit=False,
                on_quit=None,
            )
        except Exception:
            root.iconify()

    def _cleanup():
        try:
            from ui.tray_icon import stop_tray

            stop_tray(tray_ref[0])
        except Exception:
            pass

    root.protocol("WM_DELETE_WINDOW", root.withdraw)

    try:
        _launch_agent()
    except Exception:
        pass

    root.after(150, _start_tray)
    try:
        root.mainloop()
    finally:
        _cleanup()


def run_setup(force=False):
    """
    force=True  -> 로그인 후 설정 UI (역할에 따라 트레이·종료 정책 적용)
    force=False -> config.yaml 있으면 UI 없이 에이전트만 기동
    """
    if not force and os.path.exists(CONFIG_PATH):
        _launch_agent()
        return

    cfg = load_config() if os.path.exists(CONFIG_PATH) else DEFAULT_CONFIG
    ui = cfg.get("ui", {})
    if ui.get("skip_login"):
        dr = ui.get("default_role", "admin")
        role = dr if dr in ("admin", "user") else "admin"
        AppContext.set_role(role)
        login_prefill = None
    else:
        from ui.login_dialog import USER_LOGIN_BACKGROUND, run_login

        out = run_login()
        if out is None:
            return
        if out is USER_LOGIN_BACKGROUND:
            _run_user_background_shell()
            return
        role, url, user, token = out
        login_prefill = (url, user)

    app = SetupApp(role=role, login_prefill=login_prefill, token=token)
    app.mainloop()


if __name__ == "__main__":
    run_setup(force=True)
