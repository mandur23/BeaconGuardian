import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import yaml
import os
import platform
import sys
import threading
import requests
from urllib.parse import urlparse

from core.app_context import AppContext
from core.credential_store import encrypt_password, decrypt_password, is_encrypted

# 프로젝트 루트: 번들(frozen) 시 EXE 위치, 일반 실행 시 src/의 부모 폴더
if getattr(sys, 'frozen', False):
    ROOT_DIR = os.path.dirname(os.path.abspath(sys.executable))
else:
    # ui/setup_ui.py -> src/ui -> src -> project root
    ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CONFIG_PATH = os.path.join(ROOT_DIR, "config.yaml")

DEFAULT_CONFIG = {
    "beacon": {
        "server_url": "https://localhost:8080",
        "username": "admin",
        "password": "",
        "tls": {
            "require_https": True,
        },
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
    "ui": {
        "dark_mode": False,
        "skip_login": False,
        "default_role": "admin",
        "admin_usernames": [],
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
    def __init__(self, role="admin", login_prefill=None):
        super().__init__()
        self.title("BeaconGuardian Setup")
        self.minsize(920, 680)
        self.resizable(False, False)
        self.user_role = role if role in ("admin", "user") else "admin"
        AppContext.set_role(self.user_role)
        self._tray_icon = None
        self._agent_launched_session = False
        self._agent_process = None

        self.config_data = load_config()
        self.current_step = 0
        self.total_steps = 5

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
        for name in ("1. 서버", "2. 모니터링", "3. 경로/로그", "4. 고급/검토", "5. 시스템"):
            f = tk.Frame(self.nb, bg=self.BG)
            self.nb.add(f, text=name)
            self.step_frames.append(f)

        self._build_step1(self.step_frames[0])
        self._build_step2(self.step_frames[1])
        self._build_step3(self.step_frames[2])
        self._build_step4(self.step_frames[3])
        self._build_step5(self.step_frames[4])

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
            ag.get("heartbeat_interval_seconds", 60),
            from_=10,
            to=299,
            width=10,
        )

    def _build_step2(self, parent):
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

        opts = [
            ("USB", self.var_col_usb),
            ("Network", self.var_col_network),
            ("Process", self.var_col_process),
            ("Filesystem", self.var_col_filesystem),
            ("Browser History", self.var_col_browser),
            ("Input Biometric", self.var_col_biometric),
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
        ]
        title, hint = titles[self.current_step]
        self.lbl_step_title.config(text=title)
        self.lbl_step_hint.config(text=hint)
        self._draw_progress()
        self.btn_prev.config(state=("normal" if self.current_step > 0 else "disabled"))
        self.btn_next.config(state=("normal" if self.current_step < self.total_steps - 1 else "disabled"))
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
        text = (
            f"• 서버: {self.var_url.get().strip() or '(미입력)'}\n"
            f"• 계정: {self.var_user.get().strip() or '(미입력)'}\n"
            f"• 하트비트: {self.var_heartbeat.get()}초\n"
            f"• 활성 모듈: "
            f"{sum([self.var_col_usb.get(), self.var_col_network.get(), self.var_col_process.get(), self.var_col_filesystem.get(), self.var_col_browser.get(), self.var_col_biometric.get()])}개\n"
            f"• 감시 경로: {self.path_listbox.size()}개\n"
            f"• 로그 레벨: {self.var_log_level.get()}\n"
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
                "usb_check_interval":     self.var_usb.get(),
                "network_check_interval": self.var_net.get(),
                "process_check_interval": self.var_proc.get(),
                "browser_check_interval": self.var_brow.get(),
                "biometric_flush_interval": self.var_bio_flush.get(),
                "mouse_move_sample_ms": self.var_mouse_sample.get(),
                "include_traffic_raw_data": bool(self.var_include_raw.get()),
                **{k: v for k, v in monitoring_existing.items() if k not in (
                    "usb_check_interval", "network_check_interval", "process_check_interval",
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

    def _test_connection(self):
        url = self.var_url.get().strip().rstrip("/")
        user = self.var_user.get().strip()
        pwd = self.var_pass.get()

        self.lbl_conn.config(text="◔ 연결 중...", fg=self.WARNING)

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
                    self.after(0, lambda sc=r.status_code: self._on_connect_fail(f"실패 (HTTP {sc})"))
            except Exception as e:
                self.after(0, lambda en=type(e).__name__: self._on_connect_fail(f"오류: {en}"))

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


# ────────────────────────────── 에이전트 실행 ──────────────────────────────

def _launch_agent():
    import subprocess

    if getattr(sys, "frozen", False):
        agent_exe = os.path.join(ROOT_DIR, "BeaconGuardianAgent.exe")
        cmd = [agent_exe, "--no-ui", "--config", CONFIG_PATH]
    else:
        agent_path = os.path.join(ROOT_DIR, "src", "agent.py")
        cmd = [sys.executable, agent_path, "--no-ui", "--config", CONFIG_PATH]

    return subprocess.Popen(cmd, creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0))


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
        role, url, user = out
        login_prefill = (url, user)

    app = SetupApp(role=role, login_prefill=login_prefill)
    app.mainloop()


if __name__ == "__main__":
    run_setup(force=True)
