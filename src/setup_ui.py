import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import yaml
import os
import sys
import threading
import requests

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
    "monitoring": {
        "usb_check_interval": 5,
        "network_check_interval": 10,
        "process_check_interval": 5,
        "browser_check_interval": 30,
    },
    "paths": {
        "watch_dirs": [
            "C:\\Windows\\System32",
            f"C:\\Users\\{os.getenv('USERNAME', 'User')}\\Documents",
        ]
    },
    "logging": {
        "level": "INFO",
        "file": "agent.log",
        "max_bytes": 10485760,
        "backup_count": 5,
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
        self.title("BeaconGuardian — 초기 설정")
        self.resizable(False, False)
        self.config_data = load_config()
        self._setup_style()
        self._build_ui()
        self._center_window(720, 560)

    # ────────────────────────────── 스타일 ──────────────────────────────

    def _setup_style(self):
        self.BG = "#0f1117"
        self.CARD = "#1a1d27"
        self.ACCENT = "#4f8ef7"
        self.ACCENT2 = "#6c5ce7"
        self.TEXT = "#e2e8f0"
        self.MUTED = "#64748b"
        self.SUCCESS = "#22c55e"
        self.ERROR = "#ef4444"
        self.BORDER = "#2d3148"
        self.ENTRY_BG = "#252837"

        self.configure(bg=self.BG)

        style = ttk.Style(self)
        style.theme_use("clam")

        style.configure("TNotebook", background=self.BG, borderwidth=0)
        style.configure(
            "TNotebook.Tab",
            background=self.CARD,
            foreground=self.MUTED,
            padding=[18, 8],
            font=("Segoe UI", 10),
            borderwidth=0,
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", self.BG)],
            foreground=[("selected", self.ACCENT)],
        )

        style.configure(
            "TFrame", background=self.BG
        )
        style.configure(
            "Card.TFrame", background=self.CARD
        )

        style.configure(
            "TLabel",
            background=self.BG,
            foreground=self.TEXT,
            font=("Segoe UI", 10),
        )
        style.configure(
            "Muted.TLabel",
            background=self.BG,
            foreground=self.MUTED,
            font=("Segoe UI", 9),
        )
        style.configure(
            "Heading.TLabel",
            background=self.BG,
            foreground=self.TEXT,
            font=("Segoe UI Semibold", 11),
        )
        style.configure(
            "Card.TLabel",
            background=self.CARD,
            foreground=self.TEXT,
            font=("Segoe UI", 10),
        )

        style.configure(
            "Accent.TButton",
            background=self.ACCENT,
            foreground="#ffffff",
            font=("Segoe UI Semibold", 10),
            padding=[20, 9],
            borderwidth=0,
            relief="flat",
        )
        style.map("Accent.TButton", background=[("active", "#3a7bd5")])

        style.configure(
            "Ghost.TButton",
            background=self.CARD,
            foreground=self.TEXT,
            font=("Segoe UI", 10),
            padding=[12, 7],
            borderwidth=1,
            relief="flat",
        )
        style.map("Ghost.TButton", background=[("active", self.BORDER)])

        style.configure(
            "Danger.TButton",
            background="#3d1a1a",
            foreground=self.ERROR,
            font=("Segoe UI", 9),
            padding=[8, 5],
            borderwidth=0,
            relief="flat",
        )
        style.map("Danger.TButton", background=[("active", "#5a2020")])

        style.configure(
            "TEntry",
            fieldbackground=self.ENTRY_BG,
            foreground=self.TEXT,
            insertcolor=self.TEXT,
            borderwidth=1,
            relief="flat",
        )
        style.map("TEntry", bordercolor=[("focus", self.ACCENT)])

        style.configure(
            "TCombobox",
            fieldbackground=self.ENTRY_BG,
            background=self.ENTRY_BG,
            foreground=self.TEXT,
            arrowcolor=self.TEXT,
            borderwidth=1,
        )

        style.configure(
            "TSpinbox",
            fieldbackground=self.ENTRY_BG,
            foreground=self.TEXT,
            arrowcolor=self.TEXT,
            borderwidth=1,
        )

    # ────────────────────────────── UI 구성 ──────────────────────────────

    def _build_ui(self):
        # 헤더
        header = tk.Frame(self, bg=self.CARD, height=64)
        header.pack(fill="x")
        header.pack_propagate(False)

        tk.Label(
            header,
            text="🛡  BeaconGuardian",
            bg=self.CARD,
            fg=self.TEXT,
            font=("Segoe UI Semibold", 14),
        ).pack(side="left", padx=24, pady=16)

        tk.Label(
            header,
            text="보안 모니터링 에이전트 초기 설정",
            bg=self.CARD,
            fg=self.MUTED,
            font=("Segoe UI", 10),
        ).pack(side="left", pady=20)

        # 구분선
        tk.Frame(self, bg=self.BORDER, height=1).pack(fill="x")

        # 탭
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=0, pady=0)

        self.tab_server = ttk.Frame(nb)
        self.tab_monitor = ttk.Frame(nb)
        self.tab_paths = ttk.Frame(nb)
        self.tab_logging = ttk.Frame(nb)

        nb.add(self.tab_server,  text="  🌐  서버 연결  ")
        nb.add(self.tab_monitor, text="  ⏱  모니터링  ")
        nb.add(self.tab_paths,   text="  📁  감시 경로  ")
        nb.add(self.tab_logging, text="  📋  로깅  ")

        self._build_server_tab()
        self._build_monitor_tab()
        self._build_paths_tab()
        self._build_logging_tab()

        # 하단 버튼 영역
        self._build_footer()

    # ── 탭 1: 서버 연결 ──

    def _build_server_tab(self):
        p = self.tab_server
        p.configure(style="TFrame")
        self._section(p, "Beacon 서버 정보", "에이전트가 이벤트를 전송할 서버를 설정합니다.").pack(fill="x", padx=28, pady=(24, 0))

        bc = self.config_data.get("beacon", {})

        self.var_url = self._labeled_entry(p, "서버 URL", bc.get("server_url", "http://localhost:8080"))
        self.var_user = self._labeled_entry(p, "사용자 이름", bc.get("username", "admin"))
        self.var_pass = self._labeled_entry(p, "비밀번호", bc.get("password", ""), show="•")

        # 연결 테스트 버튼
        row = tk.Frame(p, bg=self.BG)
        row.pack(fill="x", padx=28, pady=(8, 0))

        ttk.Button(row, text="연결 테스트", style="Ghost.TButton", command=self._test_connection).pack(side="left")
        self.lbl_conn = tk.Label(row, text="", bg=self.BG, fg=self.MUTED, font=("Segoe UI", 9))
        self.lbl_conn.pack(side="left", padx=12)

    # ── 탭 2: 모니터링 간격 ──

    def _build_monitor_tab(self):
        p = self.tab_monitor
        self._section(p, "모니터링 간격 (초)", "각 모니터의 주기를 설정합니다. 낮을수록 정밀하지만 CPU를 더 사용합니다.").pack(fill="x", padx=28, pady=(24, 0))

        mc = self.config_data.get("monitoring", {})
        self.var_usb  = self._labeled_spinbox(p, "USB 감시 간격",      mc.get("usb_check_interval", 5))
        self.var_net  = self._labeled_spinbox(p, "네트워크 감시 간격",  mc.get("network_check_interval", 10))
        self.var_proc = self._labeled_spinbox(p, "프로세스 감시 간격",  mc.get("process_check_interval", 5))
        self.var_brow = self._labeled_spinbox(p, "브라우저 히스토리 간격", mc.get("browser_check_interval", 30))

    # ── 탭 3: 감시 경로 ──

    def _build_paths_tab(self):
        p = self.tab_paths
        self._section(p, "파일 감시 경로", "이벤트를 감지할 디렉토리 목록입니다.").pack(fill="x", padx=28, pady=(24, 0))

        list_frame = tk.Frame(p, bg=self.CARD, bd=0, highlightthickness=1, highlightbackground=self.BORDER)
        list_frame.pack(fill="both", expand=True, padx=28, pady=(12, 0))

        scrollbar = tk.Scrollbar(list_frame, bg=self.CARD, troughcolor=self.CARD)
        scrollbar.pack(side="right", fill="y")

        self.path_listbox = tk.Listbox(
            list_frame,
            bg=self.ENTRY_BG,
            fg=self.TEXT,
            selectbackground=self.ACCENT,
            selectforeground="#ffffff",
            font=("Consolas", 10),
            borderwidth=0,
            highlightthickness=0,
            activestyle="none",
            yscrollcommand=scrollbar.set,
        )
        self.path_listbox.pack(fill="both", expand=True, padx=1, pady=1)
        scrollbar.config(command=self.path_listbox.yview)

        dirs = self.config_data.get("paths", {}).get("watch_dirs", [])
        for d in dirs:
            self.path_listbox.insert("end", d)

        btn_row = tk.Frame(p, bg=self.BG)
        btn_row.pack(fill="x", padx=28, pady=(10, 0))
        ttk.Button(btn_row, text="＋ 경로 추가", style="Ghost.TButton", command=self._add_path).pack(side="left", padx=(0, 8))
        ttk.Button(btn_row, text="－ 선택 삭제", style="Danger.TButton", command=self._remove_path).pack(side="left")

    # ── 탭 4: 로깅 ──

    def _build_logging_tab(self):
        p = self.tab_logging
        self._section(p, "로그 설정", "에이전트 로그 파일과 수준을 설정합니다.").pack(fill="x", padx=28, pady=(24, 0))

        lc = self.config_data.get("logging", {})
        self.var_log_level  = self._labeled_combo(p, "로그 수준", ["DEBUG", "INFO", "WARNING", "ERROR"], lc.get("level", "INFO"))
        self.var_log_file   = self._labeled_entry(p, "로그 파일 경로", lc.get("file", "agent.log"))
        self.var_max_bytes  = self._labeled_spinbox(p, "최대 파일 크기 (bytes)", lc.get("max_bytes", 10485760), from_=1048576, to=104857600, increment=1048576)
        self.var_backup_cnt = self._labeled_spinbox(p, "백업 파일 수", lc.get("backup_count", 5), from_=1, to=20)

    # ── 하단 버튼 ──

    def _build_footer(self):
        tk.Frame(self, bg=self.BORDER, height=1).pack(fill="x")
        footer = tk.Frame(self, bg=self.CARD, height=60)
        footer.pack(fill="x")
        footer.pack_propagate(False)

        self.lbl_status = tk.Label(footer, text="", bg=self.CARD, fg=self.MUTED, font=("Segoe UI", 9))
        self.lbl_status.pack(side="left", padx=24)

        ttk.Button(footer, text="저장 후 에이전트 시작", style="Accent.TButton", command=self._save_and_start).pack(side="right", padx=12, pady=10)
        ttk.Button(footer, text="저장만", style="Ghost.TButton", command=self._save_only).pack(side="right", padx=(0, 4), pady=10)

    # ────────────────────────────── 헬퍼 위젯 ──────────────────────────────

    def _section(self, parent, title, subtitle=""):
        f = tk.Frame(parent, bg=self.BG)
        tk.Label(f, text=title, bg=self.BG, fg=self.TEXT, font=("Segoe UI Semibold", 12)).pack(anchor="w")
        if subtitle:
            tk.Label(f, text=subtitle, bg=self.BG, fg=self.MUTED, font=("Segoe UI", 9)).pack(anchor="w", pady=(2, 0))
        tk.Frame(f, bg=self.BORDER, height=1).pack(fill="x", pady=(10, 0))
        return f

    def _labeled_entry(self, parent, label, value="", show=""):
        row = tk.Frame(parent, bg=self.BG)
        row.pack(fill="x", padx=28, pady=(14, 0))
        tk.Label(row, text=label, bg=self.BG, fg=self.MUTED, font=("Segoe UI", 9), width=20, anchor="w").pack(side="left")
        var = tk.StringVar(value=str(value))
        entry_kwargs = dict(textvariable=var, style="TEntry", width=38)
        e = ttk.Entry(row, **entry_kwargs)
        if show:
            e.config(show=show)
        e.pack(side="left")
        return var

    def _labeled_spinbox(self, parent, label, value=0, from_=1, to=3600, increment=1):
        row = tk.Frame(parent, bg=self.BG)
        row.pack(fill="x", padx=28, pady=(14, 0))
        tk.Label(row, text=label, bg=self.BG, fg=self.MUTED, font=("Segoe UI", 9), width=24, anchor="w").pack(side="left")
        var = tk.IntVar(value=int(value))
        ttk.Spinbox(row, textvariable=var, from_=from_, to=to, increment=increment, width=10,
                    style="TSpinbox").pack(side="left")
        return var

    def _labeled_combo(self, parent, label, options, current):
        row = tk.Frame(parent, bg=self.BG)
        row.pack(fill="x", padx=28, pady=(14, 0))
        tk.Label(row, text=label, bg=self.BG, fg=self.MUTED, font=("Segoe UI", 9), width=20, anchor="w").pack(side="left")
        var = tk.StringVar(value=current)
        cb = ttk.Combobox(row, textvariable=var, values=options, state="readonly", width=15)
        cb.pack(side="left")
        return var

    # ────────────────────────────── 액션 ──────────────────────────────

    def _collect_config(self):
        return {
            "beacon": {
                "server_url": self.var_url.get().strip(),
                "username":   self.var_user.get().strip(),
                "password":   self.var_pass.get(),
            },
            "monitoring": {
                "usb_check_interval":     self.var_usb.get(),
                "network_check_interval": self.var_net.get(),
                "process_check_interval": self.var_proc.get(),
                "browser_check_interval": self.var_brow.get(),
            },
            "paths": {
                "watch_dirs": list(self.path_listbox.get(0, "end"))
            },
            "logging": {
                "level":        self.var_log_level.get(),
                "file":         self.var_log_file.get().strip(),
                "max_bytes":    self.var_max_bytes.get(),
                "backup_count": self.var_backup_cnt.get(),
            },
        }

    def _validate(self, cfg):
        if not cfg["beacon"]["server_url"]:
            messagebox.showerror("입력 오류", "서버 URL을 입력하세요.")
            return False
        if not cfg["beacon"]["username"]:
            messagebox.showerror("입력 오류", "사용자 이름을 입력하세요.")
            return False
        if not cfg["logging"]["file"]:
            messagebox.showerror("입력 오류", "로그 파일 경로를 입력하세요.")
            return False
        return True

    def _save_only(self):
        cfg = self._collect_config()
        if not self._validate(cfg):
            return
        save_config(cfg)
        self.lbl_status.config(text=f"✔  저장 완료: {CONFIG_PATH}", fg=self.SUCCESS)
        messagebox.showinfo("저장 완료", f"설정이 저장되었습니다.\n{CONFIG_PATH}")

    def _save_and_start(self):
        cfg = self._collect_config()
        if not self._validate(cfg):
            return
        save_config(cfg)
        self.lbl_status.config(text="에이전트를 시작합니다...", fg=self.ACCENT)
        self.update()
        self.destroy()
        _launch_agent()

    def _test_connection(self):
        url  = self.var_url.get().strip().rstrip("/")
        user = self.var_user.get().strip()
        pwd  = self.var_pass.get()

        self.lbl_conn.config(text="연결 중...", fg=self.MUTED)
        self.update()

        def do_test():
            try:
                r = requests.post(
                    f"{url}/api/auth/login",
                    json={"username": user, "password": pwd},
                    timeout=6,
                )
                if r.status_code == 200:
                    self.lbl_conn.config(text="✔  연결 성공", fg=self.SUCCESS)
                else:
                    self.lbl_conn.config(text=f"✘  실패 ({r.status_code})", fg=self.ERROR)
            except Exception as e:
                self.lbl_conn.config(text=f"✘  {type(e).__name__}", fg=self.ERROR)

        threading.Thread(target=do_test, daemon=True).start()

    def _add_path(self):
        d = filedialog.askdirectory(title="감시할 디렉토리 선택")
        if d:
            self.path_listbox.insert("end", os.path.normpath(d))

    def _remove_path(self):
        sel = self.path_listbox.curselection()
        for idx in reversed(sel):
            self.path_listbox.delete(idx)

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
    force=True  → 항상 UI 표시
    force=False → config.yaml 없을 때만 UI 표시 후 에이전트 실행,
                  있으면 바로 에이전트 실행
    """
    if force or not os.path.exists(CONFIG_PATH):
        app = SetupApp()
        app.mainloop()
    else:
        _launch_agent()


if __name__ == "__main__":
    run_setup(force=True)
