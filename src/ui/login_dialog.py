"""Beacon 로그인 다이얼로그 — 성공 시 role 결정 후 설정 UI로 이어짐."""

from __future__ import annotations

import os
import sys
import queue
import threading
import tkinter as tk
from tkinter import ttk

import requests

from core.app_context import AppContext
from core.role_utils import resolve_role_from_login_response
from beacon.beacon_client import configure_tls_session

# 프로젝트 루트 (setup_ui와 동일 규칙)
if getattr(sys, "frozen", False):
    ROOT_DIR = os.path.dirname(os.path.abspath(sys.executable))
else:
    ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CONFIG_PATH = os.path.join(ROOT_DIR, "config.yaml")

# run_login() 성공 분기 — 일반 로그인과 구분
USER_LOGIN_BACKGROUND = object()


def _load_yaml_config():
    import yaml

    if not os.path.exists(CONFIG_PATH):
        return {}
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def run_login():
    """
    모달 로그인.
    - 일반: (role, server_url, username)
    - 유저 백그라운드: USER_LOGIN_BACKGROUND (관리자가 저장한 config만 사용)
    - 취소/실패: None
    """
    result: list = [None]

    cfg = _load_yaml_config()
    ui_cfg = cfg.get("ui", {})
    beacon = cfg.get("beacon", {})
    admin_usernames = ui_cfg.get("admin_usernames") or []

    app = tk.Tk()
    app.title("BeaconGuardian 로그인")
    app.resizable(False, False)
    app.minsize(420, 320)

    # [NEW] 스레드 안전한 GUI 업데이트를 위한 큐
    gui_queue = queue.Queue()

    def poll_queue():
        """메인 스레드에서 주기적으로 큐를 확인하여 UI 작업을 실행합니다."""
        try:
            while True:
                task = gui_queue.get_nowait()
                if callable(task):
                    task()
        except queue.Empty:
            pass
        finally:
            try:
                if app.winfo_exists():
                    app.after(100, poll_queue)
            except tk.TclError:
                # 창이 이미 파괴된 경우 무시합니다.
                pass

    frm = ttk.Frame(app, padding=20)
    frm.pack(fill="both", expand=True)

    ttk.Label(frm, text="서버 URL").grid(row=0, column=0, sticky="w", pady=(0, 4))
    var_url = tk.StringVar(value=beacon.get("server_url", "https://localhost:8080"))
    ttk.Entry(frm, textvariable=var_url, width=48).grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, 12))

    ttk.Label(frm, text="사용자 이름").grid(row=2, column=0, sticky="w", pady=(0, 4))
    var_user = tk.StringVar(value=beacon.get("username", ""))
    ttk.Entry(frm, textvariable=var_user, width=48).grid(row=3, column=0, columnspan=2, sticky="ew", pady=(0, 12))

    ttk.Label(frm, text="비밀번호").grid(row=4, column=0, sticky="w", pady=(0, 4))
    var_pass = tk.StringVar()
    ttk.Entry(frm, textvariable=var_pass, width=48, show="\u2022").grid(row=5, column=0, columnspan=2, sticky="ew", pady=(0, 16))

    lbl = ttk.Label(frm, text="", foreground="gray")
    lbl.grid(row=6, column=0, columnspan=2, sticky="w")

    def fail(msg: str):
        lbl.config(text=msg)

    def on_ok():
        url = var_url.get().strip().rstrip("/")
        user = var_user.get().strip()
        pwd = var_pass.get()
        if not url or not user:
            fail("서버 URL과 사용자 이름은 필수입니다.")
            return

        lbl.config(text="로그인 중…")

        def work():
            session = requests.Session()
            configure_tls_session(session, {"verify": False})
            
            try:
                r = session.post(
                    f"{url}/api/auth/login",
                    json={"username": user, "password": pwd},
                    timeout=12,
                )
                if r.status_code != 200:
                    gui_queue.put(lambda: fail(f"실패 (HTTP {r.status_code})"))
                    return
                data = r.json() if r.content else {}
                role = resolve_role_from_login_response(data, user, admin_usernames)
                AppContext.set_role(role)

                def done():
                    result[0] = (role, url, user, data.get("token"))
                    app.destroy()

                gui_queue.put(done)
            except Exception as e:
                err_name = type(e).__name__
                gui_queue.put(lambda: fail(f"오류: {err_name}"))

        threading.Thread(target=work, daemon=True).start()

    def on_cancel():
        result[0] = None
        app.destroy()

    def on_user_background():
        """관리자가 저장한 config.yaml로 에이전트만 백그라운드 기동 (서버 로그인 생략)."""
        if not os.path.exists(CONFIG_PATH):
            fail("관리자가 config.yaml을 먼저 저장해야 합니다.")
            return
        cfg = _load_yaml_config()
        bc = cfg.get("beacon") or {}
        if not (bc.get("server_url") or "").strip():
            fail("config에 Server URL이 없습니다. 관리자 설정을 확인하세요.")
            return
        if not (bc.get("username") or "").strip():
            fail("config에 사용자 이름이 없습니다. 관리자 설정을 확인하세요.")
            return
        AppContext.set_role("user")
        result[0] = USER_LOGIN_BACKGROUND
        app.destroy()

    btn_row = ttk.Frame(frm)
    btn_row.grid(row=7, column=0, columnspan=2, sticky="e", pady=(8, 0))
    ttk.Button(btn_row, text="취소", width=12, command=on_cancel).pack(side="right", padx=(8, 0))
    ttk.Button(btn_row, text="로그인", width=12, command=on_ok).pack(side="right")

    ttk.Separator(frm, orient="horizontal").grid(row=8, column=0, columnspan=2, sticky="ew", pady=(16, 12))
    ttk.Label(
        frm,
        text="일반 사용자: 서버 로그인 없이 관리자가 맞춰 둔 설정으로만 실행합니다.",
        wraplength=400,
        font=("", 9),
        foreground="gray",
    ).grid(row=9, column=0, columnspan=2, sticky="w", pady=(0, 8))
    ttk.Button(
        frm,
        text="유저 로그인 · 백그라운드로 시작",
        command=on_user_background,
    ).grid(row=10, column=0, columnspan=2, sticky="ew")

    app.protocol("WM_DELETE_WINDOW", on_cancel)
    app.update_idletasks()
    w, h = 460, 380
    sw = app.winfo_screenwidth()
    sh = app.winfo_screenheight()
    app.geometry(f"{w}x{h}+{(sw - w) // 2}+{(sh - h) // 2}")

    # 큐 감시 시작
    poll_queue()
    app.mainloop()
    return result[0]
