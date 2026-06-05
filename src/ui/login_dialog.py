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

if getattr(sys, "frozen", False):
    ROOT_DIR = os.path.dirname(os.path.abspath(sys.executable))
else:
    ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CONFIG_PATH = os.path.join(ROOT_DIR, "config.yaml")
USER_LOGIN_BACKGROUND = object()


def _load_yaml_config():
    import yaml

    if not os.path.exists(CONFIG_PATH):
        return {}
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _parse_json_response(response):
    try:
        data = response.json() if response.content else {}
    except ValueError:
        data = {}
    return data if isinstance(data, dict) else {}


def _mfa_required(status_code, payload):
    if status_code not in (200, 202):
        return False
    return bool(
        payload.get("mfaRequired")
        or payload.get("mfa_required")
        or payload.get("requiresMfa")
    )


def _prompt_mfa_code(parent, gui_queue, fail):
    """MFA OTP 입력용 모달 창. 확인 시 6자리 문자열, 취소 시 None."""
    result = {"code": None}
    dlg = tk.Toplevel(parent)
    dlg.title("2단계 인증")
    dlg.resizable(False, False)
    dlg.transient(parent)
    dlg.grab_set()

    frm = ttk.Frame(dlg, padding=16)
    frm.pack(fill="both", expand=True)
    ttk.Label(
        frm,
        text="인증 앱(TOTP) 또는 이메일로 받은 6자리 코드를 입력하세요.",
        wraplength=360,
    ).grid(row=0, column=0, sticky="w", pady=(0, 8))
    var_code = tk.StringVar()
    ent = ttk.Entry(frm, textvariable=var_code, width=24)
    ent.grid(row=1, column=0, sticky="ew", pady=(0, 12))
    ent.focus_set()

    def on_ok():
        code = var_code.get().strip()
        if len(code) != 6 or not code.isdigit():
            fail("6자리 숫자 OTP 코드를 입력하세요.")
            return
        result["code"] = code
        dlg.destroy()

    def on_cancel():
        dlg.destroy()

    btns = ttk.Frame(frm)
    btns.grid(row=2, column=0, sticky="e")
    ttk.Button(btns, text="취소", command=on_cancel).pack(side="right", padx=(8, 0))
    ttk.Button(btns, text="확인", command=on_ok).pack(side="right")
    dlg.protocol("WM_DELETE_WINDOW", on_cancel)
    dlg.bind("<Return>", lambda _e: on_ok())
    parent.wait_window(dlg)
    return result["code"]


def run_login():
    """
    모달 로그인.
    - 일반: (role, server_url, username, token)
    - 유저 백그라운드: USER_LOGIN_BACKGROUND
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

    gui_queue = queue.Queue()

    def poll_queue():
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
            tls_cfg = beacon.get("tls", {}) if isinstance(beacon, dict) else {}
            configure_tls_session(session, tls_cfg)

            try:
                if tls_cfg.get("require_https", False) and not url.lower().startswith("https://"):
                    gui_queue.put(lambda: fail("HTTPS 강제 설정으로 https:// URL이 필요합니다."))
                    return

                r = session.post(
                    f"{url}/api/auth/login",
                    json={"username": user, "password": pwd},
                    timeout=12,
                )
                payload = _parse_json_response(r)

                if r.status_code not in (200, 202):
                    gui_queue.put(lambda: fail(f"실패 (HTTP {r.status_code})"))
                    return

                if _mfa_required(r.status_code, payload):
                    temp = payload.get("tempToken") or payload.get("temp_token")
                    if not temp:
                        gui_queue.put(lambda: fail("서버가 MFA를 요구했으나 tempToken이 없습니다."))
                        return

                    mfa_event = threading.Event()
                    mfa_holder = [None]

                    def ask_mfa():
                        mfa_holder[0] = _prompt_mfa_code(app, gui_queue, fail)
                        mfa_event.set()

                    gui_queue.put(ask_mfa)
                    if not mfa_event.wait(timeout=120):
                        gui_queue.put(lambda: fail("MFA 입력 시간이 초과되었습니다."))
                        return
                    code = mfa_holder[0]
                    if not code:
                        gui_queue.put(lambda: fail("MFA 인증이 취소되었습니다."))
                        return

                    r2 = session.post(
                        f"{url}/api/auth/mfa/verify",
                        json={"tempToken": temp, "code": code},
                        timeout=12,
                    )
                    payload = _parse_json_response(r2)
                    if r2.status_code != 200:
                        gui_queue.put(lambda: fail(f"MFA 실패 (HTTP {r2.status_code})"))
                        return

                role = resolve_role_from_login_response(payload, user, admin_usernames)
                AppContext.set_role(role)

                def done():
                    result[0] = (role, url, user, payload.get("token"))
                    app.destroy()

                gui_queue.put(done)
            except Exception as e:
                gui_queue.put(lambda: fail(f"오류: {type(e).__name__}"))

        threading.Thread(target=work, daemon=True).start()

    def on_cancel():
        result[0] = None
        app.destroy()

    def on_user_background():
        if not os.path.exists(CONFIG_PATH):
            fail("관리자가 config.yaml을 먼저 저장해야 합니다.")
            return
        cfg2 = _load_yaml_config()
        bc = cfg2.get("beacon") or {}
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

    poll_queue()
    app.mainloop()
    return result[0]
