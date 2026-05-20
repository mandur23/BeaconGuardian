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
    app.minsize(420, 360)

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
    ttk.Entry(frm, textvariable=var_pass, width=48, show="\u2022").grid(row=5, column=0, columnspan=2, sticky="ew", pady=(0, 12))

    ttk.Label(frm, text="2차 인증 코드 (OTP, 선택)").grid(row=6, column=0, sticky="w", pady=(0, 4))
    var_otp = tk.StringVar()
    ttk.Entry(frm, textvariable=var_otp, width=48).grid(row=7, column=0, columnspan=2, sticky="ew", pady=(0, 16))

    lbl = ttk.Label(frm, text="", foreground="gray")
    lbl.grid(row=8, column=0, columnspan=2, sticky="w")

    def fail(msg: str):
        lbl.config(text=msg)

    login_state = {"in_progress": False}
    btn_login = None

    def _set_login_in_progress(in_progress: bool):
        login_state["in_progress"] = in_progress
        if btn_login is not None:
            try:
                btn_login.config(state=("disabled" if in_progress else "normal"))
            except tk.TclError:
                pass

    def on_ok():
        if login_state["in_progress"]:
            return
        url = var_url.get().strip().rstrip("/")
        user = var_user.get().strip()
        pwd = var_pass.get()
        otp = var_otp.get().strip().replace(" ", "")
        if not url or not user:
            fail("서버 URL과 사용자 이름은 필수입니다.")
            return

        _set_login_in_progress(True)
        lbl.config(text="로그인 중…")

        def work():
            session = requests.Session()
            tls_cfg = beacon.get("tls", {}) if isinstance(beacon, dict) else {}
            configure_tls_session(session, tls_cfg)
            
            try:
                if tls_cfg.get("require_https", False) and not url.lower().startswith("https://"):
                    gui_queue.put(lambda: fail("HTTPS 강제 설정으로 https:// URL이 필요합니다."))
                    return

                def _extract_payload(resp):
                    try:
                        data = resp.json()
                        return data if isinstance(data, dict) else {}
                    except Exception:
                        return {}

                def _extract_error_message(resp):
                    data = _extract_payload(resp)
                    for k in ("message", "error", "detail"):
                        if data.get(k):
                            return str(data.get(k))
                    return (resp.text or "").strip()

                # 1단계: ID/PW 로그인
                r = session.post(
                    f"{url}/api/auth/login",
                    json={"username": user, "password": pwd},
                    timeout=12,
                )

                # 2단계 MFA 분기: 서버는 202 + {mfaRequired:true, tempToken} 로 응답
                payload = _extract_payload(r)
                mfa_required = (
                    r.status_code == 202
                    or bool(payload.get("mfaRequired"))
                    or bool(payload.get("tempToken"))
                )

                if mfa_required and r.status_code in (200, 202):
                    temp_token = payload.get("tempToken")
                    if not temp_token:
                        gui_queue.put(lambda: fail("서버가 MFA를 요구했지만 tempToken이 없습니다."))
                        return
                    if not otp:
                        gui_queue.put(lambda: fail("2차 인증 코드(OTP)를 입력하세요."))
                        return
                    r2 = session.post(
                        f"{url}/api/auth/mfa/verify",
                        json={"tempToken": temp_token, "otpCode": otp},
                        timeout=12,
                    )
                    if r2.status_code != 200:
                        err_msg = _extract_error_message(r2) or f"HTTP {r2.status_code}"
                        gui_queue.put(lambda m=err_msg: fail(f"OTP 인증 실패: {m}"))
                        return
                    data = _extract_payload(r2)
                elif r.status_code == 200:
                    data = _extract_payload(r)
                else:
                    err_msg = _extract_error_message(r) or f"HTTP {r.status_code}"
                    gui_queue.put(lambda m=err_msg, sc=r.status_code: fail(f"실패({sc}): {m}"))
                    return
                role = resolve_role_from_login_response(data, user, admin_usernames)
                AppContext.set_role(role)

                def done():
                    result[0] = (role, url, user, data.get("token"))
                    app.destroy()

                gui_queue.put(done)
            except Exception as e:
                err_name = type(e).__name__
                gui_queue.put(lambda: fail(f"오류: {err_name}"))
            finally:
                try:
                    session.close()
                except Exception:
                    pass
                gui_queue.put(lambda: _set_login_in_progress(False))

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
    btn_row.grid(row=9, column=0, columnspan=2, sticky="e", pady=(8, 0))
    ttk.Button(btn_row, text="취소", width=12, command=on_cancel).pack(side="right", padx=(8, 0))
    btn_login = ttk.Button(btn_row, text="로그인", width=12, command=on_ok)
    btn_login.pack(side="right")

    ttk.Separator(frm, orient="horizontal").grid(row=10, column=0, columnspan=2, sticky="ew", pady=(16, 12))
    ttk.Label(
        frm,
        text="일반 사용자: 서버 로그인 없이 관리자가 맞춰 둔 설정으로만 실행합니다.",
        wraplength=400,
        font=("", 9),
        foreground="gray",
    ).grid(row=11, column=0, columnspan=2, sticky="w", pady=(0, 8))
    ttk.Button(
        frm,
        text="유저 로그인 · 백그라운드로 시작",
        command=on_user_background,
    ).grid(row=12, column=0, columnspan=2, sticky="ew")

    app.protocol("WM_DELETE_WINDOW", on_cancel)
    app.update_idletasks()
    w, h = 460, 430
    sw = app.winfo_screenwidth()
    sh = app.winfo_screenheight()
    app.geometry(f"{w}x{h}+{(sw - w) // 2}+{(sh - h) // 2}")

    # 큐 감시 시작
    poll_queue()
    app.mainloop()
    return result[0]
