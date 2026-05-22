"""Beacon 로그인 다이얼로그 — 성공 시 role 결정 후 설정 UI로 이어짐."""

from __future__ import annotations

import os
import sys
import queue
import threading
import tkinter as tk
from tkinter import ttk

import urllib3
import requests
from requests.exceptions import SSLError as RequestsSSLError

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
                    try:
                        task()
                    except Exception as _task_err:
                        try:
                            lbl.config(text=f"UI 오류: {type(_task_err).__name__}: {_task_err}", foreground="red")
                        except Exception:
                            pass
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
    ttk.Entry(frm, textvariable=var_pass, width=48, show="\u2022").grid(row=5, column=0, columnspan=2, sticky="ew", pady=(0, 12))

    # SSL 인증서 검증 건너뛰기 — 자체 서명(mkcert) 환경 전용
    var_skip_ssl = tk.BooleanVar(value=not beacon.get("tls", {}).get("verify", True))
    ssl_row = ttk.Frame(frm)
    ssl_row.grid(row=6, column=0, columnspan=2, sticky="ew", pady=(0, 4))
    ttk.Checkbutton(
        ssl_row,
        text="SSL 인증서 검증 안함 (자체 서명 인증서·개발 환경)",
        variable=var_skip_ssl,
    ).pack(side="left")
    btn_fetch_cert = ttk.Button(ssl_row, text="서버 인증서 가져오기", width=18,
                                command=lambda: _on_fetch_cert())
    btn_fetch_cert.pack(side="right")

    lbl = ttk.Label(frm, text="", foreground="gray", wraplength=420)
    lbl.grid(row=7, column=0, columnspan=2, sticky="w")

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

    def _on_fetch_cert():
        """서버 URL에 SSL 연결하여 인증서를 가져온 뒤 확인 팝업을 띄웁니다."""
        import ssl
        import socket
        import hashlib
        from urllib.parse import urlparse

        url_str = var_url.get().strip().rstrip("/")
        if not url_str.startswith("https://"):
            lbl.config(text="HTTPS URL에서만 인증서를 가져올 수 있습니다.", foreground="red")
            return

        parsed = urlparse(url_str)
        host = parsed.hostname or ""
        port = parsed.port or 443
        if not host:
            lbl.config(text="URL에서 호스트를 인식할 수 없습니다.", foreground="red")
            return

        lbl.config(text=f"{host}:{port} 에서 인증서 가져오는 중…", foreground="gray")
        btn_fetch_cert.config(state="disabled")

        def _fetch_work():
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

                der_chain: list[bytes] = []

                with socket.create_connection((host, port), timeout=10) as raw_sock:
                    with ctx.wrap_socket(raw_sock, server_hostname=host) as ssock:
                        # Python 3.10+: 전체 체인(leaf → root) 획득
                        if hasattr(ssock, "get_unverified_chain"):
                            for c in ssock.get_unverified_chain():
                                try:
                                    der_chain.append(c.public_bytes(ssl.DER))
                                except Exception:
                                    pass

                        # 폴백: leaf cert 만
                        if not der_chain:
                            leaf = ssock.getpeercert(binary_form=True)
                            if leaf:
                                der_chain.append(leaf)

                if not der_chain:
                    raise ValueError("서버가 인증서를 제공하지 않았습니다.")

                from cryptography import x509 as _x509
                from cryptography.hazmat.backends import default_backend as _dbe

                def _load(der):
                    return _x509.load_der_x509_certificate(der, _dbe())

                def _get_cn(name):
                    attrs = name.get_attributes_for_oid(_x509.NameOID.COMMON_NAME)
                    return attrs[0].value if attrs else "(없음)"

                # ── 저장 대상 결정 ────────────────────────────────────────────
                # 자체 서명(도메인 없음·IP 서버): 서버 인증서 자체가 CA 역할.
                #   → leaf 인증서를 그대로 저장.
                # 체인이 2개 이상(mkcert·내부 CA): 체인 전체를 하나의 PEM 번들로 저장.
                #   → requests/urllib3는 번들 안에서 검증 체인을 자동으로 구성.
                leaf_der  = der_chain[0]
                save_pem  = "".join(ssl.DER_cert_to_PEM_cert(d) for d in der_chain)

                # 화면에는 서버 인증서(leaf)의 정보를 표시
                leaf_obj   = _load(leaf_der)
                cn         = _get_cn(leaf_obj.subject)
                issuer_cn  = _get_cn(leaf_obj.issuer)
                not_before = leaf_obj.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
                not_after  = leaf_obj.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%S UTC")

                is_self_signed = (leaf_obj.subject == leaf_obj.issuer)
                chain_note = (
                    "자체 서명 인증서 — 서버 인증서를 그대로 저장합니다."
                    if is_self_signed
                    else f"CA 서명 인증서 — 체인 {len(der_chain)}개를 번들로 저장합니다."
                )

                sha256_fp = hashlib.sha256(leaf_der).hexdigest().upper()
                fp_fmt = ":".join(sha256_fp[i:i+2] for i in range(0, len(sha256_fp), 2))

                gui_queue.put(lambda: _show_cert_confirm(
                    save_pem, cn, issuer_cn, not_before, not_after, fp_fmt, chain_note,
                ))
            except OSError as e:
                msg = f"연결 실패: {e}"
                gui_queue.put(lambda m=msg: lbl.config(text=m, foreground="red"))
                gui_queue.put(lambda: btn_fetch_cert.config(state="normal"))
            except Exception as e:
                msg = f"인증서 가져오기 오류: {type(e).__name__}: {e}"
                gui_queue.put(lambda m=msg: lbl.config(text=m[:80], foreground="red"))
                gui_queue.put(lambda: btn_fetch_cert.config(state="normal"))

        threading.Thread(target=_fetch_work, daemon=True).start()

    def _show_cert_confirm(pem_text: str, cn: str, issuer_cn: str,
                           not_before: str, not_after: str, fp: str,
                           chain_note: str = ""):
        """가져온 Root CA 인증서 정보를 보여 주고 저장 여부를 묻습니다."""
        cert_win = tk.Toplevel(app)
        cert_win.title("서버 인증서 확인")
        cert_win.resizable(False, False)
        cert_win.grab_set()

        app.update_idletasks()
        pw, ph = app.winfo_width(), app.winfo_height()
        px, py = app.winfo_rootx(), app.winfo_rooty()
        cw, ch = 500, 400
        cert_win.geometry(f"{cw}x{ch}+{px + (pw - cw) // 2}+{py + (ph - ch) // 2}")

        cf = ttk.Frame(cert_win, padding=20)
        cf.pack(fill="both", expand=True)

        ttk.Label(cf, text="서버 인증서 정보", font=("", 11, "bold")).pack(anchor="w", pady=(0, 4))
        if chain_note:
            ttk.Label(cf, text=chain_note, foreground="gray", font=("", 8)).pack(anchor="w", pady=(0, 8))

        info_frame = ttk.LabelFrame(cf, text="인증서 세부 정보", padding=10)
        info_frame.pack(fill="x", pady=(0, 10))

        rows = [
            ("발급 대상 (CN)", cn),
            ("발급 기관 (Issuer)", issuer_cn),
            ("유효 시작", not_before),
            ("유효 만료", not_after),
        ]
        for label, val in rows:
            row_f = ttk.Frame(info_frame)
            row_f.pack(fill="x", pady=2)
            ttk.Label(row_f, text=f"{label}:", width=16, anchor="w",
                      foreground="gray").pack(side="left")
            ttk.Label(row_f, text=val, anchor="w").pack(side="left")

        ttk.Label(info_frame, text="SHA-256 지문:", foreground="gray").pack(anchor="w", pady=(6, 2))
        fp_var = tk.StringVar(value=fp)
        # ttk.Entry 는 font 옵션을 직접 지원하지 않으므로 tk.Entry 사용
        fp_entry = tk.Entry(
            info_frame, textvariable=fp_var, state="readonly",
            font=("Consolas", 8), relief="flat",
            readonlybackground="#f0f0f0", fg="#444444",
        )
        fp_entry.pack(fill="x", ipady=3)

        save_path = os.path.join(ROOT_DIR, "certs", "rootCA.pem")
        ttk.Label(
            cf,
            text=f"저장 경로: {save_path}",
            foreground="gray",
            font=("", 8),
            wraplength=440,
        ).pack(anchor="w", pady=(0, 10))

        warn = ttk.Label(
            cf,
            text="주의: 신뢰할 수 있는 서버의 인증서인지 지문을 반드시 확인하세요.",
            foreground="#b45309",
            wraplength=440,
            font=("", 9),
        )
        warn.pack(anchor="w", pady=(0, 8))

        btn_row_c = ttk.Frame(cf)
        btn_row_c.pack(anchor="e")

        def _on_cancel_cert():
            cert_win.destroy()
            lbl.config(text="인증서 저장을 취소했습니다.", foreground="gray")
            btn_fetch_cert.config(state="normal")

        def _on_save_cert():
            try:
                os.makedirs(os.path.dirname(save_path), exist_ok=True)
                with open(save_path, "w", encoding="ascii") as f:
                    f.write(pem_text)
                cert_win.destroy()
                # destroy() 후 부모 창 업데이트는 after()로 분리
                def _post_save():
                    try:
                        lbl.config(
                            text="서버 인증서가 저장되었습니다. 이제 SSL 검증이 활성화됩니다.",
                            foreground="green",
                        )
                        var_skip_ssl.set(False)
                        btn_fetch_cert.config(state="normal")
                    except tk.TclError:
                        pass
                app.after(0, _post_save)
            except Exception as e:
                try:
                    lbl.config(text=f"저장 실패: {e}", foreground="red")
                    btn_fetch_cert.config(state="normal")
                except tk.TclError:
                    pass

        ttk.Button(btn_row_c, text="취소", width=10, command=_on_cancel_cert).pack(side="right", padx=(8, 0))
        ttk.Button(btn_row_c, text="저장", width=10, command=_on_save_cert).pack(side="right")
        cert_win.protocol("WM_DELETE_WINDOW", _on_cancel_cert)
        # finally 블록 제거 후 취소도 버튼 복원 보장
        cert_win.bind("<Destroy>", lambda _e: app.after(0, lambda: (
            btn_fetch_cert.config(state="normal") if app.winfo_exists() else None
        )) if _e.widget is cert_win else None)

    def _show_otp_dialog(temp_token: str, session, tls_cfg: dict, url: str, user: str):
        """MFA 요구 시 별도 창으로 OTP 입력을 받아 2단계 인증을 완료합니다."""
        otp_win = tk.Toplevel(app)
        otp_win.title("2차 인증 (OTP)")
        otp_win.resizable(False, False)
        otp_win.grab_set()  # 모달 동작

        # 부모 창 중앙에 위치
        app.update_idletasks()
        pw, ph = app.winfo_width(), app.winfo_height()
        px, py = app.winfo_rootx(), app.winfo_rooty()
        ow, oh = 380, 220
        otp_win.geometry(f"{ow}x{oh}+{px + (pw - ow) // 2}+{py + (ph - oh) // 2}")

        otp_frm = ttk.Frame(otp_win, padding=24)
        otp_frm.pack(fill="both", expand=True)

        ttk.Label(
            otp_frm,
            text="2차 인증 코드를 입력하세요",
            font=("", 11, "bold"),
        ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 6))
        ttk.Label(
            otp_frm,
            text="인증 앱(TOTP) 또는 이메일로 받은 6자리 코드를 입력하세요.",
            wraplength=340,
            foreground="gray",
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(0, 14))

        ttk.Label(otp_frm, text="인증 코드").grid(row=2, column=0, sticky="w", pady=(0, 4))
        var_otp = tk.StringVar()
        otp_entry = ttk.Entry(otp_frm, textvariable=var_otp, width=30)
        otp_entry.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(0, 8))
        otp_entry.focus_set()

        otp_lbl = ttk.Label(otp_frm, text="", foreground="red", wraplength=340)
        otp_lbl.grid(row=4, column=0, columnspan=2, sticky="w")

        otp_btn_row = ttk.Frame(otp_frm)
        otp_btn_row.grid(row=5, column=0, columnspan=2, sticky="e", pady=(10, 0))

        otp_state = {"in_progress": False}

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

        def on_otp_cancel():
            try:
                session.close()
            except Exception:
                pass
            otp_win.destroy()
            _set_login_in_progress(False)
            lbl.config(text="2차 인증이 취소되었습니다.")

        def on_otp_submit():
            if otp_state["in_progress"]:
                return
            otp_code = var_otp.get().strip().replace(" ", "")
            if not otp_code:
                otp_lbl.config(text="인증 코드를 입력하세요.")
                return
            otp_state["in_progress"] = True
            otp_btn_ok.config(state="disabled")
            otp_lbl.config(text="인증 중…", foreground="gray")

            def mfa_work():
                try:
                    r2 = session.post(
                        f"{url}/api/auth/mfa/verify",
                        json={"tempToken": temp_token, "otpCode": otp_code},
                        timeout=12,
                    )
                    if r2.status_code != 200:
                        err_msg = _extract_error_message(r2) or f"HTTP {r2.status_code}"
                        def _on_fail(m=err_msg):
                            otp_lbl.config(text=f"인증 실패: {m}", foreground="red")
                            otp_btn_ok.config(state="normal")
                            otp_state["in_progress"] = False
                        otp_win.after(0, _on_fail)
                        return
                    data = _extract_payload(r2)
                    role = resolve_role_from_login_response(data, user, admin_usernames)
                    AppContext.set_role(role)

                    def done():
                        result[0] = (role, url, user, data.get("token"))
                        try:
                            otp_win.destroy()
                        except Exception:
                            pass
                        app.destroy()

                    otp_win.after(0, done)
                except RequestsSSLError:
                    otp_win.after(0, lambda: otp_lbl.config(
                        text="SSL 인증서 오류. 로그인 창에서 '검증 안함'을 체크하세요.",
                        foreground="red",
                    ))
                    otp_win.after(0, lambda: otp_btn_ok.config(state="normal"))
                    otp_state["in_progress"] = False
                except Exception as e:
                    n = type(e).__name__
                    otp_win.after(0, lambda _n=n: otp_lbl.config(text=f"오류: {_n}", foreground="red"))
                    otp_win.after(0, lambda: otp_btn_ok.config(state="normal"))
                    otp_state["in_progress"] = False
                finally:
                    try:
                        session.close()
                    except Exception:
                        pass
                    gui_queue.put(lambda: _set_login_in_progress(False))

            threading.Thread(target=mfa_work, daemon=True).start()

        ttk.Button(otp_btn_row, text="취소", width=10, command=on_otp_cancel).pack(side="right", padx=(8, 0))
        otp_btn_ok = ttk.Button(otp_btn_row, text="확인", width=10, command=on_otp_submit)
        otp_btn_ok.pack(side="right")

        otp_win.protocol("WM_DELETE_WINDOW", on_otp_cancel)
        otp_frm.columnconfigure(0, weight=1)
        # Enter 키로 제출
        otp_win.bind("<Return>", lambda _e: on_otp_submit())

    def on_ok():
        if login_state["in_progress"]:
            return
        url = var_url.get().strip().rstrip("/")
        user = var_user.get().strip()
        pwd = var_pass.get()
        if not url or not user:
            fail("서버 URL과 사용자 이름은 필수입니다.")
            return

        _set_login_in_progress(True)
        lbl.config(text="로그인 중…")

        skip_ssl = var_skip_ssl.get()

        def work():
            session = requests.Session()
            tls_cfg = dict(beacon.get("tls", {}) if isinstance(beacon, dict) else {})
            # UI 체크박스가 켜지면 인증서 검증을 비활성화
            if skip_ssl:
                tls_cfg["verify"] = False
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            configure_tls_session(session, tls_cfg)

            # MFA 분기에서 session 소유권이 OTP 다이얼로그로 넘어가므로
            # finally에서 session을 닫지 않아야 합니다.
            _session_transferred = [False]

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
                    # OTP 팝업을 메인 스레드에서 열고 session 소유권도 넘김
                    _session_transferred[0] = True
                    gui_queue.put(lambda tt=temp_token, s=session, tc=tls_cfg: _show_otp_dialog(tt, s, tc, url, user))
                    lbl_text = "2차 인증 창이 열렸습니다."
                    gui_queue.put(lambda t=lbl_text: lbl.config(text=t))
                    return  # session.close()·_set_login_in_progress는 OTP 다이얼로그가 담당
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
            except RequestsSSLError:
                gui_queue.put(lambda: fail(
                    "SSL 인증서 오류: 서버가 자체 서명 인증서를 사용 중입니다.\n"
                    "'SSL 인증서 검증 안함'을 체크하거나, CA 인증서를 설치하세요."
                ))
            except Exception as e:
                err_name = type(e).__name__
                gui_queue.put(lambda n=err_name: fail(f"오류: {n}"))
            finally:
                if not _session_transferred[0]:
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
    btn_row.grid(row=8, column=0, columnspan=2, sticky="e", pady=(8, 0))
    ttk.Button(btn_row, text="취소", width=12, command=on_cancel).pack(side="right", padx=(8, 0))
    btn_login = ttk.Button(btn_row, text="로그인", width=12, command=on_ok)
    btn_login.pack(side="right")

    ttk.Separator(frm, orient="horizontal").grid(row=9, column=0, columnspan=2, sticky="ew", pady=(16, 12))
    ttk.Label(
        frm,
        text="일반 사용자: 서버 로그인 없이 관리자가 맞춰 둔 설정으로만 실행합니다.",
        wraplength=400,
        font=("", 9),
        foreground="gray",
    ).grid(row=10, column=0, columnspan=2, sticky="w", pady=(0, 8))
    ttk.Button(
        frm,
        text="유저 로그인 · 백그라운드로 시작",
        command=on_user_background,
    ).grid(row=11, column=0, columnspan=2, sticky="ew")

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
