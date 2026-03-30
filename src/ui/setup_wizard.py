"""
UI package entrypoint.

현재 구현은 기존 `setup_ui.py`를 재사용하며, 점진적으로 이 패키지로
구현을 이동할 수 있도록 경로를 표준화한다.
"""

from .setup_ui import SetupApp, run_setup

__all__ = ["SetupApp", "run_setup"]

