"""시스템 트레이 — pystray. 콜백은 Tk 메인 스레드로 root.after(0, ...)로 넘길 것."""

from __future__ import annotations

import threading
from typing import Callable

_tray_icon = None
_tray_thread = None


def _make_image():
    from PIL import Image, ImageDraw

    w, h = 64, 64
    img = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.ellipse((4, 4, 59, 59), fill=(47, 111, 237, 255))
    return img


def start_tray(
    root,
    on_open: Callable[[], None],
    can_quit: bool,
    on_quit: Callable[[], None] | None = None,
):
    """
    트레이 아이콘 시작(별도 스레드에서 Icon.run).
    can_quit=False이면 메뉴에 '종료'를 넣지 않음(일반 유저 정책).
    """
    global _tray_icon, _tray_thread

    import pystray
    from pystray import Menu, MenuItem

    image = _make_image()

    def open_action(icon, item):
        root.after(0, on_open)

    def quit_action(icon, item):
        if on_quit:
            root.after(0, on_quit)

    items = [MenuItem("창 열기", open_action)]
    if can_quit and on_quit is not None:
        items.append(MenuItem("종료", quit_action))

    menu = Menu(*items)
    icon = pystray.Icon("beacon_guardian", image, "BeaconGuardian", menu)
    _tray_icon = icon

    def run_icon():
        icon.run()

    _tray_thread = threading.Thread(target=run_icon, daemon=True)
    _tray_thread.start()
    return icon


def stop_tray(icon) -> None:
    if icon is None:
        return
    try:
        icon.stop()
    except Exception:
        pass
