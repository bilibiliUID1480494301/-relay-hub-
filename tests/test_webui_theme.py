# -*- coding: utf-8 -*-
"""0.4.0 新功能测试：TOIP 扫码登记 API + 公网面板外观（背景）。

管理台两个新面：
  * GET /api/toip/otpauth —— 管理员主动索取 otpauth 登记二维码（种子敏感，
    每次下发必须留审计）；未装 qr 扩展时降级只回 URI。
  * GET/POST /api/webui   —— 公网面板背景的自定义与白名单校验（校验不过
    就是 CSS 注入，必须 400）。
"""

from __future__ import annotations

import json
import os
import threading
import urllib.request
from contextlib import contextmanager
from pathlib import Path

from tests.test_toip import admin_console, get, post, managed_home  # noqa: F401
from tests.support import FakeUpstream, make_key

PLUGIN = "dsh-relayhub-bridge"


# -- /api/toip/otpauth -------------------------------------------------------


def test_otpauth_returns_uri_when_station_exists(tmp_path: Path) -> None:
    with managed_home(tmp_path) as home:
        from relayhub.gateway import toip

        toip.save_station(home / "toip.json", toip.StationIdentity.create(name="lab-hub"))
        with admin_console(home) as base:
            status, payload = get(base, "/api/toip/otpauth")
            assert status == 200, payload
            assert payload["enabled"] is True
            assert payload["otpauth"].startswith("otpauth://totp/relayhub:lab-hub")
            assert "secret=" in payload["otpauth"]
            # 测试环境一般没装 qrcode —— qr=False 是合法降级，不装也必须能用
            assert payload.get("qr") in (True, False)
            if payload.get("qr"):
                assert payload["png"].startswith("data:image/png;base64,")


def test_otpauth_reports_disabled_without_station(tmp_path: Path) -> None:
    with managed_home(tmp_path) as home:
        with admin_console(home) as base:
            status, payload = get(base, "/api/toip/otpauth")
            assert status == 200, payload
            assert payload == {"enabled": False}


def test_otpauth_reveal_is_audited(tmp_path: Path) -> None:
    """种子外泄可追溯：每次下发 otpauth 都必须落一条审计。"""
    with managed_home(tmp_path) as home:
        from relayhub.gateway import audit, toip

        toip.save_station(home / "toip.json", toip.StationIdentity.create(name="lab-hub"))
        with admin_console(home) as base:
            get(base, "/api/toip/otpauth")
            events = [e["event"] for e in audit.tail(home / "audit.jsonl", limit=50)]
            assert "toip.otpauth_revealed" in events


# -- /api/webui + /panel 注入 -------------------------------------------------


@contextmanager
def relay_panel():
    """起一个只服务 /panel 的中转站（DemoRouter，无真实上游）。"""
    from relayhub.gateway.service import DemoRouter, RelayServer, demo_router

    server = RelayServer(("127.0.0.1", 0), demo_router(), api_key="rh_test", event_delay=0.0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _panel_html(base: str) -> str:
    with urllib.request.urlopen(f"{base}/panel", timeout=10) as response:
        return response.read().decode("utf-8")


def test_webui_roundtrip_and_panel_injection(tmp_path: Path) -> None:
    with managed_home(tmp_path) as home:
        with admin_console(home) as base:
            status, payload = post(base, "/api/webui", {"bg_color": "#1B2A4A", "bg_image": ""})
            assert status == 200, payload
            status, payload = get(base, "/api/webui")
            assert status == 200, payload
            assert payload["bg_color"] == "#1B2A4A"
            assert payload["bg_image"] == ""

        with relay_panel() as panel:
            html = _panel_html(panel)
            assert "background-color:#1B2A4A;" in html


def test_webui_rejects_css_injection(tmp_path: Path) -> None:
    """色值/URL 校验不过必须 400 —— 这两个字段会被拼进面板 <style>。"""
    with managed_home(tmp_path) as home:
        with admin_console(home) as base:
            for body in (
                {"bg_color": "red; } body{display:none", "bg_image": ""},
                {"bg_color": "#123456", "bg_image": 'https://x/y" onerror="alert(1)'},
                {"bg_color": "#123456", "bg_image": "javascript:alert(1)"},
            ):
                status, _ = post(base, "/api/webui", body)
                assert status == 400, body


def test_panel_without_config_uses_default_bg(tmp_path: Path) -> None:
    with managed_home(tmp_path) as home:
        with relay_panel() as panel:
            html = _panel_html(panel)
            assert "background:#F7F6F3;" in html
            assert "__THEME_BG__" not in html
