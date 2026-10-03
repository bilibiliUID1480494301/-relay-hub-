"""统一控制台测试：令牌 / 请求 / 用量 / 审计 的网页 API。

安全断言照旧是最要紧的：新令牌明文只在创建响应里出现一次，
任何列表/状态接口只许尾 4 位。
"""

from __future__ import annotations

import json
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

from relayhub.gateway import audit, reqlog
from relayhub.gateway.admin import AdminServer
from relayhub.gateway.pool import KeyPool
from relayhub.gateway.tokens import TokenPool
from tests.support import make_key

from support import FakeUpstream




def _console_for(tmp_path: Path, *keys):
    pool_path = tmp_path / "pool.json"
    KeyPool(list(keys)).save(pool_path)
    server = AdminServer(
        ("127.0.0.1", 0),
        pool_path,
        audit_path=tmp_path / "audit.jsonl",
        tokens_path=tmp_path / "tokens.json",
        requests_log_path=tmp_path / "requests.jsonl",
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _with(server, thread):
    class _Ctx:
        base = f"http://127.0.0.1:{server.server_address[1]}"

        @staticmethod
        def close():
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    return _Ctx()


def _req(base: str, method: str, path: str, body=None):
    import urllib.error
    import urllib.request

    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(f"{base}{path}", data=data, method=method)
    if data is not None:
        request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def test_token_lifecycle_via_console(tmp_path: Path) -> None:
    server, thread = _console_for(tmp_path)
    ctx = _with(server, thread)
    try:
        # 发放：响应里有明文（只此一次）
        status, payload = _req(ctx.base, "POST", "/api/tokens", {"name": "app-laptop", "models_text": "glm-5.2, qwen3-32b", "note": "笔记本"})
        assert status == 200
        secret = payload["token"]
        assert secret.startswith("rht_")
        # 列表里只有尾 4 位 + 用量 + 限制
        listed = payload["tokens"][0]
        assert listed["name"] == "app-laptop"
        assert secret not in json.dumps(listed)
        assert listed["token_hint"].endswith(secret[-4:])
        assert listed["models"] == ["glm-5.2", "qwen3-32b"]

        # 文件里真有（serve 热加载会认）
        assert TokenPool.load(tmp_path / "tokens.json").find(secret) is not None

        # 禁用/启用
        status, payload = _req(ctx.base, "PUT", f"/api/tokens/{listed['token_id']}", {"enabled": False})
        assert payload["tokens"][0]["enabled"] is False
        status, payload = _req(ctx.base, "PUT", f"/api/tokens/{listed['token_id']}", {"enabled": True})
        assert payload["tokens"][0]["enabled"] is True

        # 重名拒绝
        status, payload = _req(ctx.base, "POST", "/api/tokens", {"name": "app-laptop"})
        assert status == 409

        # 吊销
        status, payload = _req(ctx.base, "DELETE", f"/api/tokens/{listed['token_id']}")
        assert payload["tokens"] == []

        # 审计留痕（不含明文）
        events = audit.tail(tmp_path / "audit.jsonl")
        assert [e["event"] for e in events] == ["token.add", "token.toggle", "token.toggle", "token.remove"]
        assert secret not in json.dumps(events)
    finally:
        ctx.close()




def test_requests_and_usage_endpoints(tmp_path: Path) -> None:
    path = tmp_path / "requests.jsonl"
    reqlog.record(path, token="app-a", model="glm-5.2", channel="local-ollama", ok=True, tokens_in=7, tokens_out=3, latency_ms=20)
    reqlog.record(path, token="app-a", model="glm-5.2", channel="local-ollama", ok=False, status=404, reason="unknown model")

    server, thread = _console_for(tmp_path)
    ctx = _with(server, thread)
    try:
        status, payload = _req(ctx.base, "GET", "/api/requests?limit=10")
        assert status == 200
        assert len(payload["entries"]) == 2
        status, payload = _req(ctx.base, "GET", "/api/requests?model=glm-5.2")
        assert len(payload["entries"]) == 2

        status, payload = _req(ctx.base, "GET", "/api/usage?days=7")
        assert status == 200
        assert payload["requests"]["window"]["requests"] == 2
        assert payload["requests"]["by_token"]["app-a"]["ok"] == 1
        assert payload["requests"]["by_channel"]["local-ollama"]["requests"] == 2
        assert "tokens" in payload
    finally:
        ctx.close()




def test_console_page_has_all_tabs(tmp_path: Path) -> None:
    server, thread = _console_for(tmp_path)
    ctx = _with(server, thread)
    try:
        import urllib.request

        html = urllib.request.urlopen(f"{ctx.base}/", timeout=10).read().decode("utf-8")
        markers = ["pane-pool", "pane-tokens", "pane-requests", "pane-usage", "pane-audit", "switchTab"]
        for marker in markers:
            assert marker in html, f"页面缺 {marker}"
        assert "function esc(" in html
    finally:
        ctx.close()
