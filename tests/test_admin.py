"""号池管理面测试。

两条最要紧的断言不是「功能能用」，而是安全边界：
  * 读接口**永远不回**上游 Key 明文（只回尾 4 位）。
  * 绑非回环地址却不给 token 时，构造期就拒绝启动。
另外一条是它和网关的接缝：管理面改完盘，网关的热加载必须立刻看见。
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

import pytest

from relayhub.gateway.admin import AdminServer, is_loopback, key_hint, probe_key
from relayhub.gateway import audit
from relayhub.gateway.pool import PROTOCOL_OPENAI_CHAT, KeyPool
from relayhub.gateway.router import ReloadingRouter
from support import REPLY_TEXT, FakeUpstream, make_key

SECRET = "sk-supersecret-9999"


@contextmanager
def admin_for(pool_path: Path, token: str | None = None) -> Iterator[str]:
    """起一个管理面，yield 出 base_url。数据面文件跟随号池所在目录（测试隔离）。"""
    parent = pool_path.parent
    server = AdminServer(
        ("127.0.0.1", 0),
        pool_path,
        token,
        audit_path=parent / "audit.jsonl",
        tokens_path=parent / "tokens.json",
        requests_log_path=parent / "requests.jsonl",
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.url
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def call(
    base: str,
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
    token: str | None = None,
) -> tuple[int, Any]:
    """返回 (status, 解析后的 JSON 或原始文本)。HTTP 错误也当返回值，不抛。"""
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(f"{base}{path}", data=data, method=method)
    if data is not None:
        request.add_header("Content-Type", "application/json")
    if token:
        request.add_header("X-Admin-Token", token)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            raw = response.read().decode("utf-8")
            status = response.status
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8")
        status = exc.code
    try:
        return status, json.loads(raw)
    except json.JSONDecodeError:
        return status, raw


def _pool_file(tmp_path: Path, *keys: Any) -> Path:
    path = tmp_path / "pool.json"
    KeyPool(list(keys)).save(path)
    return path


def _call_cookie(base: str, method: str, path: str, cookie: str | None = None, body: dict[str, Any] | None = None) -> tuple[int, Any, dict[str, str]]:
    """带 Cookie 的原始请求。返回 (status, body, response_headers)。"""
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(f"{base}{path}", data=data, method=method)
    if data is not None:
        request.add_header("Content-Type", "application/json")
    if cookie:
        request.add_header("Cookie", cookie)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.read().decode("utf-8"), dict(response.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8"), dict(exc.headers)


# ================================================================ 安全边界


def test_read_endpoints_never_return_the_upstream_secret(tmp_path: Path) -> None:
    """上游 Key 只写不读——这条挂了等于把密钥泄到浏览器里。"""
    key = make_key("local", "http://127.0.0.1:9001")
    key.api_key = SECRET
    path = _pool_file(tmp_path, key)
    with admin_for(path) as base:
        status, state = call(base, "GET", "/api/state")
    assert status == 200
    blob = json.dumps(state, ensure_ascii=False)
    assert SECRET not in blob
    assert state["keys"][0]["key_hint"] == "…9999"
    assert state["keys"][0]["has_key"] is True


def test_editing_without_a_new_secret_keeps_the_old_one(tmp_path: Path) -> None:
    key = make_key("local", "http://127.0.0.1:9001")
    key.api_key = SECRET
    path = _pool_file(tmp_path, key)
    key_id = key.key_id
    with admin_for(path) as base:
        status, _ = call(base, "PUT", f"/api/keys/{key_id}", {"label": "renamed", "api_key": ""})
        assert status == 200
    stored = KeyPool.load(path).get(key_id)
    assert stored is not None
    assert stored.label == "renamed"
    assert stored.api_key == SECRET


def test_token_is_enforced(tmp_path: Path) -> None:
    path = _pool_file(tmp_path)
    with admin_for(path, token="adm1n") as base:
        assert call(base, "GET", "/api/state")[0] == 401
        assert call(base, "GET", "/api/state", token="wrong")[0] == 401
        assert call(base, "GET", "/api/state", token="adm1n")[0] == 200
        # 未登录的浏览器拿登录页（200 引导输入），绝不能拿到面板本身
        status, html = call(base, "GET", "/")
        assert status == 200 and "doLogin" in html
        assert call(base, "GET", "/", token="adm1n")[0] == 200


def test_non_loopback_bind_requires_a_token(tmp_path: Path) -> None:
    """绑内网地址又不要凭证 = 管理面全开。

    守卫在绑端口**之前**执行，所以失败路径不会留下监听套接字（也就不用真去绑 0.0.0.0）。
    """
    for host in ("0.0.0.0", "192.168.1.10", "::"):
        with pytest.raises(ValueError, match="必须给 --token"):
            AdminServer((host, 0), tmp_path / "pool.json")


def test_loopback_hosts_are_recognised() -> None:
    for host in ("127.0.0.1", "localhost", "::1", " 127.0.0.1 "):
        assert is_loopback(host)
    for host in ("0.0.0.0", "192.168.1.10", "example.com"):
        assert not is_loopback(host)


def test_key_hint_masks_short_and_empty_secrets() -> None:
    assert key_hint("") == "<无>"
    assert key_hint("abcd") == "…"
    assert key_hint("abcdefgh") == "…efgh"


# ================================================================ 增删改


def test_add_update_toggle_delete_round_trip(tmp_path: Path) -> None:
    path = _pool_file(tmp_path)
    with admin_for(path) as base:
        status, state = call(
            base,
            "POST",
            "/api/keys",
            {
                "label": "local",
                "base_url": "http://127.0.0.1:9001",
                "api_key": SECRET,
                "protocol": PROTOCOL_OPENAI_CHAT,
                "models_text": "glm-5.2:1000000, qwen3-32b",
                "note": "自建 vLLM",
            },
        )
        assert status == 200, state
        entry = state["keys"][0]
        assert entry["models"] == ["glm-5.2", "qwen3-32b"]
        assert entry["model_windows"] == {"glm-5.2": 1000000}
        assert entry["protocol"] == PROTOCOL_OPENAI_CHAT
        assert entry["note"] == "自建 vLLM"
        key_id = entry["key_id"]

        # 重名要被挡住
        assert call(base, "POST", "/api/keys", {"label": "local", "base_url": "http://x"})[0] == 409

        status, state = call(base, "PUT", f"/api/keys/{key_id}", {"enabled": False})
        assert status == 200
        assert state["keys"][0]["enabled"] is False

        status, state = call(base, "PUT", f"/api/keys/{key_id}", {"enabled": True})
        assert state["keys"][0]["enabled"] is True

        assert call(base, "DELETE", f"/api/keys/{key_id}")[0] == 200
        assert KeyPool.load(path).keys == []
        assert call(base, "DELETE", f"/api/keys/{key_id}")[0] == 404


def test_missing_base_url_is_rejected(tmp_path: Path) -> None:
    path = _pool_file(tmp_path)
    with admin_for(path) as base:
        status, payload = call(base, "POST", "/api/keys", {"label": "x"})
    assert status == 400
    assert "base_url" in payload["error"]


def test_settings_are_validated_and_saved(tmp_path: Path) -> None:
    path = _pool_file(tmp_path)
    with admin_for(path) as base:
        status, payload = call(
            base,
            "PUT",
            "/api/settings",
            {
                "strategy": "least_failures",
                "failure_threshold": 5,
                "cooldown_tiers": {"plan": 43200, "soft": 45, "err": 900},
            },
        )
        assert status == 200, payload
        assert payload["strategy"] == "least_failures"
        assert payload["cooldown_tiers"]["soft"] == 45.0

        assert call(base, "PUT", "/api/settings", {"strategy": "nope"})[0] == 400
        assert call(base, "PUT", "/api/settings", {"failure_threshold": 0})[0] == 400
        assert call(base, "PUT", "/api/settings", {"cooldown_tiers": {"soft": 0}})[0] == 400
        assert call(base, "PUT", "/api/settings", {"cooldown_tiers": "nope"})[0] == 400

    reloaded = KeyPool.load(path)
    assert reloaded.strategy == "least_failures"
    assert reloaded.failure_threshold == 5
    assert reloaded.cooldown_tiers["err"] == 900.0


def test_reset_breaker_clears_the_cooldown(tmp_path: Path) -> None:
    key = make_key("flaky", "http://127.0.0.1:9001")
    key.consecutive_failures = 9
    key.disabled_until = 1e12
    key.last_error = "HTTP 503"
    path = _pool_file(tmp_path, key)
    with admin_for(path) as base:
        status, state = call(base, "PUT", f"/api/keys/{key.key_id}", {"reset_breaker": True})
    assert status == 200
    assert state["keys"][0]["available"] is True
    assert state["keys"][0]["last_error"] == ""


# ================================================================ 探活


def test_probe_reports_success_and_failure(tmp_path: Path) -> None:
    with FakeUpstream(protocol=PROTOCOL_OPENAI_CHAT) as healthy, FakeUpstream(
        fail_status=503
    ) as broken:
        good = make_key("good", healthy.base_url, protocol=PROTOCOL_OPENAI_CHAT)
        bad = make_key("bad", broken.base_url)
        path = _pool_file(tmp_path, good, bad)
        with admin_for(path) as base:
            status, payload = call(base, "POST", f"/api/keys/{good.key_id}/probe", {})
            assert status == 200
            assert payload["ok"] is True
            assert payload["text"] == REPLY_TEXT

            status, payload = call(base, "POST", f"/api/keys/{bad.key_id}/probe", {})
            assert status == 200
            assert payload["ok"] is False
            assert payload["status"] == 503
            assert payload["retryable"] is True

    # 上游真的收到了 OpenAI 形态的请求（探活也走完整翻译链）
    assert healthy.requests[0]["path"].endswith("/v1/chat/completions")


# ================================================================ 审计


# ================================================================ 登录会话


def test_login_flow_sets_usable_session(tmp_path: Path) -> None:
    """网页「登录」：token 换 HttpOnly 会话 cookie，之后不再需要带 token。"""
    path = _pool_file(tmp_path)
    with admin_for(path, token="adm1n") as base:
        # 未登录：页面是登录页而非面板，但仍是 200（引导人输入，不是甩错误码）
        status, html, _ = _call_cookie(base, "GET", "/")
        assert status == 200
        assert "doLogin" in html and "function esc(" not in html

        # 错 token 拿不到会话
        status, _, _ = _call_cookie(base, "POST", "/login", body={"token": "wrong"})
        assert status == 401

        # 正确 token → Set-Cookie → cookie 即可访问面板与 API
        status, _, headers = _call_cookie(base, "POST", "/login", body={"token": "adm1n"})
        assert status == 200
        cookie_header = headers.get("Set-Cookie", "")
        assert "HttpOnly" in cookie_header and "rh_admin_session=" in cookie_header
        cookie = cookie_header.split(";")[0]

        status, html, _ = _call_cookie(base, "GET", "/", cookie=cookie)
        assert status == 200 and "号池管理" in html
        status, state, _ = _call_cookie(base, "GET", "/api/state", cookie=cookie)
        assert status == 200

        # 登出即失效
        assert _call_cookie(base, "POST", "/logout", cookie=cookie)[0] == 200
        status, _, _ = _call_cookie(base, "GET", "/api/state", cookie=cookie)
        assert status == 401


def test_no_token_mode_has_no_login_page(tmp_path: Path) -> None:
    """回环信任模式（不设 token）保持原行为：直接进面板，没有登录页。"""
    path = _pool_file(tmp_path)
    with admin_for(path) as base:
        status, html, _ = _call_cookie(base, "GET", "/")
        assert status == 200 and "号池管理" in html


def test_mutations_leave_audit_without_secrets(tmp_path: Path) -> None:
    """管理面写操作要留痕（谁在什么时候删了/改了哪个渠道），
    但审计文件里绝不能出现上游 Key 明文——审计是明文 JSONL，
    把密钥抄进去等于给日志制造一个新泄露面。"""
    path = _pool_file(tmp_path)
    audit_path = path.parent / "audit.jsonl"
    with admin_for(path) as base:
        assert (
            call(
                base,
                "POST",
                "/api/keys",
                {"label": "x", "base_url": "http://x", "api_key": SECRET},
            )[0]
            == 200
        )
        assert call(base, "DELETE", "/api/keys/x")[0] == 200

    entries = audit.tail(audit_path)
    assert [e["event"] for e in entries] == ["pool.mutate", "pool.mutate"]
    assert entries[0]["method"] == "POST"
    assert entries[1] == {
        "ts": entries[1]["ts"],
        "event": "pool.mutate",
        "method": "DELETE",
        "route": "/api/keys/x",
    }
    assert SECRET not in json.dumps(entries, ensure_ascii=False), "审计不得包含密钥明文"


def test_probe_reports_an_unreachable_channel(tmp_path: Path) -> None:
    """连不上不是异常，是探活结果的一部分——管理面要把「连不上」显示出来。"""
    key = make_key("dead", "http://127.0.0.1:1")
    result = probe_key(key, timeout=1.0)
    assert result["ok"] is False
    assert result["status"] == 0
    assert result["retryable"] is True
    assert "连接上游失败" in result["error"]


# ================================================================ 与网关的接缝


def test_admin_edit_is_visible_to_the_gateway_without_restart(tmp_path: Path) -> None:
    """管理面改完盘 → 网关的热加载立刻看见。这是「改 Key 不用重启」的实证。"""
    path = _pool_file(tmp_path, make_key("a", "http://a"))
    router = ReloadingRouter(path)
    assert sorted(router.models()) == ["glm-5.2"]

    with admin_for(path) as base:
        status, _ = call(
            base,
            "POST",
            "/api/keys",
            {
                "label": "b",
                "base_url": "http://b",
                "protocol": PROTOCOL_OPENAI_CHAT,
                "models_text": "qwen3-32b:4096",
            },
        )
        assert status == 200

    assert sorted(router.models()) == ["glm-5.2", "qwen3-32b"]
    assert router.models()["qwen3-32b"] == 4096

    with admin_for(path) as base:
        key_id = KeyPool.load(path).find_by_label("b").key_id  # type: ignore[union-attr]
        assert call(base, "DELETE", f"/api/keys/{key_id}")[0] == 200
    assert sorted(router.models()) == ["glm-5.2"]


def test_admin_does_not_clobber_usage_written_by_the_gateway(tmp_path: Path) -> None:
    """管理面是读盘再改再写，不能把网关刚记的用量抹掉。"""
    key = make_key("a", "http://a")
    path = _pool_file(tmp_path, key)

    pool = KeyPool.load(path)
    pool.report_success(pool.keys[0], 100, 200)
    pool.save(path)

    with admin_for(path) as base:
        assert call(base, "PUT", f"/api/keys/{key.key_id}", {"label": "renamed"})[0] == 200

    stored = KeyPool.load(path).keys[0]
    assert stored.label == "renamed"
    assert (stored.usage.tokens_in, stored.usage.tokens_out) == (100, 200)


def test_page_is_served_and_has_no_secret(tmp_path: Path) -> None:
    key = make_key("a", "http://a")
    key.api_key = SECRET
    path = _pool_file(tmp_path, key)
    with admin_for(path) as base:
        status, html = call(base, "GET", "/")
    assert status == 200
    assert "中转站控制台" in html
    assert 'data-tab="clients"' in html
    assert SECRET not in html
    # 页面必须自己带 XSS 转义，否则上游回的错误信息能被当成 HTML 执行
    assert "function esc(" in html


def test_clients_view_distinguishes_app_from_direct_api(tmp_path: Path) -> None:
    """客户端页聚合：带身份头的流量归到「用户+设备」，直连流量按令牌归组。

    这条是管理台的核心诉求——不翻原始请求表就能回答
    「App 用户今天发了多少请求 / 这台直连令牌是谁在用」。
    """
    import time as time_module

    from relayhub.gateway import reqlog as reqlog_module

    key = make_key("a", "http://a")
    path = _pool_file(tmp_path, key)
    log = tmp_path / "requests.jsonl"
    now = time_module.time()
    # 同一台 App 设备两条请求（一好一坏）
    reqlog_module.record(
        log, ts=now - 30, token="pad-01", dialect="openai-chat", model="glm-4.6",
        channel="c1", ok=True, tokens_in=100, tokens_out=50, ip="192.168.1.60",
        ident_user="xiaoming", ident_ver="1.1.0", ident_dev="Pad-Pro", ident_did="abcd1234ef56",
    )
    reqlog_module.record(
        log, ts=now - 10, token="pad-01", dialect="openai-chat", model="glm-4.6",
        channel="c1", ok=False, status=502, reason="upstream 502", ip="192.168.1.60",
        ident_user="xiaoming", ident_ver="1.1.0", ident_dev="Pad-Pro", ident_did="abcd1234ef56",
    )
    # 直连 API：无任何 sm_* 字段
    reqlog_module.record(
        log, ts=now - 5, token="sdk-token", dialect="openai-chat", model="qwen3-32b",
        channel="c2", ok=True, tokens_in=10, tokens_out=5, ip="203.0.113.9",
    )
    with admin_for(path) as base:
        status, payload = call(base, "GET", "/api/clients")
    assert status == 200
    clients = payload["clients"]
    summary = payload["summary"]
    assert len(clients) == 2
    app = [c for c in clients if c["source"] == "app"]
    direct = [c for c in clients if c["source"] == "api"]
    assert len(app) == 1 and len(direct) == 1
    a = app[0]
    assert (a["user"], a["device"], a["device_id"]) == ("xiaoming", "Pad-Pro", "abcd1234ef56")
    assert a["token"] == "pad-01"
    assert a["total"] == 2 and a["failed"] == 1
    assert a["today"] == 2
    assert a["online"] is True  # 最近一条在 120s 窗口内
    assert a["last_ip"] == "192.168.1.60"
    assert a["top_models"] == ["glm-4.6"]
    d = direct[0]
    assert d["token"] == "sdk-token" and not d["user"]
    assert d["last_ip"] == "203.0.113.9" and d["today"] == 1
    assert d["online"] is True
    assert summary["app_devices"] == 1 and summary["api_sources"] == 1
    assert summary["today_requests"] == 3 and summary["app_requests_today"] == 2
    assert summary["online"] == 2
    # 排序：最近活跃的在前（direct 5s 前 > app 10s 前）
    assert clients[0]["source"] == "api"
