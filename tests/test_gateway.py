"""网关层测试：参考实现 + 一致性探测器 + 从网关生成 spec。

关键点是「探测器必须能抓出不合规实现」——否则它对真实网关的通过结论没有意义。
"""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from relayhub.gateway import conformance, reqlog
from relayhub.gateway.pool import KeyPool
from relayhub.gateway.router import KeyPoolRouter
from relayhub.gateway.service import Channel, ChannelPool, DemoRouter, RelayServer, demo_pool, demo_router
from relayhub.gateway.tokens import DownstreamToken, TokenPool, TokenStore
from tests.support import FakeUpstream, make_key

API_KEY = "rh_test_token"


@pytest.fixture
def relay() -> str:
    """起一个参考中转站，返回 base_url。"""
    server = RelayServer(
        ("127.0.0.1", 0), DemoRouter(demo_pool()), api_key=API_KEY, event_delay=0.03
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.base_url
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


class _BrokenHandler(BaseHTTPRequestHandler):
    """一个故意不合规的「网关」：所有请求都回 200 + 同一个 JSON，没有 SSE。"""

    protocol_version = "HTTP/1.1"

    def log_message(self, *args: object) -> None:
        return

    def _reply(self) -> None:
        raw = json.dumps({"ok": True}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    do_GET = _reply  # noqa: N815
    do_POST = _reply  # noqa: N815


@pytest.fixture
def broken_gateway() -> str:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _BrokenHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _by_name(results: list[conformance.CheckResult]) -> dict[str, conformance.CheckResult]:
    return {r.name: r for r in results}


# ---------------------------------------------------------------- 参考实现自检


def test_reference_gateway_passes_all_checks(relay: str) -> None:
    results = conformance.run_checks(relay, API_KEY)
    failures = [f"{r.name}: {r.detail}" for r in results if not r.ok]
    assert failures == [], failures
    assert "anthropic.stream.incremental" in _by_name(results)


def test_incremental_check_confirms_real_streaming(relay: str) -> None:
    results = _by_name(conformance.run_checks(relay, API_KEY))
    check = results["anthropic.stream.incremental"]
    assert check.ok, check.detail


def test_models_list_exposes_context_window(relay: str) -> None:
    probe = conformance.Probe(relay, API_KEY)
    payload = json.loads(probe.get("/v1/models").body.decode("utf-8"))
    ids = {item["id"] for item in payload["data"]}
    assert ids == {"glm-5.2", "deepseek-v4-pro", "deepseek-v4-flash"}
    assert all(item["context_window"] == 1000000 for item in payload["data"])


def test_auth_is_enforced(relay: str) -> None:
    probe = conformance.Probe(relay, API_KEY)
    response = probe.post(
        "/v1/messages", {"model": "glm-5.2", "max_tokens": 8, "messages": []}, with_auth=False
    )[0]
    assert response.status == 401


def test_unknown_model_is_404(relay: str) -> None:
    probe = conformance.Probe(relay, API_KEY)
    response = probe.post(
        "/v1/messages", {"model": "nope", "max_tokens": 8, "messages": []}
    )[0]
    assert response.status == 404


def test_server_rejects_router_without_the_interface() -> None:
    """传错对象的症状是「连接被掐断」，看不出根因，所以必须在构造期就炸。"""
    with pytest.raises(TypeError, match=r"relay\(\)/models\(\)"):
        RelayServer(("127.0.0.1", 0), demo_pool())  # type: ignore[arg-type]


def test_handler_exception_becomes_a_500_instead_of_a_dropped_connection() -> None:
    """handler 里炸了要回 500。

    不兜底的后果不是「报错」，而是 socketserver 静默掐断连接 ——
    客户端只看到 RemoteDisconnected，会去查网络，真正的堆栈在服务端 stderr 里没人看。
    """

    class Exploding:
        def models(self) -> dict[str, int]:
            return {"glm-5.2": 0}

        def relay(self, model: str, payload: dict, stream: bool) -> None:
            raise ValueError("boom")

    server = RelayServer(("127.0.0.1", 0), Exploding(), api_key=None)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        probe = conformance.Probe(server.base_url)
        response = probe.post(
            "/v1/messages", {"model": "glm-5.2", "max_tokens": 8, "messages": []}
        )[0]
        assert response.status == 500
        assert b"boom" in response.body
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_failover_uses_second_channel() -> None:
    """第一个渠道永远坏掉，仍应拿到 200，且结果来自第二个渠道。"""
    pool = ChannelPool(
        [
            Channel(name="primary-down", models={"glm-5.2": 1000}, broken=True),
            Channel(name="secondary", models={"glm-5.2": 1000}),
        ]
    )
    server = RelayServer(("127.0.0.1", 0), DemoRouter(pool), api_key=None, event_delay=0.0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        probe = conformance.Probe(server.base_url)
        response = probe.post(
            "/v1/messages", {"model": "glm-5.2", "max_tokens": 8, "messages": []}
        )[0]
        assert response.status == 200
        body = json.loads(response.body.decode("utf-8"))
        assert "secondary" in body["content"][0]["text"]
        assert pool.channels[0].failures >= 1
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


# ---------------------------------------------------------------- 探测器是否有效


def test_detector_rejects_non_conforming_gateway(broken_gateway: str) -> None:
    """核心测试：不合规实现必须被判失败，否则探测器等于橡皮章。"""
    results = _by_name(conformance.run_checks(broken_gateway))
    for name in (
        "anthropic.non_stream",
        "anthropic.stream",
        "openai.non_stream",
        "openai.stream",
        "error.unknown_model",
    ):
        assert name in results, f"{name} 没有被检查"
        assert not results[name].ok, f"{name} 竟然通过了，探测器有漏洞：{results[name].detail}"


def test_streaming_requires_event_stream_content_type(relay: str) -> None:
    probe = conformance.Probe(relay, API_KEY)
    response, _ = probe.post(
        "/v1/messages",
        {"model": "glm-5.2", "max_tokens": 8, "stream": True, "messages": []},
        streaming=True,
        read_stream=True,
    )
    assert "text/event-stream" in response.headers.get("content-type", "")


# ---------------------------------------------------------------- SSE 解析


def test_parse_sse_ignores_comments_and_ping() -> None:
    lines = [
        b": keepalive\n",
        b"\n",
        b"event: message_start\n",
        b"data: {\"type\":\"message_start\"}\n",
        b"\n",
        b"event: ping\n",
        b"data: {\"type\":\"ping\"}\n",
        b"\n",
    ]
    assert conformance.parse_sse(lines) == [
        ("message_start", '{"type":"message_start"}'),
        ("ping", '{"type":"ping"}'),
    ]


def test_parse_sse_joins_multiline_data() -> None:
    lines = [b"event: x\n", b"data: a\n", b"data: b\n", b"\n"]
    assert conformance.parse_sse(lines) == [("x", "a\nb")]




# ---------------------------------------------------------------- 下游令牌鉴权

TOKENS = {
    "app-a": "rht_secret-app-a",
    "app-b": "rht_secret-app-b",
    "limited": "rht_secret-limited",
    "paused": "rht_secret-paused",
}


def _token_store(tmp_path: Path) -> TokenStore:
    path = tmp_path / "tokens.json"
    records = [
        DownstreamToken(token_id="app-a", name="app-a", token=TOKENS["app-a"]),
        DownstreamToken(token_id="app-b", name="app-b", token=TOKENS["app-b"]),
        DownstreamToken(
            token_id="limited", name="limited", token=TOKENS["limited"], models=("glm-5.2",)
        ),
        DownstreamToken(
            token_id="paused", name="paused", token=TOKENS["paused"], enabled=False
        ),
    ]
    TokenPool(records).save(path)
    return TokenStore(path)


def _server_with_tokens(tmp_path: Path) -> RelayServer:
    return RelayServer(
        ("127.0.0.1", 0),
        DemoRouter(demo_pool()),
        api_key=API_KEY,
        event_delay=0.0,
        tokens=_token_store(tmp_path),
    )


@pytest.fixture
def token_relay(tmp_path: Path) -> str:
    server = _server_with_tokens(tmp_path)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.base_url
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_valid_token_passes_on_both_dialects(token_relay: str) -> None:
    """同一令牌在 x-api-key 与 Bearer 两种头下都必须过。"""
    probe = conformance.Probe(token_relay, TOKENS["app-a"])
    response, _ = probe.post(
        "/v1/messages", {"model": "glm-5.2", "max_tokens": 8, "messages": []}
    )
    assert response.status == 200
    # Bearer 走 OpenAI 口
    response, _ = probe.post(
        "/v1/chat/completions", {"model": "glm-5.2", "messages": []}
    )
    assert response.status == 200


def test_unknown_token_is_401(token_relay: str) -> None:
    probe = conformance.Probe(token_relay, "rht_not-issued")
    response, _ = probe.post(
        "/v1/messages", {"model": "glm-5.2", "max_tokens": 8, "messages": []}
    )
    assert response.status == 401


def test_disabled_token_is_401_and_says_so(token_relay: str) -> None:
    probe = conformance.Probe(token_relay, TOKENS["paused"])
    response, _ = probe.post(
        "/v1/messages", {"model": "glm-5.2", "max_tokens": 8, "messages": []}
    )
    assert response.status == 401
    assert "已被禁用" in response.body.decode("utf-8")


def test_master_key_still_works_alongside_tokens(token_relay: str) -> None:
    """引入令牌不破坏旧用法：master 凭证照常可用。"""
    probe = conformance.Probe(token_relay, API_KEY)
    response, _ = probe.post(
        "/v1/messages", {"model": "glm-5.2", "max_tokens": 8, "messages": []}
    )
    assert response.status == 200


def test_token_model_restriction_is_403(token_relay: str) -> None:
    probe = conformance.Probe(token_relay, TOKENS["limited"])
    response, _ = probe.post(
        "/v1/messages", {"model": "deepseek-v4-pro", "max_tokens": 8, "messages": []}
    )
    assert response.status == 403
    assert "limited" in response.body.decode("utf-8")


def test_token_usage_is_recorded_per_token(token_relay: str, tmp_path: Path) -> None:
    """按令牌记账：app-a 的三次请求记在 app-a 头上，与 app-b 无关。

    网关在写响应字节之前先落账（响应一出去客户端就可能断开），
    所以这里读完响应直接读文件是确定性的，不需要轮询。
    """
    probe = conformance.Probe(token_relay, TOKENS["app-a"])
    for model in ("glm-5.2", "glm-5.2", "deepseek-v4-pro"):
        response, _ = probe.post(
            "/v1/messages", {"model": model, "max_tokens": 8, "messages": []}
        )
        assert response.status == 200

    stats = {t["name"]: t for t in TokenStore(tmp_path / "tokens.json").stats()["tokens"]}
    assert stats["app-a"]["usage"]["ok"] == 3, "成功请求要记到令牌头上"
    assert stats["app-a"]["usage"]["tokens_in"] > 0, "非流式 usage 要回填"
    assert stats["app-b"]["usage"]["requests"] == 0, "别的令牌不能被串账"


def test_streaming_usage_reaches_the_token(tmp_path: Path) -> None:
    """流式 usage 在流尾才到，记账必须等流跑完。

    DemoRouter 不产生真 usage（events 是编好的固定事件），所以这条必须走
    真路由器 + 假上游：upstream.stream_events 的 on_usage → _TokenSink →
    RelayOutcome.usage → _record，整条链一个都不能断。
    """
    with FakeUpstream() as upstream:
        router = KeyPoolRouter(KeyPool([make_key("up", upstream.base_url)]))
        server = RelayServer(
            ("127.0.0.1", 0),
            router,
            api_key=API_KEY,
            event_delay=0.0,
            tokens=_token_store(tmp_path),
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            probe = conformance.Probe(server.base_url, TOKENS["app-b"])
            response, _ = probe.post(
                "/v1/messages",
                {"model": "glm-5.2", "max_tokens": 8, "stream": True, "messages": []},
                streaming=True,
                read_stream=True,
            )
            assert response.status == 200

            # 记账发生在流尾字节之后，与测试读盘之间是并发的，轮询等它落定
            stats = {}
            for _ in range(100):
                stats = {
                    t["name"]: t
                    for t in TokenStore(tmp_path / "tokens.json").stats()["tokens"]
                }
                if stats["app-b"]["usage"]["tokens_out"] > 0:
                    break
                time.sleep(0.05)
            assert stats["app-b"]["usage"]["ok"] == 1
            assert stats["app-b"]["usage"]["tokens_out"] == 5, "假上游流尾 usage 是 5"
            assert stats["app-b"]["usage"]["tokens_in"] == 7
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


def test_token_hot_reload_while_serving(tmp_path: Path) -> None:
    """serve 不重启，`token add` 发的新令牌立即可用。"""
    server = _server_with_tokens(tmp_path)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        probe = conformance.Probe(server.base_url, "rht_secret-newbie")
        response, _ = probe.post(
            "/v1/messages", {"model": "glm-5.2", "max_tokens": 8, "messages": []}
        )
        assert response.status == 401

        pool = TokenPool.load(tmp_path / "tokens.json")
        pool.add(DownstreamToken(token_id="newbie", name="newbie", token="rht_secret-newbie"))
        pool.save(tmp_path / "tokens.json")

        response, _ = probe.post(
            "/v1/messages", {"model": "glm-5.2", "max_tokens": 8, "messages": []}
        )
        assert response.status == 200, "新令牌必须被热加载识别"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_models_endpoint_accepts_tokens(token_relay: str) -> None:
    probe = conformance.Probe(token_relay, TOKENS["app-a"])
    assert probe.get("/v1/models").status == 200


# ================================================================ 公网三件套：测试密钥 / 限额 / 公网闸
#
# 公网语义（见 __main__ --public 与 tokens.py scope 字段）：
#   * scope=test 的令牌走 TestRouter——本地合成应答，不触达真实上游；
#   * 限额（rpm / daily_requests）对所有令牌身份生效，超限 429；
#   * 绑非回环地址前必须过 _public_safety_error 安全闸。


def _api_call(
    base: str, path: str, body: dict, credential: str | None
) -> tuple[int, dict | str]:
    """网关侧请求助手：HTTP 错误当返回值，不抛。"""
    import urllib.error
    import urllib.request

    data = json.dumps(body).encode("utf-8")
    request = urllib.request.Request(
        f"{base}{path}", data=data, method="POST"
    )
    request.add_header("Content-Type", "application/json")
    if credential:
        request.add_header("Authorization", f"Bearer {credential}")
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


@pytest.fixture
def public_relay(tmp_path: Path) -> str:
    """带下游令牌的参考网关：test 令牌 + RPM 限流令牌 + 日配额令牌各一枚。"""
    tokens = [
        DownstreamToken(
            token_id="t-test", name="bench-client", token="rht_test_secret", scope="test"
        ),
        DownstreamToken(
            token_id="t-rpm", name="rpm-client", token="rht_rpm_secret", rpm=1
        ),
        DownstreamToken(
            token_id="t-daily",
            name="daily-client",
            token="rht_daily_secret",
            daily_requests=1,
        ),
    ]
    tokens_path = tmp_path / "tokens.json"
    TokenPool(tokens).save(tokens_path)
    server = RelayServer(
        ("127.0.0.1", 0),
        DemoRouter(demo_pool()),
        api_key=None,
        tokens=TokenStore(tokens_path),
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.base_url
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_test_scope_serves_synthetic_for_any_model(public_relay: str) -> None:
    """test 令牌：任意模型名（包括号池里不存在的）都拿到合成应答。"""
    status, body = _api_call(
        public_relay,
        "/v1/chat/completions",
        {"model": "bench-fake-model", "messages": [{"role": "user", "content": "hi"}]},
        "rht_test_secret",
    )
    assert status == 200
    content = body["choices"][0]["message"]["content"]
    assert content.startswith("[relay-hub test-echo model=bench-fake-model]")
    assert body["usage"]["completion_tokens"] > 0


def test_test_scope_streaming_has_multiple_deltas(public_relay: str) -> None:
    """test 令牌的流式应答切多段 delta，压测 TPS 才有意义。"""
    import urllib.request

    request = urllib.request.Request(
        f"{public_relay}/v1/chat/completions",
        data=json.dumps(
            {
                "model": "bench-model",
                "messages": [{"role": "user", "content": "hi"}],
                "stream": True,
            }
        ).encode("utf-8"),
        method="POST",
    )
    request.add_header("Content-Type", "application/json")
    request.add_header("Authorization", "Bearer rht_test_secret")
    with urllib.request.urlopen(request, timeout=10) as response:
        raw = response.read().decode("utf-8")
    deltas = raw.count('"content"')
    assert deltas >= 3  # 24 段中的若干段 + role 帧
    assert "[DONE]" in raw


def test_normal_token_still_restricted_by_model_list(public_relay: str) -> None:
    """normal 令牌没有 test 的特权：未知模型照样 404。"""
    status, body = _api_call(
        public_relay,
        "/v1/chat/completions",
        {"model": "bench-fake-model", "messages": [{"role": "user", "content": "hi"}]},
        "rht_rpm_secret",
    )
    assert status == 404


def test_rpm_limit_returns_429(public_relay: str) -> None:
    """RPM=1：第一发放行，紧接的第二发 429。"""
    body = {"model": "glm-5.2", "messages": [{"role": "user", "content": "hi"}]}
    status1, _ = _api_call(public_relay, "/v1/chat/completions", body, "rht_rpm_secret")
    status2, body2 = _api_call(public_relay, "/v1/chat/completions", body, "rht_rpm_secret")
    assert status1 == 200
    assert status2 == 429
    assert "每分钟" in str(body2)


def test_daily_quota_returns_429(public_relay: str) -> None:
    """日配额=1：第二发 429，且错误里带「日配额」。"""
    body = {"model": "glm-5.2", "messages": [{"role": "user", "content": "hi"}]}
    status1, _ = _api_call(public_relay, "/v1/chat/completions", body, "rht_daily_secret")
    status2, body2 = _api_call(public_relay, "/v1/chat/completions", body, "rht_daily_secret")
    assert status1 == 200
    assert status2 == 429
    assert "日配额" in str(body2)


def test_public_safety_gate() -> None:
    """公网闸：无凭证拒绝（有文案），有 master 或启用令牌放行。"""
    from relayhub.gateway.__main__ import _public_safety_error

    error = _public_safety_error(None, 0)
    assert error is not None and "凭证" in error
    assert _public_safety_error("rh_dev", 0) is None
    assert _public_safety_error(None, 1) is None


# ================================================================ 转发环路防护


def test_loop_guard_counts_and_rejects() -> None:
    from relayhub.gateway.service import LoopGuard

    guard = LoopGuard(limit=3)
    fp = "fp-x"
    assert guard.acquire(fp) and guard.acquire(fp) and guard.acquire(fp)
    assert not guard.acquire(fp)  # 第 4 个同指纹在飞 → 判环
    guard.release(fp)
    assert guard.acquire(fp)  # 释放后恢复


def test_self_loop_terminates_quickly(tmp_path: Path) -> None:
    """渠道指向自己：内层请求同指纹在飞 +1 超阈值 → 508 打断，外层 502。

    关键断言是「快速失败」——没有防护时这个拓扑会互相等超时（120s×N）。
    """
    import hashlib
    import json as json_module
    import urllib.request

    from relayhub.gateway.pool import KeyPool, UpstreamKey
    from relayhub.gateway.router import KeyPoolRouter

    server = RelayServer(
        ("127.0.0.1", 0), KeyPoolRouter(KeyPool([])), api_key=None, loop_limit=2
    )
    # 把「自己」配成自己的上游（配置期护栏挡得住 127.0.0.1:8799 这种标准写法，
    # 但动态端口的自己挡不住——运行期 LoopGuard 正是给这种场景兜底的）
    key = UpstreamKey(
        key_id="self", label="self-loop",
        base_url=server.base_url, api_key="", protocol="anthropic-messages",
        models=("glm-5.2",),
    )
    server.router.pool.keys.append(key)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        request = urllib.request.Request(
            f"{server.base_url}/v1/messages",
            data=json_module.dumps(
                {"model": "glm-5.2", "max_tokens": 8, "messages": [{"role": "user", "content": "hi"}]}
            ).encode(),
            method="POST",
        )
        request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                status = response.status
        except urllib.error.HTTPError as exc:
            status = exc.code
        # 环被检测并打断：外层拿不到 200，且没有挂到超时（timeout=15 远小于上游 120s）
        assert status in (502, 508), status
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_is_self_reference_guard() -> None:
    from relayhub.gateway.pool import is_self_reference

    assert is_self_reference("http://127.0.0.1:8799/v1")
    assert is_self_reference("http://localhost:8799")
    assert not is_self_reference("http://127.0.0.1:9999")
    assert not is_self_reference("http://154.37.223.250:56960")


def test_loop_via_headers_rejected() -> None:
    """Via 含本站实例标记 或 Hops>=4 → 入口直接 508（最强的环路信号）。"""
    import urllib.error
    import urllib.request

    from relayhub.gateway.service import LoopGuard

    server = RelayServer(("127.0.0.1", 0), DemoRouter(demo_pool()), api_key=None)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        body = json.dumps({"model": "glm-5.2", "max_tokens": 8, "messages": []}).encode()
        # Via 自指
        request = urllib.request.Request(f"{server.base_url}/v1/messages", data=body, method="POST")
        request.add_header("Content-Type", "application/json")
        request.add_header("Via", f"relayhub-deadbeef, {server.instance_id}")
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                status = response.status
        except urllib.error.HTTPError as exc:
            status = exc.code
        assert status == 508
        # Hops 超限
        request = urllib.request.Request(f"{server.base_url}/v1/messages", data=body, method="POST")
        request.add_header("Content-Type", "application/json")
        request.add_header("X-Relay-Hub-Hops", "4")
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                status = response.status
        except urllib.error.HTTPError as exc:
            status = exc.code
        assert status == 508
        # 正常请求不受影响
        request = urllib.request.Request(f"{server.base_url}/v1/messages", data=body, method="POST")
        request.add_header("Content-Type", "application/json")
        request.add_header("X-Relay-Hub-Hops", "2")
        request.add_header("Via", "some-other-gateway")
        with urllib.request.urlopen(request, timeout=10) as response:
            assert response.status == 200
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_trace_headers_reach_upstream() -> None:
    """X-Request-ID 原样透传、Via 追加本站标记、Hops +1——转发链路可观测。"""
    import urllib.request

    with FakeUpstream() as up:
        pool = KeyPool([make_key("up", up.base_url)])
        server = RelayServer(("127.0.0.1", 0), KeyPoolRouter(pool), api_key=None)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            body = json.dumps({"model": "glm-5.2", "max_tokens": 8, "messages": []}).encode()
            request = urllib.request.Request(f"{server.base_url}/v1/messages", data=body, method="POST")
            request.add_header("Content-Type", "application/json")
            request.add_header("X-Request-ID", "req-abc-123")
            with urllib.request.urlopen(request, timeout=10) as response:
                assert response.status == 200
            sent = up.requests[0]["headers"]
            assert sent.get("x-request-id") == "req-abc-123"
            assert sent.get("x-relay-hub-hops") == "1"
            assert server.instance_id in sent.get("via", "")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


def test_exit_guard_skips_flooding_candidate() -> None:
    """出口查重：同指纹对同上游 60s 内超过 4 次 → 该候选被跳过。"""
    from relayhub.gateway.router import _EXIT_GUARD

    assert _EXIT_GUARD.allow("fp-e", "up") is True
    for _ in range(3):
        _EXIT_GUARD.allow("fp-e", "up")
    assert _EXIT_GUARD.allow("fp-e", "up") is False  # 第 5 次
    assert _EXIT_GUARD.allow("fp-e", "other-up") is True  # 不同上游不受影响


# ================================================================ 应答缓存与指纹规范


def test_response_cache_hit_and_key_discipline(tmp_path: Path) -> None:
    """同内容非流式请求第二次命中缓存（channel=cache，免上游）；
    语义参数不同（max_tokens 变了）→ 不同键，不命中。"""
    log_path = tmp_path / "requests.jsonl"
    server = RelayServer(
        ("127.0.0.1", 0), demo_router(), api_key=API_KEY, event_delay=0.0, request_log=log_path
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        probe = conformance.Probe(server.base_url, API_KEY)
        body = {"model": "glm-5.2", "max_tokens": 64, "messages": [{"role": "user", "content": "hi"}]}
        r1 = probe.post("/v1/messages", body)[0]
        r2 = probe.post("/v1/messages", body)[0]
        assert r1.status == 200 and r2.status == 200
        body2 = dict(body, max_tokens=128)
        r3 = probe.post("/v1/messages", body2)[0]
        assert r3.status == 200

        entries = reqlog.tail(log_path)
        channels = [e["channel"] for e in entries]
        assert channels[0] != "cache"  # 第一次真转发
        assert channels[1] == "cache"  # 第二次命中
        assert channels[2] != "cache"  # max_tokens 不同 → 不同键

        # 流式请求不进缓存：同内容流式连发两次都走真实路由
        s1 = probe.post("/v1/messages", dict(body, stream=True))[0]
        s2 = probe.post("/v1/messages", dict(body, stream=True))[0]
        assert s1.status == 200 and s2.status == 200
        entries = reqlog.tail(log_path)
        stream_channels = [e["channel"] for e in entries if e.get("stream")]
        assert all(c != "cache" for c in stream_channels)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_request_log_records_ip_and_req_id(tmp_path: Path) -> None:
    """日志带调用方 IP 与请求 ID（元数据，不含内容）。"""
    log_path = tmp_path / "requests.jsonl"
    server = RelayServer(
        ("127.0.0.1", 0), demo_router(), api_key=API_KEY, event_delay=0.0, request_log=log_path
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        probe = conformance.Probe(server.base_url, API_KEY)
        assert probe.post("/v1/messages", {"model": "glm-5.2", "max_tokens": 8, "messages": []})[0].status == 200
        entry = reqlog.tail(log_path)[0]
        assert entry.get("ip") == "127.0.0.1"
        assert entry.get("req_id")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
