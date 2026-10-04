"""配对流程测试：窗口生命周期（服务级）+ HTTP 兑换（端到端）。

配对是唯一一个「无凭证可达」的网关端点，所以这里的安全断言是硬性的：
码错要限次、过期要拒、成功即焚、发放的令牌要真能答题。
"""

from __future__ import annotations

import threading
from pathlib import Path

import pytest

from relayhub.gateway import pairing as pairing_module
from relayhub.gateway.pairing import PairingError, PairingService, open_window
from relayhub.gateway.service import DemoRouter, RelayServer, demo_pool
from relayhub.gateway.tokens import TokenStore


def _service(tmp_path: Path, *, clock=None) -> tuple[PairingService, TokenStore, Path]:
    store = TokenStore(tmp_path / "tokens.json")
    window_path = tmp_path / "pairing.json"
    kwargs = {"clock": clock} if clock else {}
    return PairingService(store, window_path, **kwargs), store, window_path


def _begin(window_path: Path, *, client_id: str = "app", ttl: float = 300.0) -> dict:
    return open_window(window_path, client_id=client_id, ttl=ttl)


# ---------------------------------------------------------------- 窗口生命周期


def test_open_window_generates_six_digit_code(tmp_path: Path) -> None:
    window = _begin(tmp_path / "pairing.json")
    assert len(window["code"]) == 6
    assert window["code"].isdigit()


def test_new_window_invalidates_the_old_one(tmp_path: Path) -> None:
    """同时只允许一枚活码：旧码必须立刻失效，不能两台设备并存配对。"""
    path = tmp_path / "pairing.json"
    first = _begin(path)
    second = _begin(path)
    service, _, _ = _service(tmp_path)
    with pytest.raises(PairingError, match="不正确"):
        service.redeem(first["code"], "laptop", "app")
    assert service.redeem(second["code"], "laptop", "app").token.startswith("rht_")


def test_wrong_code_is_counted_and_limited(tmp_path: Path) -> None:
    service, _, window_path = _service(tmp_path)
    _begin(window_path)

    # 5 次机会逐次递减；第 6 次起整个窗口作废——正确码也进不去
    for remaining in (4, 3, 2, 1, 0):
        with pytest.raises(PairingError, match=f"剩余 {remaining} 次"):
            service.redeem("000000", "laptop", "app")
    with pytest.raises(PairingError, match="次数已用尽"):
        service.redeem("000000", "laptop", "app")
    window = pairing_module._read_window(window_path)
    assert window is not None
    with pytest.raises(PairingError, match="次数已用尽"):
        service.redeem(window["code"], "laptop", "app")


def test_expired_window_is_rejected(tmp_path: Path) -> None:
    clock = {"now": 1000.0}
    service, _, window_path = _service(tmp_path, clock=lambda: clock["now"])
    # 开窗和兑换必须用同一只时钟，否则过期判定对不上
    open_window(window_path, client_id="app", ttl=300.0, clock=lambda: clock["now"])

    clock["now"] = 1299.0
    with pytest.raises(PairingError):
        service.redeem("000000", "laptop", "app")
    clock["now"] = 1301.0
    with pytest.raises(PairingError, match="过期"):
        service.redeem("000000", "laptop", "app")


def test_window_client_must_match(tmp_path: Path) -> None:
    service, _, window_path = _service(tmp_path)
    window = _begin(window_path, client_id="app")
    with pytest.raises(PairingError, match="只给客户端 app"):
        service.redeem(window["code"], "laptop", "other-app")


def test_redeem_success_mints_usable_token_and_burns_window(tmp_path: Path) -> None:
    service, store, window_path = _service(tmp_path)
    window = _begin(window_path)

    record = service.redeem(window["code"], "  my   laptop ", "app")
    assert record.name == "my laptop", "设备名要去首尾空白并压缩连续空白"
    assert store.find(record.token) is not None, "发放的令牌必须立刻可鉴权"
    assert not window_path.exists(), "成功即焚：同一枚码不能换第二枚令牌"
    with pytest.raises(PairingError, match="没有开启中的配对窗口"):
        service.redeem(window["code"], "other", "app")


def test_device_name_is_validated(tmp_path: Path) -> None:
    service, _, window_path = _service(tmp_path)
    window = _begin(window_path)
    with pytest.raises(PairingError, match="设备名"):
        service.redeem(window["code"], "   ", "app")
    with pytest.raises(PairingError, match="过长"):
        service.redeem(window["code"], "x" * 41, "app")


def test_duplicate_device_name_does_not_burn_the_window(tmp_path: Path) -> None:
    """重名是客户端可自己修复的错误（换个名字重试），窗口不该被烧掉。"""
    from relayhub.gateway.tokens import DownstreamToken

    service, store, window_path = _service(tmp_path)
    window = _begin(window_path)
    store.add(DownstreamToken(token_id="taken", name="dup", token="rht_preexisting"))

    with pytest.raises(PairingError, match="令牌发放失败"):
        service.redeem(window["code"], "dup", "app")
    assert window_path.exists(), "发放失败的窗口要保留，设备改名可重试"
    record = service.redeem(window["code"], "dup-2", "app")
    assert record.name == "dup-2"


def test_pairing_writes_audit_events(tmp_path: Path) -> None:
    service, _, window_path = _service(tmp_path)
    _begin(window_path)
    with pytest.raises(PairingError):
        service.redeem("000000", "laptop", "app")
    window = pairing_module._read_window(window_path)
    assert window is not None
    service.redeem(window["code"], "laptop", "app")

    from relayhub.gateway import audit

    events = [e["event"] for e in audit.tail(window_path.parent / "audit.jsonl")]
    assert "pair.begin" in events
    assert "pair.reject" in events
    assert "pair.success" in events


def test_sandbox_audit_stays_in_sandbox(tmp_path: Path) -> None:
    """窗口文件在临时目录时，审计必须跟着进临时目录——不能污染真实数据根。"""
    service, _, window_path = _service(tmp_path)
    _begin(window_path)
    assert (window_path.parent / "audit.jsonl").is_file()


# ---------------------------------------------------------------- HTTP 端到端


def test_pair_endpoint_end_to_end(tmp_path: Path) -> None:
    """开窗 → 无凭证 POST /v1/pair → 拿令牌 → 该令牌真能答题。"""
    from relayhub.gateway import conformance

    store = TokenStore(tmp_path / "tokens.json")
    window_path = tmp_path / "pairing.json"
    server = RelayServer(
        ("127.0.0.1", 0),
        DemoRouter(demo_pool()),
        api_key="rh_master",
        tokens=store,
        pairing=PairingService(store, window_path),
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        window = _begin(window_path)
        probe = conformance.Probe(server.base_url)
        # 未注册的客户端类型在兑换前就应被拒（不烧窗）
        response, _ = probe.post(
            "/v1/pair",
            {"code": window["code"], "name": "x", "client": "cursor"},
            with_auth=False,
        )
        assert response.status == 400

        response, _ = probe.post(
            "/v1/pair",
            {"code": window["code"], "name": "app-laptop", "client": "app"},
            with_auth=False,
        )
        assert response.status == 200, response.body
        payload = __import__("json").loads(response.body.decode("utf-8"))
        assert payload["api_key"].startswith("rht_")
        assert payload["models"], "接入载荷必须带上网关当前模型"

        # 拿到的令牌立刻能过鉴权、能拉模型
        authorized = conformance.Probe(server.base_url, payload["api_key"])
        assert authorized.get("/v1/models").status == 200

        # 窗口已焚
        assert not window_path.exists()
        response, _ = probe.post(
            "/v1/pair",
            {"code": window["code"], "name": "again", "client": "app"},
            with_auth=False,
        )
        assert response.status == 403
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_pair_endpoint_without_window_is_rejected(tmp_path: Path) -> None:
    from relayhub.gateway import conformance

    store = TokenStore(tmp_path / "tokens.json")
    server = RelayServer(
        ("127.0.0.1", 0),
        DemoRouter(demo_pool()),
        api_key="rh_master",
        tokens=store,
        pairing=PairingService(store, tmp_path / "pairing.json"),
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        probe = conformance.Probe(server.base_url)
        response, _ = probe.post(
            "/v1/pair", {"code": "123456", "name": "x", "client": "app"}, with_auth=False
        )
        assert response.status == 403
        assert "没有开启中的配对窗口" in response.body.decode("utf-8")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)




# ================================================================ 免码配对（auto-lan）


def test_auto_pair_issues_then_reuses_and_rejects_wan(tmp_path: Path) -> None:
    """免码三律：私有来源发放、同设备重绑轮换、公网来源拒绝。"""
    service, _, _ = _service(tmp_path)
    first = service.auto_pair("phone-classroom-3", "app", ip="192.168.1.50")
    assert first.token.startswith("rht_")
    again = service.auto_pair("phone-classroom-3", "app", ip="192.168.1.51")
    assert again.token != first.token, "重绑轮换：发新枚（明文令牌落盘只有哈希，无法二次下发）"
    assert again.name == first.name
    assert len(service.tokens.pool.tokens) == 1, "轮换不新增令牌位，一台设备恒占一枚"
    # 公网来源没有免码资格
    with pytest.raises(PairingError) as excinfo:
        service.auto_pair("attacker", "app", ip="8.8.8.8")
    assert "局域网" in str(excinfo.value)
    # 回环也算可信来源
    loopback = service.auto_pair("localhost-tool", "app", ip="127.0.0.1")
    assert loopback.token.startswith("rht_")


def _post_pair(base_url: str, body: dict, *, real_ip: str | None = None):
    import http.client
    import json as json_module
    from urllib.parse import urlparse

    parsed = urlparse(base_url)
    conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=10)
    headers = {"Content-Type": "application/json"}
    if real_ip:
        headers["X-Real-IP"] = real_ip
    conn.request("POST", "/v1/pair", json_module.dumps(body).encode(), headers)
    response = conn.getresponse()
    payload = json_module.loads(response.read().decode("utf-8"))
    conn.close()
    return response.status, payload


def test_auto_lan_pair_endpoint_end_to_end(tmp_path: Path) -> None:
    """免码模式下：内网来源无码即绑（重绑轮换），公网来源仍要配对码。"""
    import json as json_module

    from relayhub.gateway import conformance

    store = TokenStore(tmp_path / "tokens.json")
    server = RelayServer(
        ("127.0.0.1", 0),
        DemoRouter(demo_pool()),
        api_key="rh_master",
        tokens=store,
        pairing=PairingService(store, tmp_path / "pairing.json"),
        pair_mode="auto-lan",
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        # whoami 报告免码模式，客户端据此跳过配对码输入
        probe = conformance.Probe(server.base_url)
        who = __import__("json").loads(probe.get("/v1/whoami").body.decode("utf-8"))
        assert who["pair_mode"] == "auto-lan"

        body = {"name": "pad-student-a", "client": "app"}
        status, payload = _post_pair(server.base_url, body, real_ip="192.168.1.60")
        assert status == 200, payload
        assert payload["api_key"].startswith("rht_")
        token_a = payload["api_key"]
        assert payload["models"], "onboarding 要带模型清单"

        status, payload2 = _post_pair(server.base_url, body, real_ip="192.168.1.60")
        assert status == 200
        assert payload2["api_key"] != token_a, "重绑轮换发新枚"
        assert len(store.pool.tokens) == 1, "号池恒一台设备一枚令牌"

        status, payload3 = _post_pair(
            server.base_url, {"name": "evil", "client": "app"}, real_ip="8.8.8.8"
        )
        assert status == 403
        assert "局域网" in payload3["error"]["message"]

        # 轮换语义：旧令牌随重绑立即吊销，新令牌即刻可用
        stale = conformance.Probe(server.base_url, token_a)
        assert stale.get("/v1/models").status == 401
        fresh = conformance.Probe(server.base_url, payload2["api_key"])
        assert fresh.get("/v1/models").status == 200
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_code_mode_still_requires_pairing_code(tmp_path: Path) -> None:
    """默认 code 模式：无码请求明确告知需要配对码，窗口语义不变。"""
    store = TokenStore(tmp_path / "tokens.json")
    server = RelayServer(
        ("127.0.0.1", 0),
        DemoRouter(demo_pool()),
        api_key="rh_master",
        tokens=store,
        pairing=PairingService(store, tmp_path / "pairing.json"),
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, payload = _post_pair(
            server.base_url, {"name": "x", "client": "app"}
        )
        assert status == 403
        assert "配对码" in payload["error"]["message"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
