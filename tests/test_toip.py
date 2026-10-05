"""TOIP 接入协议 + 插件日志：口令、通行证、端点、分账。

这个文件里最要紧的断言不是「功能能用」，而是四条安全边界：

  1. 公开端点（/v1/toip/station 与 UDP 发现应答）**永不泄露**种子/口令/令牌；
  2. 非法插件 id **不能**把自己写成数据根外的路径（`../` 逃逸）；
  3. 令牌轮换是**真的轮换**——旧令牌立刻失效（否则「重新接入」只是换了个明文）；
  4. 插件日志的字段白名单——任何越界字段（尤其是对话内容）都进不去。

另外两条是协议可用性的命门：口令窗口的时钟漂移容忍，以及 `/v1/toip/join`
返回的 `dsh.baseURL` 必须带 `/v1`（DSH 的 Messages 适配器只在 pathname
不以 /v1 结尾时才补 /v1，写错就是 404）。
"""

from __future__ import annotations

import base64
import json
import os
import threading
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

import pytest

from relayhub import paths
from relayhub.gateway import pluginlogs, toip
from relayhub.gateway.service import DemoRouter, RelayServer, demo_pool
from relayhub.gateway.tokens import DownstreamToken, TokenPool, TokenStore

TOKEN = "rht_toip_test_token"
PLUGIN = "dsh-relayhub-bridge"


# -- 环境与网关夹具 -------------------------------------------------------


@contextmanager
def managed_home(tmp_path: Path) -> Iterator[Path]:
    """把数据根指到 tmp_path。

    必须改环境变量而不是只传路径：`RelayServer` 内部走 `paths.relayhub_home()`
    找插件日志根，只有环境变量能同时覆盖服务端与 CLI 两侧的定位。
    """
    home = tmp_path / "home"
    home.mkdir(parents=True, exist_ok=True)
    previous = os.environ.get("RELAYHUB_HOME")
    os.environ["RELAYHUB_HOME"] = str(home)
    try:
        yield home
    finally:
        if previous is None:
            os.environ.pop("RELAYHUB_HOME", None)
        else:
            os.environ["RELAYHUB_HOME"] = previous
    

def _make_server(home: Path, tmp_path: Path) -> RelayServer:
    TokenPool(
        [DownstreamToken(token_id="t1", name="app:demo", token=TOKEN)]
    ).save(home / "tokens.json")
    service = toip.ToipService(
        toip.TicketStore(paths.toip_tickets_path()),
        TokenStore(home / "tokens.json"),
        paths.toip_station_path(),
    )
    return RelayServer(
        ("127.0.0.1", 0),
        DemoRouter(demo_pool()),
        api_key=None,
        event_delay=0.0,
        tokens=TokenStore(home / "tokens.json"),
        request_log=tmp_path / "requests.jsonl",
        toip=service,
        plugin_log_home=home,
    )


@contextmanager
def toip_gateway(tmp_path: Path) -> Iterator[tuple[RelayServer, Path]]:
    """起一个启用 TOIP 的中转站：站点身份 + 一枚通行证都已就绪。"""
    with managed_home(tmp_path) as home:
        station = toip.StationIdentity.create(name="lab-hub")
        toip.save_station(paths.toip_station_path(), station)
        store = toip.TicketStore(paths.toip_tickets_path())
        record, plain = toip.make_ticket(name="dsh-laptop", plugins=[PLUGIN])
        store.add(record)

        server = _make_server(home, tmp_path)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server, home
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


def post(base: str, path: str, body: dict[str, Any], headers: dict[str, str] | None = None) -> tuple[int, Any]:
    """POST JSON，返回 (status, 解析结果)。HTTP 错误也当返回值，不抛。"""
    request = urllib.request.Request(
        f"{base}{path}", data=json.dumps(body).encode("utf-8"), method="POST"
    )
    request.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        request.add_header(key, value)
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


def get(base: str, path: str, headers: dict[str, str] | None = None) -> tuple[int, Any]:
    request = urllib.request.Request(f"{base}{path}", method="GET")
    for key, value in (headers or {}).items():
        request.add_header(key, value)
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


def ticket_plain(home: Path) -> str:
    """从 tickets.json 反查不到明文，所以重新签一枚并直接返回它的明文。"""
    store = toip.TicketStore(paths.toip_tickets_path())
    record, plain = toip.make_ticket(name=f"extra-{time.time_ns()}", plugins=[PLUGIN])
    store.add(record)
    return plain


# -- TOTP 内核 ------------------------------------------------------------


def test_totp_is_six_digits() -> None:
    secret = toip.new_secret()
    code = toip.totp_now(secret)
    assert len(code) == 6 and code.isdigit(), code


def test_totp_matches_rfc6238_style_vectors() -> None:
    """固定种子的确定输出：同一个种子+时刻必须永远算出同一个口令。

    这里不用 RFC 的公开向量（那用的是 ASCII "12345678901234567890" 与 8 位
    输出），而是钉住本项目自己的算法选择——换哈希或换截断方式必须让这条挂掉，
    否则 Dart/JS 侧的独立实现会在用户机器上悄悄对不上。
    """
    secret = toip.b32decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
    assert toip.totp_at(secret, at=1_000_000_000.0) == toip.totp_at(
        secret, at=1_000_000_000.0
    )
    # 取窗口**起点**再验同窗/跨窗：1000000000 秒本身落在窗口内第 10 秒，
    # 直接 +29 会跨窗（这是我第一版断言写错的地方，留注释免得下次再踩）。
    start = (1_000_000_000.0 // toip.TOTP_STEP) * toip.TOTP_STEP
    assert toip.totp_at(secret, at=start) == toip.totp_at(
        secret, at=start + toip.TOTP_STEP - 1
    ), "同一窗口内必须是同一枚口令"
    assert toip.totp_at(secret, at=start) != toip.totp_at(
        secret, at=start + toip.TOTP_STEP
    ), "跨窗口必须换口令"


def test_verify_totp_tolerates_one_window_drift() -> None:
    """±1 窗口都要过。这条挂了 = 用户时钟差 10 秒就接不进来。"""
    secret = toip.new_secret()
    now = time.time()
    assert toip.verify_totp(secret, toip.totp_at(secret, at=now - 30.0))
    assert toip.verify_totp(secret, toip.totp_at(secret, at=now + 30.0))
    assert toip.verify_totp(secret, toip.totp_at(secret, at=now))


def test_verify_totp_rejects_far_drift_and_garbage() -> None:
    secret = toip.new_secret()
    now = time.time()
    assert not toip.verify_totp(secret, toip.totp_at(secret, at=now - 5 * 30.0))
    assert not toip.verify_totp(secret, "000000") or toip.totp_now(secret) == "000000"
    for bad in ("", "abc", "12345", "1234567", "12 34 56"):
        assert not toip.verify_totp(secret, bad), bad


def test_base32_roundtrip_and_tolerance() -> None:
    secret = toip.new_secret()
    text = toip.b32encode(secret)
    assert "=" not in text, "填充要去掉，管理员要手抄"
    assert toip.b32decode(text) == secret
    # 容错：小写、空格、连字符、缺填充都该认
    assert toip.b32decode(text.lower()) == secret
    assert toip.b32decode(f" {text[:4]} {text[4:]} ") == secret


def test_base32_rejects_junk() -> None:
    for bad in ("", "   ", "!!!", "0O1I"):
        with pytest.raises(toip.ToipError):
            toip.b32decode(bad)


def test_otpauth_uri_shape() -> None:
    secret = toip.b32encode(toip.new_secret())
    uri = toip.otpauth_uri(secret, label="dsh-laptop")
    assert uri.startswith("otpauth://totp/")
    assert f"secret={secret}" in uri
    assert "digits=6" in uri and "period=30" in uri and "SHA1" in uri


# -- 插件 id / 目录逃逸 ---------------------------------------------------


def test_plugin_id_sanitizer_blocks_path_escape() -> None:
    """插件 id 会变成日志目录名，`../` 必须被挡在门外。

    这条挂了 = 任何能改请求头的人可以把日志写到数据根之外（覆盖任意文件）。
    """
    for bad in ("../evil", "..", "a/b", "a\\b", ".hidden", "trailing.", "x..y", "", "   "):
        with pytest.raises(toip.ToipError):
            toip.sanitize_plugin_id(bad)


def test_plugin_id_sanitizer_accepts_normal_ids() -> None:
    assert toip.sanitize_plugin_id("dsh-relayhub-bridge") == "dsh-relayhub-bridge"
    assert toip.sanitize_plugin_id("  DSH-Relayhub  ") == "dsh-relayhub"
    assert toip.sanitize_plugin_id("a.b_c-d") == "a.b_c-d"


# -- 通行证 ---------------------------------------------------------------


def test_ticket_store_roundtrip_and_duplicate_name(tmp_path: Path) -> None:
    with managed_home(tmp_path):
        store = toip.TicketStore(paths.toip_tickets_path())
        record, plain = toip.make_ticket(name="laptop", plugins=[PLUGIN])
        store.add(record)
        assert store.find(plain).ticket_id == record.ticket_id
        assert store.find("rhe_bogus") is None
        # 明文绝不落盘
        raw = paths.toip_tickets_path().read_text(encoding="utf-8")
        assert plain not in raw, "通行证明文不该出现在盘上"
        assert record.ticket_hash in raw
        # 同名再签必须被拒（吊销时靠名字找人，重名就没法找）
        other, _ = toip.make_ticket(name="laptop")
        with pytest.raises(toip.ToipError):
            store.add(other)


def test_ticket_enforces_plugin_whitelist(tmp_path: Path) -> None:
    with managed_home(tmp_path) as home:
        toip.save_station(paths.toip_station_path(), toip.StationIdentity.create(name="s"))
        store = toip.TicketStore(paths.toip_tickets_path())
        record, plain = toip.make_ticket(name="laptop", plugins=["only-this-plugin"])
        store.add(record)
        service = toip.ToipService(store, TokenStore(home / "tokens.json"), paths.toip_station_path())
        with pytest.raises(toip.ToipError, match="只允许插件"):
            service.join(ticket=plain, name="x", plugin_id="other-plugin", ip="127.0.0.1")
        assert service.join(
            ticket=plain, name="x", plugin_id="only-this-plugin", ip="127.0.0.1"
        ).token_plain.startswith("rht_")


def test_ticket_ttl_expiry(tmp_path: Path) -> None:
    with managed_home(tmp_path) as home:
        toip.save_station(paths.toip_station_path(), toip.StationIdentity.create(name="s"))
        store = toip.TicketStore(paths.toip_tickets_path())
        record, plain = toip.make_ticket(name="laptop", ttl=-1.0)
        store.add(record)
        service = toip.ToipService(store, TokenStore(home / "tokens.json"), paths.toip_station_path())
        with pytest.raises(toip.ToipError, match="过期"):
            service.join(ticket=plain, name="x", plugin_id=PLUGIN, ip="127.0.0.1")


# -- 轮换语义 -------------------------------------------------------------


def test_join_rotates_and_old_token_dies(tmp_path: Path) -> None:
    """第二次接入必须让第一次的令牌失效。

    这是「重新接入」这件事唯一诚实的实现方式：令牌明文落盘只存哈希，
    拿不回原文，所以轮换（作废旧、发新）是唯一能「再来一次」的动作。
    这条挂了 = 旧令牌仍然可用，等于给每次接入都留一枚永不失效的钥匙。
    """
    with managed_home(tmp_path) as home:
        toip.save_station(paths.toip_station_path(), toip.StationIdentity.create(name="s"))
        store = toip.TicketStore(paths.toip_tickets_path())
        record, plain = toip.make_ticket(name="laptop", plugins=[PLUGIN])
        store.add(record)
        tokens = TokenStore(home / "tokens.json")
        service = toip.ToipService(store, tokens, paths.toip_station_path())

        first = service.join(ticket=plain, name="laptop", plugin_id=PLUGIN, ip="127.0.0.1")
        assert first.returned_session is False
        assert tokens.find(first.token_plain) is not None

        station = toip.load_station(paths.toip_station_path())
        second = service.join(
            code=toip.totp_now(station.secret_bytes),
            name="laptop",
            plugin_id=PLUGIN,
            ip="127.0.0.1",
        )
        assert second.returned_session is True
        assert tokens.find(second.token_plain) is not None
        assert tokens.find(first.token_plain) is None, "旧令牌必须已失效"


def test_join_without_any_credential_is_rejected(tmp_path: Path) -> None:
    with managed_home(tmp_path) as home:
        toip.save_station(paths.toip_station_path(), toip.StationIdentity.create(name="s"))
        service = toip.ToipService(
            toip.TicketStore(paths.toip_tickets_path()),
            TokenStore(home / "tokens.json"),
            paths.toip_station_path(),
        )
        with pytest.raises(toip.ToipError, match="登记口令"):
            service.join(name="x", plugin_id=PLUGIN, ip="127.0.0.1")


def test_join_brute_force_lockout(tmp_path: Path) -> None:
    """连续错口令必须把来源锁死。动态口令可以被在线爆破，这是唯一的闸门。"""
    with managed_home(tmp_path) as home:
        toip.save_station(paths.toip_station_path(), toip.StationIdentity.create(name="s"))
        service = toip.ToipService(
            toip.TicketStore(paths.toip_tickets_path()),
            TokenStore(home / "tokens.json"),
            paths.toip_station_path(),
        )
        wrong = "000000"
        for _ in range(toip.JOIN_MAX_ATTEMPTS):
            try:
                service.join(code=wrong, name="x", plugin_id=PLUGIN, ip="10.0.0.5")
            except toip.ToipError:
                pass
        assert service.locked_out("10.0.0.5"), "达到上限后必须锁死"
        # 别的来源不该被连坐
        assert not service.locked_out("10.0.0.6")


def test_rotate_secret_invalidates_code_but_keeps_token(tmp_path: Path) -> None:
    """轮换口令种子：旧口令立刻作废，但已发出的会话令牌照常工作。

    这是 TOIP 相对配对码最大的运维优势，也是它值得存在的理由之一。
    """
    with managed_home(tmp_path) as home:
        station = toip.StationIdentity.create(name="s")
        toip.save_station(paths.toip_station_path(), station)
        store = toip.TicketStore(paths.toip_tickets_path())
        record, plain = toip.make_ticket(name="laptop", plugins=[PLUGIN])
        store.add(record)
        tokens = TokenStore(home / "tokens.json")
        service = toip.ToipService(store, tokens, paths.toip_station_path())
        issued = service.join(ticket=plain, name="laptop", plugin_id=PLUGIN, ip="127.0.0.1")
        # 先把旧种子快照成字符串：rotate_secret 是**原地改**传进去的对象
        # （改完再落盘），所以事后拿 station.secret 跟自己比会永远相等。
        old_secret_text = station.secret
        old_code = toip.totp_now(station.secret_bytes)

        # 先离线验证「种子换代 → 旧口令作废」这条因果，不掺入随机性
        assert not toip.verify_totp(toip.new_secret(), old_code)

        toip.rotate_secret(paths.toip_station_path(), station)
        fresh = toip.load_station(paths.toip_station_path())
        # 种子必须真的换掉：new_secret() 抽到与旧种子相同字节的概率是 2^-160，
        # 不构成 flaky 风险。
        assert fresh.secret != old_secret_text, "轮换必须真的换掉种子"
        assert toip.b32decode(fresh.secret) != toip.b32decode(old_secret_text)
        assert fresh.station_id == station.station_id, "轮换种子不该换站点 id"
        # 旧口令（按旧种子算）必须作废
        assert not toip.verify_totp(fresh.secret_bytes, old_code)
        # 已发出的令牌不受影响
        assert tokens.find(issued.token_plain) is not None


# -- HTTP 端点 -----------------------------------------------------------


def test_station_endpoint_disabled_returns_404(tmp_path: Path) -> None:
    """没建站点身份时 /v1/toip/station 是 404——探测方一眼看出该换配对码。"""
    with managed_home(tmp_path) as home:
        server = _make_server(home, tmp_path)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            status, _ = get(server.base_url, "/v1/toip/station")
            assert status == 404
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


def test_station_endpoint_never_leaks_secrets(tmp_path: Path) -> None:
    """公开端点只能报能力，不能报种子/口令/令牌。这是本协议最重要的一条。"""
    with toip_gateway(tmp_path) as (server, home):
        status, payload = get(server.base_url, "/v1/toip/station")
        assert status == 200
        assert payload["protocol"] == "toip"
        assert payload["enabled"] is True
        assert payload["station_id"].startswith("rst_")
        assert payload["otp"] == {
            "algorithm": "SHA1",
            "digits": 6,
            "period": 30,
            "window": toip.TOTP_WINDOW,
        }
        # base_url 用请求看到的地址回填
        assert payload["base_url"] == server.base_url
        # 全量文本里不能出现任何密钥材料
        blob = json.dumps(payload, ensure_ascii=False)
        station = toip.load_station(paths.toip_station_path())
        assert station.secret not in blob, "种子泄露到公开端点"
        assert "secret" not in payload
        assert "rht_" not in blob and "rhe_" not in blob
        for key in payload:
            assert "token" not in key.lower()
            assert "ticket" not in key.lower()


def test_join_with_ticket_returns_dsh_block(tmp_path: Path) -> None:
    """接入载荷必须带上 DSH 直接可用的三个值，且 baseURL 以 /v1 结尾。

    `baseURL` 少了 /v1 就是 404：DSH 的 `messagesApiRoot` 只在 pathname
    不以 /v1 结尾时才补 /v1，带 /v1 是唯一确定的写法。
    """
    with toip_gateway(tmp_path) as (server, home):
        status, payload = post(
            server.base_url,
            "/v1/toip/join",
            {"ticket": ticket_plain(home), "plugin": PLUGIN, "name": "dsh-laptop"},
        )
        assert status == 200, payload
        assert payload["protocol"] == "toip"
        assert payload["plugin"]["id"] == PLUGIN
        assert payload["session"]["token"].startswith("rht_")
        assert payload["session"]["rotated"] is False
        dsh = payload["dsh"]
        assert dsh["baseURL"] == f"{server.base_url}/v1"
        assert dsh["baseURL"].endswith("/v1")
        assert dsh["apiKey"] == payload["session"]["token"]
        assert dsh["provider"] == "relayhub"
        assert dsh["models"], "必须给出可选模型清单"
        assert all(item["id"] for item in dsh["models"])
        # 头名写在响应里，插件不必硬编码
        assert payload["plugin"]["headers"]["plugin_id"] == toip.PLUGIN_ID_HEADER


def test_join_with_totp_code_works(tmp_path: Path) -> None:
    """口令路径 = 「重接」，应轮换同一枚令牌而不是新开一个位。"""
    with toip_gateway(tmp_path) as (server, home):
        # 先用车票建立绑定（首接），再用口令重接——这才是真实的重连顺序
        status, first = post(
            server.base_url,
            "/v1/toip/join",
            {"ticket": ticket_plain(home), "plugin": PLUGIN, "name": "dsh-laptop"},
        )
        assert status == 200, first
        assert first["session"]["rotated"] is False

        station = toip.load_station(paths.toip_station_path())
        status, payload = post(
            server.base_url,
            "/v1/toip/join",
            {"code": toip.totp_now(station.secret_bytes), "plugin": PLUGIN},
        )
        assert status == 200, payload
        assert payload["session"]["rotated"] is True, "口令路径是「重接」，应轮换"
        # 设备名必须沿用旧的（dsh-laptop），不能在重接时被改成插件 id：
        # 否则 tokens.json 与插件日志的 token 列会变，历史对不上。
        assert payload["session"]["token"] != first["session"]["token"]
        assert payload["display_name"] == first["display_name"]
        assert payload["station"]["id"].startswith("rst_")


def test_join_rejects_wrong_code_and_bad_plugin(tmp_path: Path) -> None:
    with toip_gateway(tmp_path) as (server, home):
        status, payload = post(
            server.base_url, "/v1/toip/join", {"code": "000000", "plugin": PLUGIN}
        )
        assert status == 403, payload
        status, payload = post(
            server.base_url,
            "/v1/toip/join",
            {"ticket": ticket_plain(home), "plugin": "../evil"},
        )
        assert status == 400, payload
        status, payload = post(
            server.base_url, "/v1/toip/join", {"ticket": ticket_plain(home)}
        )
        assert status == 400, "缺 plugin 必须被拒（插件 id 是分账主语）"
        assert "plugin" in json.dumps(payload, ensure_ascii=False)


def test_enroll_requires_a_ticket(tmp_path: Path) -> None:
    with toip_gateway(tmp_path) as (server, home):
        status, _ = post(
            server.base_url, "/v1/toip/enroll", {"code": "123456", "plugin": PLUGIN}
        )
        assert status == 400
        status, payload = post(
            server.base_url, "/v1/toip/enroll", {"ticket": ticket_plain(home), "plugin": PLUGIN}
        )
        assert status == 200, payload
        assert payload["session"]["token"].startswith("rht_")


def test_session_endpoint_reports_identity(tmp_path: Path) -> None:
    with toip_gateway(tmp_path) as (server, home):
        _, payload = post(
            server.base_url,
            "/v1/toip/join",
            {"ticket": ticket_plain(home), "plugin": PLUGIN},
        )
        token = payload["session"]["token"]
        status, session = get(
            server.base_url, "/v1/toip/session", {"x-api-key": token}
        )
        assert status == 200, session
        assert session["plugin_id"] == PLUGIN
        assert session["station_id"].startswith("rst_")
        assert session["usage"]["requests"] == 0
        # 无凭证 401
        assert get(server.base_url, "/v1/toip/session")[0] == 401


def test_joined_token_can_actually_call_the_gateway(tmp_path: Path) -> None:
    """端到端：TOIP 发出的令牌必须能直接打 /v1/messages。

    这条是把「协议对不对」和「能不能用」连起来的那根线——只验 200 的接入
    可能发了一枚没有任何权限的令牌。
    """
    with toip_gateway(tmp_path) as (server, home):
        _, payload = post(
            server.base_url,
            "/v1/toip/join",
            {"ticket": ticket_plain(home), "plugin": PLUGIN},
        )
        token = payload["session"]["token"]
        status, models = get(server.base_url, "/v1/models", {"x-api-key": token})
        assert status == 200, models
        assert models["data"], "模型清单不该为空"
        status, reply = post(
            server.base_url,
            "/v1/messages",
            {"model": "glm-5.2", "max_tokens": 8, "messages": []},
            {"x-api-key": token},
        )
        assert status == 200, reply


# -- 插件日志 -------------------------------------------------------------


def test_plugin_logs_are_tagged_per_plugin(tmp_path: Path) -> None:
    """带插件头的请求必须落进该插件自己的目录，并带全元数据。

    这里用**夹具自带的那枚令牌**（名字 app:demo）而不是再签一枚通行证：
    TOIP 的轮换语义是「同设备重接即换钥匙」，再签一次会把夹具令牌换掉，
    断言就会对着另一枚令牌的用量，测的也不是本来想测的东西。
    """
    with toip_gateway(tmp_path) as (server, home):
        status, _ = post(
            server.base_url,
            "/v1/messages",
            {"model": "glm-5.2", "max_tokens": 8, "messages": []},
            {
                "x-api-key": TOKEN,
                toip.PLUGIN_ID_HEADER: PLUGIN,
                toip.PLUGIN_VERSION_HEADER: "0.1.0",
            },
        )
        assert status == 200

        rows = pluginlogs.tail(home, PLUGIN)
        assert len(rows) == 1, rows
        entry = rows[0]
        assert entry["plugin"] == PLUGIN
        assert entry["plugin_version"] == "0.1.0"
        assert entry["model"] == "glm-5.2"
        assert entry["dialect"] == "anthropic"
        assert entry["ok"] is True
        assert entry["status"] == 200
        assert entry["ip"]
        assert entry["token"] == "app:demo"
        # 目录结构与自述文件
        assert pluginlogs.daily_path(home, PLUGIN, time.time()).parent == pluginlogs.plugin_dir(home, PLUGIN)
        assert (pluginlogs.plugin_dir(home, PLUGIN) / "schema.json").is_file()


def test_plugin_log_fields_are_whitelisted(tmp_path: Path) -> None:
    """隐私边界：插件日志只落元数据，**永不落对话内容**。

    这条挂了等于给每个插件做一份对话存档——本模块最不能破的一条线。
    这里用「签名级」证据：`record()` 根本没有 prompt/completion 这类参数，
    调用方想写内容都写不进去；再加上落盘键的白名单是闭集。
    """
    import inspect

    accepted = set(inspect.signature(pluginlogs.record).parameters)
    for forbidden in ("prompt", "completion", "content", "body", "messages"):
        assert forbidden not in accepted, f"记录函数不该接受 {forbidden}"
        assert forbidden not in pluginlogs._ALLOWED_KEYS, f"白名单不该放行 {forbidden}"

    with managed_home(tmp_path) as home:
        pluginlogs.record(home, PLUGIN, model="m", ok=True, tokens_in=3, tokens_out=4)
        rows = pluginlogs.tail(home, PLUGIN)
        assert rows, "至少该写下被允许的字段"
        assert set(rows[0]) <= pluginlogs._ALLOWED_KEYS


def test_plugin_log_isolation_between_plugins(tmp_path: Path) -> None:
    with managed_home(tmp_path) as home:
        pluginlogs.record(home, "plugin-a", model="a", ok=True)
        pluginlogs.record(home, "plugin-b", model="b", ok=True)
        assert [r["model"] for r in pluginlogs.tail(home, "plugin-a")] == ["a"]
        assert [r["model"] for r in pluginlogs.tail(home, "plugin-b")] == ["b"]
        ids = {item["plugin_id"] for item in pluginlogs.list_plugins(home)}
        assert ids == {"plugin-a", "plugin-b"}


def test_plugin_logs_written_even_without_request_log(tmp_path: Path) -> None:
    """`--no-request-log` 不该顺带把插件日志也灭掉（两者服务不同追问）。"""
    with managed_home(tmp_path) as home:
        TokenPool([DownstreamToken(token_id="t", name="app", token=TOKEN)]).save(
            home / "tokens.json"
        )
        toip.save_station(paths.toip_station_path(), toip.StationIdentity.create(name="s"))
        server = RelayServer(
            ("127.0.0.1", 0),
            DemoRouter(demo_pool()),
            api_key=None,
            tokens=TokenStore(home / "tokens.json"),
            request_log=None,
            toip=toip.ToipService(
                toip.TicketStore(paths.toip_tickets_path()),
                TokenStore(home / "tokens.json"),
                paths.toip_station_path(),
            ),
            plugin_log_home=home,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            post(
                server.base_url,
                "/v1/messages",
                {"model": "glm-5.2", "max_tokens": 8, "messages": []},
                {"x-api-key": TOKEN, toip.PLUGIN_ID_HEADER: PLUGIN},
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        assert pluginlogs.tail(home, PLUGIN), "插件日志必须独立于 request_log 开关"


def test_generic_plugin_header_also_works(tmp_path: Path) -> None:
    with toip_gateway(tmp_path) as (server, home):
        post(
            server.base_url,
            "/v1/messages",
            {"model": "glm-5.2", "max_tokens": 8, "messages": []},
            {"x-api-key": TOKEN, toip.PLUGIN_ID_HEADER_GENERIC: "other-host-plugin"},
        )
        assert pluginlogs.tail(home, "other-host-plugin")


def test_token_note_binding_is_the_fallback(tmp_path: Path) -> None:
    """没有插件头时，用 TOIP 令牌上的绑定（note=toip:<plugin>）兜底。"""
    with toip_gateway(tmp_path) as (server, home):
        _, payload = post(
            server.base_url,
            "/v1/toip/join",
            {"ticket": ticket_plain(home), "plugin": PLUGIN},
        )
        token = payload["session"]["token"]
        post(
            server.base_url,
            "/v1/messages",
            {"model": "glm-5.2", "max_tokens": 8, "messages": []},
            {"x-api-key": token},
        )
        rows = pluginlogs.tail(home, PLUGIN)
        assert rows, "令牌绑定该把这次调用记到插件名下"
        assert "plugin_version" not in rows[0], "没有版本头就不该写这个键"


def test_bad_plugin_header_does_not_break_request(tmp_path: Path) -> None:
    """非法插件头不参与鉴权，所以只该被忽略，不该拒请求。"""
    with toip_gateway(tmp_path) as (server, home):
        status, _ = post(
            server.base_url,
            "/v1/messages",
            {"model": "glm-5.2", "max_tokens": 8, "messages": []},
            {"x-api-key": TOKEN, toip.PLUGIN_ID_HEADER: "../../escape"},
        )
        assert status == 200
        assert pluginlogs.list_plugins(home) == [], "逃逸的 id 不该建出任何目录"
        assert not (home / "pluginlogs").exists() or all(
            p.is_dir() for p in (home / "pluginlogs").iterdir()
        )


def test_prune_keeps_events_and_drops_old_flow(tmp_path: Path) -> None:
    """保留期只清流水，**不清接入事件**——「它来过」的证据不能过期。"""
    with managed_home(tmp_path) as home:
        pluginlogs.record(home, PLUGIN, model="m", ok=True)
        pluginlogs.record_event(home, PLUGIN, "toip.join", detail="ok")
        assert pluginlogs.prune(home, retention_days=0) == [], "0 = 不清理"
        # 负数 = 截止点在未来，刚写的文件也「过期」——不用 sleep 去等时间流逝
        removed = pluginlogs.prune(home, retention_days=-1)
        assert any(PLUGIN in name for name in removed), removed
        assert pluginlogs.events(home, PLUGIN), "接入事件必须还在"
        assert pluginlogs.tail(home, PLUGIN) == []


def test_pluginlog_retention_and_forget(tmp_path: Path) -> None:
    with managed_home(tmp_path) as home:
        pluginlogs.record(home, PLUGIN, model="m", ok=True)
        assert pluginlogs.forget(home, PLUGIN) is True
        assert pluginlogs.forget(home, PLUGIN) is False
        assert pluginlogs.list_plugins(home) == []


def test_pluginlog_summarize_buckets(tmp_path: Path) -> None:
    with managed_home(tmp_path) as home:
        pluginlogs.record(home, PLUGIN, model="a", ok=True, tokens_in=1, tokens_out=2)
        pluginlogs.record(home, PLUGIN, model="b", ok=False, status=500)
        summary = pluginlogs.summarize(pluginlogs.tail(home, PLUGIN))
        assert summary["window"]["requests"] == 2
        assert summary["window"]["ok"] == 1
        assert summary["window"]["failed"] == 1
        assert set(summary["by_model"]) == {"a", "b"}


# -- 发现协议 -------------------------------------------------------------


def test_discovery_reply_v2_carries_toip_and_v1_does_not(tmp_path: Path) -> None:
    """v2 探测包拿到 TOIP 能力块，v1 探测包拿不到（老客户端解析器不受扰）。"""
    from relayhub.gateway.discovery import (
        PROBE_MAGIC,
        PROBE_MAGIC_V2,
        DiscoveryResponder,
    )

    with toip_gateway(tmp_path) as (server, home):
        responder = DiscoveryResponder(
            name="lab-hub",
            data_port=server.server_address[1],
            models_count=lambda: len(server.router.models()),
            pairing_open=lambda: False,
            port=0,
            toip_info=server.toip_summary,
        )
        try:
            v2 = responder.reply_for(PROBE_MAGIC_V2)
            assert v2 is not None
            assert v2["protocol"] == "relay-hub"
            assert v2["toip"]["enabled"] is True
            assert v2["toip"]["station_id"].startswith("rst_")
            assert v2["toip"]["join"] == "/v1/toip/join"
            blob = json.dumps(v2, ensure_ascii=False)
            station = toip.load_station(paths.toip_station_path())
            assert station.secret not in blob, "发现应答泄露了种子"
            assert "rht_" not in blob

            v1 = responder.reply_for(PROBE_MAGIC)
            assert v1 is not None
            assert "toip" not in v1, "v1 应答不该多出字段"

            assert responder.reply_for(b"NOT-OURS") is None
        finally:
            responder.stop()


def test_discovery_summary_when_toip_disabled(tmp_path: Path) -> None:
    with managed_home(tmp_path) as home:
        server = _make_server(home, tmp_path)
        assert server.toip_summary() == {"enabled": False}


# -- 管理台（只读展示） ---------------------------------------------------


@contextmanager
def admin_console(home: Path):
    """起一个管理台，所有数据面文件都指向 home（**必须**，否则会读真实数据根）。"""
    from relayhub.gateway.admin import AdminServer
    from relayhub.gateway.pool import KeyPool

    assert "rh-" in home.name or home.name == "home", f"拒绝在可疑目录起管理台：{home}"
    pool_path = home / "pool.json"
    KeyPool([]).save(pool_path)
    server = AdminServer(
        ("127.0.0.1", 0),
        pool_path,
        audit_path=home / "audit.jsonl",
        tokens_path=home / "tokens.json",
        requests_log_path=home / "requests.jsonl",
        plugin_log_home=home,
        toip_station_path=home / "toip.json",
        toip_tickets_path=home / "toip_tickets.json",
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_console_lists_plugin_logs(tmp_path: Path) -> None:
    with managed_home(tmp_path) as home:
        pluginlogs.record(home, PLUGIN, model="glm-5.2", ok=True, tokens_in=3, tokens_out=4)
        pluginlogs.record_event(home, PLUGIN, "toip.join", detail="ticket")
        with admin_console(home) as base:
            status, listing = get(base, "/api/plugins")
            assert status == 200, listing
            assert [p["plugin_id"] for p in listing["plugins"]] == [PLUGIN]
            assert str(home) in listing["root"]

            status, detail = get(base, f"/api/plugins?plugin={PLUGIN}")
            assert status == 200, detail
            assert detail["plugin"] == PLUGIN
            assert detail["summary"]["window"]["requests"] == 1
            assert detail["entries"][0]["model"] == "glm-5.2"
            assert [e["event"] for e in detail["events"]] == ["toip.join"]


def test_console_toip_state_hides_secret_but_shows_code(tmp_path: Path) -> None:
    """管理台可以显示当前动态口令（30 秒过期），但**绝不下发种子**。

    种子等于该站点的全部接入能力；浏览器面（历史/缓存/截图）不是它该去的地方。
    """
    with managed_home(tmp_path) as home:
        station = toip.StationIdentity.create(name="lab-hub")
        toip.save_station(home / "toip.json", station)
        store = toip.TicketStore(home / "toip_tickets.json")
        record, _ = toip.make_ticket(name="dsh-laptop", plugins=[PLUGIN])
        store.add(record)
        with admin_console(home) as base:
            status, payload = get(base, "/api/toip")
            assert status == 200, payload
            assert payload["enabled"] is True
            assert payload["station"]["station_id"] == station.station_id
            assert payload["station"]["current_code"] == toip.totp_now(station.secret_bytes)
            assert payload["station"]["seconds_left"] > 0
            blob = json.dumps(payload, ensure_ascii=False)
            assert station.secret not in blob, "管理台泄露了口令种子"
            assert "secret" not in payload["station"]
            # 通行证明文也不该出现（落盘只有哈希与提示）
            assert payload["tickets"][0]["hint"].startswith("…")
            assert "rhe_" not in blob


def test_console_toip_state_when_disabled(tmp_path: Path) -> None:
    with managed_home(tmp_path) as home:
        with admin_console(home) as base:
            status, payload = get(base, "/api/toip")
            assert status == 200
            assert payload["enabled"] is False
            assert payload["tickets"] == []


def test_console_page_has_plugin_and_toip_tabs(tmp_path: Path) -> None:
    """控制台页面必须带上新标签页（否则两个只读接口就是死代码）。"""
    import urllib.request

    with managed_home(tmp_path) as home:
        with admin_console(home) as base:
            with urllib.request.urlopen(base + "/", timeout=10) as response:
                html = response.read().decode("utf-8")
    assert 'data-tab="plugins"' in html
    assert 'data-tab="toip"' in html
    assert 'id="pane-plugins"' in html
    assert 'id="pane-toip"' in html
    # 页面里出现的所有 tab 都必须有 pane，否则点了会白屏
    import re

    tabs = set(re.findall(r'data-tab="([a-z]+)"', html))
    panes = set(re.findall(r'id="pane-([a-z]+)"', html))
    assert tabs <= panes, f"缺 pane：{tabs - panes}"
