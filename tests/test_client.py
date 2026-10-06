# -*- coding: utf-8 -*-
"""客户端 SDK（relayhub.client.StationClient）测试。

覆盖四层：

1. **版本单一来源**——``relayhub.__version__`` 必须与 pyproject 一致
   （0.6.x 时代 __init__ 写死 0.3.0 的版本腐烂不能再发生）；
2. **seal_envelope 单元闭环**——封→开互为镜像，凭证绑定成立；
3. **起真站的端到端**——明文/E2E 信封、auto 降级、require 拒绝、
   key 轮换自适应、TOIP join→adopt→session→models；
4. **MCP / A2A 走客户端**——含信封形态（六条 JSON 路服务端都吃信封）。
"""

from __future__ import annotations

import json
import os
import uuid
import re
from contextlib import contextmanager
from pathlib import Path

import pytest

import relayhub
from relayhub.client import StationClient, StationError
from relayhub.gateway import e2e as e2e_module
from relayhub.gateway.a2a import A2aAgent, A2aPool
from relayhub.gateway.mcp import McpChannel, McpChannelPool
from tests.support import REPLY_TEXT, FakeUpstream, make_key
from tests.test_relay_chain import relay_server

API_KEY = "rh_sdk_down"

def _message() -> dict:
    """每次给一条内容唯一的消息。

    站端出口查重（_EXIT_GUARD）按「指纹 × 上游」计数，不同测试共用同一份
    MESSAGE 会在全量跑时把 key_rotation 的重试误判成环路——真实客户端不会
    在窗口内反复重发同一份请求体，测试也不该。
    """
    return {
        "model": "glm-5.2",
        "max_tokens": 8,
        "messages": [
            {"role": "user", "content": [{"type": "text", "text": f"hi-{uuid.uuid4().hex[:8]}"}]}
        ],
    }

#: FakeUpstream 非流式回 dict、流式回 SSE 文本——断言统一序列化后找标记串。
def _text(reply: object) -> str:
    return reply if isinstance(reply, str) else json.dumps(reply, ensure_ascii=False)


# -- 夹具：起真站 -----------------------------------------------------------


@contextmanager
def plain_gateway():
    """最小网关：一个假上游 + 一枚 master 凭证。"""
    with FakeUpstream() as upstream:
        from relayhub.gateway.pool import KeyPool
        from relayhub.gateway.router import KeyPoolRouter

        router = KeyPoolRouter(KeyPool([make_key("real", upstream.base_url)]))
        with relay_server(router, api_key=API_KEY) as server:
            yield server


@contextmanager
def isolated_home(tmp_path: Path):
    """把数据根指到 tmp（服务端与测试两侧同一环境变量，见 test_toip.managed_home）。"""
    previous = os.environ.get("RELAYHUB_HOME")
    home = tmp_path / "home"
    home.mkdir(parents=True, exist_ok=True)
    os.environ["RELAYHUB_HOME"] = str(home)
    try:
        yield home
    finally:
        if previous is None:
            os.environ.pop("RELAYHUB_HOME", None)
        else:
            os.environ["RELAYHUB_HOME"] = previous


@contextmanager
def gateway_with_home(tmp_path: Path):
    """isolated_home + 网关，服务端读 paths.* 时落在 tmp 数据根里。"""
    with isolated_home(tmp_path) as home:
        from relayhub.gateway.pool import KeyPool
        from relayhub.gateway.router import KeyPoolRouter

        router = KeyPoolRouter(KeyPool([make_key("real", "http://127.0.0.1:9")]))
        with relay_server(router, api_key=API_KEY) as server:
            yield server, home


# -- 1. 版本单一来源 ----------------------------------------------------------


def test_version_single_source() -> None:
    pyproject = Path(relayhub.__file__).resolve().parent.parent / "pyproject.toml"
    expected = re.search(
        r'^version\s*=\s*"([^"]+)"', pyproject.read_text(encoding="utf-8"), re.M
    )
    assert expected is not None, "pyproject.toml 里找不到 version 字段"
    assert relayhub.__version__ == expected.group(1)


# -- 2. seal_envelope 单元闭环 -------------------------------------------------


def test_seal_envelope_roundtrip() -> None:
    identity = e2e_module.E2eIdentity.create()
    payload = {"model": "glm-5.2", "n": 1, "messages": [{"role": "user", "content": "hi"}]}
    envelope = e2e_module.seal_envelope(identity.public_b64(), identity.key_id, payload, "rh_cred")
    assert envelope["v"] == 1 and envelope["key_id"] == identity.key_id
    opened = e2e_module.open_envelope(identity, envelope, "rh_cred", e2e_module.ReplayGuard())
    assert opened == payload


def test_seal_envelope_binds_credential() -> None:
    """盐绑定凭证：换个令牌构造的密文必须解不开。"""
    identity = e2e_module.E2eIdentity.create()
    envelope = e2e_module.seal_envelope(identity.public_b64(), identity.key_id, {"a": 1}, "cred_a")
    with pytest.raises(e2e_module.E2eError):
        e2e_module.open_envelope(identity, envelope, "cred_b", e2e_module.ReplayGuard())


def test_seal_envelope_rejects_bad_public_key() -> None:
    identity = e2e_module.E2eIdentity.create()
    with pytest.raises(e2e_module.E2eError):
        e2e_module.seal_envelope("not-base64!!", identity.key_id, {}, "cred")
    with pytest.raises(e2e_module.E2eError):
        e2e_module.seal_envelope("AAAA", identity.key_id, {}, "cred")


# -- 3. 端到端：公开面 / 模型通道 ------------------------------------------------


def test_whoami_and_models() -> None:
    with plain_gateway() as server:
        client = StationClient(server.base_url, API_KEY, e2e="off")
        assert client.whoami()["server"] == "relay-hub"
        listing = client.models()
        assert any(item["id"] == "glm-5.2" for item in listing["data"])


def test_messages_plain_reply() -> None:
    with plain_gateway() as server:
        client = StationClient(server.base_url, API_KEY, e2e="off")
        reply = client.messages(_message())
        assert REPLY_TEXT in _text(reply)
        assert client.last_enveloped is False


def test_bad_token_raises_station_error() -> None:
    with plain_gateway() as server:
        client = StationClient(server.base_url, "rh_wrong_token", e2e="off")
        with pytest.raises(StationError) as excinfo:
            client.models()
        assert excinfo.value.status == 401


def test_invalid_base_url_raises_connect_error() -> None:
    client = StationClient("127.0.0.1:9", API_KEY, timeout=2.0)
    with pytest.raises(StationError) as excinfo:
        client.whoami()
    assert excinfo.value.status == 0


def test_invalid_e2e_mode_rejected() -> None:
    with pytest.raises(ValueError):
        StationClient("http://127.0.0.1:9", e2e="sometimes")


# -- 3b. 端到端：E2E 信封三态 ----------------------------------------------------


def test_messages_e2e_auto_seals() -> None:
    with plain_gateway() as server:
        client = StationClient(server.base_url, API_KEY)  # 默认 auto
        reply = client.messages(_message())
        assert client.last_enveloped is True
        assert REPLY_TEXT in _text(reply)
        params = client.e2e_params()
        assert params is not None and params["key_id"]


def test_e2e_off_stays_plain() -> None:
    with plain_gateway() as server:
        client = StationClient(server.base_url, API_KEY, e2e="off")
        client.messages(_message())
        assert client.last_enveloped is False


def test_e2e_auto_falls_back_to_plain_without_crypto(monkeypatch: pytest.MonkeyPatch) -> None:
    with plain_gateway() as server:
        monkeypatch.setattr(e2e_module, "_crypto", lambda: None)
        client = StationClient(server.base_url, API_KEY)  # auto：站不支持 → 明文
        reply = client.messages(_message())
        assert client.last_enveloped is False
        assert REPLY_TEXT in _text(reply)


def test_e2e_require_refuses_plain_station(monkeypatch: pytest.MonkeyPatch) -> None:
    with plain_gateway() as server:
        monkeypatch.setattr(e2e_module, "_crypto", lambda: None)
        client = StationClient(server.base_url, API_KEY, e2e="require")
        with pytest.raises(StationError) as excinfo:
            client.messages(_message())
        assert excinfo.value.status == 501


def test_e2e_key_rotation_adapts() -> None:
    """站点轮换 E2E 身份（key_id 变了）：客户端清缓存重拉重封，用户无感。"""
    with plain_gateway() as server:
        client = StationClient(server.base_url, API_KEY)
        client.messages(_message())
        assert client.last_enveloped is True
        client.e2e_params(refresh=False)  # 缓存就位
        client._params_cache = {**dict(client._params_cache or {}), "key_id": "stale0000"}
        reply = client.messages(_message())
        assert REPLY_TEXT in _text(reply)
        fresh = client.e2e_params()
        assert fresh is not None and fresh["key_id"] != "stale0000"


def test_e2e_missing_crypto_locally_is_loud(monkeypatch: pytest.MonkeyPatch) -> None:
    """本机封不了信封而站点支持 E2E：auto 模式报错说清楚，绝不静默发明文。

    补丁目标是 relayhub.client.seal_envelope：client 按名字绑定导入，patch
    e2e 模块上的同名函数动不到它——第一版就踩了这个坑（DID NOT RAISE）。
    """
    with plain_gateway() as server:
        import relayhub.client as client_module

        client = StationClient(server.base_url, API_KEY)
        monkeypatch.setattr(
            client_module, "seal_envelope",
            lambda *a, **k: (_ for _ in ()).throw(
                e2e_module.E2eError("未安装 cryptography（pip install \"hubrelay[e2e]\"）")
            ),
        )
        with pytest.raises(StationError) as excinfo:
            client.messages(_message())
        assert "E2E 封信封失败" in str(excinfo.value)
        assert client.last_enveloped is False


# -- 3c. 端到端：TOIP 接入生命周期 -----------------------------------------------


def test_join_adopt_session_models(tmp_path: Path) -> None:
    from tests.test_toip import ticket_plain, toip_gateway

    with toip_gateway(tmp_path) as (server, home):
        client = StationClient(server.base_url, plugin_id="dsh-relayhub-bridge")
        payload = client.join(ticket=ticket_plain(home), name="sdk-laptop")
        assert payload.get("api_key") or (payload.get("dsh") or {}).get("apiKey")
        client.adopt(payload)
        assert client.token, "adopt 后必须有令牌"
        session = client.session()
        assert isinstance(session, dict) and session
        listing = client.models()
        assert listing["data"], "demo 站至少要有一个模型"


def test_join_requires_code_or_ticket() -> None:
    client = StationClient("http://127.0.0.1:9")
    with pytest.raises(StationError):
        client.join()


# -- 4. MCP / A2A 走客户端 ------------------------------------------------------


def test_mcp_through_client_including_envelope(tmp_path: Path) -> None:
    from tests.test_mcp import mcp_upstream

    with mcp_upstream() as url:
        with gateway_with_home(tmp_path) as (server, home):
            pool = McpChannelPool()
            pool.add(McpChannel(channel_id="c1", name="web", url=url, created_at=1.0))
            pool.save(home / "mcp_channels.json")

            client = StationClient(server.base_url, API_KEY)  # auto：MCP 也走信封
            handshake = client.mcp_initialize()
            assert handshake["result"]["serverInfo"]["name"] == "relay-hub"
            tools = client.mcp_list_tools()
            assert [t["name"] for t in tools["tools"]] == ["web.search"]
            reply = client.mcp_call_tool("web.search", {"q": "hello"})
            assert reply["result"]["content"][0]["text"] == "called:hello"
            assert client.last_enveloped is True


def test_a2a_through_client(tmp_path: Path) -> None:
    from tests.test_a2a import a2a_downstream

    with a2a_downstream() as url:
        with gateway_with_home(tmp_path) as (server, home):
            pool = A2aPool()
            pool.add(A2aAgent(agent_id="a1", name="peer", url=url, created_at=1.0))
            pool.save(home / "a2a_agents.json")

            client = StationClient(server.base_url, API_KEY)
            reply = client.a2a_send("peer", {"role": "user", "parts": [{"type": "text", "text": "hi"}]})
            assert reply["result"]["task"]["status"] == "done"
            card = client.a2a_card()
            assert card["name"] == "relay-hub"
