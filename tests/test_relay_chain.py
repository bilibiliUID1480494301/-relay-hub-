# -*- coding: utf-8 -*-
"""级联中继兼容测试：两家都部署 relay-hub 时，上下游**不能**被环路检测误伤。

防环路防的是「照镜子」（请求绕回同一个实例）。判环依据是每次启动随机生成
的唯一实例标记（relayhub-<hex8>），部署之间不会撞——所以 A 站 → B 站的合法
链路必须畅通；真环（B 的上游指回 A）才 508。这里用两个真实 RelayServer
串起来验证前半句，再用手工 Via 验证后半句。

Hops 上限（RELAYHUB_MAX_HOPS，默认 4）只防失控长链，是纵深防御的第二层，
可由部署方按级联深度放宽。
"""

from __future__ import annotations

import json
import threading
import urllib.request
from contextlib import contextmanager
from pathlib import Path

import pytest

from relayhub.gateway import conformance
from relayhub.gateway.pool import KeyPool
from relayhub.gateway.router import KeyPoolRouter
from relayhub.gateway.service import RelayServer
from tests.support import REPLY_TEXT, FakeUpstream, make_key

API_KEY = "rh_chain_down"
UP_KEY = "up_key"  # make_key 的默认上游凭证


@contextmanager
def relay_server(router, api_key: str | None = None):
    server = RelayServer(("127.0.0.1", 0), router, api_key=api_key, event_delay=0.0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _post_messages(base: str, api_key: str, headers: dict[str, str] | None = None) -> tuple[int, str]:
    body = json.dumps({
        "model": "glm-5.2",
        "max_tokens": 8,
        "messages": [{"role": "user", "content": [{"type": "text", "text": "hi"}]}],
    }).encode("utf-8")
    request = urllib.request.Request(f"{base}/v1/messages", data=body, method="POST")
    request.add_header("Content-Type", "application/json")
    request.add_header("x-api-key", api_key)
    for key, value in (headers or {}).items():
        request.add_header(key, value)
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:  # noqa: TID251 - 测试直接看错误体
        return exc.code, exc.read().decode("utf-8")


def test_two_relayhubs_chain_without_false_loop(tmp_path: Path) -> None:
    """A 站的上游是 B 站（两家都用 relay-hub）：合法链路，绝不能 508。"""
    with FakeUpstream() as upstream:
        # B 站：真实上游。A 站转发过来的凭证 = B 站的 api_key。
        router_b = KeyPoolRouter(KeyPool([make_key("real", upstream.base_url)]))
        with relay_server(router_b, api_key=UP_KEY) as b_server:
            # A 站：唯一上游 = B 站；make_key 的 api_key 固定 up_key，正好对上。
            router_a = KeyPoolRouter(KeyPool([make_key("chain-b", b_server.base_url)]))
            with relay_server(router_a, api_key=API_KEY) as a_server:
                status, raw = _post_messages(a_server.base_url, API_KEY)
                assert status == 200, raw
                assert REPLY_TEXT in raw, raw


def test_request_returning_to_same_instance_is_rejected(tmp_path: Path) -> None:
    """真环：Via 里已经带上了本站实例标记 → 508（照镜子必须拦）。"""
    with FakeUpstream() as upstream:
        router = KeyPoolRouter(KeyPool([make_key("real", upstream.base_url)]))
        with relay_server(router, api_key=API_KEY) as server:
            instance = server.instance_id
            status, raw = _post_messages(
                server.base_url, API_KEY, headers={"Via": f"relayhub-other, {instance}"}
            )
            assert status == 508, raw
            assert "环路" in raw


def test_hops_limit_is_configurable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """级联深度用 RELAYHUB_MAX_HOPS 放宽：合法长链不该撞默认上限。"""
    from relayhub.gateway import service as service_module

    with FakeUpstream() as upstream:
        router = KeyPoolRouter(KeyPool([make_key("real", upstream.base_url)]))
        with relay_server(router, api_key=API_KEY) as server:
            monkeypatch.setattr(service_module, "MAX_HOPS", 1)
            # hops=1 已到上限（进入时 hops >= MAX_HOPS）→ 508
            status, _ = _post_messages(server.base_url, API_KEY, headers={"X-Relay-Hub-Hops": "1"})
            assert status == 508
            # 放宽到 3 之后同样的 hops=1 放行
            monkeypatch.setattr(service_module, "MAX_HOPS", 3)
            status, raw = _post_messages(server.base_url, API_KEY, headers={"X-Relay-Hub-Hops": "1"})
            assert status == 200, raw
