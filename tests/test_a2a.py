# -*- coding: utf-8 -*-
"""A2A 路由测试：agent 池加密、agent card、message/send 转发与记账、鉴权、级联头。"""

from __future__ import annotations

import json
import os
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from relayhub.gateway import a2a as a2a_module
from relayhub.gateway.a2a import A2aAgent, A2aPool


class FakeA2aDownstream(BaseHTTPRequestHandler):
    """最小 A2A 下游：回 message/send 结果，并回显收到的 Via（验证级联头）。"""

    protocol_version = "HTTP/1.1"
    last_via = ""

    def log_message(self, *args: object) -> None:
        return

    def do_POST(self) -> None:  # noqa: N815
        length = int(self.headers.get("Content-Length") or 0)
        request = json.loads(self.rfile.read(length).decode("utf-8"))
        FakeA2aDownstream.last_via = self.headers.get("Via") or ""
        body = json.dumps({
            "jsonrpc": "2.0", "id": request.get("id"),
            "result": {"task": {"id": "t1", "status": "done"}},
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


from contextlib import contextmanager  # noqa: E402


@contextmanager
def a2a_downstream():
    server = ThreadingHTTPServer(("127.0.0.1", 0), FakeA2aDownstream)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_agent_pool_roundtrip_is_sealed(tmp_path: Path) -> None:
    pool_path = tmp_path / "a2a_agents.json"
    pool = A2aPool()
    pool.add(A2aAgent(agent_id="a1", name="peer", url="http://127.0.0.1:9",
                      token="a2a_sekrit", created_at=1.0))
    pool.save(pool_path)
    raw = pool_path.read_text(encoding="utf-8")
    assert '"enc"' in raw and "a2a_sekrit" not in raw
    back = A2aPool.load(pool_path)
    assert back.agents[0].token == "a2a_sekrit"


def test_agent_card_lists_skills(tmp_path: Path) -> None:
    pool_path = tmp_path / "a2a_agents.json"
    pool = A2aPool()
    pool.add(A2aAgent(agent_id="a1", name="peer", url="http://127.0.0.1:9",
                      description="the other hub"))
    pool.save(pool_path)
    card = a2a_module.agent_card(pool_path, "lab-hub", "http://10.0.0.2:8799")
    assert card["name"] == "lab-hub"
    assert card["skills"][0]["id"] == "peer"


API_KEY = "rh_a2a_down"


@contextmanager
def relay_with_a2a(tmp_path: Path, downstream_url: str):
    from relayhub.gateway.pool import KeyPool
    from relayhub.gateway.router import KeyPoolRouter
    from relayhub.gateway.service import RelayServer
    from tests.support import make_key

    previous = os.environ.get("RELAYHUB_HOME")
    home = tmp_path / "home"
    home.mkdir(parents=True, exist_ok=True)
    os.environ["RELAYHUB_HOME"] = str(home)
    pool_path = home / "a2a_agents.json"
    pool = A2aPool()
    pool.add(A2aAgent(agent_id="a1", name="peer", url=downstream_url,
                      token="down_token", created_at=1.0))
    pool.save(pool_path)
    router = KeyPoolRouter(KeyPool([make_key("real", "http://127.0.0.1:9")]))
    server = RelayServer(("127.0.0.1", 0), router, api_key=API_KEY, event_delay=0.0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.base_url
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        if previous is None:
            os.environ.pop("RELAYHUB_HOME", None)
        else:
            os.environ["RELAYHUB_HOME"] = previous


def _rpc(base: str, payload: dict, credential: str | None = API_KEY) -> tuple[int, dict]:
    request = urllib.request.Request(
        f"{base}/a2a", data=json.dumps(payload).encode("utf-8"), method="POST"
    )
    request.add_header("Content-Type", "application/json")
    if credential:
        request.add_header("x-api-key", credential)
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:  # noqa: TID251
        return exc.code, json.loads(exc.read().decode("utf-8"))


def test_gateway_agent_card_endpoint(tmp_path: Path) -> None:
    with a2a_downstream() as url:
        with relay_with_a2a(tmp_path, url) as base:
            with urllib.request.urlopen(f"{base}/.well-known/agent.json", timeout=10) as response:
                card = json.loads(response.read().decode("utf-8"))
            assert card["skills"][0]["id"] == "peer"


def test_gateway_message_send_forwards_with_cascade_headers(tmp_path: Path) -> None:
    """message/send 转发：Via 带上本站实例标记（级联判环依赖它）。"""
    with a2a_downstream() as url:
        with relay_with_a2a(tmp_path, url) as base:
            status, reply = _rpc(base, {"jsonrpc": "2.0", "id": 7, "method": "message/send",
                                        "params": {"agent": "peer", "message": {"text": "hi"}}})
            assert status == 200, reply
            assert reply["result"]["task"]["status"] == "done"
            assert "relayhub-" in FakeA2aDownstream.last_via


def test_gateway_message_send_requires_auth(tmp_path: Path) -> None:
    with a2a_downstream() as url:
        with relay_with_a2a(tmp_path, url) as base:
            status, reply = _rpc(base, {"jsonrpc": "2.0", "id": 1, "method": "message/send",
                                        "params": {"agent": "peer"}}, credential=None)
            assert status == 401, reply


def test_gateway_unknown_agent_is_clean_error(tmp_path: Path) -> None:
    with a2a_downstream() as url:
        with relay_with_a2a(tmp_path, url) as base:
            status, reply = _rpc(base, {"jsonrpc": "2.0", "id": 2, "method": "message/send",
                                        "params": {"agent": "ghost", "message": {}}})
            assert status == 200
            assert reply["error"]["code"] == -32602
