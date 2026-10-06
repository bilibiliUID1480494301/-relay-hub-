# -*- coding: utf-8 -*-
"""MCP 网关测试：渠道池加密、工具目录前缀、tools/call 转发与记账、鉴权。"""

from __future__ import annotations

import json
import os
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from relayhub.gateway import mcp as mcp_module
from relayhub.gateway.mcp import McpChannel, McpChannelPool


class FakeMcpUpstream(BaseHTTPRequestHandler):
    """一个最小可用的上游 MCP server：tools/list 与 tools/call 都有真实应答。"""

    protocol_version = "HTTP/1.1"

    def log_message(self, *args: object) -> None:
        return

    def do_POST(self) -> None:  # noqa: N815
        length = int(self.headers.get("Content-Length") or 0)
        request = json.loads(self.rfile.read(length).decode("utf-8"))
        method = request.get("method")
        if method == "tools/list":
            result = {"tools": [{"name": "search", "description": "web search"}]}
        elif method == "tools/call":
            arguments = (request.get("params") or {}).get("arguments") or {}
            result = {"content": [{"type": "text", "text": f"called:{arguments.get('q', '')}"}]}
        else:
            result = {}
        body = json.dumps({"jsonrpc": "2.0", "id": request.get("id"), "result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


from contextlib import contextmanager


@contextmanager
def mcp_upstream():
    server = ThreadingHTTPServer(("127.0.0.1", 0), FakeMcpUpstream)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_channel_pool_roundtrip_is_sealed(tmp_path: Path) -> None:
    pool_path = tmp_path / "mcp_channels.json"
    pool = McpChannelPool()
    pool.add(McpChannel(channel_id="c1", name="web", url="http://127.0.0.1:9/mcp",
                        headers={"Authorization": "Bearer sekrit"}, created_at=1.0))
    pool.save(pool_path)
    # 落盘必须是 secretbox 密文，不能看到明文凭证
    raw = pool_path.read_text(encoding="utf-8")
    assert '"enc"' in raw and "sekrit" not in raw
    back = McpChannelPool.load(pool_path)
    assert back.channels[0].headers["Authorization"] == "Bearer sekrit"


def test_tools_list_prefixes_and_call_routes(tmp_path: Path) -> None:
    with mcp_upstream() as url:
        pool_path = tmp_path / "mcp_channels.json"
        pool = McpChannelPool()
        pool.add(McpChannel(channel_id="c1", name="web", url=url, created_at=1.0))
        pool.save(pool_path)

        listing = mcp_module.list_tools(pool_path)
        assert [t["name"] for t in listing["tools"]] == ["web.search"]
        assert listing["errors"] == []

        response, channel = mcp_module.call_tool(pool_path, "web.search", {"q": "hello"})
        assert channel == "web"
        text = response["result"]["content"][0]["text"]
        assert text == "called:hello"


def test_call_unknown_channel_is_rejected(tmp_path: Path) -> None:
    pool_path = tmp_path / "mcp_channels.json"
    McpChannelPool().save(pool_path)
    response, channel = mcp_module.call_tool(pool_path, "nope.search", {})
    assert channel == ""
    assert response["error"]["code"] == mcp_module.JSONRPC_METHOD_NOT_FOUND


# -- 走真网关的全链路 ---------------------------------------------------------


API_KEY = "rh_mcp_down"


@contextmanager
def relay_with_mcp(tmp_path: Path, upstream_url: str):
    from relayhub.gateway.pool import KeyPool
    from relayhub.gateway.router import KeyPoolRouter
    from relayhub.gateway.service import RelayServer
    from tests.support import make_key

    # 网关进程内走 paths.mcp_channels_path()：必须把数据根指到 tmp，
    # 否则它读的是真实数据根（与 managed_home 同一手法）。
    previous = os.environ.get("RELAYHUB_HOME")
    home = tmp_path / "home"
    home.mkdir(parents=True, exist_ok=True)
    os.environ["RELAYHUB_HOME"] = str(home)
    pool_path = home / "mcp_channels.json"
    pool = McpChannelPool()
    pool.add(McpChannel(channel_id="c1", name="web", url=upstream_url, created_at=1.0))
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


def _rpc_post(base: str, payload: dict) -> tuple[int, dict]:
    request = urllib.request.Request(
        f"{base}/mcp", data=json.dumps(payload).encode("utf-8"), method="POST"
    )
    request.add_header("Content-Type", "application/json")
    request.add_header("x-api-key", API_KEY)
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:  # noqa: TID251
        return exc.code, json.loads(exc.read().decode("utf-8"))


def test_gateway_mcp_full_flow(tmp_path: Path) -> None:
    with mcp_upstream() as url:
        with relay_with_mcp(tmp_path, url) as base:
            status, reply = _rpc_post(base, {"jsonrpc": "2.0", "id": 1, "method": "initialize"})
            assert status == 200
            assert reply["result"]["serverInfo"]["name"] == "relay-hub"

            status, reply = _rpc_post(base, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
            assert status == 200
            assert reply["result"]["tools"][0]["name"] == "web.search"

            status, reply = _rpc_post(base, {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                             "params": {"name": "web.search",
                                                        "arguments": {"q": "hello"}}})
            assert status == 200, reply
            assert reply["result"]["content"][0]["text"] == "called:hello"

            status, reply = _rpc_post(base, {"jsonrpc": "2.0", "id": 4, "method": "bogus"})
            assert status == 200
            assert reply["error"]["code"] == mcp_module.JSONRPC_METHOD_NOT_FOUND


def test_gateway_mcp_requires_auth(tmp_path: Path) -> None:
    with mcp_upstream() as url:
        with relay_with_mcp(tmp_path, url) as base:
            request = urllib.request.Request(f"{base}/mcp",
                data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode(),
                method="POST")
            request.add_header("Content-Type", "application/json")
            try:
                urllib.request.urlopen(request, timeout=10)
                raise AssertionError("未带凭证的 MCP 调用不应放行")
            except urllib.error.HTTPError as exc:
                assert exc.code == 401
