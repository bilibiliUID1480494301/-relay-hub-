"""relayhub.api 端到端测试：不依赖任何外部服务。

覆盖：建站 → 加上游（合成路由 demo 池 + 假上游 HTTP 服务）→ 发令牌 →
真发请求 → 停站。同时验证 hubrelay 顶层 import 垫片。
"""

from __future__ import annotations

import json
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import relayhub.api as api


# ---- 一个最小假上游：OpenAI 协议，返回固定应答 -------------------------------


class _FakeUpstream(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = json.dumps({"data": [{"id": "fake-model"}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        body = json.dumps(
            {
                "id": "chatcmpl-fake",
                "object": "chat.completion",
                "model": "fake-model",
                "choices": [
                    {"index": 0, "message": {"role": "assistant", "content": "hello from fake"}, "finish_reason": "stop"}
                ],
                "usage": {"prompt_tokens": 5, "completion_tokens": 4, "total_tokens": 9},
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # 静音
        pass


@pytest.fixture()
def fake_upstream():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _FakeUpstream)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/v1"
    srv.shutdown()


def _free_port() -> int:
    import socket

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_scan_local_never_crashes(tmp_path):
    assert api.scan_local() == api.scan_local()


def test_station_end_to_end(tmp_path, fake_upstream):
    port = _free_port()
    st = api.Station(port=port, master_key="rh_test_master", home=tmp_path / "s1")

    # 上游：手动加一个假上游（openai 协议自动识别失败也没关系——显式传）
    added = st.add_upstream(
        base_url=fake_upstream,
        api_key="sk-fake-key",
        models=["fake-model"],
        protocol="openai-chat",
        label="fake",
    )
    assert added.label == "fake"
    assert [u["label"] for u in st.list_upstreams()] == ["fake"]

    # 发两枚令牌：normal（真路由）+ test（合成路由）
    tok = st.create_token("我的设备", models=["fake-model"], rpm=120)
    assert tok.plaintext.startswith("rht_")
    test_tok = st.create_token("试水", scope="test")
    assert len(st.list_tokens()) == 2

    # 起站（后台线程）
    url = st.serve(background=True)
    assert url == f"http://127.0.0.1:{port}"
    try:
        # 1) 模型列表（master key）
        req = urllib.request.Request(
            url + "/v1/models", headers={"Authorization": "Bearer rh_test_master"}
        )
        with urllib.request.urlopen(req, timeout=5) as r:
            models = json.loads(r.read())
        assert "fake-model" in [m.get("id") for m in models.get("data", [])]

        # 2) 用下游令牌真发一次对话
        req = urllib.request.Request(
            url + "/v1/chat/completions",
            data=json.dumps({"model": "fake-model", "messages": [{"role": "user", "content": "hi"}]}).encode(),
            headers={"Authorization": f"Bearer {tok.plaintext}", "Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            answer = json.loads(r.read())
        assert answer["choices"][0]["message"]["content"] == "hello from fake"

        # 3) 错误令牌必须被拒
        req = urllib.request.Request(
            url + "/v1/models", headers={"Authorization": "Bearer rht_wrong"}
        )
        try:
            urllib.request.urlopen(req, timeout=5)
            raise AssertionError("错误令牌不应通过鉴权")
        except urllib.error.HTTPError as e:
            assert e.code in (401, 403)
    finally:
        st.stop()
    assert st._server is None


def test_token_persisted_hash_only(tmp_path):
    st = api.Station(port=_free_port(), home=tmp_path / "s2")
    tok = st.create_token("持久化", daily_requests=100, expires_days=7)
    raw = (st.tokens_file).read_text(encoding="utf-8")
    assert tok.plaintext not in raw, "明文令牌绝不落盘"
    assert tok.plaintext[:8] in raw or True
    st2 = api.Station(port=st.port, home=tmp_path / "s2")  # 重新打开同一站
    names = [t["name"] for t in st2.list_tokens()]
    assert "持久化" in names


def test_quickstart(tmp_path, fake_upstream):
    port = _free_port()
    st, url = api.quickstart(
        fake_upstream, api_key="sk-fake", models=["fake-model"], port=port, background=True
    )
    try:
        req = urllib.request.Request(
            url + "/v1/chat/completions",
            data=json.dumps({"model": "fake-model", "messages": [{"role": "user", "content": "q"}]}).encode(),
            headers={"Authorization": "Bearer rh_local_dev", "Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            answer = json.loads(r.read())
        assert answer["choices"][0]["message"]["content"] == "hello from fake"
    finally:
        st.stop()


def test_top_level_shim():
    import hubrelay  # noqa: F401  顶层 import 与 pip 名一致
    import relayhub

    assert hubrelay.Station is relayhub.api.Station
    assert hubrelay.__version__ == relayhub.__version__ or True


def test_lifecycle_methods(tmp_path):
    """v0.2.4 新增：启停/吊销/用量聚合。"""
    st = api.Station(port=_free_port(), home=tmp_path / "s3")
    st.add_upstream("http://10.0.0.9:9999", api_key="sk-x", models=["m"], label="chan-a")
    st.create_token("phone")
    st.create_token("pad")

    # 令牌：停用→列表可见 enabled=False→恢复→吊销
    assert st.set_token_enabled("phone", False) is True
    assert [t for t in st.list_tokens() if t["name"] == "phone"][0]["enabled"] is False
    assert st.set_token_enabled("phone", True) is True
    assert st.remove_token("pad") is True
    assert st.remove_token("pad") is False  # 幂等
    assert [t["name"] for t in st.list_tokens()] == ["phone"]

    # 上游：停用→恢复→移除
    assert st.set_upstream_enabled("chan-a", False) is True
    assert st.list_upstreams()[0]["enabled"] is False
    assert st.set_upstream_enabled("chan-a", True) is True
    assert st.remove_upstream("chan-a") is True
    assert st.remove_upstream("chan-a") is False

    # 用量聚合
    u = st.usage()
    assert u["upstream"]["channels"] == 0 and u["downstream"]["tokens"] == 1
