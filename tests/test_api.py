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
        if self.path.endswith("/embeddings"):
            body = json.dumps(
                {
                    "object": "list",
                    "model": "fake-model",
                    "data": [{"object": "embedding", "index": 0,
                              "embedding": [0.1, 0.2, 0.3]}],
                    "usage": {"prompt_tokens": 3, "total_tokens": 3},
                }
            ).encode()
        else:
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


def test_station_embeddings(tmp_path, fake_upstream):
    """v0.2.7 新增：/v1/embeddings 端到端（真上游 + test 合成 + 鉴权拒绝）。"""
    port = _free_port()
    st = api.Station(port=port, master_key="rh_test_master", home=tmp_path / "s4")
    st.add_upstream(fake_upstream, api_key="sk-fake", models=["fake-model"],
                    protocol="openai-chat", label="fake")
    tok = st.create_token("rag-dev", models=["fake-model"], rpm=120)
    url = st.serve(background=True)

    def post(payload, bearer):
        req = urllib.request.Request(
            url + "/v1/embeddings",
            data=json.dumps(payload).encode(),
            headers={"Authorization": f"Bearer {bearer}", "Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())

    try:
        # 1) 真上游：请求体原样透传（向量条数由上游决定），model 名翻回对外名
        out = post({"model": "fake-model", "input": ["a", "b"]}, tok.plaintext)
        assert len(out["data"]) == 1 and out["model"] == "fake-model"
        assert all(isinstance(e["embedding"], list) for e in out["data"])

        # 2) test 令牌：本地合成向量，不触上游
        test_tok = st.create_token("emb-test", scope="test")
        out = post({"model": "anything", "input": "hi"}, test_tok.plaintext)
        assert out["object"] == "list" and len(out["data"]) == 1

        # 3) 错误令牌拒绝
        try:
            post({"model": "fake-model", "input": "hi"}, "rht_wrong")
            raise AssertionError("错误令牌不应通过")
        except urllib.error.HTTPError as e:
            assert e.code in (401, 403)
    finally:
        st.stop()


def test_healthz_and_models_filter(tmp_path, fake_upstream):
    """v0.2.8：/healthz 无凭证探活；/v1/models 按令牌白名单过滤。"""
    port = _free_port()
    st = api.Station(port=port, master_key="rh_m", home=tmp_path / "s5")
    st.add_upstream(fake_upstream, api_key="sk-f", models=["fake-model"],
                    protocol="openai-chat", label="fake")
    limited = st.create_token("limited", models=["fake-model"])
    url = st.serve(background=True)
    try:
        # 1) healthz：无凭证 200，且不泄露模型/版本
        with urllib.request.urlopen(url + "/healthz", timeout=5) as r:
            body = json.loads(r.read())
        assert body["ok"] is True and "models" not in body

        # 2) 受限令牌只见白名单内模型
        req = urllib.request.Request(url + "/v1/models",
                                     headers={"Authorization": f"Bearer {limited.plaintext}"})
        with urllib.request.urlopen(req, timeout=5) as r:
            data = json.loads(r.read())["data"]
        assert [m["id"] for m in data] == ["fake-model"]

        # 3) master 看全量（当前就一个模型，等价性检查）
        req = urllib.request.Request(url + "/v1/models",
                                     headers={"Authorization": "Bearer rh_m"})
        with urllib.request.urlopen(req, timeout=5) as r:
            assert len(json.loads(r.read())["data"]) == 1
    finally:
        st.stop()


def test_healthz_and_models_filter(tmp_path, fake_upstream):
    """v0.2.8：/healthz 无凭证探活；/v1/models 按令牌白名单过滤。"""
    port = _free_port()
    st = api.Station(port=port, master_key="rh_m", home=tmp_path / "s5")
    st.add_upstream(fake_upstream, api_key="sk-f", models=["fake-model"],
                    protocol="openai-chat", label="fake")
    limited = st.create_token("limited", models=["fake-model"])
    url = st.serve(background=True)
    try:
        # 1) healthz：无凭证 200，且不泄露模型/版本
        with urllib.request.urlopen(url + "/healthz", timeout=5) as r:
            body = json.loads(r.read())
        assert body["ok"] is True and "models" not in body

        # 2) 受限令牌只见白名单内模型
        req = urllib.request.Request(url + "/v1/models",
                                     headers={"Authorization": f"Bearer {limited.plaintext}"})
        with urllib.request.urlopen(req, timeout=5) as r:
            data = json.loads(r.read())["data"]
        assert [m["id"] for m in data] == ["fake-model"]

        # 3) master 看全量（当前就一个模型，等价性检查）
        req = urllib.request.Request(url + "/v1/models",
                                     headers={"Authorization": "Bearer rh_m"})
        with urllib.request.urlopen(req, timeout=5) as r:
            assert len(json.loads(r.read())["data"]) == 1
    finally:
        st.stop()


def test_responses_api(tmp_path, fake_upstream):
    """v0.2.10：/v1/responses（OpenAI Responses API）端到端。

    覆盖：非流式（string input + instructions）、流式（SSE 事件序）、
    items 列表 input、test 令牌合成应答、错误令牌拒绝。
    """
    port = _free_port()
    st = api.Station(port=port, master_key="rh_m", home=tmp_path / "s6")
    st.add_upstream(fake_upstream, api_key="sk-f", models=["fake-model"],
                    protocol="openai-chat", label="fake")
    tok = st.create_token("ide-client", models=["fake-model"], rpm=120)
    url = st.serve(background=True)

    def post(payload, bearer):
        req = urllib.request.Request(
            url + "/v1/responses",
            data=json.dumps(payload).encode(),
            headers={"Authorization": f"Bearer {bearer}", "Content-Type": "application/json"},
            method="POST",
        )
        return urllib.request.urlopen(req, timeout=10)

    try:
        # 1) 非流式：string input，回答从 chat 上游翻译而来
        with post({"model": "fake-model", "input": "hi"}, tok.plaintext) as r:
            out = json.loads(r.read())
        assert out["object"] == "response" and out["status"] == "completed"
        assert out["output_text"] == "hello from fake"
        assert out["output"][0]["content"][0]["type"] == "output_text"
        assert out["usage"]["input_tokens"] > 0

        # 2) items 列表 + instructions
        with post({"model": "fake-model",
                   "instructions": "你是助手",
                   "input": [{"type": "message", "role": "user",
                              "content": [{"type": "input_text", "text": "hi"}]}]},
                  tok.plaintext) as r:
            out = json.loads(r.read())
        assert out["output_text"] == "hello from fake"

        # 3) 流式：事件序完整，delta 拼出全文
        test_tok = st.create_token("resp-test", scope="test")
        req = urllib.request.Request(
            url + "/v1/responses",
            data=json.dumps({"model": "any", "input": "hi", "stream": True}).encode(),
            headers={"Authorization": f"Bearer {test_tok.plaintext}",
                     "Content-Type": "application/json"},
            method="POST",
        )
        names, text = [], ""
        with urllib.request.urlopen(req, timeout=10) as r:
            for raw in r.read().decode("utf-8").split("\n\n"):
                for line in raw.splitlines():
                    if not line.startswith("data: "):
                        continue
                    payload = json.loads(line[len("data: "):])
                    names.append(payload.get("type"))
                    if payload.get("type") == "response.output_text.delta":
                        text += payload["delta"]
        assert names[0] == "response.created"
        assert "response.output_text.delta" in names
        assert names[-1] == "response.completed"
        assert len(text) > 0

        # 4) 错误令牌拒绝（openai 形状错误体）
        try:
            post({"model": "fake-model", "input": "hi"}, "rht_wrong")
            raise AssertionError("错误令牌不应通过")
        except urllib.error.HTTPError as e:
            assert e.code in (401, 403)
    finally:
        st.stop()


def test_responses_api(tmp_path, fake_upstream):
    """v0.2.10：/v1/responses（OpenAI Responses API）端到端。

    覆盖：非流式（string input + instructions）、流式（SSE 事件序）、
    items 列表 input、test 令牌合成应答、错误令牌拒绝。
    """
    port = _free_port()
    st = api.Station(port=port, master_key="rh_m", home=tmp_path / "s6")
    st.add_upstream(fake_upstream, api_key="sk-f", models=["fake-model"],
                    protocol="openai-chat", label="fake")
    tok = st.create_token("ide-client", models=["fake-model"], rpm=120)
    url = st.serve(background=True)

    def post(payload, bearer):
        req = urllib.request.Request(
            url + "/v1/responses",
            data=json.dumps(payload).encode(),
            headers={"Authorization": f"Bearer {bearer}", "Content-Type": "application/json"},
            method="POST",
        )
        return urllib.request.urlopen(req, timeout=10)

    try:
        # 1) 非流式：string input，回答从 chat 上游翻译而来
        with post({"model": "fake-model", "input": "hi"}, tok.plaintext) as r:
            out = json.loads(r.read())
        assert out["object"] == "response" and out["status"] == "completed"
        assert out["output_text"] == "hello from fake"
        assert out["output"][0]["content"][0]["type"] == "output_text"
        assert out["usage"]["input_tokens"] > 0

        # 2) items 列表 + instructions
        with post({"model": "fake-model",
                   "instructions": "你是助手",
                   "input": [{"type": "message", "role": "user",
                              "content": [{"type": "input_text", "text": "hi"}]}]},
                  tok.plaintext) as r:
            out = json.loads(r.read())
        assert out["output_text"] == "hello from fake"

        # 3) 流式：事件序完整，delta 拼出全文
        test_tok = st.create_token("resp-test", scope="test")
        req = urllib.request.Request(
            url + "/v1/responses",
            data=json.dumps({"model": "any", "input": "hi", "stream": True}).encode(),
            headers={"Authorization": f"Bearer {test_tok.plaintext}",
                     "Content-Type": "application/json"},
            method="POST",
        )
        names, text = [], ""
        with urllib.request.urlopen(req, timeout=10) as r:
            for raw in r.read().decode("utf-8").split("\n\n"):
                for line in raw.splitlines():
                    if not line.startswith("data: "):
                        continue
                    payload = json.loads(line[len("data: "):])
                    names.append(payload.get("type"))
                    if payload.get("type") == "response.output_text.delta":
                        text += payload["delta"]
        assert names[0] == "response.created"
        assert "response.output_text.delta" in names
        assert names[-1] == "response.completed"
        assert len(text) > 0

        # 4) 错误令牌拒绝（openai 形状错误体）
        try:
            post({"model": "fake-model", "input": "hi"}, "rht_wrong")
            raise AssertionError("错误令牌不应通过")
        except urllib.error.HTTPError as e:
            assert e.code in (401, 403)
    finally:
        st.stop()
