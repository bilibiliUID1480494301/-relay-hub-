"""本机推理服务扫描测试：假 OpenAI 服务 + 假 Ollama 服务 + 导入幂等。"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from relayhub.gateway import localscan
from relayhub.gateway.localscan import LocalServer, import_to_pool, probe, scan
from relayhub.gateway.pool import KeyPool, PROTOCOL_OPENAI_CHAT


class _OpenAIServer(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        return

    def do_GET(self):
        if self.path == "/v1/models":
            payload = {
                "data": [
                    {"id": "qwen3-32b", "max_model_len": 32768},
                    {"id": "glm-5.2"},
                ]
            }
            raw = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()


class _OllamaServer(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        return

    def do_GET(self):
        if self.path == "/api/tags":
            payload = {"models": [{"name": "deepseek-v4:32b"}, {"name": "llama4:8b"}]}
            raw = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        # Ollama 也支持 /v1/models，但这里故意只给 /api/tags，测 ollama 识别分支
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()


class _FakeSites:
    def __init__(self):
        self.openai = ThreadingHTTPServer(("127.0.0.1", 0), _OpenAIServer)
        self.ollama = ThreadingHTTPServer(("127.0.0.1", 0), _OllamaServer)
        self.threads = [
            threading.Thread(target=self.openai.serve_forever, daemon=True),
            threading.Thread(target=self.ollama.serve_forever, daemon=True),
        ]

    def __enter__(self):
        for t in self.threads:
            t.start()
        return self

    def __exit__(self, *exc):
        self.openai.shutdown()
        self.ollama.shutdown()
        self.openai.server_close()
        self.ollama.server_close()


def _port_of(server: ThreadingHTTPServer) -> int:
    return server.server_address[1]


# ---------------------------------------------------------------- probe


def test_probe_recognises_openai_compatible() -> None:
    with _FakeSites() as sites:
        server = probe(f"http://127.0.0.1:{_port_of(sites.openai)}", "lm-studio", timeout=3)
    assert server is not None
    assert server.source == "openai"
    assert server.models == ["qwen3-32b", "glm-5.2"]
    assert server.model_windows == {"qwen3-32b": 32768}, "max_model_len 要被当作上下文长度收下"


def test_probe_recognises_ollama_tags() -> None:
    with _FakeSites() as sites:
        server = probe(f"http://127.0.0.1:{_port_of(sites.ollama)}", "ollama", timeout=3)
    assert server is not None
    assert server.source == "ollama"
    assert server.models == ["deepseek-v4:32b", "llama4:8b"]


def test_probe_rejects_plain_web_page() -> None:
    """一个恰好开着的普通网页绝不能被当成模型渠道。"""

    class _Web(BaseHTTPRequestHandler):
        def log_message(self, *args):
            return

        def do_GET(self):
            raw = b"<html><body>hello</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    web = ThreadingHTTPServer(("127.0.0.1", 0), _Web)
    thread = threading.Thread(target=web.serve_forever, daemon=True)
    thread.start()
    try:
        assert probe(f"http://127.0.0.1:{web.server_address[1]}", timeout=2) is None
    finally:
        web.shutdown()
        web.server_close()
        thread.join(timeout=3)


def test_probe_dead_port_returns_none() -> None:
    assert probe("http://127.0.0.1:1", timeout=0.5) is None


# ---------------------------------------------------------------- scan


def test_scan_finds_both_kinds_on_given_ports() -> None:
    with _FakeSites() as sites:
        found = scan(ports=[_port_of(sites.openai), _port_of(sites.ollama)], timeout=3)
    kinds = {s.kind for s in found}
    # OpenAI 形态保持传入 kind；/api/tags 识别出来的一律归 ollama
    assert kinds == {"openai", "ollama"}


# ---------------------------------------------------------------- 导入


def test_import_creates_local_channels_and_is_idempotent(tmp_path: Path) -> None:
    path = tmp_path / "pool.json"
    servers = [
        LocalServer(
            kind="ollama",
            base_url="http://127.0.0.1:11434",
            models=["deepseek-v4:32b"],
            source="ollama",
        )
    ]
    imported, skipped = import_to_pool(path, servers)
    assert skipped == []
    assert [k.label for k in imported] == ["local-ollama"]
    assert imported[0].protocol == PROTOCOL_OPENAI_CHAT

    # 第二次导入 = 覆盖刷新，不堆重复渠道；模型列表要跟得上变化
    servers[0].models = ["llama4:8b"]
    imported, _ = import_to_pool(path, servers)
    assert [k.label for k in imported] == ["local-ollama"]
    pool = KeyPool.load(path)
    assert len(pool.keys) == 1
    assert pool.keys[0].models == ("llama4:8b",)


def test_import_never_overwrites_manual_channel_with_same_label(tmp_path: Path) -> None:
    """local- 前缀是本工具保留的；用户手工渠道撞名时不覆盖，如实跳过。"""
    from relayhub.gateway.pool import UpstreamKey

    path = tmp_path / "pool.json"
    pool = KeyPool(
        [
            UpstreamKey(
                key_id="m1",
                label="local-ollama",
                base_url="http://manual",
                api_key="",
                protocol=PROTOCOL_OPENAI_CHAT,
                models=("manual-model",),
            )
        ]
    )
    pool.save(path)

    imported, skipped = import_to_pool(
        path,
        [LocalServer(kind="ollama", base_url="http://127.0.0.1:11434", models=["x"], source="ollama")],
    )
    assert imported == []
    assert len(skipped) == 1
    assert KeyPool.load(path).keys[0].models == ("manual-model",)
