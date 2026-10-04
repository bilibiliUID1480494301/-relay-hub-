"""请求明细测试：记录器本身 + 网关接线（真实请求产出真实明细）。"""

from __future__ import annotations

import threading
import time
from pathlib import Path

from relayhub.gateway import conformance, reqlog
from relayhub.gateway.service import RelayServer, demo_router
from relayhub.gateway.tokens import DownstreamToken, TokenPool, TokenStore

API_KEY = "rh_master"


def test_record_and_tail_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "requests.jsonl"
    reqlog.record(path, token="app-a", model="glm-5.2", channel="ch", ok=True, tokens_in=10, tokens_out=4, latency_ms=12.3)
    reqlog.record(path, token="app-a", model="glm-5.2", channel="ch", ok=False, status=404, reason="unknown model")

    entries = reqlog.tail(path)
    assert len(entries) == 2
    assert entries[0]["ok"] is True
    assert entries[1]["ok"] is False
    assert entries[1]["reason"] == "unknown model"
    assert "prompt" not in json_keys(entries)


def json_keys(entries: list[dict]) -> set:
    keys: set = set()
    for e in entries:
        keys.update(e.keys())
    return keys


def test_log_never_contains_content_fields(tmp_path: Path) -> None:
    """隐私边界：明细只许有元数据字段，谁往里塞对话文本谁破坏契约。"""
    path = tmp_path / "requests.jsonl"
    reqlog.record(path, token="t", model="m", ok=True)
    keys = json_keys(reqlog.tail(path))
    assert keys <= {
        "ts", "token", "dialect", "model", "channel", "ok", "stream",
        "status", "tokens_in", "tokens_out", "latency_ms", "reason",
    }


def test_tail_missing_file(tmp_path: Path) -> None:
    assert reqlog.tail(tmp_path / "nope.jsonl") == []


def test_summarize_buckets() -> None:
    now = time.time()
    entries = [
        {"ts": now, "token": "app-a", "model": "glm-5.2", "channel": "local-ollama", "ok": True, "tokens_in": 7, "tokens_out": 5, "latency_ms": 100},
        {"ts": now, "token": "app-a", "model": "glm-5.2", "channel": "local-ollama", "ok": False, "status": 502},
        {"ts": now, "token": "app-b", "model": "deepseek-v4", "channel": "official", "ok": True, "tokens_in": 3, "tokens_out": 2, "latency_ms": 50},
    ]
    summary = reqlog.summarize(entries)
    assert summary["window"]["requests"] == 3
    assert summary["window"]["failed"] == 1
    assert summary["window"]["avg_latency_ms"] == 75.0
    assert summary["by_token"]["app-a"]["requests"] == 2
    assert summary["by_model"]["deepseek-v4"]["ok"] == 1
    assert summary["by_channel"]["local-ollama"]["failed"] == 1
    assert len(summary["by_day"]) == 1


# ---------------------------------------------------------------- 网关接线


def test_gateway_writes_request_log_for_success_and_stream(tmp_path: Path) -> None:
    path = tmp_path / "requests.jsonl"
    server = RelayServer(
        ("127.0.0.1", 0), demo_router(), api_key=API_KEY, event_delay=0.0, request_log=path
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        probe = conformance.Probe(server.base_url, API_KEY)
        assert probe.post("/v1/messages", {"model": "glm-5.2", "max_tokens": 8, "messages": []})[0].status == 200
        assert probe.post(
            "/v1/chat/completions",
            {"model": "glm-5.2", "messages": [], "stream": True},
            streaming=True,
            read_stream=True,
        )[0].status == 200
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    entries = reqlog.tail(path)
    assert len(entries) == 2
    non_stream, stream = entries
    assert non_stream["ok"] is True and non_stream["stream"] is False
    assert non_stream["channel"] == "secondary", "演示池第一个渠道是坏的，应记到接住的渠道"
    assert non_stream["tokens_in"] > 0
    assert stream["stream"] is True
    assert stream["dialect"] == "openai"
    assert stream["latency_ms"] >= 0


def test_gateway_logs_rejected_requests_with_token_identity(tmp_path: Path) -> None:
    """拒绝的请求也要留痕：404 未知模型记失败原因，401 记不到身份时归 master/-。"""
    tokens_path = tmp_path / "tokens.json"
    TokenPool([DownstreamToken(token_id="t1", name="app-a", token="rht_secret-app-a")]).save(tokens_path)

    path = tmp_path / "requests.jsonl"
    server = RelayServer(
        ("127.0.0.1", 0),
        demo_router(),
        api_key=API_KEY,
        tokens=TokenStore(tokens_path),
        request_log=path,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        probe = conformance.Probe(server.base_url, "rht_secret-app-a")
        assert probe.post("/v1/messages", {"model": "nope", "max_tokens": 8, "messages": []})[0].status == 404
        bad = conformance.Probe(server.base_url, "rht_wrong")
        assert bad.post("/v1/messages", {"model": "glm-5.2", "max_tokens": 8, "messages": []})[0].status == 401
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    entries = reqlog.tail(path)
    assert [e["status"] for e in entries] == [404, 401]
    assert entries[0]["token"] == "app-a"
    assert entries[0]["reason"] == "unknown model"
    assert entries[1]["token"] == "master", "无效令牌的 401 记不到设备名，归 master 层"


def test_gateway_without_log_writes_nothing(tmp_path: Path) -> None:
    server = RelayServer(("127.0.0.1", 0), demo_router(), api_key=None, request_log=None)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        probe = conformance.Probe(server.base_url)
        assert probe.post("/v1/messages", {"model": "glm-5.2", "max_tokens": 8, "messages": []})[0].status == 200
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert not (tmp_path / "requests.jsonl").exists()
