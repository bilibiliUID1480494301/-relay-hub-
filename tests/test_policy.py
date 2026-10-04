"""接入策略：拉黑（IP/设备）+ 优先队列，与网关端到端。"""

from __future__ import annotations

import hashlib
import json
import threading
import time

import pytest

from relayhub.gateway import reqlog as reqlog_module
from relayhub.gateway import policy as policy_module
from relayhub.gateway.policy import KIND_DEVICE, KIND_IP, PolicyError, PolicyStore
from relayhub.gateway.service import ConcurrencyGate, DemoRouter, RelayServer, demo_pool
from relayhub.gateway.tokens import DownstreamToken, TokenPool, TokenStore

TOKEN = "rht_policy_test_token"
TOKEN_HASH = hashlib.sha256(TOKEN.encode()).hexdigest()


# -- PolicyStore 本体 ------------------------------------------------------


def test_set_and_state(tmp_path) -> None:
    store = PolicyStore(tmp_path / "policy.json")
    store.set(KIND_IP, "1.2.3.4", blocked=True, note="刷请求")
    store.set(KIND_DEVICE, "did-abc", priority=True)
    state = store.state()
    assert state["ips"]["1.2.3.4"]["blocked"] is True
    assert state["devices"]["did-abc"]["priority"] is True


def test_blocked_and_priority_are_mutually_exclusive(tmp_path) -> None:
    store = PolicyStore(tmp_path / "policy.json")
    store.set(KIND_IP, "1.2.3.4", priority=True)
    store.set(KIND_IP, "1.2.3.4", blocked=True)
    # 拉黑赢：变黑的同时优先被取消
    assert store.is_ip_blocked("1.2.3.4")
    assert not store.is_ip_priority("1.2.3.4")
    # 黑的不能直接改优先，要先移除
    with pytest.raises(PolicyError):
        store.set(KIND_IP, "1.2.3.4", priority=True)
    store.remove(KIND_IP, "1.2.3.4")
    assert not store.is_ip_blocked("1.2.3.4")


def test_hot_reload_between_stores(tmp_path) -> None:
    """数据面与控制台各持一个实例：控制台改文件，数据面下一查即生效。"""
    path = tmp_path / "policy.json"
    data_plane = PolicyStore(path)
    console = PolicyStore(path)
    console.set(KIND_DEVICE, "did-x", blocked=True)
    assert data_plane.is_device_blocked("did-x"), "指纹变了要重读文件"


def test_empty_value_rejected(tmp_path) -> None:
    with pytest.raises(PolicyError):
        PolicyStore(tmp_path / "p.json").set(KIND_IP, "  ", blocked=True)


def test_missing_file_is_allowing(tmp_path) -> None:
    store = PolicyStore(tmp_path / "nonexistent.json")
    assert not store.is_ip_blocked("1.2.3.4")
    assert not store.is_device_priority("anything")


# -- 优先队列（ConcurrencyGate） --------------------------------------------


def test_priority_waiter_wakes_before_normal() -> None:
    gate = ConcurrencyGate(max_in_flight=1, queue_size=4, queue_timeout=5.0)
    assert gate.acquire()  # 占住唯一名额
    normal_got: list[bool] = []
    priority_got: list[bool] = []

    def _wait(priority: bool, sink: list[bool]) -> None:
        sink.append(gate.acquire(priority=priority))

    t_norm = threading.Thread(target=_wait, args=(False, normal_got), daemon=True)
    t_prio = threading.Thread(target=_wait, args=(True, priority_got), daemon=True)
    t_norm.start()
    time.sleep(0.05)  # 让普通等待者先进队
    t_prio.start()
    time.sleep(0.05)  # 让 VIP 也排好
    gate.release()
    t_prio.join(timeout=3)
    assert priority_got == [True], "名额释放要先给 VIP"
    gate.release()  # 兜底放名额，普通等待者（若还挂着）能退出，进程不悬挂


# -- 网关端到端：拉黑 -------------------------------------------------------


def _relay(tmp_path, *, blocked_ip: str | None = None, blocked_device: str | None = None) -> RelayServer:
    policy = PolicyStore(tmp_path / "policy.json")
    if blocked_ip:
        policy.set(KIND_IP, blocked_ip, blocked=True)
    if blocked_device:
        policy.set(KIND_DEVICE, blocked_device, blocked=True)
    token_path = tmp_path / "tokens.json"
    TokenPool([DownstreamToken(token_id="sm", name="app:demo", token=TOKEN)]).save(token_path)
    return RelayServer(
        ("127.0.0.1", 0),
        DemoRouter(demo_pool()),
        api_key=None,
        event_delay=0.0,
        tokens=TokenStore(token_path),
        request_log=tmp_path / "requests.jsonl",
        policy=policy,
    )


def _post(server: RelayServer, body: dict, headers: dict) -> tuple[int, bytes]:
    import http.client

    conn = http.client.HTTPConnection(
        server.server_address[0], server.server_address[1], timeout=10
    )
    conn.request(
        "POST", "/v1/messages", json.dumps(body).encode(),
        {"Content-Type": "application/json", **headers},
    )
    response = conn.getresponse()
    payload = response.read()
    conn.close()
    return response.status, payload


def _wait_entries(path, n: int = 1, timeout: float = 5.0):
    """等日志落盘：错误路径是先写响应再记日志，读端要小轮询。"""
    deadline = time.time() + timeout
    entries = []
    while time.time() < deadline:
        entries = reqlog_module.tail(path)
        if len(entries) >= n:
            return entries
        time.sleep(0.05)
    return entries


def test_blocked_ip_is_403(tmp_path) -> None:
    server = _relay(tmp_path, blocked_ip="127.0.0.1")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, body = _post(
            server, {"model": "glm-5.2", "max_tokens": 8, "messages": []}, {}
        )
        assert status == 403
        assert "拉黑" in body.decode("utf-8")
        entry = _wait_entries(tmp_path / "requests.jsonl")[-1]
        assert entry["reason"] == "ip blacklisted"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


