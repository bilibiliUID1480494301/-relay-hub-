"""局域网发现测试：应答器 + 探测器在真实 UDP 套接字上对跑。"""

from __future__ import annotations

import socket

from relayhub.gateway.discovery import (
    PROBE_MAGIC,
    DiscoveryResponder,
    discover,
    _broadcast_targets,
)


def _responder(**kwargs) -> DiscoveryResponder:
    defaults = dict(
        name="gw",
        data_port=59999,
        models_count=lambda: 3,
        pairing_open=lambda: True,
        # 临时端口：不和生产发现端口 8795 抢——本机常驻网关开着发现时，
        # SO_REUSEADDR 会让两者同时收广播，真实应答会污染断言。
        port=0,
    )
    defaults.update(kwargs)
    responder = DiscoveryResponder(**defaults)
    thread_target = responder
    thread_target.start()
    return responder


def test_discover_finds_local_responder() -> None:
    responder = _responder(name="lab-gw", data_port=8799)
    try:
        found = discover(port=responder.port, timeout=1.5)
        # 多网卡机器会从每个可达接口各看到一条——按实例去重后必须只有这一个网关
        instances = {(info.name, info.port) for info in found}
        assert instances == {("lab-gw", 8799)}, found
        loopback = [info for info in found if info.host == "127.0.0.1"]
        assert loopback, "回环探测必须可达（单机测试与多实例的命门）"
        info = loopback[0]
        assert info.port == 8799
        assert info.models == 3
        assert info.pairing_open is True
    finally:
        responder.stop()
        responder.join(timeout=3)
    assert not responder.is_alive(), "stop 之后线程必须收工"


def test_responder_reflects_live_pairing_state() -> None:
    state = {"open": False}
    responder = _responder(pairing_open=lambda: state["open"])
    try:
        assert discover(port=responder.port, timeout=1.0)[0].pairing_open is False
        state["open"] = True
        assert discover(port=responder.port, timeout=1.0)[0].pairing_open is True
    finally:
        responder.stop()
        responder.join(timeout=3)


def _free_udp_port() -> int:
    """抳一个空闲 UDP 端口给测试应答器用（绑完就还，容忍极小竞争窗口）。"""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def test_two_responders_are_both_found() -> None:
    # 多实例必须同端口：discover 只往一个发现端口广播
    shared = _free_udp_port()
    first = _responder(name="a", data_port=8001, port=shared)
    try:
        second = _responder(name="b", data_port=8002, port=shared)
        try:
            found = discover(port=first.port, timeout=1.5)
            names = {info.name for info in found}
            assert names == {"a", "b"}
        finally:
            second.stop()
            second.join(timeout=3)
    finally:
        first.stop()
        first.join(timeout=3)


def test_responder_ignores_garbage_probes() -> None:
    """非探测包不得触发应答——发现端口不该对扫描器回任何信息。"""
    responder = _responder()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        try:
            sock.sendto(b"GET / HTTP/1.1", ("127.0.0.1", responder.port))
            try:
                data, _ = sock.recvfrom(2048)
                raise AssertionError(f"垃圾包收到了应答：{data!r}")
            except socket.timeout:
                pass  # 期望行为：沉默
            # 随后合法探测仍然正常工作（应答器没被垃圾包弄挂）
            sock.sendto(PROBE_MAGIC, ("127.0.0.1", responder.port))
            data, _ = sock.recvfrom(2048)
            assert b"relay-hub" in data
        finally:
            sock.close()
    finally:
        responder.stop()
        responder.join(timeout=3)


def test_broadcast_targets_include_loopback() -> None:
    """回环是单机测试与多实例的命门；全网广播是跨设备的主路径。"""
    targets = {host for host, _ in _broadcast_targets(8795)}
    assert "127.0.0.1" in targets
    assert "255.255.255.255" in targets
