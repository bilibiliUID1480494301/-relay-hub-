"""局域网发现：UDP 广播应答器 + 客户端探测（目标链路的第一环）。

设计从 README「六」的规划做了两点简化，都是标准库约束下的主动取舍：

  * **UDP 广播而不是 mDNS/Zeroconf**：mDNS 要手写 DNS-SD 报文或引第三方库，
    本项目零依赖是红线。UDP 广播 + JSON 载荷在同网段效果等价，
    代价是不跨网段——中转站本来就是同网段的东西。
  * **载荷只放元数据，不放凭证**：name / 数据端口 / 模型数 / 配对窗口是否开着。
    README 要求的「TXT 只放公钥」属加密套件那一步；现阶段发现只回答
    「这儿有没有网关」，接入信任走 6 位码带外配对（pairing.py）。

防火墙提示：Windows 上第一次监听 UDP 端口会弹防火墙授权，放行专用网络即可。
"""

from __future__ import annotations

import json
import socket
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable

PROBE_MAGIC = b"RELAYHUB-DISCOVER-v1"
DISCOVERY_PORT = 8795
RECV_BUFFER = 2048


@dataclass(frozen=True)
class GatewayInfo:
    name: str
    host: str  # 应答包的来源地址——用哪个接口发现就用哪个地址访问
    port: int  # 数据面端口（HTTP）
    models: int
    pairing_open: bool


class DiscoveryResponder(threading.Thread):
    """监听 UDP 广播端口，对合法探测包回一份实例元数据。

    独立线程 + 短超时循环：stop() 半秒内收工，serve 退出不吊着。
    回包里的 host 刻意不写——客户端该信自己看到的来源地址，
    网关自己报的地址在多网卡机器上十有八九是错的。
    """

    def __init__(
        self,
        *,
        name: str,
        data_port: int,
        models_count: Callable[[], int],
        pairing_open: Callable[[], bool],
        port: int = DISCOVERY_PORT,
        clock: Callable[[], float] = time.time,
    ) -> None:
        super().__init__(daemon=True, name="relayhub-discovery")
        self.name_label = name
        self.data_port = data_port
        self._models_count = models_count
        self._pairing_open = pairing_open
        self._clock = clock
        self._stop_event = threading.Event()  # 不能叫 _stop：会和 Thread._stop() 撞名，join 收尾时 TypeError
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("", port))
        self._sock.settimeout(0.5)
        self.port = self._sock.getsockname()[1]

    def run(self) -> None:
        while not self._stop_event.is_set():
            try:
                data, addr = self._sock.recvfrom(RECV_BUFFER)
            except socket.timeout:
                continue
            except OSError:
                break  # stop() 关了套接字
            if data.strip() != PROBE_MAGIC:
                continue  # 不是我们的探测：静默忽略，不回包不给探测者任何信息
            reply: dict[str, Any] = {
                "protocol": "relay-hub",
                "name": self.name_label,
                "port": self.data_port,
                "models": int(self._models_count()),
                "pairing": bool(self._pairing_open()),
            }
            try:
                self._sock.sendto(json.dumps(reply).encode("utf-8"), addr)
            except OSError:
                continue

    def stop(self) -> None:
        self._stop_event.set()
        try:
            self._sock.close()
        except OSError:
            pass


def discover(
    *, timeout: float = 3.0, port: int = DISCOVERY_PORT
) -> list[GatewayInfo]:
    """广播探测，收集 timeout 秒内的应答。同一 (host, port) 只留一条。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(("", 0))
    sock.settimeout(0.3)
    deadline = time.monotonic() + timeout
    try:
        for target in _broadcast_targets(port):
            try:
                sock.sendto(PROBE_MAGIC, target)
            except OSError:
                continue  # 某个接口没有广播路由很正常，别的地址会补上
        found: dict[tuple[str, int], GatewayInfo] = {}
        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(RECV_BUFFER)
            except socket.timeout:
                continue
            except OSError:
                break
            info = _parse_reply(data, addr[0])
            if info is not None:
                found[(info.host, info.port)] = info
        return sorted(found.values(), key=lambda g: (g.host, g.port))
    finally:
        sock.close()


def _parse_reply(data: bytes, host: str) -> GatewayInfo | None:
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict) or payload.get("protocol") != "relay-hub":
        return None
    port = int(payload.get("port") or 0)
    if not (0 < port < 65536):
        return None
    return GatewayInfo(
        name=str(payload.get("name") or "unnamed"),
        host=host,
        port=port,
        models=int(payload.get("models") or 0),
        pairing_open=bool(payload.get("pairing")),
    )


def _broadcast_targets(port: int) -> list[tuple[str, int]]:
    """广播地址候选：全网广播 + 各本机 IPv4 的 /24 段广播 + 本机回环。

    回环那一项看着多余，其实是测试与单机多实例的命门——广播包在本机
    送达监听者并不可靠（Windows 尤甚），直连 127.0.0.1 永远可达。
    """
    targets = {("255.255.255.255", port), ("127.0.0.1", port)}
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip.startswith("127."):
                continue
            targets.add((ip.rsplit(".", 1)[0] + ".255", port))
    except OSError:
        pass
    return sorted(targets)
