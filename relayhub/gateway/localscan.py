"""本机大模型自动扫描：发现局域网/本机上已起的标准推理服务，一键收进号池。

「我们自己就是中转站」——本机跑的 Ollama / LM Studio / vLLM / llama.cpp 不是
二等公民，扫描到就当普通上游渠道纳入号池：轮转、熔断、用量、令牌全一样。

识别策略（保守，宁漏勿误）：
  * 先探 `{base}/v1/models`（OpenAI 兼容标准，四家全都支持）；
  * 再探 `{base}/api/tags`（Ollama 原生；Ollama 的 OpenAI 兼容层在 /v1，两者都通）;
  * 两个都答不上来的端口**不算**服务——响应形状对不上号的绝不导入，
    否则一个恰好开在 8080 的普通网页会被当成模型渠道，请求打过去全 4xx。
  * Ollama 的上下文长度 /api/tags 不给，/api/show 要逐模型再调一轮——
    值不值得由 `--deep` 决定，默认不做（扫描要快，宁可上下文空着）。

导入是幂等的：label 固定为 `local-<kind>`，重复扫描 = 覆盖刷新（模型列表变了
能跟得上），不会在号池里堆出 local-ollama-1、local-ollama-2。
"""

from __future__ import annotations

import json
import socket
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from http.client import HTTPConnection
from typing import Any
from urllib.parse import urlsplit

from .pool import PROTOCOL_OPENAI_CHAT, KeyPool, UpstreamKey

SCAN_TIMEOUT = 2.0

# (kind, 默认端口)。kind 同时决定导入后的渠道 label（local-<kind>）。
KNOWN_PORTS: tuple[tuple[str, int], ...] = (
    ("ollama", 11434),
    ("lm-studio", 1234),
    ("vllm", 8000),
    ("llamacpp", 8080),
    ("jan", 1337),
    ("textgen", 5000),
    ("sglang", 30000),
)


@dataclass
class LocalServer:
    kind: str
    base_url: str  # 不带 /v1（upstream._open 会归一化补齐）
    models: list[str] = field(default_factory=list)
    model_windows: dict[str, int] = field(default_factory=dict)
    source: str = ""  # "openai" | "ollama"——按哪个端点识别出来的
    api_key: str = ""  # 本机服务一般无鉴权；留位（LM Studio 可设 key）

    @property
    def label(self) -> str:
        return f"local-{self.kind}"


def _http_get(url: str, timeout: float) -> tuple[int, str] | None:
    """一次 GET。连接失败返回 None（端口没开/拒绝），HTTP 错误原样上抛给调用方判断。"""
    parts = urlsplit(url)
    host = parts.hostname or "127.0.0.1"
    port = parts.port or (443 if parts.scheme == "https" else 80)
    try:
        connection = HTTPConnection(host, port, timeout=timeout)
    except OSError:
        return None
    try:
        connection.request("GET", parts.path or "/", headers={"Accept": "application/json"})
        response = connection.getresponse()
        return response.status, response.read().decode("utf-8", errors="replace")[:200_000]
    except (OSError, ConnectionError):
        return None
    finally:
        connection.close()


def _extract_models_openai(payload: dict) -> tuple[list[str], dict[str, int]]:
    models: list[str] = []
    windows: dict[str, int] = {}
    for item in payload.get("data") or []:
        if not isinstance(item, dict):
            continue
        model_id = str(item.get("id") or "").strip()
        if not model_id:
            continue
        models.append(model_id)
        window = item.get("context_window") or item.get("max_model_len") or item.get("context_length")
        if window:
            windows[model_id] = int(window)
    return models, windows


def _extract_models_ollama(payload: dict) -> list[str]:
    return [str(item.get("name")) for item in payload.get("models") or [] if item.get("name")]


def probe(base_url: str, kind: str = "openai", timeout: float = SCAN_TIMEOUT) -> LocalServer | None:
    """探测一个 base URL 是不是标准推理服务。不是则返回 None。"""
    server = LocalServer(kind=kind, base_url=base_url.rstrip("/"))
    result = _http_get(f"{server.base_url}/v1/models", timeout)
    if result is not None and result[0] == 200:
        try:
            payload = json.loads(result[1])
        except json.JSONDecodeError:
            payload = None
        if isinstance(payload, dict):
            models, windows = _extract_models_openai(payload)
            if models:
                server.models, server.model_windows, server.source = models, windows, "openai"
                return server

    result = _http_get(f"{server.base_url}/api/tags", timeout)
    if result is not None and result[0] == 200:
        try:
            payload = json.loads(result[1])
        except json.JSONDecodeError:
            return None
        if isinstance(payload, dict):
            models = _extract_models_ollama(payload)
            if models:
                # 只有 Ollama 家族才有 /api/tags：kind 修正为 ollama，
                # 否则随机端口上发现的 Ollama 会被挂个 openai 的名字
                server.kind = "ollama"
                server.models, server.source = models, "ollama"
                return server
    return None


def scan(
    host: str = "127.0.0.1",
    *,
    ports: list[int] | None = None,
    timeout: float = SCAN_TIMEOUT,
) -> list[LocalServer]:
    """并行扫一组端口，返回识别出的服务（按端口排序）。"""
    candidates = ports if ports else [port for _, port in KNOWN_PORTS]
    kind_by_port = {port: kind for kind, port in KNOWN_PORTS}

    def _probe_one(port: int) -> LocalServer | None:
        base = f"http://{host}:{port}"
        try:
            return probe(base, kind_by_port.get(port, "openai"), timeout)
        except (OSError, ValueError):
            return None

    with ThreadPoolExecutor(max_workers=min(16, max(1, len(candidates)))) as pool:
        results = list(pool.map(_probe_one, candidates))
    return [server for server in results if server is not None]


def import_to_pool(
    pool_path: Any,
    servers: list[LocalServer],
    *,
    replace: bool = True,
) -> tuple[list[UpstreamKey], list[str]]:
    """把扫描结果收进号池。返回 (导入的渠道, 跳过原因列表)。

    幂等：同 label（local-<kind>）覆盖刷新。判定「是不是我们导的」看 note
    标记（"自动扫描"前缀）而不是 label——用户自己起个 local-ollama 的名字
    也尊重，绝不覆盖手工渠道。
    """
    pool = KeyPool.load(pool_path)
    imported: list[UpstreamKey] = []
    skipped: list[str] = []
    for server in servers:
        existing = pool.find_by_label(server.label)
        if existing is not None:
            ours = existing.note.startswith("自动扫描")
            if not (replace and ours):
                reason = (
                    "已存在，--import 覆盖需 --replace" if not replace else "手工渠道，不覆盖"
                )
                skipped.append(f"{server.label}（{reason}）")
                continue
            pool.remove(server.label)
        key = UpstreamKey(
            key_id=str(uuid.uuid4()),
            label=server.label,
            base_url=server.base_url,
            api_key=server.api_key,
            protocol=PROTOCOL_OPENAI_CHAT,
            models=tuple(server.models),
            model_windows=dict(server.model_windows),
            note=f"自动扫描（{server.source}）",
        )
        try:
            pool.add(key)
        except Exception as exc:  # PoolError：撞 label 等，如实跳过
            skipped.append(f"{server.label}（{exc}）")
            continue
        imported.append(key)
    if imported:
        pool.save(pool_path)
    return imported, skipped


def host_is_local(host: str) -> bool:
    """只有回环地址才允许默认扫描：全网段扫描是另一件事，必须显式提供网段。"""
    return host in ("127.0.0.1", "localhost", "::1")


def port_alive(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False
