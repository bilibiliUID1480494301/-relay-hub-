# -*- coding: utf-8 -*-
"""MCP 网关：中转站对下游说 MCP（JSON-RPC 2.0），上游接入 MCP server 渠道。

设计（docs/PROTOCOL-ROADMAP.md）：
  * 上游 MCP server 像模型渠道一样入池（`hubrelay mcp add <名称> <地址>`），
    凭证头随渠道存（secretbox 加密落盘——与号池同一纪律）。
  * 下游看到的工具名带渠道前缀（`<渠道>.<工具>`）：两家上游暴露同名工具
    也不冲突，前缀即路由。
  * `tools/call` 按下游令牌 × 渠道双维记账（reqlog），与 LLM 调用同一纪律。
  * JSON-RPC 2.0 over HTTP，纯标准库 urllib 转发；上游不支持的方法原样
    透传错误（id 对齐），下游拿到的错误形态与直连上游一致。
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .. import paths
from . import secretbox

JSONRPC_PARSE_ERROR = -32700
JSONRPC_METHOD_NOT_FOUND = -32601
JSONRPC_INTERNAL_ERROR = -32603

MCP_PROTOCOL_VERSION = "2024-11-05"


@dataclass
class McpChannel:
    """一个上游 MCP server 渠道。headers 携带上游要求的鉴权头。"""

    channel_id: str = ""
    name: str = ""
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    enabled: bool = True
    created_at: float = 0.0


class McpChannelPool:
    """MCP 渠道池（mcp_channels.json，secretbox 加密——headers 可能有凭证）。"""

    def __init__(self, channels: list[McpChannel] | None = None) -> None:
        self.channels = list(channels or [])

    @classmethod
    def load(cls, path: Path) -> "McpChannelPool":
        raw = secretbox.unseal(Path(path))
        if not raw:
            return cls([])
        items = raw.get("channels") or []
        return cls([McpChannel(**{k: v for k, v in item.items()
                                 if k in McpChannel.__dataclass_fields__}) for item in items])

    def save(self, path: Path) -> None:
        secretbox.seal(
            {"schemaVersion": 1, "channels": [asdict(c) for c in self.channels]},
            path=Path(path),
        )

    def find(self, name: str) -> McpChannel | None:
        name = name.strip().lower()
        return next((c for c in self.channels if c.name.lower() == name), None)

    def add(self, channel: McpChannel) -> None:
        if self.find(channel.name) is not None:
            raise ValueError(f"渠道名已存在：{channel.name}")
        self.channels.append(channel)

    def remove(self, name: str) -> bool:
        channel = self.find(name)
        if channel is None:
            return False
        self.channels.remove(channel)
        return True

    def enabled(self) -> list[McpChannel]:
        return [c for c in self.channels if c.enabled]


def _rpc(method: str, params: dict[str, Any] | None = None, rpc_id: int | str = 1) -> dict[str, Any]:
    payload: dict[str, Any] = {"jsonrpc": "2.0", "id": rpc_id, "method": method}
    if params is not None:
        payload["params"] = params
    return payload


def _post_rpc(channel: McpChannel, payload: dict[str, Any], timeout: float = 60.0) -> dict[str, Any]:
    """向上游 MCP server 发一条 JSON-RPC，返回其响应（含 error 字段的可能）。"""
    request = urllib.request.Request(
        channel.url, data=json.dumps(payload).encode("utf-8"), method="POST"
    )
    request.add_header("Content-Type", "application/json")
    request.add_header("Accept", "application/json, text/event-stream")
    for key, value in (channel.headers or {}).items():
        request.add_header(key, value)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:200]
        return {"jsonrpc": "2.0", "id": payload.get("id"),
                "error": {"code": JSONRPC_INTERNAL_ERROR,
                          "message": f"上游 {channel.name} HTTP {exc.code}: {detail}"}}
    # 有的 server 用 SSE 包 JSON-RPC 响应（data: 行）；把 data: 行剥出来。
    text = raw.strip()
    if text.startswith("event:") or "\ndata:" in text or text.startswith("data:"):
        for line in reversed(text.splitlines()):
            if line.startswith("data:"):
                text = line[5:].strip()
                break
    try:
        parsed = json.loads(text)
    except ValueError:
        return {"jsonrpc": "2.0", "id": payload.get("id"),
                "error": {"code": JSONRPC_PARSE_ERROR,
                          "message": f"上游 {channel.name} 返回的不是 JSON"}}
    return parsed if isinstance(parsed, dict) else {
        "jsonrpc": "2.0", "id": payload.get("id"),
        "error": {"code": JSONRPC_PARSE_ERROR, "message": "上游响应不是对象"},
    }


def _split_prefixed(tool: str, pool_path: Path) -> tuple[McpChannel | None, str, str]:
    """`渠道.工具` → (渠道, 真名, 错误信息)。找不到渠道时渠道为 None。"""
    if "." not in tool:
        return None, tool, f"工具名必须形如 <渠道>.<工具>，收到：{tool!r}"
    channel_name, real = tool.split(".", 1)
    channel = McpChannelPool.load(pool_path).find(channel_name)
    if channel is None:
        return None, real, f"未知 MCP 渠道：{channel_name}"
    return channel, real, ""


def list_tools(pool_path: Path) -> dict[str, Any]:
    """聚合所有启用渠道的 tools/list，工具名加渠道前缀。单个上游挂了不拖垮整体。"""
    tools: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    for channel in McpChannelPool.load(pool_path).enabled():
        response = _post_rpc(channel, _rpc("tools/list"))
        if "error" in response:
            errors.append({"channel": channel.name, "error": response["error"]})
            continue
        for item in response.get("result", {}).get("tools", []) or []:
            entry = dict(item)
            entry["name"] = f"{channel.name}.{item.get('name', '')}"
            entry["_channel"] = channel.name
            tools.append(entry)
    return {"tools": tools, "errors": errors}


def call_tool(pool_path: Path, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """转发 tools/call。返回 (result, channel_name)；channel_name 供记账。"""
    channel, real, error = _split_prefixed(name, pool_path)
    if channel is None:
        return {"jsonrpc": "2.0", "id": None,
                "error": {"code": JSONRPC_METHOD_NOT_FOUND, "message": error}}, ""
    response = _post_rpc(channel, _rpc("tools/call", {"name": real, "arguments": arguments}))
    return response, channel.name
