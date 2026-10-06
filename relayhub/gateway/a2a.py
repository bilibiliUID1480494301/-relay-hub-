# -*- coding: utf-8 -*-
"""A2A 路由：站点对外发布 agent card，task 转发到注册的下游 agent。

设计（docs/PROTOCOL-ROADMAP.md）：
  * 下游 agent 像渠道一样注册（`hubrelay a2a add <名称> <地址> [--token ...]`），
    凭证 secretbox 加密落盘。
  * `/.well-known/agent.json` 对外发布本站 agent card——skills 由注册的
    路由自动派生（一个下游 agent = 一个 skill）。
  * `POST /a2a` JSON-RPC（message/send）：按 params.agent 选择下游转发，
    请求带上与 LLM 中转相同的级联头（Via / X-Relay-Hub-Hops）——级联判环
    机制原样生效：两站互指会 508，合法链路畅通。
  * 调用方鉴权与 LLM/MCP 同一面（下游令牌）；每个 agent 身份发独立令牌，
    记账与拉黑按 agent 维度（token 名即 agent 名）。
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


@dataclass
class A2aAgent:
    """一个下游 A2A agent（另一家中转站或任何说 A2A 的 agent）。"""

    agent_id: str = ""
    name: str = ""
    url: str = ""
    token: str = ""  # 下游 agent 的接入凭证（发出去时放头里）
    description: str = ""
    enabled: bool = True
    created_at: float = 0.0


class A2aPool:
    """A2A agent 池（a2a_agents.json，secretbox 加密——token 是凭证）。"""

    def __init__(self, agents: list[A2aAgent] | None = None) -> None:
        self.agents = list(agents or [])

    @classmethod
    def load(cls, path: Path) -> "A2aPool":
        raw = secretbox.unseal(Path(path))
        if not raw:
            return cls([])
        items = raw.get("agents") or []
        return cls([A2aAgent(**{k: v for k, v in item.items()
                                if k in A2aAgent.__dataclass_fields__}) for item in items])

    def save(self, path: Path) -> None:
        secretbox.seal(
            {"schemaVersion": 1, "agents": [asdict(a) for a in self.agents]},
            path=Path(path),
        )

    def find(self, name: str) -> A2aAgent | None:
        name = name.strip().lower()
        return next((a for a in self.agents if a.name.lower() == name), None)

    def add(self, agent: A2aAgent) -> None:
        if self.find(agent.name) is not None:
            raise ValueError(f"agent 名已存在：{agent.name}")
        self.agents.append(agent)

    def remove(self, name: str) -> bool:
        agent = self.find(name)
        if agent is None:
            return False
        self.agents.remove(agent)
        return True


def agent_card(pool_path: Path, station_name: str, base_url: str) -> dict[str, Any]:
    """对外 agent card：一个注册的下游 agent = 一个 skill（A2A 语义里的能力项）。"""
    pool = A2aPool.load(pool_path)
    return {
        "name": station_name,
        "description": f"{station_name} — relay-hub A2A gateway",
        "url": base_url,
        "version": "0.6.0",
        "capabilities": {"streaming": False},
        "skills": [
            {
                "id": agent.name,
                "name": agent.name,
                "description": agent.description or f"tasks routed to {agent.url}",
            }
            for agent in pool.agents if agent.enabled
        ],
    }


def send_task(pool_path: Path, agent_name: str, task: dict[str, Any],
              cascade_headers: dict[str, str] | None = None,
              timeout: float = 120.0) -> dict[str, Any]:
    """message/send 转发。级联头原样带上（调用方已累加 Via/Hops）。"""
    pool = A2aPool.load(pool_path)
    agent = pool.find(agent_name)
    if agent is None:
        return {"jsonrpc": "2.0", "id": task.get("id"),
                "error": {"code": -32602, "message": f"未知 agent：{agent_name}"}}
    if not agent.enabled:
        return {"jsonrpc": "2.0", "id": task.get("id"),
                "error": {"code": -32602, "message": f"agent {agent.name} 已停用"}}
    request = urllib.request.Request(
        agent.url, data=json.dumps(task).encode("utf-8"), method="POST"
    )
    request.add_header("Content-Type", "application/json")
    if agent.token:
        request.add_header("Authorization", f"Bearer {agent.token}")
    for key, value in (cascade_headers or {}).items():
        request.add_header(key, value)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            text = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:200]
        return {"jsonrpc": "2.0", "id": task.get("id"),
                "error": {"code": -32603, "message": f"下游 {agent.name} HTTP {exc.code}: {detail}"}}
    except (urllib.error.URLError, TimeoutError) as exc:
        return {"jsonrpc": "2.0", "id": task.get("id"),
                "error": {"code": -32603, "message": f"下游 {agent.name} 不可达：{exc}"}}
    try:
        parsed = json.loads(text)
    except ValueError:
        return {"jsonrpc": "2.0", "id": task.get("id"),
                "error": {"code": -32700, "message": f"下游 {agent.name} 返回的不是 JSON"}}
    return parsed if isinstance(parsed, dict) else {
        "jsonrpc": "2.0", "id": task.get("id"),
        "error": {"code": -32700, "message": "下游响应不是对象"},
    }
