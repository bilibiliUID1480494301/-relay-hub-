"""hubrelay 高层 Python API —— 十行代码建一个中转站。

面向不想碰命令行的用户::

    import hubrelay

    st = hubrelay.Station(port=8799, master_key="rh_master")  # 建站（默认本机回环）
    print(hubrelay.scan_local())          # 1) 扫描本机推理服务（Ollama/LM Studio/...）
    st.scan_and_import()                  # 2) 扫到的一键入池
    st.add_upstream(                      #    或手动加远程上游（官方 API Key）
        base_url="https://api.example.com/v1",
        api_key="sk-xxx",
        models=["gpt-4o", "gpt-4o-mini"],
    )
    token = st.create_token("我的手机", rpm=60)   # 3) 发下游令牌（明文只显示这一次）
    st.serve()                            # 4) 起站（Ctrl+C 停）；background=True 起线程

所有函数都有中文 docstring；底层与 CLI 共用同一套号池/令牌文件，格式互通。
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from . import paths
from .gateway.localscan import LocalServer, import_to_pool, scan as _scan
from .gateway.pool import (
    PROTOCOL_ANTHROPIC,
    PROTOCOL_OPENAI_CHAT,
    KeyPool,
    UpstreamKey,
)
from .gateway.router import KeyPoolRouter
from .gateway.service import RelayServer
from .gateway.tokens import (
    SCOPE_NORMAL,
    SCOPE_TEST,
    DownstreamToken,
    TokenPool,
    TokenStore,
    generate_token,
)

__all__ = [
    "Station",
    "TokenIssued",
    "UpstreamAdded",
    "scan_local",
    "quickstart",
]


# --------------------------------------------------------------------------
# 本机扫描
# --------------------------------------------------------------------------


def scan_local(
    host: str = "127.0.0.1",
    ports: Sequence[int] | None = None,
    timeout: float = 2.0,
) -> list[LocalServer]:
    """扫描本机推理服务（Ollama / LM Studio / vLLM / llama.cpp 常用端口）。

    返回识别出的服务列表；每个元素带 .kind（如 "ollama"）、.base_url、
    .models（探测到的模型名）。扫描不到就返回空列表——不影响手动加远程上游。
    """
    return _scan(host=host, ports=list(ports) if ports else None, timeout=timeout)


@dataclass
class UpstreamAdded:
    """一次 add_upstream 的回执。"""

    label: str
    base_url: str
    models: list[str]
    pool_file: str

    def __str__(self) -> str:  # pragma: no cover - 打印友好
        return f"上游 [{self.label}] {self.base_url}  模型 {self.models or '(全部)'}"


@dataclass
class TokenIssued:
    """一次 create_token 的回执。plaintext 只在发放时出现这一次，务必保存。"""

    name: str
    plaintext: str
    models: list[str]
    rpm: int
    daily_requests: int
    tokens_file: str

    def __str__(self) -> str:  # pragma: no cover
        return f"令牌 [{self.name}] {self.plaintext[:12]}…（只显示这一次）"


# --------------------------------------------------------------------------
# Station：一座中转站
# --------------------------------------------------------------------------


class Station:
    """一座中转站 = 一个号池文件 + 一个令牌文件 + 一个端口。

    参数::

        port        监听端口（默认 8799）
        host        绑定地址；默认 127.0.0.1（仅本机）。要给局域网/公网用
                    传 "0.0.0.0"，且必须配 master_key 或至少一枚令牌（安全闸）
        master_key  管理员直连密钥（客户端 Authorization 直接用它）
        name        实例名（局域网发现与管理面展示用）
        home        数据目录；默认 ~/.local/share/relay-hub-<port>/
                    号池 pool.json、令牌 tokens.json 都放在这里，与 CLI 格式互通
    """

    def __init__(
        self,
        port: int = 8799,
        host: str = "127.0.0.1",
        master_key: str = "rh_local_dev",
        name: str = "relay-hub",
        home: str | Path | None = None,
    ) -> None:
        self.port = int(port)
        self.host = str(host)
        self.master_key = str(master_key)
        self.name = str(name)
        base = Path(home) if home else paths.relayhub_home() / f"station-{self.port}"
        base.mkdir(parents=True, exist_ok=True)
        self.home = base
        self.pool_file = base / "pool.json"
        self.tokens_file = base / "tokens.json"
        self._server: RelayServer | None = None
        self._thread: threading.Thread | None = None
        # 首次访问惰性建文件，避免空目录残留
        self._pool()  # noqa: 触发建文件
        if not self.tokens_file.exists():
            TokenPool.load(self.tokens_file).save(self.tokens_file)

    # -- 内部 ------------------------------------------------------------

    def _pool(self) -> KeyPool:
        pool = KeyPool.load(self.pool_file)
        if not self.pool_file.exists():
            pool.save(self.pool_file)
        return pool

    def _save_pool(self, pool: KeyPool) -> None:
        pool.save(self.pool_file)

    @staticmethod
    def _guess_protocol(base_url: str, protocol: str | None) -> str:
        if protocol:
            p = protocol.lower()
            if p in (PROTOCOL_ANTHROPIC, PROTOCOL_OPENAI_CHAT):
                return p
            raise ValueError(f"protocol 只支持 '{PROTOCOL_ANTHROPIC}' 或 '{PROTOCOL_OPENAI_CHAT}'，收到 {protocol!r}")
        # 猜测：anthropic 字样优先，其余（OpenAI 兼容网/本地推理）走 openai-chat
        return PROTOCOL_ANTHROPIC if "anthropic" in base_url.lower() else PROTOCOL_OPENAI_CHAT

    # -- 上游 ------------------------------------------------------------

    def add_upstream(
        self,
        base_url: str,
        api_key: str = "",
        models: Sequence[str] = (),
        protocol: str | None = None,
        label: str | None = None,
        priority: int = 0,
        weight: int = 1,
        note: str = "",
    ) -> UpstreamAdded:
        """添加一个上游渠道（远程 API Key 或自托管推理服务）。

        参数::

            base_url  上游地址，如 https://api.example.com/v1 或 http://127.0.0.1:11434
            api_key   上游密钥（sk-…）。本地 Ollama 等无需鉴权的服务可留空
            models    该渠道可用的模型名；留空 = 不限制（透传任何模型名）
            protocol  "anthropic-messages" | "openai-chat"；不传自动猜
                      （URL 含 anthropic → Anthropic 协议，否则 OpenAI 协议）
            label     渠道别名（默认自动生成）
            priority  主备优先级：数字越大越优先，主渠道全冷却后才落备
            weight    同优先级内的负载权重
        """
        pool = self._pool()
        lab = (label or "").strip() or f"up-{len(pool.keys) + 1}"
        key = UpstreamKey(
            key_id=str(uuid.uuid4()),
            label=lab,
            base_url=base_url.strip().rstrip("/"),
            api_key=api_key,
            protocol=self._guess_protocol(base_url, protocol),
            models=tuple(models),
            priority=int(priority),
            weight=int(weight),
            note=note,
        )
        pool.add(key)
        self._save_pool(pool)
        return UpstreamAdded(
            label=lab,
            base_url=key.base_url,
            models=list(key.models),
            pool_file=str(self.pool_file),
        )

    def scan_and_import(self, host: str = "127.0.0.1") -> list[UpstreamAdded]:
        """扫描本机推理服务并把扫到的一键入池（幂等：重复执行只刷新）。"""
        servers = _scan(host=host)
        if not servers:
            return []
        imported, _skipped = import_to_pool(self.pool_file, servers)
        return [
            UpstreamAdded(
                label=k.label,
                base_url=k.base_url,
                models=list(k.models),
                pool_file=str(self.pool_file),
            )
            for k in imported
        ]

    def list_upstreams(self) -> list[dict[str, Any]]:
        """当前号池里的所有上游（label/地址/模型/启用状态/用量）。"""
        return [
            {
                "label": k.label,
                "base_url": k.base_url,
                "protocol": k.protocol,
                "models": list(k.models),
                "enabled": k.enabled,
                "priority": k.priority,
                "requests": k.usage.requests,
                "ok": k.usage.ok,
                "failed": k.usage.failed,
            }
            for k in self._pool().keys
        ]

    def remove_upstream(self, label: str) -> bool:
        """按别名移除一个上游；返回是否真的删了。"""
        pool = self._pool()
        target = pool.find_by_label(label)
        if target is None:
            return False
        pool.remove(target.key_id)
        self._save_pool(pool)
        return True

    # -- 下游令牌 ---------------------------------------------------------

    def create_token(
        self,
        name: str,
        models: Sequence[str] = (),
        rpm: int = 0,
        daily_requests: int = 0,
        expires_days: float = 0,
        scope: str = SCOPE_NORMAL,
    ) -> TokenIssued:
        """发放一枚下游令牌（给手机/平板/第三方设备用的钥匙）。

        参数::

            name           设备/用途名（管理面按它区分）
            models         允许的模型白名单；空 = 不限
            rpm            每分钟请求上限；0 = 不限
            daily_requests 每日请求上限；0 = 不限
            expires_days   有效天数；0 = 永不过期
            scope          "normal"（正常）| "test"（合成应答，发第三方试水用）

        返回的 TokenIssued.plaintext 是明文令牌，**只在发放这一次可见**，
        落盘的是 SHA-256 哈希。丢了就 create_token 重发一枚。
        """
        if scope not in (SCOPE_NORMAL, SCOPE_TEST):
            raise ValueError("scope 只能是 'normal' 或 'test'")
        plain = generate_token()
        token = DownstreamToken(
            token_id=str(uuid.uuid4()),
            name=str(name).strip() or "unnamed",
            token=plain,
            models=tuple(models),
            scope=scope,
            rpm=int(rpm),
            daily_requests=int(daily_requests),
            expires_at=(expires_days * 86400 + __import__("time").time()) if expires_days else 0,
        )
        pool = TokenPool.load(self.tokens_file)
        pool.add(token)
        pool.save(self.tokens_file)
        return TokenIssued(
            name=token.name,
            plaintext=plain,
            models=list(token.models),
            rpm=token.rpm,
            daily_requests=token.daily_requests,
            tokens_file=str(self.tokens_file),
        )

    def list_tokens(self) -> list[dict[str, Any]]:
        """当前所有下游令牌（不含明文——明文只在发放时出现过）。"""
        pool = TokenPool.load(self.tokens_file)
        return [
            {
                "name": t.name,
                "hint": t.token_hint,
                "enabled": t.enabled,
                "models": list(t.models),
                "rpm": t.rpm,
                "daily_requests": t.daily_requests,
                "expired": t.is_expired(),
                "requests": t.usage.requests,
            }
            for t in pool.tokens
        ]

    # -- 起站 / 停站 ------------------------------------------------------

    def serve(self, background: bool = False, discover: bool = False, verbose: bool = False) -> str:
        """启动中转站。

        background=False（默认）：阻塞当前线程直到 Ctrl+C——脚本/Notebook 里
        请用 background=True。

        background=True：起在守护线程里，立即返回 base_url；用 .stop() 停。

        discover=True：同时开启局域网 UDP 发现（支持本协议的客户端可"扫到即连"）。
        """
        if self._server is not None:
            return self.base_url
        router = KeyPoolRouter(self._pool(), persist_path=self.pool_file)
        token_store = TokenStore(self.tokens_file)
        from .gateway import pairing as pairing_module  # 局部导入避免环

        pairing = pairing_module.PairingService(
            tokens=token_store, path=self.home / "pairing.json"
        )
        server = RelayServer(
            (self.host, self.port),
            router,
            api_key=self.master_key or None,
            tokens=token_store,
            pairing=pairing,
            verbose=verbose,
        )
        responder = None
        if discover:
            from .gateway import discovery as discovery_module

            responder = discovery_module.DiscoveryResponder(
                name=self.name,
                data_port=self.port,
                models_count=lambda: len(router.models()),
                pairing_open=pairing.window_open,
            )
            responder.start()
        self._responder = responder
        self._server = server
        if background:
            self._thread = threading.Thread(
                target=server.serve_forever, daemon=True, name=f"hubrelay-{self.port}"
            )
            self._thread.start()
        else:
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                self.stop()
        return self.base_url

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}".replace("0.0.0.0", "127.0.0.1")

    def stop(self) -> None:
        """停止后台模式起的服务（阻塞模式 Ctrl+C 会自动调它）。"""
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if getattr(self, "_responder", None) is not None:
            self._responder.stop()
            self._responder = None
        self._thread = None

    def __repr__(self) -> str:  # pragma: no cover
        state = "running" if self._server else "stopped"
        return f"<Station {self.base_url} {state}>"


# --------------------------------------------------------------------------
# 一行快开
# --------------------------------------------------------------------------


def quickstart(
    base_url: str,
    api_key: str = "",
    models: Sequence[str] = (),
    port: int = 8799,
    master_key: str = "rh_local_dev",
    background: bool = True,
) -> tuple[Station, str]:
    """最快路径：一行把「一个上游」变成「一个站」。

    ::

        st, url = hubrelay.quickstart("http://127.0.0.1:11434", models=["qwen2.5"])
        print(url, st.create_token("手机") )   # 立刻能接客户端
    """
    st = Station(port=port, master_key=master_key)
    st.add_upstream(base_url=base_url, api_key=api_key, models=models)
    url = st.serve(background=background)
    return st, url
