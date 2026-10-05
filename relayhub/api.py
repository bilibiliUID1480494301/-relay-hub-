"""hubrelay high-level Python API — build a relay station in ten lines.

::

    import hubrelay

    st = hubrelay.Station(port=8799, master_key="rh_master")  # create a station (loopback only)
    print(hubrelay.scan_local())          # 1) scan local inference servers (Ollama/LM Studio/...)
    st.scan_and_import()                  # 2) import whatever was found, one call
    st.add_upstream(                      #    ...or add a remote upstream manually
        base_url="https://api.example.com/v1",
        api_key="sk-xxx",
        models=["gpt-4o", "gpt-4o-mini"],
    )
    token = st.create_token("my-phone", rpm=60)   # 3) issue a downstream token (plaintext shown ONCE)
    st.serve()                            # 4) serve (Ctrl+C to stop); background=True for a thread

Every method is documented in English and Chinese (中文). The pool/token files are
the same format the CLI uses, so both tools stay interchangeable.

高层中文 API —— 十行代码建一个中转站；所有方法均有中英双语说明，
号池/令牌文件与 CLI 完全互通。
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from . import paths
from .doctor import run_checks as doctor
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

__version__ = "0.2.11"

__all__ = [
    "Station",
    "TokenIssued",
    "UpstreamAdded",
    "scan_local",
    "quickstart",
    "doctor",
    "__version__",
]


# --------------------------------------------------------------------------
# Local scan / 本机扫描
# --------------------------------------------------------------------------


def scan_local(
    host: str = "127.0.0.1",
    ports: Sequence[int] | None = None,
    timeout: float = 2.0,
) -> list[LocalServer]:
    """Scan local inference servers (Ollama / LM Studio / vLLM / llama.cpp).

    扫描本机推理服务，返回识别出的服务列表；每个元素带 .kind（如 "ollama"）、
    .base_url、.models（探测到的模型名）。Nothing found → empty list; manual
    remote upstreams are unaffected.

    Returns:
        List of LocalServer; empty list when nothing is running locally.
    """
    return _scan(host=host, ports=list(ports) if ports else None, timeout=timeout)


@dataclass
class UpstreamAdded:
    """Receipt of one add_upstream call / 一次 add_upstream 的回执。"""

    label: str
    base_url: str
    models: list[str]
    pool_file: str

    def __str__(self) -> str:  # pragma: no cover - print friendly
        return f"upstream [{self.label}] {self.base_url}  models {self.models or '(all)'}"


@dataclass
class TokenIssued:
    """Receipt of one create_token call / 一次 create_token 的回执。

    plaintext is shown exactly once at issue time — save it immediately.
    plaintext 只在发放时出现这一次，务必立即保存。
    """

    name: str
    plaintext: str
    models: list[str]
    rpm: int
    daily_requests: int
    tokens_file: str

    def __str__(self) -> str:  # pragma: no cover
        return f"token [{self.name}] {self.plaintext[:12]}…（shown once）"


# --------------------------------------------------------------------------
# Station: one relay station / 一座中转站
# --------------------------------------------------------------------------


class Station:
    """One relay station = a key pool file + a token file + a port.

    Args:
        port: listen port (default 8799).
        host: bind address; default ``127.0.0.1`` (local only). Use ``"0.0.0.0"``
            for LAN/public — then a master_key or at least one token is REQUIRED
            (safety gate, same as the CLI).
        master_key: admin direct-connect key clients use as Bearer credential.
        name: instance name (LAN discovery & admin console display).
        home: data directory; default ``~/.local/share/relay-hub-<port>/``.
            pool.json / tokens.json live here, same format as the CLI.
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
        self._pool()  # create files on first touch / 首次访问即建文件
        if not self.tokens_file.exists():
            TokenPool.load(self.tokens_file).save(self.tokens_file)

    # -- internal / 内部 ---------------------------------------------------

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
            raise ValueError(
                f"protocol must be '{PROTOCOL_ANTHROPIC}' or '{PROTOCOL_OPENAI_CHAT}', got {protocol!r}"
            )
        # guess: anthropic in URL → Anthropic protocol; otherwise OpenAI-compatible
        return PROTOCOL_ANTHROPIC if "anthropic" in base_url.lower() else PROTOCOL_OPENAI_CHAT

    # -- upstreams / 上游 ----------------------------------------------------

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
        """Add an upstream channel (remote API key or self-hosted server).

        Args:
            base_url: upstream address, e.g. ``https://api.example.com/v1`` or
                ``http://127.0.0.1:11434`` (Ollama).
            api_key: upstream secret (``sk-…``). Leave empty for unauthenticated
                local servers.
            models: model names this channel serves; empty = no restriction.
            protocol: ``"anthropic-messages"`` | ``"openai-chat"``; auto-guessed
                when omitted (URL contains "anthropic" → Anthropic).
            label: channel alias (auto-generated when omitted).
            priority: higher = preferred; used for primary/backup semantics.
            weight: load-balancing weight within the same priority.

        添加一个上游渠道。protocol 不传自动猜；priority 大者优先（主备语义）。
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
        """Scan local inference servers and import what was found (idempotent).

        扫描本机推理服务并一键入池；幂等：重复执行只刷新，不产生重复渠道。
        """
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
        """All upstreams with status & usage / 当前所有上游（含启用状态与用量）。"""
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
        """Remove an upstream by label; returns True when actually removed.

        按别名移除一个上游；返回是否真的删了。
        """
        pool = self._pool()
        target = pool.find_by_label(label)
        if target is None:
            return False
        pool.remove(target.key_id)
        self._save_pool(pool)
        return True

    def set_upstream_enabled(self, label: str, enabled: bool = True) -> bool:
        """Enable/disable an upstream without deleting it (backup / maintenance).

        启停一个上游（不删除）。返回是否找到并修改了该渠道。
        """
        pool = self._pool()
        target = pool.find_by_label(label)
        if target is None:
            return False
        pool.set_enabled(target.key_id, enabled)
        self._save_pool(pool)
        return True

    # -- downstream tokens / 下游令牌 ---------------------------------------

    def create_token(
        self,
        name: str,
        models: Sequence[str] = (),
        rpm: int = 0,
        daily_requests: int = 0,
        expires_days: float = 0,
        scope: str = SCOPE_NORMAL,
    ) -> TokenIssued:
        """Issue a downstream token (the key you hand to devices/third parties).

        Args:
            name: device/purpose name (shows in the admin console).
            models: model whitelist; empty = all models allowed.
            rpm: requests-per-minute cap; 0 = unlimited.
            daily_requests: per-calendar-day cap; 0 = unlimited.
            expires_days: validity in days; 0 = never expires.
            scope: ``"normal"`` (real routing) | ``"test"`` (synthetic replies,
                never touches real upstreams — safe to hand out for benchmarks).

        发放一枚下游令牌。返回的 plaintext **只在这一次可见**，落盘的是
        SHA-256 哈希；丢了就重新 create_token 一枚。
        """
        if scope not in (SCOPE_NORMAL, SCOPE_TEST):
            raise ValueError("scope must be 'normal' or 'test'")
        plain = generate_token()
        token = DownstreamToken(
            token_id=str(uuid.uuid4()),
            name=str(name).strip() or "unnamed",
            token=plain,
            models=tuple(models),
            scope=scope,
            rpm=int(rpm),
            daily_requests=int(daily_requests),
            expires_at=(expires_days * 86400 + time.time()) if expires_days else 0,
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
        """All downstream tokens (no plaintext — it is only shown once at issue).

        当前所有下游令牌（不含明文——明文只在发放时出现过一次）。
        """
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

    def remove_token(self, name: str) -> bool:
        """Revoke a token by its name (the device loses access immediately).

        按设备名吊销一枚令牌；设备即刻失去访问权。返回是否真的删了。
        """
        pool = TokenPool.load(self.tokens_file)
        target = pool.find_by_name(name)
        if target is None:
            return False
        pool.remove(target.token_id)
        pool.save(self.tokens_file)
        return True

    def set_token_enabled(self, name: str, enabled: bool = True) -> bool:
        """Temporarily enable/disable a token without revoking it.

        临时停用/恢复一枚令牌（不删除，随时可恢复）。返回是否找到并修改。
        """
        pool = TokenPool.load(self.tokens_file)
        target = pool.find_by_name(name)
        if target is None:
            return False
        pool.set_enabled(target.token_id, enabled)
        pool.save(self.tokens_file)
        return True

    def usage(self) -> dict[str, Any]:
        """Aggregate usage snapshot (upstreams + tokens) for dashboards.

        聚合用量快照（上游渠道 + 下游令牌），可直接喂给监控面板。
        """
        pool = self._pool()
        tp = TokenPool.load(self.tokens_file)
        up = {
            "channels": len(pool.keys),
            "enabled": sum(1 for k in pool.keys if k.enabled),
            "requests": sum(k.usage.requests for k in pool.keys),
            "ok": sum(k.usage.ok for k in pool.keys),
            "failed": sum(k.usage.failed for k in pool.keys),
            "tokens_in": sum(k.usage.tokens_in for k in pool.keys),
            "tokens_out": sum(k.usage.tokens_out for k in pool.keys),
        }
        down = {
            "tokens": len(tp.tokens),
            "enabled": sum(1 for t in tp.tokens if t.enabled and not t.is_expired()),
            "requests": sum(t.usage.requests for t in tp.tokens),
        }
        return {"upstream": up, "downstream": down}

    # -- serve / stop: 起站与停站 --------------------------------------------

    def serve(
        self,
        background: bool = False,
        discover: bool = False,
        verbose: bool = False,
    ) -> str:
        """Start serving.

        Args:
            background: False (default) blocks until Ctrl+C — use True inside
                scripts/notebooks, then call :meth:`stop`.
            discover: also answer LAN UDP discovery broadcasts (clients can
                "scan & connect" with zero input).
            verbose: log each request line to stdout.

        启动中转站。background=False 阻塞到 Ctrl+C；脚本里传 background=True
        再用 stop() 停。discover=True 同时开启局域网 UDP 发现（支持本协议的
        客户端可"扫到即连"）。
        """
        if self._server is not None:
            return self.base_url
        router = KeyPoolRouter(self._pool(), persist_path=self.pool_file)
        token_store = TokenStore(self.tokens_file)
        from .gateway import pairing as pairing_module  # local import to avoid cycles

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
        """Base URL of this station (0.0.0.0 reported as 127.0.0.1)."""
        return f"http://{self.host}:{self.port}".replace("0.0.0.0", "127.0.0.1")

    def stop(self) -> None:
        """Stop a background-started server (blocking mode stops via Ctrl+C).

        停止后台模式起的服务；阻塞模式 Ctrl+C 会自动调用它。
        """
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
# One-liner / 一行快开
# --------------------------------------------------------------------------


def quickstart(
    base_url: str,
    api_key: str = "",
    models: Sequence[str] = (),
    port: int = 8799,
    master_key: str = "rh_local_dev",
    background: bool = True,
) -> tuple[Station, str]:
    """Fastest path: turn ONE upstream into ONE station in a single call.

    ::

        st, url = hubrelay.quickstart("http://127.0.0.1:11434", models=["qwen2.5"])
        print(url, st.create_token("phone"))   # immediately client-ready

    一行把「一个上游」变成「一个站」，返回 (Station, base_url)。
    """
    st = Station(port=port, master_key=master_key)
    st.add_upstream(base_url=base_url, api_key=api_key, models=models)
    url = st.serve(background=background)
    return st, url
