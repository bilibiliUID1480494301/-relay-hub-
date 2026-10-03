"""号池管理面：本地网页，独立进程 + 独立端口。

**为什么独立进程**：管理面能改号池，等于能改上游凭证；推理面只是发请求。
两者同进程的话，网关的一个鉴权漏洞就直接等于号池沦陷。分开跑，网关被打穿也不牵连管理面。

两边只共享一个 `pool.json`：管理面改完立刻写盘，网关侧 `ReloadingRouter` 的配置指纹
一变就热加载，所以改 Key 不用重启网关、不会掐断正在答题的客户端。

安全边界（都是刻意的）：
  * 默认只绑回环地址；要绑非回环地址**必须**显式给 `--token`，否则拒绝启动。
  * **上游 Key 是只写的**：读接口一律只回尾 4 位，明文永不进浏览器。
    编辑时留空 = 不改这把 Key（免得为了改个名字把密钥重新贴一遍，也免得它出现在浏览器历史里）。
  * 探活接口会真的发一次上游请求，**会消耗一点额度**，所以只由用户手动点，不做自动轮询。
  * 管理面不做合法审查：`pool add` 加什么渠道是使用者的取舍。这里只做运维。
"""

from __future__ import annotations

import argparse
import hmac
import json
import secrets
import sys
import threading
import time
import uuid
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, unquote, urlsplit

from .. import paths
from . import audit as audit_module
from . import reqlog as reqlog_module
from . import upstream
from .policy import KIND_DEVICE, KIND_IP, PolicyError, PolicyStore
from .users import RedeemStore, UserError, UserPool, hash_password
from .pool import (
    DEFAULT_TIER_DURATIONS,
    is_self_reference,
    PROTOCOL_ANTHROPIC,
    PROTOCOL_OPENAI_CHAT,
    STRATEGIES,
    KeyPool,
    PoolError,
    UpstreamKey,
    key_from_spec,
)
from .tokens import DownstreamToken, TokenError, TokenPool, generate_token
from .upstream import UpstreamError

ADMIN_HEADER = "X-Admin-Token"
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}
SESSION_COOKIE = "rh_admin_session"
SESSION_TTL = 86400.0

# 登录页：只在设置了 token 的管理面上出现；回环信任模式直接进面板。
LOGIN_HTML = """<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>relay-hub 管理面登录</title>
<style>
 body{font-family:system-ui,sans-serif;display:flex;justify-content:center;padding-top:18vh;background:#111;color:#eee}
 form{background:#1c1c1e;padding:2rem 2.5rem;border-radius:12px;min-width:320px}
 h1{font-size:1.1rem;margin:0 0 1rem}
 input{width:100%;padding:.5rem;margin:.4rem 0 1rem;border-radius:8px;border:1px solid #444;background:#111;color:#eee;box-sizing:border-box}
 button{width:100%;padding:.55rem;border:0;border-radius:8px;background:#3b82f6;color:#fff;font-size:1rem}
 .err{color:#f87171;min-height:1.2em;font-size:.85rem}
</style></head><body>
<form onsubmit="return doLogin()">
 <h1>relay-hub 号池管理</h1>
 <label>管理面 token</label>
 <input id="token" type="password" autofocus>
 <div class="err" id="err"></div>
 <button type="submit">登录</button>
</form>
<script>
async function doLogin(){
  const r = await fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({token:document.getElementById('token').value})});
  if(r.ok){location.href='/';return false;}
  document.getElementById('err').textContent = r.status===401 ? 'token 不正确' : ('登录失败：HTTP '+r.status);
  return false;
}
</script></body></html>"""


def is_loopback(host: str) -> bool:
    return host.strip().lower() in LOOPBACK_HOSTS


def key_hint(api_key: str) -> str:
    if not api_key:
        return "<无>"
    return f"…{api_key[-4:]}" if len(api_key) > 4 else "…"


def public_key(key: UpstreamKey, now: float) -> dict[str, Any]:
    """给浏览器看的 Key 视图。**永远不含 api_key 明文。**"""
    return {
        "key_id": key.key_id,
        "priority": key.priority,
        "model_mapping": key.model_mapping,
        "label": key.label,
        "protocol": key.protocol,
        "base_url": key.base_url,
        "models": list(key.models),
        "model_windows": dict(key.model_windows),
        "weight": key.weight,
        "note": key.note,
        "enabled": key.enabled,
        "available": key.is_available(now),
        "cooling_down_for": round(key.cooling_down_for(now), 1),
        "cooldown_tier": key.cooldown_tier,
        "credits": key.credits,
        "consecutive_failures": key.consecutive_failures,
        "last_error": key.last_error,
        "key_hint": key_hint(key.api_key),
        "has_key": bool(key.api_key),
        "usage": asdict(key.usage),
    }


def probe_key(key: UpstreamKey, model: str | None = None, timeout: float = 15.0) -> dict[str, Any]:
    """对单个渠道发一次最小请求，确认它现在能不能用。

    **会消耗一点上游额度**（max_tokens=1）。只由用户手动触发。
    """
    chosen = model or (key.models[0] if key.models else "probe")
    payload: dict[str, Any] = {
        "model": chosen,
        "max_tokens": 1,
        "messages": [{"role": "user", "content": "ping"}],
    }
    started = time.monotonic()
    try:
        reply = upstream.call_once(key, payload, timeout)
    except UpstreamError as exc:
        return {
            "ok": False,
            "status": exc.status,
            "error": exc.detail,
            "ms": round((time.monotonic() - started) * 1000, 1),
            "retryable": exc.retryable,
        }
    text = ""
    for block in reply.message.get("content") or []:
        if isinstance(block, dict) and block.get("type") == "text":
            text += str(block.get("text") or "")
    return {
        "ok": True,
        "status": 200,
        "ms": round((time.monotonic() - started) * 1000, 1),
        "text": text[:200],
        "tokens_in": reply.tokens_in,
        "tokens_out": reply.tokens_out,
    }


def _parse_model_tokens(text: str) -> tuple[list[str], dict[str, int]]:
    """接受 "glm-5.2:1000000, qwen3-32b" 或换行分隔。"""
    models: list[str] = []
    windows: dict[str, int] = {}
    for token in (text or "").replace("\n", ",").split(","):
        model_id, _, ctx = token.partition(":")
        model_id = model_id.strip()
        if not model_id:
            continue
        models.append(model_id)
        if ctx.strip():
            windows[model_id] = int(ctx)
    return models, windows


def _parse_mapping_text(text: str) -> dict[str, str] | None:
    """解析模型映射文本：'对外名=上游名'，逗号或换行分隔。空文本 = 无映射。

    格式错（缺 '='）返回 None 让调用方回 400，而不是静默丢掉半截映射。
    """
    mapping: dict[str, str] = {}
    for token in (text or "").replace("\n", ",").split(","):
        if not token.strip():
            continue
        public, _, up = token.partition("=")
        if not public.strip() or not up.strip():
            return None
        mapping[public.strip()] = up.strip()
    return mapping


def _apply_user_settings(
    pool: UserPool,
    *,
    allow_register=None,
    default_quota=None,
    price_in=None,
    price_out=None,
    groups=None,
) -> None:
    """计费规则/注册开关的 PUT 应用。None = 不改。"""
    if allow_register is not None:
        pool.allow_register = bool(allow_register)
    if default_quota is not None:
        pool.default_quota = max(0, int(default_quota))
    if price_in is not None:
        pool.price_in_per_1k = max(0.0, float(price_in))
    if price_out is not None:
        pool.price_out_per_1k = max(0.0, float(price_out))
    if groups is not None and isinstance(groups, dict):
        cleaned = {str(k).strip(): max(0.0, float(v)) for k, v in groups.items() if str(k).strip()}
        if cleaned:
            pool.groups = cleaned


class AdminHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "relayhub-admin/0.1"

    # -- 基础设施 --------------------------------------------------------

    @property
    def pool_path(self) -> Path:
        return self.server.pool_path  # type: ignore[attr-defined]

    @property
    def token(self) -> str | None:
        return self.server.token  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:
        if self.server.verbose:  # type: ignore[attr-defined]
            super().log_message(fmt, *args)

    def _send_json(self, status: int, payload: Any) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _send_html(self, html: str) -> None:
        raw = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _error(self, status: int, message: str) -> None:
        self._send_json(status, {"error": message})

    def _authorized(self) -> bool:
        if not self.token:
            return True
        supplied = self.headers.get(ADMIN_HEADER, "")
        if not supplied:
            query = parse_qs(urlsplit(self.path).query)
            supplied = (query.get("token") or [""])[0]
        if supplied and hmac.compare_digest(supplied, self.token):
            return True
        # 登录会话：浏览器登录一次后用 HttpOnly cookie，免去把 token 长期挂在 URL 里
        return self._session_valid()

    # -- 登录会话 ----------------------------------------------------------

    def _session_valid(self) -> bool:
        """校验 Cookie 里的会话 id。会话表在 AdminServer 内存里，重启即失效。"""
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            name, _, value = part.strip().partition("=")
            if name != SESSION_COOKIE or not value:
                continue
            sessions = self.server.sessions  # type: ignore[attr-defined]
            expires = sessions.get(value)
            if expires is None:
                return False
            if time.time() >= expires:
                with self.server.session_lock:  # type: ignore[attr-defined]
                    sessions.pop(value, None)
                return False
            return True
        return False

    def _start_session(self) -> str:
        sid = secrets.token_urlsafe(24)
        sessions = self.server.sessions  # type: ignore[attr-defined]
        with self.server.session_lock:  # type: ignore[attr-defined]
            now = time.time()
            for key in [k for k, exp in sessions.items() if exp <= now]:
                sessions.pop(key, None)
            sessions[sid] = now + SESSION_TTL
        return sid

    def _end_session(self) -> None:
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            name, _, value = part.strip().partition("=")
            if name == SESSION_COOKIE and value:
                with self.server.session_lock:  # type: ignore[attr-defined]
                    self.server.sessions.pop(value, None)  # type: ignore[attr-defined]

    def _login(self) -> None:
        """POST /login：管理面令牌换一个会话 cookie（网页「登录」）。"""
        if not self.token:
            self._error(400, "本管理面未设置 token（回环信任模式），无需登录")
            return
        body = self._read_json()
        if body is None:
            return
        supplied = str(body.get("token") or "")
        if not supplied or not hmac.compare_digest(supplied, self.token):
            self._error(401, "token 不正确")
            return
        sid = self._start_session()
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header(
            "Set-Cookie",
            f"{SESSION_COOKIE}={sid}; HttpOnly; Path=/; SameSite=Strict; Max-Age={int(SESSION_TTL)}",
        )
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")

    def _logout(self) -> None:
        self._end_session()
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header(
            "Set-Cookie", f"{SESSION_COOKIE}=; HttpOnly; Path=/; SameSite=Strict; Max-Age=0"
        )
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")

    def _read_json(self) -> dict[str, Any] | None:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._error(400, "Content-Length 非法")
            return None
        raw = self.rfile.read(length) if length else b""
        try:
            parsed = json.loads(raw.decode("utf-8") or "{}")
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            self._error(400, f"请求体不是合法 JSON：{exc}")
            return None
        if not isinstance(parsed, dict):
            self._error(400, "请求体必须是 JSON 对象")
            return None
        return parsed

    # -- 号池读写 --------------------------------------------------------

    def _state(self) -> dict[str, Any]:
        now = time.time()
        pool = KeyPool.load(self.pool_path)
        return {
            "pool_path": str(self.pool_path),
            "exists": self.pool_path.is_file(),
            "strategy": pool.strategy,
            "strategies": list(STRATEGIES),
            "failure_threshold": pool.failure_threshold,
            "cooldown_tiers": pool.cooldown_tiers,
            "protocols": [PROTOCOL_ANTHROPIC, PROTOCOL_OPENAI_CHAT],
            "totals": asdict(pool.totals()),
            "keys": [public_key(key, now) for key in pool.keys],
        }

    def _mutate(self, change: Callable[[KeyPool], Any]) -> Any:
        """读盘 → 改 → 写回，并留下审计。

        读盘而不是用内存副本，是为了别把网关刚写进去的用量抹掉。
        窗口只有「读」到「写」之间那几微秒，最坏情况是丢掉一个请求的计数增量，
        不会丢 Key——所以这里不做跨进程锁，但要知道这个取舍。

        审计只记 method + 路由，**不记请求体**：加/改渠道的 body 里有上游 Key
        明文，审计文件是明文 JSONL，把密钥抄进去就制造了一个新的泄露面。
        """
        pool = KeyPool.load(self.pool_path)
        result = change(pool)
        pool.save(self.pool_path)
        audit_module.record(
            "pool.mutate",
            path=self.server.audit_path,  # type: ignore[attr-defined]
            method=self.command,
            route=self.path.split("?")[0],
        )
        return result

    def _find(self, pool: KeyPool, identifier: str) -> UpstreamKey | None:
        return pool.get(identifier) or pool.find_by_label(identifier)

    # -- 路由 ------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path.rstrip("/") or "/"
        if path == "/":
            # 页面本身不含密钥，但仍要求凭证，免得内网里谁都能看到号池结构。
            # 设置了 token 时，未登录的浏览器拿到的是登录页而不是裸 401。
            if not self._authorized():
                if self.token:
                    self._send_html(LOGIN_HTML)
                    return
                self._error(401, "缺少或错误的 token（?token=… 或 X-Admin-Token）")
                return
            self._send_html(PAGE_HTML)
            return
        if path == "/api/state":
            if not self._authorized():
                self._error(401, "缺少或错误的 token")
                return
            self._send_json(200, self._state())
            return
        read_routes = {
            "/api/clients": self._clients_state,
            "/api/tokens": self._tokens_state,
            "/api/users": self._users_state,
            "/api/codes": self._codes_state,
            "/api/requests": self._requests_state,
            "/api/usage": self._usage_state,
            "/api/audit": self._audit_state,
            "/api/policy": lambda: self.server.policy.state(),
        }
        if path in read_routes:
            if not self._authorized():
                self._error(401, "缺少或错误的 token")
                return
            self._send_json(200, read_routes[path]())
            return
        self._error(404, f"未知路径 {self.path}")

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path.rstrip("/")
        if path == "/login":
            self._login()
            return
        if path == "/logout":
            self._logout()
            return
        self._handle("POST")

    def do_PUT(self) -> None:  # noqa: N802
        self._handle("PUT")

    def do_DELETE(self) -> None:  # noqa: N802
        self._handle("DELETE")

    def _handle(self, method: str) -> None:
        if not self._authorized():
            self._error(401, "缺少或错误的 token")
            return
        parts = [unquote(segment) for segment in urlsplit(self.path).path.strip("/").split("/")]
        # 期望形态：api / keys [ / <id> [ / probe ] ] | api / settings
        known = parts[:2] in (
            ["api", "keys"], ["api", "tokens"],
            ["api", "users"], ["api", "codes"], ["api", "policy"],
        ) or parts in (
            ["api", "settings"],
        )
        if not known:
            self._error(404, f"未知路径 {self.path}")
            return

        if parts == ["api", "policy"]:
            if method == "GET":
                self._send_json(200, self.server.policy.state())
                return
            if method == "POST":
                self._mutate_policy()
                return
            self._error(405, "策略：GET 查看 / POST 设置")
            return
        if parts == ["api", "settings"]:
            if method != "PUT":
                self._error(405, "设置只支持 PUT")
                return
            self._update_settings()
            return
        if parts[:2] == ["api", "tokens"]:
            self._handle_tokens(method, parts)
            return
        if parts[:2] == ["api", "users"]:
            self._handle_users(method, parts)
            return
        if parts[:2] == ["api", "codes"]:
            self._handle_codes(method, parts)
            return
        if len(parts) == 2:
            if method != "POST":
                self._error(405, "添加渠道用 POST /api/keys")
                return
            self._add_key()
            return
        identifier = parts[2]
        if len(parts) == 4 and parts[3] == "probe":
            if method != "POST":
                self._error(405, "探活用 POST /api/keys/<id>/probe")
                return
            self._probe(identifier)
            return
        if len(parts) != 3:
            self._error(404, f"未知路径 {self.path}")
            return
        if method == "PUT":
            self._update_key(identifier)
        elif method == "DELETE":
            self._delete_key(identifier)
        else:
            self._error(405, f"{method} 不支持")

    # -- 各动作 ----------------------------------------------------------

    def _add_key(self) -> None:
        body = self._read_json()
        if body is None:
            return
        if not str(body.get("base_url") or "").strip():
            self._error(400, "缺少 base_url")
            return
        models, windows = _parse_model_tokens(str(body.get("models_text") or ""))
        if is_self_reference(str(body.get("base_url") or "")):
            self._error(400, "base_url 指向本网关自己——这会构成转发自环，已拒绝")
            return
        mapping = _parse_mapping_text(str(body.get("mapping_text") or ""))
        if mapping is None:
            self._error(400, "模型映射格式不合法，期望 '对外名=上游名' 用逗号分隔")
            return
        try:
            key = key_from_spec(
                {
                    "base_url": body.get("base_url"),
                    "api_key": body.get("api_key") or "",
                    "protocol": body.get("protocol") or PROTOCOL_ANTHROPIC,
                    "label": body.get("label"),
                    "models": models,
                    "model_windows": windows,
                    "model_mapping": mapping,
                    "priority": int(body.get("priority") or 0),
                    "note": body.get("note") or "",
                }
            )
        except (PoolError, ValueError) as exc:
            self._error(400, f"参数不合法：{exc}")
            return

        def change(pool: KeyPool) -> None:
            if pool.find_by_label(key.label):
                raise PoolError(f"名称已存在：{key.label}")
            pool.add(key)

        try:
            self._mutate(change)
        except PoolError as exc:
            self._error(409, str(exc))
            return
        self._send_json(200, self._state())

    def _update_key(self, identifier: str) -> None:
        body = self._read_json()
        if body is None:
            return
        # api_key 留空 = 不改。这样改个名字不需要重新贴一遍密钥。
        new_secret = str(body.get("api_key") or "")
        models_text = body.get("models_text")
        models: list[str] | None = None
        windows: dict[str, int] = {}
        if models_text is not None:
            models, windows = _parse_model_tokens(str(models_text))

        def change(pool: KeyPool) -> None:
            key = self._find(pool, identifier)
            if key is None:
                raise PoolError(f"找不到渠道 {identifier}")
            if body.get("label") is not None and str(body["label"]).strip():
                wanted = str(body["label"]).strip()
                clash = pool.find_by_label(wanted)
                if clash is not None and clash.key_id != key.key_id:
                    raise PoolError(f"名称已被占用：{wanted}")
                key.label = wanted
            if body.get("protocol"):
                key.protocol = str(body["protocol"])
            if body.get("base_url"):
                key.base_url = str(body["base_url"]).strip()
            if new_secret:
                key.api_key = new_secret
            if models is not None:
                key.models = tuple(models)
                key.model_windows = windows
            if body.get("mapping_text") is not None:
                mapping = _parse_mapping_text(str(body["mapping_text"]))
                if mapping is None:
                    self._error(400, "模型映射格式不合法，期望 '对外名=上游名' 用逗号分隔")
                    return
                key.model_mapping = mapping
            if body.get("priority") is not None:
                key.priority = int(body["priority"] or 0)
            if body.get("note") is not None:
                key.note = str(body["note"])
            if body.get("weight") is not None:
                key.weight = int(body["weight"])
            if body.get("enabled") is not None:
                enabled = bool(body["enabled"])
                key.enabled = enabled
                if enabled:
                    key.consecutive_failures = 0
                    key.disabled_until = 0.0
                    pool.config_epoch += 1
            # 手动重置熔断：让一个被判冷却的渠道立刻重新参与。
            # 冷却态是 serve 内存里的东西，config_epoch 自增才能让它热加载到清理后的文件。
            if body.get("reset_breaker"):
                key.consecutive_failures = 0
                key.disabled_until = 0.0
                key.last_error = ""
                pool.config_epoch += 1

        try:
            self._mutate(change)
        except (PoolError, ValueError) as exc:
            self._error(409 if "找不到" not in str(exc) else 404, str(exc))
            return
        self._send_json(200, self._state())

    def _delete_key(self, identifier: str) -> None:
        def change(pool: KeyPool) -> None:
            if not pool.remove(identifier):
                raise PoolError(f"找不到渠道 {identifier}")

        try:
            self._mutate(change)
        except PoolError as exc:
            self._error(404, str(exc))
            return
        self._send_json(200, self._state())

    def _update_settings(self) -> None:
        body = self._read_json()
        if body is None:
            return
        try:
            strategy = str(body.get("strategy") or "")
            threshold = int(body.get("failure_threshold") or 0)
            raw_tiers = body.get("cooldown_tiers") or {}
            if not isinstance(raw_tiers, dict):
                raise ValueError("cooldown_tiers 必须是对象")
            tiers = {}
            for name in sorted(DEFAULT_TIER_DURATIONS):
                seconds = float(raw_tiers.get(name) or 0)
                if seconds <= 0:
                    raise ValueError(f"{name} 档冷却秒数必须 > 0")
                tiers[name] = seconds
            if strategy not in STRATEGIES:
                raise ValueError(f"策略只能是 {list(STRATEGIES)}")
            if threshold < 1:
                raise ValueError("熔断阈值必须 >= 1")
        except (TypeError, ValueError) as exc:
            self._error(400, f"参数不合法：{exc}")
            return

        def change(pool: KeyPool) -> None:
            pool.strategy = strategy
            pool.failure_threshold = threshold
            pool.cooldown_tiers.update(tiers)

        self._mutate(change)
        self._send_json(200, self._state())


    def _probe(self, identifier: str) -> None:
        pool = KeyPool.load(self.pool_path)
        key = self._find(pool, identifier)
        if key is None:
            self._error(404, f"找不到渠道 {identifier}")
            return
        body = self._read_json() or {}
        model = str(body.get("model") or "") or None
        self._send_json(200, {"label": key.label, **probe_key(key, model, timeout=15.0)})

    # -- 统一控制台：令牌 / 平台账号 / 请求 / 用量 / 审计 / 任务 ------------

    def _tokens_state(self) -> dict[str, Any]:
        return {
            "path": str(self.server.tokens_path),  # type: ignore[attr-defined]
            "tokens": TokenPool.load(self.server.tokens_path).stats()["tokens"],  # type: ignore[attr-defined]
        }

    # -- 接入策略（拉黑 / 优先队列） ----------------------------------------

    def _mutate_policy(self) -> None:
        """POST /api/policy：{kind, value, blocked?, priority?, note?, action}。

        action=set（默认）新增/更新；action=remove 移除。改完立即落盘，
        网关数据面按指纹热加载，下一请求即生效。
        """
        body = self._read_json() or {}
        kind = str(body.get("kind") or "")
        value = str(body.get("value") or "").strip()
        policy: PolicyStore = self.server.policy  # type: ignore[attr-defined]
        action = str(body.get("action") or "set")
        try:
            if action == "remove":
                if not policy.remove(kind, value):
                    self._error(404, f"策略里没有 {value}")
                    return
                audit_module.record(
                    "policy.remove", kind=kind, value=value,
                    path=self.server.audit_path,  # type: ignore[attr-defined]
                )
            else:
                entry = policy.set(
                    kind,
                    value,
                    blocked=body.get("blocked"),
                    priority=body.get("priority"),
                    note=str(body.get("note") or "") or None,
                )
                audit_module.record(
                    "policy.set", kind=kind, value=value,
                    blocked=entry.blocked, priority=entry.priority,
                    path=self.server.audit_path,  # type: ignore[attr-defined]
                )
        except PolicyError as exc:
            self._error(400, str(exc))
            return
        self._send_json(200, policy.state())

    # -- 用户 / 兑换码 / 计费规则 ------------------------------------------

    def _users_state(self) -> dict[str, Any]:
        pool = UserPool.load(self.server.users_path)  # type: ignore[attr-defined]
        return {
            "path": str(self.server.users_path),  # type: ignore[attr-defined]
            "allow_register": pool.allow_register,
            "default_quota": pool.default_quota,
            "price_in_per_1k": pool.price_in_per_1k,
            "price_out_per_1k": pool.price_out_per_1k,
            "groups": pool.groups,
            "users": [
                {
                    "user_id": u.user_id,
                    "username": u.username,
                    "role": u.role,
                    "enabled": u.enabled,
                    "quota": u.quota,
                    "used": u.used,
                    "group": u.group,
                    "note": u.note,
                }
                for u in pool.users
            ],
        }

    def _codes_state(self) -> dict[str, Any]:
        codes = self.server.redeem_store.list()  # type: ignore[attr-defined]
        return {"codes": [c.to_dict() for c in codes]}

    def _handle_users(self, method: str, parts: list[str]) -> None:
        users_path = self.server.users_path  # type: ignore[attr-defined]
        if len(parts) == 2:
            if method == "POST":
                body = self._read_json() or {}

                def add(pool: UserPool) -> None:
                    user = pool.register(
                        str(body.get("username") or ""), str(body.get("password") or "")
                    )
                    user.quota = int(body.get("quota") if body.get("quota") is not None else pool.default_quota)
                    if str(body.get("group") or "").strip():
                        user.group = str(body["group"]).strip()
                    if body.get("note"):
                        user.note = str(body["note"])

                try:
                    self._mutate_users(add)
                except UserError as exc:
                    self._error(409, str(exc))
                    return
                self._send_json(200, self._users_state())
                return
            if method == "PUT":
                body = self._read_json() or {}
                self._mutate_users(
                    lambda pool: _apply_user_settings(
                        pool, allow_register=body.get("allow_register"),
                        default_quota=body.get("default_quota"),
                        price_in=body.get("price_in_per_1k"),
                        price_out=body.get("price_out_per_1k"),
                        groups=body.get("groups"),
                    )
                )
                self._send_json(200, self._users_state())
                return
            self._error(405, "用 POST 建用户 / PUT 改计费设置")
            return
        if len(parts) != 3:
            self._error(404, f"未知路径 {self.path}")
            return
        target = parts[2]

        def _with_user(change) -> None:
            def inner(pool: UserPool) -> None:
                user = pool.get(target) or pool.find_by_name(target)
                if user is None:
                    raise UserError(f"找不到用户 {target}")
                change(user)

            self._mutate_users(inner)

        if method == "PUT":
            body = self._read_json() or {}
            changes = []

            def apply(user: User) -> None:
                if "enabled" in body:
                    user.enabled = bool(body["enabled"])
                    changes.append(f"enabled={user.enabled}")
                if body.get("quota") is not None:
                    user.quota = int(body["quota"])
                    changes.append(f"quota={user.quota}")
                if body.get("add_quota") is not None:
                    add = int(body["add_quota"])
                    user.quota = user.quota if user.quota < 0 else user.quota + add
                    changes.append(f"quota+={add}")
                if body.get("group"):
                    user.group = str(body["group"]).strip()
                    changes.append(f"group={user.group}")
                if body.get("password"):
                    user.password_hash = hash_password(str(body["password"]))
                    changes.append("password=重置")

            try:
                _with_user(apply)
            except UserError as exc:
                self._error(404, str(exc))
                return
            audit_module.record(
                "user.update", path=self.server.audit_path,  # type: ignore[attr-defined]
                user=target, changes=",".join(changes),
            )
            self._send_json(200, self._users_state())
            return
        if method == "DELETE":
            def remove(pool: UserPool) -> None:
                user = pool.get(target) or pool.find_by_name(target)
                if user is None:
                    raise UserError(f"找不到用户 {target}")
                pool.users.remove(user)

            try:
                self._mutate_users(remove)
            except UserError as exc:
                self._error(404, str(exc))
                return
            audit_module.record(
                "user.remove", path=self.server.audit_path,  # type: ignore[attr-defined]
                user=target,
            )
            self._send_json(200, self._users_state())
            return
        self._error(405, f"{method} 不支持")

    def _mutate_users(self, change) -> None:
        users_path = self.server.users_path  # type: ignore[attr-defined]
        with self.server.user_lock:  # type: ignore[attr-defined]
            pool = UserPool.load(users_path)
            change(pool)
            pool.save(users_path)

    def _handle_codes(self, method: str, parts: list[str]) -> None:
        if method == "POST" and len(parts) == 2:
            body = self._read_json() or {}
            try:
                count = max(1, min(100, int(body.get("count") or 1)))
                credits = max(1, int(body.get("credits") or 100))
            except (TypeError, ValueError):
                self._error(400, "count / credits 必须是正整数")
                return
            fresh = self.server.redeem_store.generate(count, credits)  # type: ignore[attr-defined]
            audit_module.record(
                "codes.generate", path=self.server.audit_path,  # type: ignore[attr-defined]
                count=count, credits=credits,
            )
            # 明文兑换码只此一次回给管理员
            self._send_json(200, {"codes": [c.to_dict() for c in fresh]})
            return
        self._error(405, "兑换码只支持 POST /api/codes 生成")

    def _handle_tokens(self, method: str, parts: list[str]) -> None:
        tokens_path = self.server.tokens_path  # type: ignore[attr-defined]
        if len(parts) == 2:
            if method != "POST":
                self._error(405, "发放令牌用 POST /api/tokens")
                return
            body = self._read_json()
            if body is None:
                return
            name = str(body.get("name") or "").strip()
            if not name:
                self._error(400, "缺少设备名 name")
                return
            models = [m.strip() for m in str(body.get("models_text") or "").split(",") if m.strip()]
            scope = str(body.get("scope") or "normal")
            if scope not in ("normal", "test"):
                self._error(400, f"未知 scope {scope!r}，可选 normal / test")
                return
            try:
                rpm = max(0, int(body.get("rpm") or 0))
                daily = max(0, int(body.get("daily_requests") or 0))
                days = max(0, int(body.get("days") or 0))
            except (TypeError, ValueError):
                self._error(400, "rpm / daily_requests / days 必须是非负整数")
                return
            secret = generate_token()
            pool = TokenPool.load(tokens_path)
            try:
                pool.add(
                    DownstreamToken(
                        token_id=str(uuid.uuid4()),
                        name=name,
                        token=secret,
                        models=tuple(models),
                        scope=scope,
                        rpm=rpm,
                        daily_requests=daily,
                        expires_at=(time.time() + days * 86400) if days > 0 else 0.0,
                        note=str(body.get("note") or ""),
                        group=str(body.get("group") or "default"),
                    )
                )
            except TokenError as exc:
                self._error(409, str(exc))
                return
            pool.save(tokens_path)
            audit_module.record(
                "token.add",
                path=self.server.audit_path,  # type: ignore[attr-defined]
                name=name,
                token_hint=key_hint(secret),
                models=models,
                scope=scope,
                rpm=rpm,
                daily_requests=daily,
            )
            # 明文只此一次：回给创建者，列表接口永远只有尾 4 位
            self._send_json(200, {"token": secret, "tokens": pool.stats()["tokens"]})
            return
        if len(parts) != 3:
            self._error(404, f"未知路径 {self.path}")
            return
        identifier = parts[2]
        pool = TokenPool.load(tokens_path)
        record = (
            pool.get(identifier)
            or pool.find_by_name(identifier)
            or next((t for t in pool.tokens if t.token == identifier), None)
        )
        if record is None:
            self._error(404, f"找不到令牌 {identifier}")
            return
        if method == "PUT":
            body = self._read_json() or {}
            changed = []
            if "enabled" in body:
                pool.set_enabled(record.token_id, bool(body["enabled"]))
                changed.append(f"enabled={bool(body['enabled'])}")
            # 限额/作用域可热改：写盘后网关令牌热加载立刻生效，不用重发令牌。
            if "rpm" in body:
                try:
                    record.rpm = max(0, int(body["rpm"] or 0))
                    changed.append(f"rpm={record.rpm}")
                except (TypeError, ValueError):
                    self._error(400, "rpm 必须是非负整数")
                    return
            if "daily_requests" in body:
                try:
                    record.daily_requests = max(0, int(body["daily_requests"] or 0))
                    changed.append(f"daily={record.daily_requests}")
                except (TypeError, ValueError):
                    self._error(400, "daily_requests 必须是非负整数")
                    return
            if "scope" in body:
                if body["scope"] not in ("normal", "test"):
                    self._error(400, "scope 只能是 normal / test")
                    return
                record.scope = str(body["scope"])
                changed.append(f"scope={record.scope}")
            if changed:
                pool.save(tokens_path)
                # 只动 enabled 时沿用历史事件名 token.toggle（既有审计/测试的契约）；
                # 带限额/作用域的改动才是 token.update。
                is_toggle_only = changed == [f"enabled={bool(body['enabled'])}"]
                audit_module.record(
                    "token.toggle" if is_toggle_only else "token.update",
                    path=self.server.audit_path,  # type: ignore[attr-defined]
                    name=record.name,
                    changes=",".join(changed),
                )
            self._send_json(200, self._tokens_state())
            return
        if method == "DELETE":
            pool.remove(record.token_id)
            pool.save(tokens_path)
            audit_module.record(
                "token.remove",
                path=self.server.audit_path,  # type: ignore[attr-defined]
                name=record.name,
            )
            self._send_json(200, self._tokens_state())
            return
        self._error(405, f"{method} 不支持")


    def _requests_state(self) -> dict[str, Any]:
        query = parse_qs(urlsplit(self.path).query)
        limit = min(int((query.get("limit") or ["100"])[0] or 100), 2000)
        entries = reqlog_module.tail(self.server.requests_log_path, limit=limit * 4)  # type: ignore[attr-defined]
        token_filter = (query.get("token") or [""])[0]
        model_filter = (query.get("model") or [""])[0]
        ident_user_filter = (query.get("ident_user") or [""])[0]
        if token_filter:
            entries = [e for e in entries if e.get("token") == token_filter]
        if model_filter:
            entries = [e for e in entries if e.get("model") == model_filter]
        if ident_user_filter:
            # 客户端身份过滤：用户名/设备号模糊匹配，排障「这个用户今天都发了什么」
            needle = ident_user_filter.lower()
            entries = [
                e for e in entries
                if needle in str(e.get("ident_user") or "").lower()
                or needle in str(e.get("ident_did") or "").lower()
                or needle in str(e.get("ident_dev") or "").lower()
            ]
        return {"path": str(self.server.requests_log_path), "entries": entries[-limit:]}  # type: ignore[attr-defined]

    def _clients_state(self) -> dict[str, Any]:
        """客户端总览：把请求日志聚合成「谁、哪台设备、用了多少」的人话视图。

        来源判定：日志行带任一 sm_* 字段 = 客户端 App（客户端身份头）；
        否则 = 直连 API（第三方 SDK / curl）。聚合维度：App 按
        (令牌, 用户, 设备, 设备 ID)，直连按 (令牌, IP)——这样管理台
        一眼分清两类流量，再不用去原始请求表里翻。
        """
        entries = reqlog_module.tail(self.server.requests_log_path, limit=200_000)  # type: ignore[attr-defined]
        now = time.time()
        day_start = time.mktime(time.strptime(time.strftime("%Y-%m-%d"), "%Y-%m-%d"))
        groups: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
        for e in entries:
            token_name = str(e.get("token") or "-")
            user = str(e.get("ident_user") or "")
            dev = str(e.get("ident_dev") or "")
            did = str(e.get("ident_did") or "")
            ip = str(e.get("ip") or "")
            is_app = bool(user or dev or did)
            key = (
                (token_name, user, dev, did, "")
                if is_app
                else (token_name, "", "", "", ip)
            )
            g = groups.get(key)
            if g is None:
                g = groups[key] = {
                    "source": "app" if is_app else "api",
                    "token": token_name,
                    "user": user,
                    "device": dev,
                    "device_id": did,
                    "ver": str(e.get("ident_ver") or ""),
                    "last_ip": ip,
                    "last_ts": 0.0,
                    "last_model": "",
                    "today": 0,
                    "total": 0,
                    "failed": 0,
                    "tokens_in": 0,
                    "tokens_out": 0,
                    "models": {},
                }
            ts = float(e.get("ts") or 0)
            g["total"] += 1
            if not e.get("ok"):
                g["failed"] += 1
            g["tokens_in"] += int(e.get("tokens_in") or 0)
            g["tokens_out"] += int(e.get("tokens_out") or 0)
            if ts >= day_start:
                g["today"] += 1
            if ts > g["last_ts"]:
                g["last_ts"] = ts
                g["last_model"] = str(e.get("model") or "")
                if ip:
                    g["last_ip"] = ip
            model = str(e.get("model") or "")
            if model:
                g["models"][model] = g["models"].get(model, 0) + 1
        clients: list[dict[str, Any]] = []
        for g in groups.values():
            g["online"] = bool(g["last_ts"] and now - g["last_ts"] <= 120)
            g["top_models"] = [
                m for m, _ in sorted(g["models"].items(), key=lambda kv: -kv[1])[:3]
            ]
            del g["models"]
            clients.append(g)
        clients.sort(key=lambda c: -c["last_ts"])
        app_devices = sum(1 for c in clients if c["source"] == "app")
        return {
            "clients": clients,
            "summary": {
                "app_devices": app_devices,
                "api_sources": len(clients) - app_devices,
                "online": sum(1 for c in clients if c["online"]),
                "today_requests": sum(c["today"] for c in clients),
                "app_requests_today": sum(
                    c["today"] for c in clients if c["source"] == "app"
                ),
            },
        }

    def _usage_state(self) -> dict[str, Any]:
        query = parse_qs(urlsplit(self.path).query)
        days = (query.get("days") or [None])[0]
        entries = reqlog_module.tail(self.server.requests_log_path, limit=200_000)  # type: ignore[attr-defined]
        if days:
            cutoff = time.time() - float(days) * 86400
            entries = [e for e in entries if float(e.get("ts") or 0) >= cutoff]
        summary = reqlog_module.summarize(entries)
        pool = KeyPool.load(self.pool_path)
        return {
            "days": days,
            "requests": summary,
            "channels": asdict(pool.totals()),
            "tokens": TokenPool.load(self.server.tokens_path).stats()["tokens"],  # type: ignore[attr-defined]
        }

    def _audit_state(self) -> dict[str, Any]:
        query = parse_qs(urlsplit(self.path).query)
        limit = min(int((query.get("limit") or ["100"])[0] or 100), 1000)
        return {
            "path": str(self.server.audit_path),  # type: ignore[attr-defined]
            "entries": audit_module.tail(self.server.audit_path, limit=limit),  # type: ignore[attr-defined]
        }



class AdminServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request: Any, client_address: tuple[str, int]) -> None:
        """客户端半途掐连接（预览器/探活脚本常见）只值得一行日志，不值得整段堆栈刷屏。"""
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionResetError, ConnectionAbortedError, TimeoutError)):
            if getattr(self, "verbose", False):
                self.log_message("客户端断开 %s: %r", client_address, exc)
            return
        super().handle_error(request, client_address)

    def __init__(
        self,
        address: tuple[str, int],
        pool_path: Path,
        token: str | None = None,
        verbose: bool = False,
        audit_path: Path | None = None,
        tokens_path: Path | None = None,
        requests_log_path: Path | None = None,
    ) -> None:
        # 绑非回环地址却不要凭证 = 把号池管理面挂到内网上，先拦下来。
        if not is_loopback(address[0]) and not token:
            raise ValueError(
                f"绑定非回环地址 {address[0]} 时必须给 --token："
                "否则号池管理面等于对内网完全开放（能改上游凭证）。"
            )
        super().__init__(address, AdminHandler)
        self.pool_path = Path(pool_path)
        self.token = token
        self.verbose = verbose
        self.audit_path = audit_path or paths.audit_path()
        # 统一控制台的数据面：令牌 / 请求明细（默认走标准数据根）
        self.tokens_path = tokens_path or paths.tokens_path()
        self.requests_log_path = requests_log_path or paths.requests_log_path()
        # 接入策略（IP/设备 拉黑与优先名单）：与网关数据面共享同一文件，
        # 控制台改完网关下一请求即生效（PolicyStore 指纹热加载）
        self.policy = PolicyStore(paths.policy_path())
        # 用户体系（公网用户/额度/兑换码）。users.json 不存在 = 未开放注册的空池。
        self.users_path = paths.users_path()
        self.redeem_store = RedeemStore(paths.redeem_codes_path())
        self.user_lock = threading.Lock()
        # 登录会话表（内存态）：重启即全体下线——对管理面是特性不是缺陷
        self.sessions: dict[str, float] = {}
        self.session_lock = threading.Lock()


    @property
    def url(self) -> str:
        host, port = self.server_address[0], self.server_address[1]
        return f"http://{host}:{port}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="relayhub.gateway admin",
        description="号池管理面（本地网页，独立进程 + 独立端口）",
    )
    parser.add_argument("--pool", type=Path, default=None, help="号池文件（默认与网关同一个）")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8801)
    parser.add_argument(
        "--token",
        default=None,
        help="管理面凭证；绑非回环地址时必填。页面用 ?token=… 打开",
    )
    parser.add_argument("--open", action="store_true", dest="open_browser", help="启动后自动打开浏览器")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass

    pool_path = args.pool or paths.pool_path()
    if not pool_path.is_file():
        # 先建一个空的，免得第一眼看到的是 500
        KeyPool([]).save(pool_path)

    try:
        server = AdminServer((args.host, args.port), pool_path, args.token, args.verbose)
    except ValueError as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 2

    suffix = f"?token={args.token}" if args.token else ""
    url = f"{server.url}/{suffix}"
    print(f"号池管理面：{url}")
    print(f"号池文件：{pool_path}")
    print("改完即写盘；网关侧会热加载，不用重启、不掐断客户端。Ctrl+C 停止。")
    if args.open_browser:
        import webbrowser

        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止。")
    finally:
        server.server_close()
    return 0


PAGE_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>中转站控制台</title>
<style>
:root{--bg:#F7F6F3;--panel:#FFFFFF;--fg:#26215C;--muted:#5F5E5A;--line:#E3E1DA;
--accent:#185FA5;--accent-soft:#E6F1FB;--ok:#0F6E56;--ok-soft:#E1F5EE;--warn:#854F0B;
--warn-soft:#FAEEDA;--bad:#A32D2D;--bad-soft:#FCEBEB}
@media(prefers-color-scheme:dark){:root{--bg:#1B1B19;--panel:#242422;--fg:#E8E6E0;
--muted:#A5A29A;--line:#3A3A37;--accent:#85B7EB;--accent-soft:#1E2A38;--ok:#5DCAA5;
--ok-soft:#122A22;--warn:#EF9F27;--warn-soft:#33260E;--bad:#F09595;--bad-soft:#331A1A}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:13px/1.6 -apple-system,"Segoe UI","Microsoft YaHei",system-ui,sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:24px 20px 60px}
header{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap;margin-bottom:18px}
h1{font-size:15px;font-weight:500;margin:0}
h2{font-size:14px;font-weight:500;margin:0 0 12px}
.meta{color:var(--muted);font-size:12px;font-family:ui-monospace,Consolas,monospace}
.spacer{flex:1}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;
padding:16px;margin-bottom:14px;box-shadow:0 1px 2px rgba(38,33,92,.04)}
.cards{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;
padding:12px 16px;min-width:132px;transition:box-shadow .15s ease,transform .15s ease}
.card:hover{box-shadow:0 3px 10px rgba(38,33,92,.10);transform:translateY(-1px)}
.card b{display:block;font-size:19px;font-weight:500;margin-top:2px}
.card span{color:var(--muted);font-size:12px}
.row{display:flex;gap:14px;align-items:flex-end;flex-wrap:wrap}
label{display:flex;flex-direction:column;gap:4px;color:var(--muted);font-size:12px}
input,select,textarea{background:var(--bg);color:var(--fg);border:1px solid var(--line);
border-radius:8px;padding:6px 9px;font:inherit;min-width:120px}
input:focus,select:focus,textarea:focus{outline:none;border-color:var(--accent)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}
.grid .wide{grid-column:1/-1}
button{background:var(--accent-soft);color:var(--accent);border:1px solid var(--accent);
border-radius:8px;padding:6px 12px;font:inherit;cursor:pointer;transition:opacity .12s ease}
button:hover{opacity:.82}
button.ghost{background:transparent;border-color:var(--line);color:var(--muted)}
button.danger{background:var(--bad-soft);border-color:var(--bad);color:var(--bad)}
button[disabled]{opacity:.45;cursor:not-allowed}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);
vertical-align:top;font-size:12px}
th{color:var(--muted);font-weight:500;white-space:nowrap}
td.mono,.mono{font-family:ui-monospace,Consolas,monospace}
tbody tr{transition:background .12s ease}
tbody tr:hover{background:var(--accent-soft)}
tr:last-child td{border-bottom:none}
.tag{display:inline-block;padding:1px 7px;border-radius:999px;font-size:11px;white-space:nowrap}
.t-ok{background:var(--ok-soft);color:var(--ok)}
.t-warn{background:var(--warn-soft);color:var(--warn)}
.t-bad{background:var(--bad-soft);color:var(--bad)}
.t-off{background:var(--bg);color:var(--muted)}
.ops{display:flex;gap:6px;flex-wrap:wrap}
.ops button{padding:3px 9px;font-size:12px}
.hint{color:var(--muted);font-size:12px;margin:10px 0 0}
.tabs{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:14px}
.tabs button{border-radius:999px}
.tabs button.active{background:var(--accent);color:#fff;border-color:var(--accent)}
.pane{display:none}
#toast{position:sticky;bottom:12px;margin-top:14px;padding:10px 14px;border-radius:8px;
display:none;border:1px solid var(--line);background:var(--panel)}
#toast.ok{border-color:var(--ok);color:var(--ok)}
#toast.err{border-color:var(--bad);color:var(--bad)}
.err{color:var(--bad);font-size:11px;max-width:280px;word-break:break-word}
.t-app{background:var(--accent-soft);color:var(--accent);font-weight:600}
.t-api{background:var(--bg);color:var(--muted);border:1px solid var(--line)}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px;vertical-align:baseline}
.dot.on{background:var(--ok);box-shadow:0 0 0 3px var(--ok-soft)}
.dot.off{background:var(--line)}
.tabs .gap{width:12px;flex:none}
</style>
</head>
<body>
<div class="wrap">
<header>
  <h1>中转站控制台</h1>
  <div class="meta" id="meta"></div>
  <div class="spacer"></div>
  <label style="flex-direction:row;align-items:center;gap:6px">
    <input type="checkbox" id="auto" checked style="min-width:auto"> 自动刷新
  </label>
  <button class="ghost" id="refresh">刷新</button>
</header>

<nav class="tabs" id="tabs">
  <button data-tab="clients">客户端</button>
  <span class="gap"></span>
  <button data-tab="pool" class="active">渠道</button>
  <button data-tab="tokens">下游令牌</button>
  <button data-tab="policy">接入策略</button>
  <span class="gap"></span>
  <span class="gap"></span>
  <button data-tab="users">用户</button>
  <span class="gap"></span>
  <button data-tab="requests">请求</button>
  <button data-tab="usage">用量</button>
  <button data-tab="audit">审计</button>
</nav>

<div class="pane" id="pane-clients" style="display:none">
<section class="cards" id="cl-cards"></section>
<section class="panel">
  <h2>接入客户端</h2>
  <p class="hint">App 流量按「客户端身份+ 设备」聚合；没有身份头的按直连 API 令牌聚合。
  在线 = 最近 2 分钟有请求。这里是所有接入方的总账，请求明细在「请求」页。</p>
  <div style="overflow-x:auto"><table>
    <thead><tr><th>来源</th><th>用户 / 令牌</th><th>设备</th><th>设备 ID</th><th>版本</th>
    <th>最近 IP</th><th>状态</th><th>今日请求</th><th>累计（失败）</th><th>tokens</th>
    <th>常用模型</th><th>最近活跃</th></tr></thead>
    <tbody id="cl-rows"></tbody>
  </table></div>
</section>
</div>

<div class="pane" id="pane-pool" style="display:none">

<section class="cards" id="cards"></section>

<section class="panel">
  <h2>调度与熔断</h2>
  <div class="row">
    <label>调度策略 <select id="strategy"></select></label>
    <label>连续失败阈值 <input type="number" id="threshold" min="1" step="1" style="min-width:88px"></label>
    <label>plan 冷却秒 <input type="number" id="tier-plan" min="1" step="1" style="min-width:76px"></label>
    <label>soft 冷却秒 <input type="number" id="tier-soft" min="1" step="1" style="min-width:76px"></label>
    <label>err 冷却秒 <input type="number" id="tier-err" min="1" step="1" style="min-width:76px"></label>
    <button id="save-settings">保存</button>
  </div>
  <p class="hint">改动立刻写盘，网关会热加载——不用重启，也不会掐断正在答题的客户端。
  四档冷却里 disable 不在此列：它没有时长，是 401/403 触发的禁用，只能人工 enable 恢复。</p>
</section>

<section class="panel">
  <h2 id="form-title">添加渠道</h2>
  <div class="grid">
    <label>名称 <input id="f-label" placeholder="留空则自动生成"></label>
    <label>上游协议 <select id="f-protocol"></select></label>
    <label class="wide">Base URL <input id="f-base-url" placeholder="http://127.0.0.1:8000"></label>
    <label class="wide">上游 Key <input id="f-api-key" type="password"
      placeholder="可留空（自建无鉴权）；编辑时留空表示不改动"></label>
    <label class="wide">模型 <input id="f-models"
      placeholder="glm-5.2:1000000, qwen3-32b　（留空 = 对全部模型开放）"></label>
    <label class="wide">模型映射 <input id="f-mapping"
      placeholder="对外名=上游名, 如 glm-5.2=[满血]GLM-5.2　（留空 = 不映射）"></label>
    <label>优先级 <input id="f-priority" type="number" step="1" placeholder="0"></label>
    <label class="wide">备注 <input id="f-note"></label>
  </div>
  <div class="row" style="margin-top:12px">
    <button id="submit">保存</button>
    <button class="ghost" id="cancel" hidden>取消编辑</button>
  </div>
  <p class="hint">上游 Key 只写不读：页面永远只显示尾 4 位，明文不会回到浏览器。
  优先级越大越优先（高优先级全灭才落到低优先级）；映射让客户端只用干净模型名。</p>
</section>

<section class="panel">
  <h2>渠道</h2>
  <div style="overflow-x:auto"><table>
    <thead><tr><th>名称</th><th>协议</th><th>状态</th><th>模型</th><th>用量</th>
    <th>Key</th><th>操作</th></tr></thead>
    <tbody id="rows"></tbody>
  </table></div>
  <p class="hint">探活会真的发一次上游请求（max_tokens=1），会消耗一点额度，所以只在你点的时候跑。</p>
</section>

</div>

<div class="pane" id="pane-tokens" style="display:none">
<section class="panel">
  <h2>发放下游令牌</h2>
  <div class="row">
    <label>设备名 <input id="t-name" placeholder="教室平板-01"></label>
    <label>分组 <input id="t-group" placeholder="default（如 class-2 / vip）"></label>
    <label>模型限制 <input id="t-models" placeholder="逗号分隔；留空 = 不限制"></label>
    <label>作用域 <select id="t-scope">
      <option value="normal">normal（真实模型）</option>
      <option value="test">test（合成应答，公网性能测试）</option>
    </select></label>
    <label>RPM <input id="t-rpm" type="number" min="0" step="1" placeholder="0=不限"></label>
    <label>日配额 <input id="t-daily" type="number" min="0" step="1" placeholder="0=不限"></label>
    <label>有效期(天) <input id="t-days" type="number" min="0" step="1" placeholder="0=永久"></label>
    <label>备注 <input id="t-note"></label>
    <button id="t-add">发放</button>
  </div>
  <div id="t-new" style="display:none" class="panel" style="margin-top:12px">
    <b>新令牌明文（只显示这一次）：</b>
    <div class="mono" id="t-new-token" style="margin-top:6px;word-break:break-all"></div>
  </div>
  <p class="hint">每台设备一枚；吊销后该设备立刻 401。serve 不重启即可识别新令牌。
  公网模式给第三方只发 test 令牌：应答是本地合成的（带 [relay-hub test-echo] 标签），
  不碰真实模型、不烧渠道配额；RPM/日配额按受理计数，超了回 429。</p>
</section>
<section class="panel">
  <h2>下游令牌</h2>
  <div style="overflow-x:auto"><table>
    <thead><tr><th>设备</th><th>分组</th><th>状态</th><th>作用域</th><th>模型限制</th><th>限额</th><th>用量</th><th>最近来源（客户端身份）</th><th>令牌</th><th>操作</th></tr></thead>
    <tbody id="t-rows"></tbody>
  </table></div>
  <p class="hint">分组筛选：
    <select id="t-filter" style="min-width:130px"><option value="">全部分组</option></select>
    （发放时填了分组的令牌可按组筛选/汇总，适合按班级/批次管理）</p>
</section>
</div>


<div class="pane" id="pane-users" style="display:none">
<section class="panel">
  <h2>计费规则</h2>
  <div class="row">
    <label>开放注册 <select id="u-register"><option value="0">关闭</option><option value="1">开放</option></select></label>
    <label>注册送额度 <input id="u-default" type="number" min="0" step="1" style="min-width:90px"></label>
    <label>输入 价/1k tokens <input id="u-price-in" type="number" min="0" step="0.1" style="min-width:100px"></label>
    <label>输出 价/1k tokens <input id="u-price-out" type="number" min="0" step="0.1" style="min-width:100px"></label>
    <label>分组倍率 <input id="u-groups" placeholder='default=1, vip=0.5'></label>
    <button id="u-save-settings">保存规则</button>
  </div>
  <p class="hint">成本 = (输入/1k×输入价 + 输出/1k×输出价) × 分组倍率，向上取整，成功才扣。
  额度单位是「点」。关闭注册后 /panel 的注册入口消失，仍可在此手工建号。</p>
</section>
<section class="panel">
  <h2>添加用户</h2>
  <div class="row">
    <label>用户名 <input id="u-name" placeholder="3-32 字符"></label>
    <label>密码 <input id="u-pass" type="password" placeholder="至少 8 位"></label>
    <label>初始额度 <input id="u-quota" type="number" step="1" placeholder="默认=注册送额度"></label>
    <label>分组 <input id="u-group" placeholder="default"></label>
    <button id="u-add">创建</button>
  </div>
</section>
<section class="panel">
  <h2>兑换码</h2>
  <div class="row">
    <label>生成数量 <input id="c-count" type="number" min="1" max="100" value="1" style="min-width:80px"></label>
    <label>每张面额 <input id="c-credits" type="number" min="1" value="100" style="min-width:80px"></label>
    <button id="c-gen">生成</button>
  </div>
  <div class="mono" id="c-new" style="margin-top:10px;word-break:break-all"></div>
  <div style="overflow-x:auto"><table style="margin-top:10px">
    <thead><tr><th>兑换码</th><th>面额</th><th>状态</th></tr></thead>
    <tbody id="c-rows"></tbody>
  </table></div>
</section>
<section class="panel">
  <h2>用户</h2>
  <div style="overflow-x:auto"><table>
    <thead><tr><th>用户名</th><th>状态</th><th>分组</th><th>额度/已用</th><th>操作</th></tr></thead>
    <tbody id="u-rows"></tbody>
  </table></div>
</section>
</div>


<div class="pane" id="pane-policy" style="display:none">
<section class="panel">
  <h2>接入策略（拉黑 / 优先队列）</h2>
  <p class="hint">拉黑：该 IP / 设备立即 403（设备按客户端身份头里的设备 ID 或令牌名匹配）。
  优先：并发排队时 VIP 插队。改动即时落盘，网关下一请求生效，无需重启。</p>
  <div class="row" style="margin-top:10px">
    <label>类型 <select id="p-kind"><option value="ip">IP</option><option value="device">设备</option></select></label>
    <label>值 <input id="p-value" placeholder="1.2.3.4 或 设备ID/令牌名"></label>
    <label>动作 <select id="p-flag"><option value="blocked">拉黑</option><option value="priority">优先</option></select></label>
    <label>备注 <input id="p-note" placeholder="为什么（可选）"></label>
    <button id="p-add">应用</button>
  </div>
  <div class="grid" style="margin-top:12px">
    <div><h2>IP 策略</h2><table><thead><tr><th>IP</th><th>状态</th><th>备注</th><th>操作</th></tr></thead>
      <tbody id="p-ip-rows"></tbody></table></div>
    <div><h2>设备策略</h2><table><thead><tr><th>设备（ID / 令牌名）</th><th>状态</th><th>备注</th><th>操作</th></tr></thead>
      <tbody id="p-dev-rows"></tbody></table></div>
  </div>
</section>
</div>

<div class="pane" id="pane-requests" style="display:none">
<section class="panel">
  <h2>请求明细</h2>
  <div class="row">
    <label>来源 <select id="r-source"><option value="">全部</option><option value="app">App 客户端</option><option value="api">直连 API</option></select></label>
    <label>令牌 <input id="r-token" placeholder="按设备过滤"></label>
    <label>客户端用户 <input id="r-user" placeholder="按客户端身份过滤"></label>
    <label>模型 <input id="r-model" placeholder="按模型过滤"></label>
    <label>条数 <select id="r-limit"><option>50</option><option selected>200</option><option>500</option></select></label>
    <button id="r-load">查询</button>
  </div>
  <div style="overflow-x:auto;margin-top:10px"><table>
    <thead><tr><th>时间</th><th>结果</th><th>来源</th><th>令牌</th><th>客户端身份</th><th>模型</th><th>渠道</th><th>tokens</th><th>耗时</th><th>IP</th><th>归因</th></tr></thead>
    <tbody id="r-rows"></tbody>
  </table></div>
  <p class="hint">只记元数据，不含对话内容。明细落在 RELAYHUB_HOME\requests.jsonl。</p>
</section>
</div>

<div class="pane" id="pane-usage" style="display:none">
<section class="panel">
  <h2>用量统计</h2>
  <div class="row">
    <label>窗口 <select id="u-days"><option value="">全部</option><option value="1">最近 1 天</option><option value="7" selected>最近 7 天</option><option value="30">最近 30 天</option></select></label>
    <button id="u-load">刷新</button>
  </div>
  <section class="cards" id="u-cards" style="margin-top:12px"></section>
  <div class="grid">
    <div><h2>按令牌</h2><table><tbody id="u-token"></tbody></table></div>
    <div><h2>按分组</h2><table><tbody id="u-group"></tbody></table></div>
    <div><h2>按模型</h2><table><tbody id="u-model"></tbody></table></div>
    <div><h2>按渠道</h2><table><tbody id="u-channel"></tbody></table></div>
  </div>
  <h2 style="margin-top:12px">按日</h2>
  <table><tbody id="u-day"></tbody></table>
</section>
</div>

<div class="pane" id="pane-audit" style="display:none">
<section class="panel">
  <h2>操作审计</h2>
  <div class="row">
    <label>条数 <select id="al-limit"><option>100</option><option>300</option></select></label>
    <button id="al-load">刷新</button>
  </div>
  <div style="overflow-x:auto;margin-top:10px"><table>
    <thead><tr><th>时间</th><th>事件</th><th>详情</th></tr></thead>
    <tbody id="al-rows"></tbody>
  </table></div>
  <p class="hint">覆盖配对、令牌变动、号池管理动作与手动任务；不记请求体（含密钥明文的字段一律不落审计）。</p>
</section>
</div>

<div id="toast"></div>
</div>
<script>
var state=null,editing=null,toastTimer=null;
var token=new URLSearchParams(location.search).get('token')||'';

function api(method,path,body){
  var opt={method:method,headers:{}};
  if(token){opt.headers['X-Admin-Token']=token;}
  if(body!==undefined){opt.headers['Content-Type']='application/json';
    opt.body=JSON.stringify(body);}
  return fetch(path,opt).then(function(r){
    return r.text().then(function(t){
      var data={};try{data=t?JSON.parse(t):{};}catch(e){data={error:t};}
      if(!r.ok){throw new Error(data.error||('HTTP '+r.status));}
      return data;
    });
  });
}

function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){
  return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}

function toast(msg,ok){
  var el=document.getElementById('toast');
  el.textContent=msg;el.className=ok?'ok':'err';el.style.display='block';
  clearTimeout(toastTimer);
  toastTimer=setTimeout(function(){el.style.display='none';},4200);
}

function statusTag(k){
  if(!k.enabled){
    return k.cooldown_tier==='disable'
      ? '<span class="tag t-off">已禁用(鉴权失效)</span>'
      : '<span class="tag t-off">已禁用</span>';
  }
  if(!k.available){return '<span class="tag t-warn">冷却['+k.cooldown_tier+'] '+k.cooling_down_for+'s</span>';}
  if(k.consecutive_failures>0){return '<span class="tag t-warn">可用 · 连败 '+k.consecutive_failures+'</span>';}
  return '<span class="tag t-ok">可用</span>';
}

function render(){
  if(!state){return;}
  document.getElementById('meta').textContent=state.pool_path;
  var t=state.totals;
  document.getElementById('cards').innerHTML=
    card('渠道',state.keys.length)+
    card('总请求',t.requests)+
    card('成功',t.ok)+card('失败',t.failed)+
    card('tokens 输入',t.tokens_in)+card('tokens 输出',t.tokens_out)+
    card('缓存命中',t.cache_read||0);

  document.getElementById('strategy').value=state.strategy;
  document.getElementById('threshold').value=state.failure_threshold;
  var tiers=state.cooldown_tiers||{};
  document.getElementById('tier-plan').value=tiers.plan;
  document.getElementById('tier-soft').value=tiers.soft;
  document.getElementById('tier-err').value=tiers.err;

  var rows=state.keys.map(function(k){
    var models=k.models.length?esc(k.models.join(', ')):'<span class="tag t-off">全部模型</span>';
    var u=k.usage;
    var err=k.last_error?'<div class="err">'+esc(k.last_error)+'</div>':'';
    return '<tr><td><b>'+esc(k.label)+'</b>'+(k.note?'<div class="err">'+esc(k.note)+'</div>':'')+'</td>'+
      '<td class="mono">'+esc(k.protocol)+'</td>'+
      '<td>'+statusTag(k)+
      (k.priority?'<div><span class="tag t-off">优先级 '+k.priority+'</span></div>':'')+
      (k.model_mapping&&Object.keys(k.model_mapping).length?'<div><span class="tag t-off">映射×'+Object.keys(k.model_mapping).length+'</span></div>':'')+
      err+'</td>'+
      '<td>'+models+'</td>'+
      '<td class="mono">'+u.requests+' / '+u.ok+' / '+u.failed+'<br>'+u.tokens_in+'&rarr;'+u.tokens_out+'</td>'+
      '<td class="mono">'+esc(k.key_hint)+'</td>'+
      '<td><div class="ops">'+
        '<button data-probe="'+esc(k.key_id)+'">探活</button>'+
        '<button data-edit="'+esc(k.key_id)+'">编辑</button>'+
        '<button data-toggle="'+esc(k.key_id)+'">'+(k.enabled?'禁用':'启用')+'</button>'+
        (k.consecutive_failures>0?'<button data-reset="'+esc(k.key_id)+'">复位熔断</button>':'')+
        '<button class="danger" data-del="'+esc(k.key_id)+'">删除</button>'+
      '</div></td></tr>';
  }).join('');
  document.getElementById('rows').innerHTML=rows||
    '<tr><td colspan="7" style="color:var(--muted)">还没有渠道，用上面的表单加一个。</td></tr>';

  document.getElementById('form-title').textContent=editing?('编辑渠道：'+editing.label):'添加渠道';
  document.getElementById('cancel').hidden=!editing;
}

function card(label,value){
  return '<div class="card"><span>'+esc(label)+'</span><b>'+esc(value)+'</b></div>';
}

function load(){
  api('GET','/api/state').then(function(s){
    state=s;
    if(document.getElementById('strategy').options.length===0){
      s.strategies.forEach(function(v){
        var o=document.createElement('option');o.value=v;o.textContent=v;
        document.getElementById('strategy').appendChild(o);});
      s.protocols.forEach(function(v){
        var o=document.createElement('option');o.value=v;o.textContent=v;
        document.getElementById('f-protocol').appendChild(o);});
    }
    render();
  }).catch(function(e){toast('加载失败：'+e.message,false);});
}

function formBody(){
  return {
    label:document.getElementById('f-label').value.trim(),
    protocol:document.getElementById('f-protocol').value,
    base_url:document.getElementById('f-base-url').value.trim(),
    api_key:document.getElementById('f-api-key').value,
    models_text:document.getElementById('f-models').value,
    mapping_text:document.getElementById('f-mapping').value,
    priority:parseInt(document.getElementById('f-priority').value,10)||0,
    note:document.getElementById('f-note').value.trim()
  };
}

function clearForm(){
  ['f-label','f-base-url','f-api-key','f-models','f-mapping','f-priority','f-note'].forEach(function(id){
    document.getElementById(id).value='';});
  editing=null;render();
}

function startEdit(k){
  editing=k;
  document.getElementById('f-label').value=k.label;
  document.getElementById('f-protocol').value=k.protocol;
  document.getElementById('f-base-url').value=k.base_url;
  document.getElementById('f-api-key').value='';
  document.getElementById('f-models').value=k.models.map(function(m){
    var w=k.model_windows[m];return w?(m+':'+w):m;}).join(', ');
  document.getElementById('f-mapping').value=Object.keys(k.model_mapping||{}).map(function(p){
    return p+'='+k.model_mapping[p];}).join(', ');
  document.getElementById('f-priority').value=k.priority||0;
  document.getElementById('f-note').value=k.note||'';
  render();
  window.scrollTo({top:0,behavior:'smooth'});
}

document.getElementById('submit').onclick=function(){
  var body=formBody();
  if(!body.base_url){toast('Base URL 不能为空',false);return;}
  var req=editing
    ? api('PUT','/api/keys/'+encodeURIComponent(editing.key_id),body)
    : api('POST','/api/keys',body);
  req.then(function(s){state=s;clearForm();toast('已保存，网关会立刻生效',true);})
     .catch(function(e){toast('保存失败：'+e.message,false);});
};
document.getElementById('cancel').onclick=clearForm;
document.getElementById('refresh').onclick=load;
document.getElementById('save-settings').onclick=function(){
  api('PUT','/api/settings',{
    strategy:document.getElementById('strategy').value,
    failure_threshold:document.getElementById('threshold').value,
    cooldown_tiers:{
      plan:document.getElementById('tier-plan').value,
      soft:document.getElementById('tier-soft').value,
      err:document.getElementById('tier-err').value
    }
  }).then(function(s){state=s;render();toast('设置已保存',true);})
    .catch(function(e){toast('保存失败：'+e.message,false);});
};

document.getElementById('rows').onclick=function(ev){
  var b=ev.target.closest('button');if(!b){return;}
  var key=state.keys.filter(function(k){
    return k.key_id===(b.dataset.probe||b.dataset.edit||b.dataset.toggle||
                      b.dataset.reset||b.dataset.del);})[0];
  if(!key){return;}
  if(b.dataset.edit){startEdit(key);return;}
  if(b.dataset.probe){
    b.disabled=true;b.textContent='探测中…';
    api('POST','/api/keys/'+encodeURIComponent(key.key_id)+'/probe',{})
      .then(function(r){
        toast(r.ok?('「'+r.label+'」正常，'+r.ms+'ms，回文：'+r.text)
                  :('「'+r.label+'」失败：'+r.error),r.ok);
        load();})
      .catch(function(e){toast('探活失败：'+e.message,false);})
      .then(function(){b.disabled=false;b.textContent='探活';});
    return;
  }
  if(b.dataset.toggle){
    api('PUT','/api/keys/'+encodeURIComponent(key.key_id),{enabled:!key.enabled})
      .then(function(s){state=s;render();}).catch(function(e){toast(e.message,false);});
    return;
  }
  if(b.dataset.reset){
    api('PUT','/api/keys/'+encodeURIComponent(key.key_id),{reset_breaker:true})
      .then(function(s){state=s;render();toast('已复位熔断',true);})
      .catch(function(e){toast(e.message,false);});
    return;
  }
  if(b.dataset.del){
    if(!confirm('删除渠道「'+key.label+'」？')){return;}
    api('DELETE','/api/keys/'+encodeURIComponent(key.key_id))
      .then(function(s){state=s;render();toast('已删除',true);})
      .catch(function(e){toast(e.message,false);});
  }
};

// ================================================================ 标签页与统一控制台

function switchTab(name){
  document.querySelectorAll('#tabs button').forEach(function(b){
    b.classList.toggle('active',b.dataset.tab===name);});
  document.querySelectorAll('.pane').forEach(function(p){
    p.style.display=(p.id==='pane-'+name)?'block':'none';});
  loadPane(name);
}

function loadPane(name){
  if(name==='clients'){loadClients();return;}
  if(name==='pool'){load();return;}
  if(name==='tokens'){loadTokens();return;}
  if(name==='policy'){loadPolicy();return;}
  if(name==='users'){loadUsers();return;}
  if(name==='requests'){loadRequests();return;}
  if(name==='usage'){loadUsage();return;}
  if(name==='audit'){loadAudit();return;}
}

document.getElementById('tabs').onclick=function(ev){
  var b=ev.target.closest('button');if(!b){return;}
  switchTab(b.dataset.tab);
};

// ---- 客户端总览 ----

function sourceTag(src){
  return src==='app'
    ?'<span class="tag t-app">App 客户端</span>'
    :'<span class="tag t-api">直连 API</span>';
}

function loadClients(){
  api('GET','/api/clients').then(function(s){
    var w=s.summary;
    document.getElementById('cl-cards').innerHTML=
      card('App 设备',w.app_devices)+card('直连来源',w.api_sources)+
      card('在线（2 分钟内）',w.online)+card('今日请求',w.today_requests)+
      card('其中 App 流量',w.app_requests_today);
    var rows=s.clients.map(function(c){
      var isApp=c.source==='app';
      var who=isApp
        ?'<b>'+esc(c.user||'—')+'</b><div class="err">'+esc(c.token)+'</div>'
        :'<b>'+esc(c.token)+'</b><div class="err">直连 API，无客户端身份</div>';
      var device=isApp?esc(c.device||'—'):'<span style="color:var(--muted)">—</span>';
      var did=isApp?'<span class="mono" style="color:var(--muted)">'+esc(c.device_id||'—')+'</span>'
        :'<span style="color:var(--muted)">—</span>';
      var ver=isApp?(c.ver?esc(c.ver):'<span style="color:var(--muted)">—</span>')
        :'<span style="color:var(--muted)">—</span>';
      var online=c.online?'<span class="dot on"></span>在线':'<span class="dot off"></span>离线';
      var last=c.last_ts?new Date(c.last_ts*1000).toLocaleString():'-';
      return '<tr><td>'+sourceTag(c.source)+'</td>'+
        '<td>'+who+'</td>'+
        '<td>'+device+'</td>'+
        '<td>'+did+'</td>'+
        '<td>'+ver+'</td>'+
        '<td class="mono">'+esc(c.last_ip||'-')+'</td>'+
        '<td>'+online+'</td>'+
        '<td class="mono"><b>'+(c.today||0)+'</b></td>'+
        '<td class="mono">'+(c.total||0)+'（'+(c.failed||0)+'）</td>'+
        '<td class="mono">'+(c.tokens_in||0)+'&rarr;'+(c.tokens_out||0)+'</td>'+
        '<td>'+(c.top_models&&c.top_models.length?esc(c.top_models.join(', ')):'<span style="color:var(--muted)">—</span>')+'</td>'+
        '<td class="mono">'+esc(last)+'</td></tr>';
    }).join('');
    document.getElementById('cl-rows').innerHTML=rows||
      '<tr><td colspan="12" style="color:var(--muted)">还没有任何请求流量。</td></tr>';
  }).catch(function(e){toast('加载失败：'+e.message,false);});
}

// ---- 用户 / 兑换码 ----

function loadUsers(){
  api('GET','/api/users').then(function(s){
    document.getElementById('u-register').value=s.allow_register?'1':'0';
    document.getElementById('u-default').value=s.default_quota;
    document.getElementById('u-price-in').value=s.price_in_per_1k;
    document.getElementById('u-price-out').value=s.price_out_per_1k;
    document.getElementById('u-groups').value=Object.keys(s.groups).map(function(g){
      return g+'='+s.groups[g];}).join(', ');
    var rows=s.users.map(function(u){
      var st=u.enabled?'<span class="tag t-ok">启用</span>':'<span class="tag t-off">禁用</span>';
      var quota=u.quota<0?'<span class="tag t-ok">不限</span>':(u.quota+' / '+u.used+' 点');
      return '<tr><td><b>'+esc(u.username)+'</b>'+(u.role==='admin'?' <span class="tag t-warn">管理员</span>':'')+
        (u.note?'<div class="err">'+esc(u.note)+'</div>':'')+'</td>'+
        '<td>'+st+'</td><td>'+esc(u.group)+'</td><td class="mono">'+quota+'</td>'+
        '<td><div class="ops">'+
          '<button data-ua="'+esc(u.user_id)+'" data-cur="'+(u.quota<0?-1:u.quota)+'">发额度</button>'+
          '<button data-ut="'+esc(u.user_id)+'">'+(u.enabled?'禁用':'启用')+'</button>'+
          '<button class="danger" data-ud="'+esc(u.user_id)+'">删除</button>'+
        '</div></td></tr>';
    }).join('');
    document.getElementById('u-rows').innerHTML=rows||
      '<tr><td colspan="5" style="color:var(--muted)">还没有用户。</td></tr>';
    api('GET','/api/codes').then(function(cs){
      document.getElementById('c-rows').innerHTML=cs.codes.map(function(c){
        var st=c.used_by?'<span class="tag t-off">已用（'+esc(c.used_by)+'）</span>':'<span class="tag t-ok">有效</span>';
        return '<tr><td class="mono">'+esc(c.code)+'</td><td class="mono">'+c.credits+' 点</td><td>'+st+'</td></tr>';
      }).join('')||'<tr><td colspan="3" style="color:var(--muted)">还没有兑换码。</td></tr>';
    }).catch(function(){});
  }).catch(function(e){toast('加载失败：'+e.message,false);});
}

document.getElementById('u-save-settings').onclick=function(){
  var groups={};
  document.getElementById('u-groups').value.split(',').forEach(function(p){
    var kv=p.split('=');if(kv.length===2&&kv[0].trim()){groups[kv[0].trim()]=parseFloat(kv[1])||0;}});
  api('PUT','/api/users',{
    allow_register:document.getElementById('u-register').value==='1',
    default_quota:parseInt(document.getElementById('u-default').value,10)||0,
    price_in_per_1k:parseFloat(document.getElementById('u-price-in').value)||0,
    price_out_per_1k:parseFloat(document.getElementById('u-price-out').value)||0,
    groups:groups
  }).then(function(){toast('计费规则已保存，网关热加载生效',true);})
    .catch(function(e){toast('保存失败：'+e.message,false);});
};

document.getElementById('u-add').onclick=function(){
  var body={username:document.getElementById('u-name').value.trim(),
    password:document.getElementById('u-pass').value,
    group:document.getElementById('u-group').value.trim()};
  var q=parseInt(document.getElementById('u-quota').value,10);
  if(!isNaN(q)){body.quota=q;}
  api('POST','/api/users',body).then(function(){toast('用户已创建',true);loadUsers();})
    .catch(function(e){toast('创建失败：'+e.message,false);});
};

document.getElementById('u-rows').onclick=function(ev){
  var b=ev.target.closest('button');if(!b){return;}
  if(b.dataset.ua){
    var add=prompt('给该用户发多少点？（当前 '+(b.dataset.cur==='-1'?'不限':b.dataset.cur)+'，负数=扣减，-1=改为不限量）');
    if(add===null){return;}
    if(add==='-1'){api('PUT','/api/users/'+encodeURIComponent(b.dataset.ua),{quota:-1}).then(loadUsers);return;}
    api('PUT','/api/users/'+encodeURIComponent(b.dataset.ua),{add_quota:parseInt(add,10)||0})
      .then(loadUsers).catch(function(e){toast(e.message,false);});
    return;
  }
  if(b.dataset.ut){
    api('GET','/api/users').then(function(s){
      var u=s.users.filter(function(x){return x.user_id===b.dataset.ut;})[0];
      api('PUT','/api/users/'+encodeURIComponent(b.dataset.ut),{enabled:!(u&&u.enabled)}).then(loadUsers);
    });
    return;
  }
  if(b.dataset.ud){
    if(!confirm('删除该用户？其 API Key 不再计费（余额不退）。')){return;}
    api('DELETE','/api/users/'+encodeURIComponent(b.dataset.ud)).then(loadUsers)
      .catch(function(e){toast(e.message,false);});
  }
};

document.getElementById('c-gen').onclick=function(){
  api('POST','/api/codes',{
    count:parseInt(document.getElementById('c-count').value,10)||1,
    credits:parseInt(document.getElementById('c-credits').value,10)||100
  }).then(function(s){
    document.getElementById('c-new').textContent=s.codes.map(function(c){return c.code;}).join('\n');
    toast('已生成（只显示这一次）',true);loadUsers();
  }).catch(function(e){toast('生成失败：'+e.message,false);});
};

// ---- 令牌 ----

function loadTokens(){
  api('GET','/api/tokens').then(function(s){
    window.__tokens=s.tokens;
    var groups={};
    s.tokens.forEach(function(t){groups[t.group||'default']=1;});
    var sel=document.getElementById('t-filter');
    var cur=sel.value;
    sel.innerHTML='<option value="">全部分组</option>'+
      Object.keys(groups).sort().map(function(g){
        return '<option'+(g===cur?' selected':'')+'>'+esc(g)+'</option>';}).join('');
    var wanted=sel.value;
    var rows=s.tokens.filter(function(t){return !wanted||(t.group||'default')===wanted;})
      .map(function(t){
      var state=t.enabled?'<span class="tag t-ok">启用</span>':'<span class="tag t-off">已禁用</span>';
      var usage=t.usage;
      var scopeTag=t.scope==='test'
        ?'<span class="tag t-warn">test·合成</span>'
        :'<span class="tag t-ok">normal</span>';
      var groupTag='<span class="tag t-api">'+esc(t.group||'default')+'</span>';
      var limits=[];
      if(t.rpm){limits.push(t.rpm+'/分');}
      if(t.daily_requests){limits.push(t.daily_requests+'/天');}
      if(t.expires_at){limits.push('至 '+new Date(t.expires_at*1000).toLocaleDateString());}
      var limitText=limits.length?esc(limits.join(' + ')):'<span class="tag t-off">不限</span>';
      var seen=[];
      if(usage.last_user){seen.push(esc(usage.last_user));}
      if(usage.last_device){seen.push(esc(usage.last_device));}
      if(usage.last_ver){seen.push('v'+esc(usage.last_ver));}
      if(usage.last_device_id){seen.push('<span class="mono">'+esc(usage.last_device_id)+'</span>');}
      if(usage.last_ip){seen.push('<span class="mono">'+esc(usage.last_ip)+'</span>');}
      var seenText=seen.length?seen.join('<br>'):'<span style="color:var(--muted)">无客户端身份</span>';
      return '<tr><td><b>'+esc(t.name)+'</b>'+(t.note?'<div class="err">'+esc(t.note)+'</div>':'')+'</td>'+
        '<td>'+groupTag+'</td>'+
        '<td>'+state+'</td>'+
        '<td>'+scopeTag+'</td>'+
        '<td>'+(t.models.length?esc(t.models.join(', ')):'<span class="tag t-off">不限制</span>')+'</td>'+
        '<td>'+limitText+'</td>'+
        '<td class="mono">'+usage.requests+'（败 '+usage.failed+'）<br>'+usage.tokens_in+'&rarr;'+usage.tokens_out+'</td>'+
        '<td>'+seenText+'</td>'+
        '<td class="mono">'+esc(t.token_hint)+'</td>'+
        '<td><div class="ops">'+
          '<button data-tt="'+esc(t.token_id)+'">'+(t.enabled?'禁用':'启用')+'</button>'+
          '<button class="danger" data-td="'+esc(t.token_id)+'">吊销</button>'+
        '</div></td></tr>';
    }).join('');
    document.getElementById('t-rows').innerHTML=rows||
      '<tr><td colspan="10" style="color:var(--muted)">还没有令牌，用上面的表单发放。</td></tr>';
  }).catch(function(e){toast('加载失败：'+e.message,false);});
}

document.getElementById('t-add').onclick=function(){
  var name=document.getElementById('t-name').value.trim();
  if(!name){toast('设备名不能为空',false);return;}
  api('POST','/api/tokens',{
    name:name,
    group:document.getElementById('t-group').value.trim(),
    models_text:document.getElementById('t-models').value,
    scope:document.getElementById('t-scope').value,
    rpm:parseInt(document.getElementById('t-rpm').value,10)||0,
    daily_requests:parseInt(document.getElementById('t-daily').value,10)||0,
    days:parseInt(document.getElementById('t-days').value,10)||0,
    note:document.getElementById('t-note').value.trim()
  }).then(function(s){
    document.getElementById('t-new').style.display='';
    document.getElementById('t-new-token').textContent=s.token;
    toast('令牌已发放（明文只显示这一次）',true);
    loadTokens();
  }).catch(function(e){toast('发放失败：'+e.message,false);});
};

document.getElementById('t-rows').onclick=function(ev){
  var b=ev.target.closest('button');if(!b){return;}
  var list=window.__tokens||[];
  var rec=list.filter(function(t){return t.token_id===(b.dataset.tt||b.dataset.td);})[0];
  if(!rec){return;}
  if(b.dataset.tt){
    api('PUT','/api/tokens/'+encodeURIComponent(rec.token_id),{enabled:!rec.enabled})
      .then(loadTokens).catch(function(e){toast(e.message,false);});
    return;
  }
  if(b.dataset.td){
    if(!confirm('吊销令牌「'+rec.name+'」？该设备会立刻 401。')){return;}
    api('DELETE','/api/tokens/'+encodeURIComponent(rec.token_id))
      .then(loadTokens).catch(function(e){toast(e.message,false);});
  }
};

// ---- 接入策略（拉黑 / 优先队列） ----

function policyEntryRow(kind,value,e){
  var state=e.blocked?'<span class="tag t-bad">已拉黑</span>'
    :e.priority?'<span class="tag t-ok">优先队列</span>':'<span class="tag t-off">无动作</span>';
  return '<tr><td class="mono">'+esc(value)+'</td><td>'+state+'</td>'+
    '<td>'+esc(e.note||'')+'</td>'+
    '<td><div class="ops">'+
      '<button data-pk="'+esc(kind)+'" data-pv="'+esc(value)+'" data-act="remove">移除</button>'+
    '</div></td></tr>';
}

function loadPolicy(){
  api('GET','/api/policy').then(function(s){
    document.getElementById('p-ip-rows').innerHTML=Object.keys(s.ips||{}).map(function(v){
      return policyEntryRow('ip',v,s.ips[v]);}).join('')||
      '<tr><td colspan="4" style="color:var(--muted)">没有 IP 策略。</td></tr>';
    document.getElementById('p-dev-rows').innerHTML=Object.keys(s.devices||{}).map(function(v){
      return policyEntryRow('device',v,s.devices[v]);}).join('')||
      '<tr><td colspan="4" style="color:var(--muted)">没有设备策略。</td></tr>';
  }).catch(function(e){toast('加载失败：'+e.message,false);});
}

document.getElementById('p-add').onclick=function(){
  var kind=document.getElementById('p-kind').value;
  var value=document.getElementById('p-value').value.trim();
  var flag=document.getElementById('p-flag').value;
  if(!value){toast('值不能为空',false);return;}
  var body={kind:kind,value:value,action:'set'};
  body[flag]=true;
  body.note=document.getElementById('p-note').value.trim();
  api('POST','/api/policy',body).then(function(){
    toast(flag==='blocked'?'已拉黑（网关即时生效）':'已加入优先队列',true);
    document.getElementById('p-value').value='';
    loadPolicy();
  }).catch(function(e){toast(e.message,false);});
};

document.getElementById('pane-policy').onclick=function(ev){
  var b=ev.target.closest('button');if(!b){return;}
  api('POST','/api/policy',{kind:b.dataset.pk,value:b.dataset.pv,action:'remove'})
    .then(function(){toast('已移除',true);loadPolicy();})
    .catch(function(e){toast(e.message,false);});
};



// ---- 请求明细 ----

function loadRequests(){
  var q=new URLSearchParams();
  var t=document.getElementById('r-token').value.trim();
  var u=document.getElementById('r-user').value.trim();
  var m=document.getElementById('r-model').value.trim();
  if(t){q.set('token',t);}
  if(u){q.set('ident_user',u);}
  if(m){q.set('model',m);}
  q.set('limit',document.getElementById('r-limit').value);
  api('GET','/api/requests?'+q.toString()).then(function(s){
    var srcSel=document.getElementById('r-source').value;
    var rows=s.entries.filter(function(e){
      var isApp=!!(e.ident_user||e.ident_dev||e.ident_did);
      return !srcSel||(srcSel==='app'?isApp:!isApp);
    }).map(function(e){
      var when=new Date(e.ts*1000).toLocaleString();
      var mark=e.ok?'<span class="tag t-ok">✓</span>':'<span class="tag t-bad">✗</span>';
      var stream=e.stream?'<span class="tag t-off">流</span>':'';
      var reason=e.reason?'<div class="err">'+esc(e.reason)+'</div>':'';
      var smBits=[];
      if(e.ident_user){smBits.push(esc(e.ident_user));}
      if(e.ident_dev){smBits.push(esc(e.ident_dev));}
      if(e.ident_ver){smBits.push('v'+esc(e.ident_ver));}
      if(e.ident_did){smBits.push('<span class="mono">'+esc(e.ident_did)+'</span>');}
      if(e.ident_src){
        var src=String(e.ident_src);
        smBits.push(src.indexOf('bad:')===0
          ?'<span class="tag t-bad">'+esc(src)+'</span>'
          :'<span class="tag t-off">'+esc(src==='header'?'头':'body')+'</span>');
      }
      var smText=smBits.length?smBits.join(' '):'<span style="color:var(--muted)">-</span>';
      var srcTag=(e.ident_user||e.ident_dev||e.ident_did)
        ?'<span class="tag t-app">App</span>'
        :'<span class="tag t-api">直连</span>';
      return '<tr><td class="mono">'+esc(when)+'</td>'+
        '<td>'+mark+stream+'</td>'+
        '<td>'+srcTag+'</td>'+
        '<td>'+esc(e.token)+'</td>'+
        '<td>'+smText+'</td>'+
        '<td>'+esc(e.model||'-')+'</td>'+
        '<td>'+esc(e.channel||'-')+'</td>'+
        '<td class="mono">'+(e.tokens_in||0)+'&rarr;'+(e.tokens_out||0)+'</td>'+
        '<td class="mono">'+(e.latency_ms||0)+'ms</td>'+
        '<td class="mono">'+esc(e.ip||'-')+'</td><td>'+reason+'</td></tr>';
    }).join('');
    document.getElementById('r-rows').innerHTML=rows||
      '<tr><td colspan="11" style="color:var(--muted)">没有匹配的请求记录。</td></tr>';
  }).catch(function(e){toast('加载失败：'+e.message,false);});
}
document.getElementById('r-load').onclick=loadRequests;

// ---- 用量 ----

function usageRow(name,slot){
  return '<tr><td>'+esc(name)+'</td><td class="mono">'+slot.requests+'（败 '+slot.failed+'）</td>'+
    '<td class="mono">'+slot.tokens_in+'&rarr;'+slot.tokens_out+'</td></tr>';
}

function fillUsageTable(id, buckets){
  var keys=Object.keys(buckets).sort(function(a,b){
    return buckets[b].requests-buckets[a].requests;});
  document.getElementById(id).innerHTML=keys.map(function(k){
    return usageRow(k,buckets[k]);}).join('')||
    '<tr><td style="color:var(--muted)">（无数据）</td></tr>';
}

function loadUsage(){
  var days=document.getElementById('u-days').value;
  api('GET','/api/usage'+(days?('?days='+days):'')).then(function(s){
    var w=s.requests.window;
    document.getElementById('u-cards').innerHTML=
      card('请求',w.requests)+card('成功',w.ok)+card('失败',w.failed)+
      card('tokens 输入',w.tokens_in)+card('tokens 输出',w.tokens_out)+
      card('平均耗时',w.avg_latency_ms+'ms');
    fillUsageTable('u-token',s.requests.by_token);
    fillUsageTable('u-model',s.requests.by_model);
    fillUsageTable('u-channel',s.requests.by_channel);
    // 按分组：从令牌的组标签现场聚合（组是令牌属性，用量跟着令牌走）
    var byGroup={};
    (s.tokens||[]).forEach(function(t){
      var g=t.group||'default';
      var b=byGroup[g]||(byGroup[g]={requests:0,failed:0,tokens_in:0,tokens_out:0});
      b.requests+=t.usage.requests;b.failed+=t.usage.failed;
      b.tokens_in+=t.usage.tokens_in;b.tokens_out+=t.usage.tokens_out;
    });
    fillUsageTable('u-group',byGroup);
    document.getElementById('u-day').innerHTML=
      Object.keys(s.requests.by_day).sort().reverse().map(function(d){
        return usageRow(d,s.requests.by_day[d]);}).join('')||
      '<tr><td style="color:var(--muted)">（无数据）</td></tr>';
  }).catch(function(e){toast('加载失败：'+e.message,false);});
}
document.getElementById('u-load').onclick=loadUsage;

// ---- 审计 ----

function loadAudit(){
  var limit=document.getElementById('al-limit').value;
  api('GET','/api/audit?limit='+limit).then(function(s){
    var rows=s.entries.map(function(e){
      var when=new Date(e.ts*1000).toLocaleString();
      var detail=Object.keys(e).filter(function(k){return k!=='ts'&&k!=='event';})
        .map(function(k){return k+'='+esc(e[k]);}).join('　');
      return '<tr><td class="mono">'+esc(when)+'</td>'+
        '<td><span class="tag t-off">'+esc(e.event)+'</span></td><td>'+detail+'</td></tr>';
    }).join('');
    document.getElementById('al-rows').innerHTML=rows||
      '<tr><td colspan="3" style="color:var(--muted)">（还没有审计记录）</td></tr>';
  }).catch(function(e){toast('加载失败：'+e.message,false);});
}
document.getElementById('al-load').onclick=loadAudit;

// ---- 自动刷新只作用于当前标签页 ----

function refreshActive(){
  var active=document.querySelector('#tabs button.active');
  if(active){loadPane(active.dataset.tab);}
}
setInterval(function(){
  if(document.getElementById('auto').checked&&!document.hidden){refreshActive();}
},4000);
switchTab('clients');
</script>
</body>
</html>
"""


if __name__ == "__main__":
    raise SystemExit(main())
