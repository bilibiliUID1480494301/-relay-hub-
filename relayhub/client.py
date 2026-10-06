# -*- coding: utf-8 -*-
"""relay-hub 客户端 SDK：`StationClient` —— 第三方 Python 程序接入中转站的函数面。

为什么要有这个文件：0.6.0 之前，包的 Python 函数面只有「服务端半边」——
``mcp.list_tools``/``a2a.send_task`` 读的是本站密封池文件（网关内部转发用），
``e2e.open_envelope`` 只有解密没有加密。一个 Python 程序想作为**客户端**连
远程中转站（发模型请求、列 MCP 工具、发 A2A 任务、TOIP 接入），只能手写
HTTP。这里是补上的那一半。

设计立场（与 docs/CLIENT-SDK.md 一致）：

* **纯标准库**：urllib 一条路，零依赖安装即用；E2E 是可选升级（装了
  ``hubrelay[e2e]`` 才会封信封），明文流量永远可用、永不被静默降级——
  auto 模式下封不了信封就报错说清楚，绝不偷偷发明文。
* **远程站，不碰本地池**：所有方法都走 HTTP 到 ``base_url`` 指向的站；
  与 ``gateway/mcp.py``、``gateway/a2a.py`` 那组服务端内部函数是两个世界。
* **凭证即盐**：封信封用当前令牌做 HKDF 盐，与服务端
  ``_supplied_credential()`` 同一口径——同一份密文换个令牌就解不开。
* **key 轮换自适应**：站点轮换 E2E 身份后旧 key_id 会被 400 拒绝；
  客户端清缓存重拉参数重封一次，用户无感（测试钉在 test_client.py）。

流式说明：``stream=True`` 的请求返回原始 SSE 文本（本 SDK 不做流式解析）；
非流式请求返回解析后的 dict。HTTP 4xx/5xx 一律抛 :class:`StationError`。
"""

from __future__ import annotations

import itertools
import json
import urllib.error
import urllib.request
from typing import Any

from . import __version__ as _PKG_VERSION
from .gateway.e2e import ENVELOPE_CONTENT_TYPE, E2eError, seal_envelope

__all__ = ["StationClient", "StationError"]

#: 客户端在 TOIP 接入与插件日志里的默认身份。
PLUGIN_ID = "hubrelay-client"

_rpc_ids = itertools.count(1)


class StationError(RuntimeError):
    """中转站返回 4xx/5xx，或网络层连不上（status=0）。

    ``payload`` 是服务端原始应答（能解析时是 dict，否则是原始文本）；
    ``message`` 已提取服务端 error.message，可直接展示给用户。
    """

    def __init__(self, status: int, message: str, payload: Any = None) -> None:
        super().__init__(message)
        self.status = status
        self.payload = payload


def _parse_body(raw: str) -> Any:
    try:
        return json.loads(raw)
    except ValueError:
        return raw


def _error_message(status: int, body: Any) -> str:
    """把服务端错误体压成一句话：{"error":{"message":..}} / {"error":..} / 原文。"""
    if isinstance(body, dict):
        error = body.get("error")
        if isinstance(error, dict):
            text = str(error.get("message") or "").strip()
            if text:
                return text
            return json.dumps(error, ensure_ascii=False)
        if isinstance(error, str) and error.strip():
            return error.strip()
        if body:
            return json.dumps(body, ensure_ascii=False)
    if isinstance(body, str) and body.strip():
        return body.strip()[:300]
    return f"中转站返回 HTTP {status}"


class StationClient:
    """一台中转站的客户端句柄。

    :param base_url: 站点地址，任意可粘贴形态（``http://`` 可省略，尾部
        ``/`` 会被剥掉；TOIP 接入后 :meth:`adopt` 会按站点下发的 baseURL 覆写）。
    :param token: 下游令牌（面板创建或 TOIP 接入获得）；master 凭证同样可用。
    :param timeout: 单请求超时秒数。
    :param e2e: ``"auto"``（默认：站点支持就封信封，否则明文）/ ``"off"``
        （强制明文）/ ``"require"``（站点必须支持 E2E，否则拒绝发送）。
    :param plugin_id: TOIP 接入与插件日志里的身份标识。
    """

    def __init__(
        self,
        base_url: str,
        token: str = "",
        *,
        timeout: float = 60.0,
        e2e: str = "auto",
        plugin_id: str = PLUGIN_ID,
    ) -> None:
        if e2e not in ("auto", "off", "require"):
            raise ValueError(f"e2e 取值必须是 auto/off/require，收到 {e2e!r}")
        root = str(base_url or "").strip()
        if root and "://" not in root:
            root = "http://" + root
        self.base_url = root.rstrip("/")
        self.token = str(token or "")
        self.timeout = float(timeout)
        self.e2e = e2e
        self.plugin_id = str(plugin_id or PLUGIN_ID)
        #: 上一次 POST 是否走了信封（调试与测试用）。
        self.last_enveloped: bool = False
        self.station_id: str = ""
        self._params_cache: dict[str, Any] | None = None

    # -- E2E 参数 ---------------------------------------------------------

    def e2e_params(self, *, refresh: bool = False) -> dict[str, Any] | None:
        """站点的信封参数（公钥等，公开材料）。``refresh=True`` 强制重拉。

        auto 模式下站点不支持 E2E 返回 ``None``；require 模式下不支持直接抛
        :class:`StationError`。
        """
        required = self.e2e == "require"
        if refresh:
            self._params_cache = None
        if self._params_cache is not None:
            return self._params_cache
        try:
            params = self._http("GET", "/v1/e2e/params")
        except StationError as exc:
            if exc.status in (404, 501):
                if not required:
                    return None
                raise StationError(
                    exc.status,
                    "本站未启用 E2E（服务端缺 cryptography？服务端装 "
                    "\"hubrelay[e2e]\"），而客户端 e2e='require' 拒绝明文发送",
                    exc.payload,
                ) from exc
            raise
        self._params_cache = params
        return params

    def _post(self, path: str, payload: dict[str, Any]) -> Any:
        """POST JSON。e2e 激活时封信封——覆盖全部 JSON 端点（模型四通道 +
        MCP + A2A），服务端对这六条路都先解信封再走原链路。"""
        self.last_enveloped = False
        if self.e2e == "off" or not self.token:
            return self._http("POST", path, payload=payload)
        params = self.e2e_params()
        if params is None:
            return self._http("POST", path, payload=payload)
        try:
            return self._post_sealed(path, payload, params)
        except StationError as exc:
            # 站点轮换了 E2E 身份：旧 key_id 被 400 拒 → 重拉参数重封一次。
            if exc.status == 400 and "key_id" in str(exc):
                fresh = self.e2e_params(refresh=True)
                if fresh is not None:
                    return self._post_sealed(path, payload, fresh)
            raise

    def _post_sealed(
        self, path: str, payload: dict[str, Any], params: dict[str, Any]
    ) -> Any:
        try:
            envelope = seal_envelope(
                params["server_public"], params["key_id"], payload, self.token
            )
        except E2eError as exc:
            # 封不了就明说（本机缺 cryptography），绝不静默降级成明文。
            raise StationError(0, f"E2E 封信封失败：{exc}") from exc
        self.last_enveloped = True
        return self._http(
            "POST", path, payload=envelope, content_type=ENVELOPE_CONTENT_TYPE
        )

    # -- HTTP 内核 ---------------------------------------------------------

    def _http(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None = None,
        content_type: str = "application/json",
    ) -> Any:
        data = None
        if payload is not None:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(f"{self.base_url}{path}", data=data, method=method)
        if data is not None:
            request.add_header("Content-Type", content_type)
        request.add_header("Accept", "application/json")
        if self.token:
            request.add_header("x-api-key", self.token)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return _parse_body(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:  # noqa: TID251 - SDK 直接翻译错误体
            raw = exc.read().decode("utf-8", "replace")
            body = _parse_body(raw)
            raise StationError(exc.code, _error_message(exc.code, body), body) from exc
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            raise StationError(0, f"连接中转站失败：{exc}") from exc

    # -- 公开信息（无凭证） -------------------------------------------------

    def whoami(self) -> dict[str, Any]:
        """``GET /v1/whoami``：协议身份与能力开关，填个网址就能探测。"""
        return self._http("GET", "/v1/whoami")

    def probe(self) -> dict[str, Any]:
        """``GET /v1/toip/station``：本站支不支持 TOIP、口令往哪发。

        站点未启用 TOIP 时服务端 404 → 抛 :class:`StationError`（status=404）。
        """
        return self._http("GET", "/v1/toip/station")

    # -- TOIP 接入生命周期 ---------------------------------------------------

    def join(
        self,
        *,
        code: str = "",
        ticket: str = "",
        name: str = "",
        client_id: str = "dsh",
    ) -> dict[str, Any]:
        """``POST /v1/toip/join``：动态口令或登记口令换会话令牌 + 接入载荷。

        返回的载荷就是「接入所需的一切」（含 api_key/base_url/模型清单）；
        :meth:`adopt` 一步吃下它。code 与 ticket 至少给一个。
        """
        if not code and not ticket:
            raise StationError(0, "join 需要动态口令 code 或登记口令 ticket 之一")
        body = {
            "code": str(code),
            "ticket": str(ticket),
            "name": str(name),
            "plugin": self.plugin_id,
            "plugin_version": _PKG_VERSION,
            "client": str(client_id),
        }
        return self._http("POST", "/v1/toip/join", payload=body)

    def adopt(self, payload: dict[str, Any]) -> "StationClient":
        """吃一份 :meth:`join` 载荷：令牌、baseURL、站点 id 一次到位（返回 self）。

        三种字段形态都认：顶层 ``api_key`` / dsh 档案 ``dsh.apiKey`` /
        会话 ``session.token``——与 dsh 插件同一条解析规则。
        """
        dsh = payload.get("dsh") if isinstance(payload.get("dsh"), dict) else {}
        api_key = str(
            payload.get("api_key")
            or dsh.get("apiKey")
            or (payload.get("session") or {}).get("token")
            or ""
        )
        if api_key:
            self.token = api_key
        # 根地址优先取 station.base_url（站点根）；dsh.baseURL 是给 DSH
        # Messages 适配器的端点形态（带 /v1 后缀），直接当根用会拼出
        # /v1/v1/...——SDK 的路径都自带 /v1 前缀，所以只能兜底时收编并剥后缀。
        station = payload.get("station") if isinstance(payload.get("station"), dict) else {}
        base = str(station.get("base_url") or payload.get("base_url") or "")
        if not base and dsh.get("baseURL"):
            base = str(dsh["baseURL"])
            if base.endswith("/v1"):
                base = base[: -len("/v1")]
        if base:
            self.base_url = base.rstrip("/")
        station = payload.get("station") if isinstance(payload.get("station"), dict) else {}
        self.station_id = str(station.get("id") or "")
        # 换站/换凭证后参数缓存作废：公钥虽是公开材料，但旧站缓存的
        # key_id 会让第一个请求白吃一次 400 再重试，不如直接重拉。
        self._params_cache = None
        return self

    def session(self) -> dict[str, Any]:
        """``GET /v1/toip/session``：我是谁、还剩多久、我这个令牌用了多少。"""
        return self._http("GET", "/v1/toip/session")

    # -- 模型四通道 -----------------------------------------------------------

    def models(self) -> dict[str, Any]:
        """``GET /v1/models``：OpenAI 形态的模型清单（含令牌级白名单过滤）。"""
        return self._http("GET", "/v1/models")

    def messages(self, payload: dict[str, Any]) -> Any:
        """``POST /v1/messages``（Anthropic 协议）。流式返回原始 SSE 文本。"""
        return self._post("/v1/messages", payload)

    def chat_completions(self, payload: dict[str, Any]) -> Any:
        """``POST /v1/chat/completions``（OpenAI 协议）。流式返回原始 SSE 文本。"""
        return self._post("/v1/chat/completions", payload)

    def responses(self, payload: dict[str, Any]) -> Any:
        """``POST /v1/responses``（OpenAI Responses 协议）。"""
        return self._post("/v1/responses", payload)

    def embeddings(self, payload: dict[str, Any]) -> Any:
        """``POST /v1/embeddings``（OpenAI 向量协议）。"""
        return self._post("/v1/embeddings", payload)

    # -- MCP 网关 -------------------------------------------------------------

    def mcp_initialize(self) -> dict[str, Any]:
        """``POST /mcp`` initialize：握手并报网关身份。"""
        return self._post(
            "/mcp",
            {"jsonrpc": "2.0", "id": next(_rpc_ids), "method": "initialize"},
        )

    def mcp_list_tools(self) -> dict[str, Any]:
        """``POST /mcp`` tools/list → result（``{"tools": [...]}``，名带渠道前缀）。

        JSON-RPC error 时返回含 ``error`` 键的应答（HTTP 仍是 200，不抛异常）。
        """
        reply = self._post(
            "/mcp",
            {"jsonrpc": "2.0", "id": next(_rpc_ids), "method": "tools/list"},
        )
        return reply.get("result", reply) if isinstance(reply, dict) else reply

    def mcp_call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        """``POST /mcp`` tools/call：完整 JSON-RPC 应答（result 或 error 都在里面），
        名带渠道前缀（如 ``web.search``）。"""
        return self._post(
            "/mcp",
            {
                "jsonrpc": "2.0",
                "id": next(_rpc_ids),
                "method": "tools/call",
                "params": {"name": str(name), "arguments": dict(arguments or {})},
            },
        )

    # -- A2A 路由 ---------------------------------------------------------------

    def a2a_card(self) -> dict[str, Any]:
        """``GET /.well-known/agent.json``：本站对外声明的 A2A agent 卡片。"""
        return self._http("GET", "/.well-known/agent.json")

    def a2a_send(
        self, agent: str, message: dict[str, Any], *, rpc_id: int | str | None = None
    ) -> dict[str, Any]:
        """``POST /a2a`` message/send：把任务转发给站内注册的下游 agent。

        ``message`` 是 A2A message 对象（``{"role":..,"parts":[..]}`` 或下游
        自定义形态，由下游 agent 解释）。
        """
        return self._post(
            "/a2a",
            {
                "jsonrpc": "2.0",
                "id": next(_rpc_ids) if rpc_id is None else rpc_id,
                "method": "message/send",
                "params": {"agent": str(agent), "message": message},
            },
        )
