# Client SDK / 客户端 SDK

**Status / 状态**: shipped in 0.7.0 · 0.7.0 起随包发布
**Module / 模块**: `relayhub.client.StationClient` — stdlib-only, zero deps · 纯标准库，零依赖

## Why / 为什么

Until 0.6.x the Python package exposed only the **server half** of the
function surface: `mcp.list_tools` / `a2a.send_task` read the station's own
sealed pool files (gateway-internal forwarding), and `e2e` only had
`open_envelope` (decrypt). A Python program that wants to act as a
**client** of a remote relay-hub station — send model requests, list MCP
tools, dispatch A2A tasks, join via TOIP — had to hand-write HTTP.
`StationClient` is the missing half.

0.6.x 之前，Python 包的函数面只有「服务端半边」：`mcp.list_tools` /
`a2a.send_task` 读的是本站密封池文件（网关内部转发用），`e2e` 只有解密。
一个想作为**客户端**连远程中转站的 Python 程序——发模型请求、列 MCP
工具、发 A2A 任务、TOIP 接入——只能手写 HTTP。`StationClient` 补上了这一半。

## Quick start / 快速上手

```python
from relayhub.client import StationClient, StationError

client = StationClient("http://192.168.1.10:8799", "rh_your_token")

# Model lanes / 模型四通道（Anthropic / OpenAI / Responses / Embeddings）
reply = client.messages({
    "model": "deepseek-chat", "max_tokens": 1024,
    "messages": [{"role": "user", "content": "ping"}],
})

# MCP gateway / MCP 网关
tools = client.mcp_list_tools()               # {"tools": [...]} — names carry channel prefix
result = client.mcp_call_tool("web.search", {"q": "relay-hub"})

# A2A routing / A2A 路由
card = client.a2a_card()                       # GET /.well-known/agent.json
reply = client.a2a_send("peer", {"role": "user", "parts": [{"type": "text", "text": "hi"}]})
```

### TOIP enrollment / TOIP 接入

```python
client = StationClient("http://192.168.1.10:8799")          # no token yet / 尚无令牌
payload = client.join(code="482913", name="my-etl-job")     # dynamic code or ticket
client.adopt(payload)                                        # token + baseURL + station id, one shot
who = client.session()                                       # who am I, how long left, usage
```

`adopt` 认三种令牌字段形态（顶层 `api_key` / `dsh.apiKey` / `session.token`），
根地址优先取 `station.base_url`；`dsh.baseURL` 是给 DSH Messages 适配器的
端点形态（带 `/v1` 后缀），仅在缺失前两者时收编并剥掉后缀——SDK 的路径
自带 `/v1` 前缀。

## E2E envelopes / E2E 信封

`e2e="auto"`（默认）：station 支持 E2E（`GET /v1/e2e/params` 可用且服务端装了
cryptography）就封信封，否则明文。`e2e="require"`：站点必须支持，否则拒绝发送。
`e2e="off"`：强制明文。

- Envelopes cover **all six JSON lanes**: messages / chat_completions /
  responses / embeddings / mcp / a2a — the station unwraps before dispatch.
  信封覆盖全部六条 JSON 通道，站点先解信封再走原链路。
- The HKDF salt is the **supplied credential string** — same rule as the
  server's `_supplied_credential()`. Same ciphertext under a different token
  will not decrypt. 盐取本次供应的凭证串，与服务端同口径；同一份密文换个
  令牌解不开。
- **Key rotation is transparent**: a station-side E2E identity rotation gets a
  400 (`key_id 不匹配`); the client refreshes params and re-seals once.
  站点轮换 E2E 身份后客户端清缓存重拉参数重封一次，用户无感。
- **No silent downgrade**: if the local machine cannot seal (cryptography
  missing) while the station supports E2E, auto mode raises instead of
  falling back to plaintext. 本机封不了信封就报错说清楚，绝不静默发明文。
- Streaming requests (`stream: true`) return the raw SSE text; the SDK does
  not parse streams. 流式请求返回原始 SSE 文本，SDK 不做流式解析。

Errors: HTTP 4xx/5xx and connection failures raise `StationError`
(`.status`, `.payload`; connection failures are `status=0`).
错误面：4xx/5xx 与连不上都抛 `StationError`（连接失败 status=0）。

## CLI cross-reference / CLI 对照

The same capabilities are scriptable without writing Python — the CLI talks
to the station the same way:

不动手写 Python 也能用命令行完成同一批事（CLI 与 SDK 同源同口径）：

| SDK | CLI (0.7.0 plans unless noted) |
|---|---|
| `join` + `adopt` | `hubrelay toip …`（已有，面向站点方） |
| `mcp_list_tools` / `mcp_call_tool` | — |
| `a2a_card` / `a2a_send` | — |

MCP / A2A client-side commands are SDK-first in 0.7.0; CLI surfaces follow
demand. MCP / A2A 客户端命令 0.7.0 以 SDK 为先，CLI 按需求跟进。

## Testing / 测试

`tests/test_client.py` (19 cases): version single-sourcing, `seal_envelope`
round-trip and credential binding, plain/E2E/auto-degrade/require-refuse,
key-rotation adaptation, TOIP join→adopt→session→models, MCP and A2A over
real gateways — including MCP over an envelope.
版本单一来源、seal→open 闭环与凭证绑定、明文/E2E/auto 降级/require 拒绝、
key 轮换自适应、TOIP 全流程、真网关上的 MCP 与 A2A（含信封形态）。
