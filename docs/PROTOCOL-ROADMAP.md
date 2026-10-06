# Protocol Roadmap — MCP Gateway & A2A Routing / 协议路线图 — MCP 网关与 A2A 路由

**Status / 状态**: design · 排期 0.5.x（与 E2E 信封实现同批，见 E2E-ENCRYPTION.md）

## Threat model recap / 威胁模型回顾（抓包能拿到什么）

```
plugin ──(downstream token)──▶ relay-hub station ──(upstream sk-***)──▶ real upstream
          wire-visible              wire-visible:            NEVER crosses the wire
                                   payload + station's own
                                   credentials
```

* Upstream keys never leave the station (and since 0.4.0 they are DPAPI-sealed
  at rest). Sniffing the plugin↔station wire yields **prompt contents and the
  downstream token — not upstream keys**.
* E2E envelope (0.5.x) closes the remaining two holes: payload confidentiality
  and token replay (monotonic nonce per session).
* 上游密钥从不过网、落盘已加密：抓包插件↔中转站的流量只能看到 prompt 内容与
  下游令牌，看不到上游密钥。E2E 信封补掉剩下两个洞——内容机密性与令牌重放。

## One wire, three protocols / 一条线缆，三种协议

| Surface | Endpoint | Payload | Accounting |
|---|---|---|---|
| LLM relay (shipped) | `POST /v1/messages`, `/v1/chat/completions`, `/v1/embeddings` | Anthropic / OpenAI | tokens per key/token |
| MCP gateway (0.5.x) | `POST /mcp` (JSON-RPC 2.0), `/mcp/sse` | tool calls / resources | per tool call, per downstream token |
| A2A routing (0.5.x+) | `GET /.well-known/agent.json`, `POST /a2a/tasks` | agent card + task envelope | per task, per agent identity |

The E2E envelope (`application/x-relayhub-envelope+json`) is transport-level
and protocol-agnostic: the same session key derived at TOIP join protects all
three surfaces. Auth, blacklist/allow-list, RPM limits and per-plugin log
accounting are data-plane features and apply unchanged.
信封协议在传输层、与具体协议无关：TOIP join 派生的同一把会话密钥保护三种
端点；鉴权、拉黑/白名单、RPM 限流、按插件分账都是数据面能力，原样复用。

## MCP gateway design / MCP 网关设计

* **Server side / 服务端**: relay-hub speaks JSON-RPC 2.0 over HTTP/SSE —
  `initialize`, `tools/list`, `tools/call`, `resources/*`. stdlib-only
  (we already run SSE for streaming). Upstream MCP servers are registered in
  the pool like model channels: `hubrelay mcp add <name> <url> [--header ...]`.
  中转站自己说 MCP：JSON-RPC 2.0 over HTTP/SSE，纯标准库（流式 SSE 已有）。
  上游 MCP server 像模型渠道一样入池：`hubrelay mcp add <名称> <地址>`。
* **Tool catalogue / 工具目录**: `tools/list` aggregates upstream tools with
  the channel prefix (`<channel>.<tool>`), so two upstreams exposing the same
  tool name never collide. 下游看到的工具名带渠道前缀，多上游同名工具不冲突。
* **Accounting / 记账**: every `tools/call` is logged per downstream token and
  per channel (the same plugin-logs discipline as LLM calls); upstream errors
  surface as JSON-RPC errors, never as crashes.
  每次 tools/call 按下游令牌与渠道双维记账（与 LLM 的插件日志同一纪律）。
* **Already half-built / 已有雏形**: the AnySearch MCP integration
  (`searchrelay`) becomes the first registered upstream MCP channel.
  现有 AnySearch 集成（searchrelay）迁为第一个 MCP 渠道。

## A2A routing design / A2A 路由设计

* **Agent card / 智能体卡片**: `/.well-known/agent.json` advertises this
  station as an A2A server; skills are derived from configured routes
  (model routes → `text-generation` skill; MCP tools → per-tool skills).
  站点对外发布 agent card；skills 由配置的路由自动派生。
* **Task routing / 任务路由**: `tasks/send` forwards to a configured
  downstream agent (another relay-hub station or any A2A-speaking agent),
  mapped onto the existing cascading-relay machinery — instance markers,
  hop ceiling and loop detection apply unchanged.
  `tasks/send` 转发到配置的下游 agent（可以是另一家 relay-hub），直接复用
  级联中继那套机制：实例标记、跳数上限、判环全部原样生效。
* **Identity / 身份**: A2A callers authenticate with downstream tokens like
  any other client; per-agent identities get their own token so accounting
  and blacklist work per agent, not per IP.
  A2A 调用方与普通客户端一样用下游令牌鉴权；每个 agent 身份发独立令牌，
  记账与拉黑按 agent 维度而不是按 IP。

## Ordering / 实施顺序

1. 0.5.0 — E2E envelope (station + plugin) per E2E-ENCRYPTION.md.
2. 0.5.x — MCP gateway: JSON-RPC endpoint, channel registration, tool
   catalogue + accounting; migrate `searchrelay` as the first channel.
3. 0.6.x — A2A: agent card, task routing over the cascade machinery.

实施顺序：先 E2E 信封（它是三协议共用的保护层），再 MCP 网关（雏形已备），
最后 A2A（复用级联机制，增量最小）。
