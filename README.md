# relay-hub · Self-hosted LLM Relay / 局域网自托管大模型中转站

[![CI](https://github.com/bilibiliUID1480494301/relay-hub/actions/workflows/ci.yml/badge.svg)](https://github.com/bilibiliUID1480494301/relay-hub/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)

**English** | A self-hosted LLM relay/gateway: unify many upstreams (official API
keys, local self-hosted inference servers) behind one OpenAI/Anthropic-compatible
endpoint, with key-pool scheduling, downstream tokens, usage accounting, tiered
circuit breaking, and conformance probing. Pure Python standard library — zero
third-party runtime dependencies.

**中文** | 一个自托管的大模型中转站：把多家上游（官方 API Key、本地自托管推理服务）
统一成一个 OpenAI/Anthropic 兼容入口，带号池调度、下游令牌、用量记账、分级熔断和
一致性探测。纯 Python 标准库实现，零第三方运行时依赖。

## Features (English)

- **Upstream key pool**: multi-channel round-robin / least-failure / credit-aware
  scheduling; priority & weight (primary/backup); four-tier cooldown (quota /
  rate-limit / 5xx / auth-failure); hot reload.
- **Downstream tokens**: per-device tokens (one-api style) with model whitelist,
  RPM/daily limits, usage accounting; plaintext shown once, SHA-256 at rest.
- **Dual protocol + embeddings**: `POST /v1/messages` (Anthropic),
  `POST /v1/chat/completions` and `POST /v1/embeddings` (OpenAI) behind the same
  credential — RAG / text tools work out of the box.
- **Pairing**: out-of-band pairing codes (single-use, expiring) + optional LAN
  zero-input pairing.
- **TOIP dynamic-password onboarding**: a plugin joins with *just a URL + a
  rolling 6-digit code* (RFC 6238 TOTP) — no `pair begin`, no ticket to beg for.
  `/v1/toip/join` returns the session token, the exact `baseURL` to write, and
  the selectable model list in one call. LAN discovery (UDP v2 probe) already
  carries the TOIP capability, so a client can find the station and its join
  endpoint from a single broadcast.
- **Per-plugin log accounting**: each plugin gets its own log directory
  (`pluginlogs/<plugin_id>/`), written alongside — not instead of — the global
  request log. `X-DSH-Plugin-Id` tags the traffic; a TOIP-issued token is
  already bound to a plugin, so tagging works even without the header.
- **Admin console**: local web UI for channels / tokens / policies / request log /
  usage / audit / **plugins** / **dynamic password** — with an EN/中文 toggle in
  the header.
- **Conformance probe**: run compliance probes against any compatible gateway.
- **Request audit**: control-plane audit log and (redacted) request details.

## 功能 Features（中文）

- **上游号池** Upstream key pool：多渠道轮询/最少失败/额度感知调度，优先级与权重，
  四档分级冷却（额度耗尽 / 限流 / 5xx / 鉴权失效），热加载。
- **下游令牌** Downstream tokens：per-device 令牌（对标 one-api 的「令牌」），模型白名单、
  RPM/每日限额、用量记账，明文只在发放时出现一次。
- **多协议入口** Multi-protocol：`POST /v1/messages`（Anthropic）、
  `POST /v1/chat/completions`、`POST /v1/embeddings`、`POST /v1/responses`
  （OpenAI，含流式；新版 IDE/Agent 客户端开箱即用），同一令牌多种鉴权头都认。
- **配对发放** Pairing：带外配对码（成功即焚、限次）+ 可选的局域网免码配对。
- **TOIP 动态口令接入**：插件只要「一个网址 + 一枚滚动 6 位口令」（RFC 6238 TOTP）
  就能接入——不需要管理员先 `pair begin`，也不需要找人要配对码。
  `POST /v1/toip/join` 一次调用就回齐会话令牌、要写进客户端的 `baseURL`
  和可选模型清单。局域网发现（UDP v2 探测包）直接带上 TOIP 能力块，
  客户端一次广播就能拿到站点地址与接入入口。
- **按插件分账的插件日志**：每个插件一个目录（`pluginlogs/<插件 id>/`），
  与全局请求明细**并行**写而不是取代它。`X-DSH-Plugin-Id` 头是分账标签；
  TOIP 发出的令牌本身就绑定了插件，所以不带这个头也能分账。
- **管理控制台** Admin console：本地网页，管理渠道/令牌/策略/请求明细/用量/审计/**插件**/**动态口令**。
- **一致性探测** Conformance probe：对着任意兼容网关跑合规探测，抓出不合规实现。
- **请求审计** Request audit：控制面操作审计与请求明细（脱敏）。

## TOIP 动态口令接入 (English)

**TOIP** (Time-based One-time password Ingestion Protocol) is the onboarding
path built for *plugins* rather than for humans with a console. The older
pairing flow is deliberately manual and single-use; that is the right shape for
"a person adds a phone", and the wrong shape for "a plugin on ten machines
rejoins after a reinstall".

> Full wire specification (EN + 中文): [`docs/TOIP.md`](./docs/TOIP.md)

```bash
# 1) one-time, on the gateway: establish the station identity
hubrelay toip station --name lab-hub
#    prints the current 6-digit code and an otpauth:// URI (any TOTP app works)

# 2) one-time per device: issue a ticket (the enrollment secret is shown ONCE)
hubrelay toip ticket --name dsh-laptop --plugins dsh-relayhub-bridge

# 3) the plugin joins with either credential
#    ticket  -> first contact
#    code    -> rejoin (rotates the same token)
curl -s http://192.168.1.10:8799/v1/toip/join \
  -H 'content-type: application/json' \
  -d '{"code":"123456","plugin":"dsh-relayhub-bridge"}'
```

The response contains a `dsh` block ready for a DeepSeek Harness provider:

```json
{
  "protocol": "toip", "version": 1,
  "base_url": "http://192.168.1.10:8799",
  "models": [{"model_id": "deepseek-v4-pro", "context_window": 1000000}],
  "dsh": {
    "provider": "relayhub",
    "baseURL": "http://192.168.1.10:8799/v1",
    "apiKey": "rht_…",
    "models": [{"id": "deepseek-v4-pro", "contextWindow": 1000000}]
  },
  "session": {"token": "rht_…", "rotated": false},
  "otp": {"algorithm": "SHA1", "digits": 6, "period": 30, "seconds_left": 21.4}
}
```

`baseURL` always ends in `/v1`: the DeepSeek Messages adapter only appends `/v1`
when the path does **not** already end with it.

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /v1/toip/station` | none | Capability advertisement. **Never** contains the seed, a code, or a token. `404` when TOIP is off. |
| `POST /v1/toip/join` | code or ticket | Exchange a credential for a session token + onboarding payload. |
| `POST /v1/toip/enroll` | ticket only | First-contact enrollment (a code alone will not enroll a new plugin). |
| `GET /v1/toip/session` | token | Self-check: which plugin am I, when do I expire, how much have I used. |

Operational properties worth knowing:

- **Rotating the station secret does not disturb live plugins.**
  `hubrelay toip station --force` invalidates every *code* immediately, while
  already-issued session tokens keep working. That is the whole point of
  choosing a rotatable shared secret over a one-shot pairing code.
- **Joining is idempotent per device.** A code-based rejoin revokes the previous
  session token and issues a new one — plaintext tokens are only stored as
  SHA-256, so "issue it again" is the only honest way to hand one out twice.
- **Attempts are rate-limited per source IP** (8 per 5-minute window) and every
  rejection is written to the audit log as `toip.reject`.
- **The code lives 30 seconds** with ±1 window of clock-drift tolerance. A
  gateway and client whose clocks differ by more than 30 s will fail; the error
  message says so explicitly rather than blaming the key.

### Per-plugin logs

Each plugin gets `pluginlogs/<plugin_id>/<YYYYMMDD>.jsonl` (calls) plus
`events.jsonl` (enrollments, rotations, rejections) and a `schema.json`
self-description. The global `requests.<date>.jsonl` is still written, so
existing tooling keeps working — the two answer different questions:

| File | Subject | Answers | Rotation |
|---|---|---|---|
| `audit.jsonl` | admin actions | "who changed the config, when" | never (append-only) |
| `requests.<date>.jsonl` | token (device) | "how much did this device use" | daily |
| `pluginlogs/<id>/*` | plugin | "what did this plugin do overall" | daily + retention |

```bash
hubrelay toip logs list                       # every plugin with logs
hubrelay toip logs show dsh-relayhub-bridge   # events + summary + recent calls
hubrelay toip logs prune --days 30            # drop old call logs (events are kept)
hubrelay toip revoke dsh-laptop               # revoke ticket + reclaim its token
```

**DeepSeek Harness client:** the companion plugin
[`dsh-relayhub-bridge`](https://github.com/bilibiliUID1480494301/dsh-relayhub-bridge)
does the join for you and rides `X-DSH-Plugin-Id` on every request, which is what
makes the per-plugin accounting below work:

```bash
dsh plugin --profile <profile> add dsh-relayhub-bridge
```

Log lines are metadata only — model, dialect, status, token counts, latency, IP.
**Prompt and completion text are never written** (enforced by the writer's
signature and a key whitelist, both covered by tests).

## TOIP 动态口令接入（中文）

**TOIP**（Time-based One-time password Ingestion Protocol）是给**插件**准备的接入
通道，不是给「坐在控制台前的人」准备的。老的配对流程刻意做成手动 + 一次性——
那对「人给手机加一台设备」是对的，对「插件装在十台机器上、重装后要自己回来」
就是错的。

> 完整线协议规范（中英对照）：[`docs/TOIP.md`](./docs/TOIP.md)

```bash
# 1) 网关侧一次性：建立站点身份
hubrelay toip station --name lab-hub
#    打印当前 6 位口令与 otpauth:// 链接（手机上任一验证器 App 都能读）

# 2) 每台设备一次性：签一枚通行证（登记口令只显示这一次）
hubrelay toip ticket --name dsh-laptop --plugins dsh-relayhub-bridge

# 3) 插件拿任一凭证接入
#    ticket -> 首接
#    code   -> 重接（轮换同一枚令牌）
curl -s http://192.168.1.10:8799/v1/toip/join \
  -H 'content-type: application/json' \
  -d '{"code":"123456","plugin":"dsh-relayhub-bridge"}'
```

响应里的 `dsh` 块可以直接喂给 DeepSeek Harness 的 provider（见上方 JSON）。
`baseURL` 一定以 `/v1` 结尾——DSH 的 Messages 适配器只在 pathname **不**以
`/v1` 结尾时才补 `/v1`。

| 端点 | 鉴权 | 用途 |
|---|---|---|
| `GET /v1/toip/station` | 无 | 能力声明。**绝不含**种子、口令、令牌；未启用 TOIP 时 404。 |
| `POST /v1/toip/join` | 口令或通行证 | 换会话令牌 + 接入载荷。 |
| `POST /v1/toip/enroll` | 仅通行证 | 首接登记（只有动态口令不能登记新插件）。 |
| `GET /v1/toip/session` | 令牌 | 自查：我是哪个插件、何时过期、用了多少。 |

几个值得知道的运维性质：

- **轮换站点口令种子不影响正在跑的插件。** `hubrelay toip station --force`
  让所有**口令**立刻作废，而已经发出的会话令牌照常工作——这正是「可轮换的
  共享秘密」相对「一次性配对码」的全部价值。
- **接入是按设备幂等的。** 用口令重接会作废旧会话令牌并发新枚——令牌明文
  落盘只存 SHA-256，拿不回原文，所以「再发一次」是唯一诚实的做法。
- **按来源 IP 限次**（5 分钟窗口内 8 次），每次拒绝都写 `toip.reject` 审计。
- **口令 30 秒滚动**，容错 ±1 个窗口。网关与插件时钟相差超过 30 秒会失败，
  报错里会明说这一点，而不是把锅甩给密钥。

### 插件日志

每个插件有 `pluginlogs/<插件 id>/<YYYYMMDD>.jsonl`（调用流水）+
`events.jsonl`（登记/轮换/被拒）+ `schema.json`（目录自述）。全局
`requests.<日期>.jsonl` 仍然照写，老工具不受影响——两者回答不同问题：

| 文件 | 主语 | 回答 | 轮转 |
|---|---|---|---|
| `audit.jsonl` | 管理员动作 | 「谁什么时候改了配置」 | 不轮转（不可变） |
| `requests.<日>.jsonl` | 令牌（设备） | 「这台设备用了多少」 | 按天 |
| `pluginlogs/<id>/*` | 插件 | 「这个插件整体干了什么」 | 按天 + 保留期 |

```bash
hubrelay toip logs list                       # 列出所有有日志的插件
hubrelay toip logs show dsh-relayhub-bridge    # 接入事件 + 汇总 + 最近调用
hubrelay toip logs prune --days 30            # 清理过期流水（接入事件保留）
hubrelay toip revoke dsh-laptop               # 吊销通行证并收回其会话令牌
```

流水只记元数据：模型、协议、状态、token 数、延迟、IP。
**prompt 与 completion 文本永不落盘**（由写入函数的签名与键白名单双重保证，
两处都有测试钉住）。

## Highlights (English)

- **A2A routing (0.6.0)**: the station publishes an agent card
  (`/.well-known/agent.json`) and forwards `message/send` tasks to registered
  downstream agents (`hubrelay a2a add`). Cascade loop markers ride along, so
  two relay-hub stations chaining over A2A behave exactly like model relaying.
- **A2A 路由（0.6.0）见中文段 / see the Chinese section.**
- **E2E envelope encryption (0.5.0)**: opt-in end-to-end payload encryption
  between plugin and station — X25519 + HKDF-SHA256 + AES-256-GCM, per-request
  ephemeral keys, monotonic-nonce replay rejection, credentials bound into the
  key derivation. Optional extra (`hubrelay[e2e]`); plain traffic keeps working.
- **MCP gateway (0.5.0)**: the station speaks MCP (JSON-RPC 2.0). Upstream MCP
  servers are pooled like model channels (`hubrelay mcp add`), tools are
  namespaced `<channel>.<tool>`, and every call is accounted per downstream
  token x channel. Same auth, blacklist and E2E envelope as LLM traffic.
- **Cascading relays are first-class**: the loop marker is a per-boot random
  instance id (`relayhub-<hex8>`), so two parties both running relay-hub chain
  just fine (A's upstream = B's URL) — only a request that actually returns to
  the *same* instance is rejected. The hop ceiling is tunable
  (`RELAYHUB_MAX_HOPS`, default 4) for legitimately deeper cascades.
- **Secrets encrypted at rest**: upstream keys (`pool.json`) and the TOIP seed
  (`toip.json`) are sealed with Windows DPAPI (CurrentUser) — a stolen file on
  another machine/account is worthless. Legacy plaintext files upgrade on next
  save; non-Windows falls back to 0600 with a startup warning.
- **TOIP QR onboarding**: `hubrelay toip qr` prints the `otpauth://` QR in the
  terminal; the admin console has a "show enrollment QR" button (server-side
  PNG with the optional `qr` extra, audited per reveal).
- **Panel theming**: customize the `/panel` background (color / image URL)
  from the admin console, with strict allow-list validation (no CSS injection).
- **Three-layer loop protection**: forwarding chain markers (`Via` /
  `X-Relay-Hub-Hops` / `X-Request-ID`, accumulated per hop; a mark from this very
  instance immediately means a loop) + in-flight content-fingerprint counting at
  ingress + egress "same fingerprint × same upstream" time-window dedup. Works
  even when a third-party gateway in between rewrites parameters — built
  specifically for "upstream points back at itself" topologies.
- **Semantic-fingerprint response cache**: non-streaming 200 responses cached for
  5 minutes by a fingerprint over semantic fields only (model, normalized
  messages, tools, sampling params) — never link markers/auth/timestamps (they
  would kill every hit). Isolated per caller; cache hits never touch upstream nor
  pre-consume quota.
- **Cache accounting**: upstream cache hits (Anthropic's
  `cache_read/cache_creation_input_tokens`, OpenAI's `cached_tokens`) are folded
  into channel usage and the request log, visible in the admin console.
- **Pre-consume billing**: requests bound to a user first freeze an estimated
  quota by input size, then settle on actual usage; upstream failure refunds in
  full — closes the "send a huge prompt, disconnect midway, get upstream for
  free" hole.
- **Queue, don't reject**: when concurrency is full, requests enter a VIP/normal
  dual waiting pool (priority devices/IPs may jump the queue); 429 only when the
  queue is full or times out. Stacked with per-IP and per-token RPM limits.
- **Local inference scan**: one call discovers Ollama / LM Studio / vLLM /
  llama.cpp and imports them into the pool, scheduled/broken-in/accounted exactly
  like official API channels.

## 特色 Highlights（中文）

- **A2A 路由（0.6.0）**：站点发布 agent card（`/.well-known/agent.json`），
  `message/send` 任务转发到注册的下游 agent（`hubrelay a2a add`）——级联判环
  头原样随行，两家中转站经 A2A 串联的行为与模型中转完全一致。
- **E2E 信封加密（0.5.0）**：插件↔中转站载荷端到端加密（可选启用）——
  X25519 + HKDF-SHA256 + AES-256-GCM，每请求一次性密钥，单调 nonce 拒重放，
  凭证参与密钥派生（信封与身份绑定）。可选依赖 `hubrelay[e2e]`，明文流量照常。
- **MCP 网关（0.5.0）**：站点说 MCP（JSON-RPC 2.0）。上游 MCP server 像模型
  渠道一样入池（`hubrelay mcp add`），工具名 `<渠道>.<工具>` 前缀防撞，
  每次调用按下游令牌 × 渠道记账——鉴权、拉黑、E2E 信封与 LLM 流量同一套。
- **级联中继是一等公民**：判环标记是每次启动随机生成的唯一实例 id
  （`relayhub-<hex8>`），两家都部署 relay-hub 时 A 的上游指 B 完全没问题——
  只有请求真的绕回**同一个**实例才判环。级联更深时用 `RELAYHUB_MAX_HOPS`
  （默认 4）放宽跳数上限。
- **落盘凭证加密**：上游密钥（pool.json）与 TOIP 口令种子（toip.json）用
  Windows DPAPI（当前用户域）加密——文件被拷到别的机器/账户等于废纸；历史
  明文文件下次保存自动升级；非 Windows 诚实降级 0600 + 启动警告。
- **TOIP 扫码接入**：`hubrelay toip qr` 终端直接打印 otpauth 二维码；管理台
  有「显示扫码登记」按钮（装可选 `qr` 扩展出 PNG 图，每次下发都留审计）。
- **面板外观自定义**：管理台配置 `/panel` 背景（纯色 / 图片 URL），入参
  白名单严格校验，拒绝 CSS 注入。
- **三层防环路** Loop protection：转发链路标识（`Via` / `X-Relay-Hub-Hops` /
  `X-Request-ID`，逐跳累加，本站实例标记一现即判环）+ 入口请求内容指纹在飞计数 +
  出口「同指纹 × 同上游」时间窗查重。就算中间隔了会改写参数的第三方网关也能兜住，
  专治「上游指回自己」的拓扑环。
- **语义指纹应答缓存** Response cache：非流式 200 应答按语义指纹缓存 5 分钟——指纹只含
  模型、规范化 messages、tools、采样参数等语义字段，绝不混入链路标识/鉴权/时间戳
  （否则永不命中）；按调用者隔离，不跨用户串答案；命中即回、不触上游、不预扣额度。
- **缓存记账** Cache accounting：上游 usage 中的缓存命中量（Anthropic 的
  `cache_read/cache_creation_input_tokens`、OpenAI 的 `cached_tokens` 折算）记入
  渠道用量与请求明细，管理控制台直接可见。
- **额度预扣与多退少补** Pre-consume：绑定用户的请求先按输入体量预估冻结额度，
  完工后按实际用量结算，上游失败全额退——堵「发大 prompt 中途断开白嫖上游」的洞。
- **排队而非硬拒** Concurrency gate：并发满员进入 VIP/普通双等待池排队（优先名单
  设备/IP 插队），队满或超时才 429；叠加单 IP 与令牌双层 RPM 限流。
- **本机推理服务扫描** Local scan：Ollama / LM Studio / vLLM / llama.cpp 等一键扫进号池，
  与官方 API 渠道同权参与调度、熔断与记账。

## Quick Start (English)

> ⚠️ **Note**: the `relay-hub` package **on PyPI belongs to someone else** and has
> nothing to do with this repo — do NOT `pip install relay-hub`.
> Our distribution name on PyPI is **`hubrelay`**.

```bash
pip install hubrelay          # install from PyPI (recommended)
# or from source: pip install git+https://github.com/bilibiliUID1480494301/relay-hub.git

# 1) create a key pool and add an upstream key
python -m relayhub.gateway pool init
python -m relayhub.gateway pool add --base-url https://api.example.com \
  --api-key sk-xxx --protocol openai-chat --model my-model

# 2) start the relay
python -m relayhub.gateway serve --pool pool.json --api-key rh_master

# 3) (optional) local web admin console
python -m relayhub.gateway admin
```

More subcommands (`token` / `clients` / `pair` / `toip` / `audit` / `check` / `scan` /
`requests` / `usage`) — see each one's `--help`.

## 快速开始 Quick Start（中文）

> ⚠️ **注意**：PyPI 上的 `relay-hub` 是**别人的同名项目**，与本仓库无关，请勿
> `pip install relay-hub`。本项目在 PyPI 上的分发名是 **`hubrelay`**。

```bash
pip install hubrelay          # PyPI 安装（推荐）
# 或源码安装：pip install git+https://github.com/bilibiliUID1480494301/relay-hub.git

# 1) 建号池并添加一个上游 Key
python -m relayhub.gateway pool init
python -m relayhub.gateway pool add --base-url https://api.example.com \
  --api-key sk-xxx --protocol openai-chat --model my-model

# 2) 启动中转站
python -m relayhub.gateway serve --pool pool.json --api-key rh_master

# 3)（可选）本地网页控制台
python -m relayhub.gateway admin
```

更多子命令（`token` / `clients` / `pair` / `toip` / `audit` / `check` / `scan` / `requests` /
`usage`）见各自主命令的 `--help`。

## Provider Presets (English)

```python
import hubrelay
st.add_upstream(provider="deepseek", api_key="sk-…")   # one line per vendor
st.add_upstream(provider="kimi", api_key="sk-…")       # aliases: kimi/qwen/glm …
print(hubrelay.list_providers())                        # 16 built-in presets
```

Built-ins include openai / deepseek / moonshot(kimi) / zhipu(glm) /
dashscope(qwen) / openrouter / siliconflow / groq / mistral / together /
fireworks / xai and local servers (ollama / lmstudio / vllm / llamacpp).
`add_upstream` also exposes `model_mapping`, `extra_headers` and `auth_mode`;
explicit version paths in `base_url` (e.g. zhipu's `/api/paas/v4`) are respected.
`Station` additionally offers `stats()` (channel health / circuit breaker),
`request_logs(limit)` and `usage_summary()`.
Note: `/v1/responses` uses protocol normalization (same approach as one-api /
new-api); text & streaming work end to end, function-call round-trips are on
the roadmap.

## 渠道预设（中文）

```python
st.add_upstream(provider="deepseek", api_key="sk-…")   # 一行接一家
print(hubrelay.list_providers())                        # 内置 16 个预设
```

内置 openai / deepseek / moonshot(kimi) / zhipu(glm) / dashscope(qwen) /
openrouter / siliconflow / groq / mistral / together / fireworks / xai 以及
本机推理（ollama / lmstudio / vllm / llamacpp）。`add_upstream` 同时暴露
`model_mapping`（对外名→上游名）、`extra_headers`、`auth_mode`；base_url 里
显式写了版本路径（如智谱 `/api/paas/v4`）会被原样尊重。`Station` 另有
`stats()`（渠道健康/熔断）、`request_logs(limit)`、`usage_summary()`。
说明：`/v1/responses` 采用与 one-api / new-api 相同的协议归一化思路实现，
文本与流式已完整支持，function call 往返在路线图上。

## Provider Presets (English)

```python
import hubrelay
st.add_upstream(provider="deepseek", api_key="sk-…")   # one line per vendor
st.add_upstream(provider="kimi", api_key="sk-…")       # aliases: kimi/qwen/glm …
print(hubrelay.list_providers())                        # 16 built-in presets
```

Built-ins include openai / deepseek / moonshot(kimi) / zhipu(glm) /
dashscope(qwen) / openrouter / siliconflow / groq / mistral / together /
fireworks / xai and local servers (ollama / lmstudio / vllm / llamacpp).
`add_upstream` also exposes `model_mapping`, `extra_headers` and `auth_mode`;
explicit version paths in `base_url` (e.g. zhipu's `/api/paas/v4`) are respected.
`Station` additionally offers `stats()` (channel health / circuit breaker),
`request_logs(limit)` and `usage_summary()`.
Note: `/v1/responses` uses protocol normalization (same approach as one-api /
new-api); text & streaming work end to end, function-call round-trips are on
the roadmap.

## 渠道预设（中文）

```python
st.add_upstream(provider="deepseek", api_key="sk-…")   # 一行接一家
print(hubrelay.list_providers())                        # 内置 16 个预设
```

内置 openai / deepseek / moonshot(kimi) / zhipu(glm) / dashscope(qwen) /
openrouter / siliconflow / groq / mistral / together / fireworks / xai 以及
本机推理（ollama / lmstudio / vllm / llamacpp）。`add_upstream` 同时暴露
`model_mapping`（对外名→上游名）、`extra_headers`、`auth_mode`；base_url 里
显式写了版本路径（如智谱 `/api/paas/v4`）会被原样尊重。`Station` 另有
`stats()`（渠道健康/熔断）、`request_logs(limit)`、`usage_summary()`。
说明：`/v1/responses` 采用与 one-api / new-api 相同的协议归一化思路实现，
文本与流式已完整支持，function call 往返在路线图上。

## Python API (English)

```python
import hubrelay

st = hubrelay.Station(port=8799, master_key="rh_master")  # loopback-only by default
print(hubrelay.scan_local())     # find Ollama / LM Studio / vLLM / llama.cpp locally
st.scan_and_import()             # import discovered servers into the key pool

st.add_upstream(base_url="https://api.example.com/v1",
                api_key="sk-xxx", models=["gpt-4o", "gpt-4o-mini"])  # protocol auto-guessed

token = st.create_token("my-phone", rpm=60)  # plaintext shown exactly ONCE (SHA-256 on disk)
st.set_token_enabled("my-phone", False)      # pause without revoking; remove_token() to revoke
st.set_upstream_enabled("up-1", False)       # take a channel offline for maintenance
print(st.usage())                            # aggregated usage snapshot

url = st.serve(background=True)  # non-blocking; st.stop() to shut down
```

One-liner: `st, url = hubrelay.quickstart("http://127.0.0.1:11434", models=["qwen2.5"])`.
Every method carries bilingual (EN/中文) docstrings; pool & token files are fully
interchangeable with the CLI.

## Python API 建站（中文，不想碰命令行看这里）

```python
import hubrelay

st = hubrelay.Station(port=8799, master_key="rh_master")  # 建站（默认仅本机可访问）
print(hubrelay.scan_local())     # 扫描本机推理服务（Ollama / LM Studio / vLLM / llama.cpp）
st.scan_and_import()             # 扫到的一键入池

st.add_upstream(base_url="https://api.example.com/v1",
                api_key="sk-xxx", models=["gpt-4o", "gpt-4o-mini"])  # 协议自动识别

token = st.create_token("我的手机", rpm=60)  # 明文只在发放这一次显示（落盘为 SHA-256）
st.set_token_enabled("我的手机", False)      # 临时停用；remove_token() 吊销
st.set_upstream_enabled("up-1", False)       # 渠道停用维护
print(st.usage())                            # 聚合用量快照

url = st.serve(background=True)  # 非阻塞；st.stop() 停站
```

一行版：`st, url = hubrelay.quickstart("http://127.0.0.1:11434", models=["qwen2.5"])`。
号池/令牌文件与 CLI 完全互通（`Station(home=...)` 对应 CLI 的 `--pool/--tokens`）。

## Docker (English)

```bash
docker compose up -d
docker compose exec relay hubrelay token add my-phone   # issue a token
curl http://127.0.0.1:8799/v1/models -H "Authorization: Bearer <token>"
```

All state (pool / tokens / logs) lives in the mounted `./data` volume; the
server-side safety gate is unchanged — `--public` refuses to start without
credentials.

## Docker（中文）

`docker compose up -d` 一条命令起站；号池 / 令牌 / 日志全部落在挂载的 `./data`
卷里，换机器搬目录即迁移。服务端安全闸不变：`--public` 无凭证拒绝启动。
建议先 `docker compose exec relay hubrelay token add my-phone` 发一枚令牌。

Health: `GET /healthz` (no credentials) is wired into the image `HEALTHCHECK`;
request logs auto-prune after 30 days (`--log-retention-days`, 0 = keep forever).

健康检查：镜像内置 `HEALTHCHECK` 打 `/healthz`（无需凭证）；请求明细默认保留
30 天自动清理（`--log-retention-days` 调整，0=永久）。`/v1/models` 现在按令牌
白名单过滤——受限令牌只看到自己能用的模型。

Health: `GET /healthz` (no credentials) is wired into the image `HEALTHCHECK`;
request logs auto-prune after 30 days (`--log-retention-days`, 0 = keep forever).

健康检查：镜像内置 `HEALTHCHECK` 打 `/healthz`（无需凭证）；请求明细默认保留
30 天自动清理（`--log-retention-days` 调整，0=永久）。`/v1/models` 现在按令牌
白名单过滤——受限令牌只看到自己能用的模型。

## Doctor 环境自检 (English)

```bash
hubrelay doctor          # python / data root / pool & tokens / local inference / port / firewall
hubrelay doctor --json   # machine-readable
```

Or from Python: `hubrelay.doctor(port=8799)` → list of `{name, ok, detail, fix}`.

## Doctor 环境自检（中文）

一条命令体检建站环境：Python 版本、数据目录可写、号池与令牌状态、本机推理服务
（Ollama / LM Studio / vLLM / llama.cpp）、端口占用、Windows 防火墙提示——每项
带 ✓/✗ 与可执行的修复建议；`--json` 供脚本消费，API 里是 `hubrelay.doctor()`。

## Troubleshooting (English)

- **Windows firewall prompt on first listen / LAN devices can't connect?**
  Windows Defender blocks the listen port the first time: click "Allow access";
  if you already clicked cancel, re-enable it under Windows Security → Firewall →
  Allow an app through firewall (both private/public for Python). Starting with
  `--discover` (UDP 8795) triggers its own prompt.
- **Phone can't reach `http://192.168.x.x:8799`?** The default binds to loopback
  (localhost only). For LAN use `serve --host 0.0.0.0 --public` (credentials
  required — the safety gate), or `Station(host="0.0.0.0")` in the Python API.
- **Client gets an empty model list?** No key in the pool declares models
  (`pool add --model` or `scan_and_import()`), or the token's model whitelist
  doesn't include it.
- **`import hubrelay` fails after install?** Upgrade to ≥ 0.2.3
  (`pip install -U hubrelay`); 0.2.1/0.2.2 were broken releases (now yanked).

## 常见问题 Troubleshooting（中文）

- **Windows 首次起站弹防火墙提示 / 局域网设备连不上？** Windows Defender 首次会拦截
  监听端口：弹窗时点「允许访问」；如果已点过取消，到「Windows 安全中心 → 防火墙 →
  允许应用通过防火墙」里勾选 Python 的专用/公用网络。只开 `--discover`（UDP 8795）
  时也会触发一次弹窗。
- **手机连不上 `http://192.168.x.x:8799`？** 默认只绑回环（本机）。给局域网用要
  `serve --host 0.0.0.0 --public`（必须已配 master key 或下游令牌——安全闸），
  Python API 里则 `Station(host="0.0.0.0")`。
- **客户端拉不到模型列表？** 号池里没有任何 Key 声明模型（`pool add --model` 或
  `scan_and_import()`），或该下游令牌的模型白名单没包含它。
- **装了 hubrelay 但 `import hubrelay` 报错？** 请升级到 ≥ 0.2.3
  （`pip install -U hubrelay`）；0.2.1/0.2.2 是坏版本（已 yank）。

## Requirements (English)

- Python 3.10+ (standard library only, no dependencies)
- Windows / macOS / Linux

## 运行环境 Requirements（中文）

- Python 3.10+（仅标准库，零依赖）
- Windows / macOS / Linux

## Security Notes (English)

- Upstream keys are stored as plaintext JSON in the local pool file (same as most
  clients); protect file permissions and disk encryption yourself, and **never**
  commit the pool file to version control or share it.
- Before binding a non-loopback address (LAN/public), the gateway REQUIRES
  credentials (master key or at least one downstream token); all traffic must
  carry credentials.
- The admin console binds to loopback by default; binding elsewhere requires an
  explicit `--token`.
- **TOIP**: the station secret (`toip.json`) grants the ability to mint valid
  codes — it stays on the gateway, is never sent to a browser, and is not in the
  admin API. Tickets are stored as SHA-256 only, and the enrollment secret is
  printed exactly once at `toip ticket`. Over plain HTTP a code or token is
  visible to anyone on the same segment (same residual risk as pairing codes);
  put TLS in front for untrusted networks. Rotate the secret with
  `toip station --force` — live session tokens survive it.
- Suspected key leak? Revoke immediately (`token rm` / rotate upstream keys).

## 安全须知 Security Notes（中文）

- 上游 Key 以明文 JSON 存放在本地号池文件中（与常见客户端做法一致）；请自行做好
  文件权限与磁盘加密，**不要**把号池文件提交进版本库或分享给他人。
- 绑定非回环地址（公网/局域网）前，网关强制要求已配置凭证（master Key 或下游令牌），
  且所有流量都必须携带凭证。
- 管理控制台默认只监听回环地址；绑非回环地址必须显式提供 `--token`。
- **TOIP**：站点口令种子（`toip.json`）等于「能算出所有有效口令」的能力，它只留在
  网关磁盘上，不下发浏览器、不进管理 API。通行证只存 SHA-256，登记口令只在
  `toip ticket` 打印一次。走明文 HTTP 时，同网段的人能看到口令与令牌（与配对码
  相同的残余风险）；不可信网络请在前面加 TLS。轮换种子用
  `toip station --force`——已发出的会话令牌不受影响。
- 遇到疑似密钥泄露请立即吊销（`token rm` / 更换上游 Key）。

## Disclaimer 免责声明

> **English**: This project is provided for learning, research, and personal
> self-hosting purposes only. You are solely responsible for ensuring that your
> use complies with applicable laws and regulations in your jurisdiction as well
> as the terms of service of any upstream services you connect to. The software
> is provided "AS IS", without warranty of any kind. In no event shall the
> authors be liable for any claim, damages, or other liability arising from the
> use of this software. Any risk arising from use in violation of upstream terms
> of service rests solely with the user.

> **中文**：本项目仅供学习、研究与个人自托管用途。使用者应自行确保其使用行为符合
> 所在地区法律法规，以及其接入的上游服务的用户协议与服务条款。本项目按「现状」提供，
> 不附带任何明示或暗示的担保；作者不对任何人因使用本项目而产生的直接或间接损失负责。
> 请勿将本项目用于任何违反上游服务条款或损害第三方权益的用途，由此产生的一切风险与
> 责任由使用者自行承担。

## License 许可证

[MIT](./LICENSE)
