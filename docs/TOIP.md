# TOIP — Time-based One-time password Ingestion Protocol

**English** · [中文往下翻](#toip-中文)

TOIP is the onboarding protocol this gateway speaks so that a **plugin** can
join a relay station knowing only a station address and a rotating 6-digit
code. It is deliberately separate from the older pairing flow
(`POST /v1/pair`), which is manual and single-use by design.

- Protocol id: `toip`, version `1`
- Credential: an RFC 6238 TOTP code (SHA-1, 6 digits, 30 s period)
- Transport: HTTP/1.1, `application/json`, UTF-8
- Dependencies: none (Python standard library on the server side; the client
  needs only `fetch` plus an HMAC-SHA1 implementation)

---

## 1. Discovery (optional, LAN only)

The station can answer UDP broadcast probes on a configurable port
(default `8795`).

| Probe payload (ASCII) | Reply contains `toip` block |
|---|---|
| `RELAYHUB-DISCOVER-v1` | no |
| `RELAYHUB-DISCOVER-v2` | yes |

A `v2` reply is a JSON object:

```json
{
  "protocol": "relay-hub",
  "name": "lab-hub",
  "port": 8799,
  "models": 3,
  "pairing": false,
  "toip": {
    "enabled": true,
    "protocol": "toip",
    "version": 1,
    "station_id": "rst_f0aab35bb25108f7",
    "join": "/v1/toip/join",
    "station": "/v1/toip/station"
  }
}
```

Rules:

- The reply **omits the host**: the client must use the UDP source address,
  because a multi-homed gateway cannot know which of its addresses is reachable.
- Paths in `toip` are relative to the HTTP root. Resolve them against
  `http://<source-address>:<port>`.
- Discovery only advertises capability. It **never** contains a seed, a code, or
  a token. If `toip.enabled` is false or the field is absent, fall back to
  `POST /v1/pair`.
- Cross-subnet stations cannot be discovered; use a configured base URL.

## 2. `GET /v1/toip/station`

Public capability probe. No credentials.

`200`:

```json
{
  "protocol": "toip",
  "version": 1,
  "enabled": true,
  "station_id": "rst_…",
  "name": "lab-hub",
  "base_url": "http://192.168.1.10:8799",
  "otp": {"algorithm": "SHA1", "digits": 6, "period": 30, "window": 1},
  "session_ttl": 7776000,
  "endpoints": {
    "station": "/v1/toip/station",
    "enroll": "/v1/toip/enroll",
    "join": "/v1/toip/join",
    "session": "/v1/toip/session",
    "messages": "/v1/messages",
    "chat": "/v1/chat/completions",
    "models": "/v1/models"
  }
}
```

`404` when TOIP is not enabled on this station.

Clients MUST NOT expect the seed here. `otp` describes how to *compute* a code;
the shared secret is provisioned out of band by the operator.

## 3. `POST /v1/toip/enroll` (first contact)

Requires a **ticket** — the one-time enrollment secret printed by
`hubrelay toip ticket`. A rotating code alone cannot enroll a new plugin.

```json
{"ticket": "rhe_…", "plugin": "dsh-relayhub-bridge", "plugin_version": "0.1.0",
 "name": "optional device name", "client": "dsh"}
```

`plugin` is required. It is a **log-accounting label**, not a credential:
allowed characters are lowercase letters, digits, `.`, `_`, `-`; it may not
start or end with `.` and may not contain `..` (it becomes a directory name).

## 4. `POST /v1/toip/join` (rejoin / rotate)

```json
{"code": "123456", "plugin": "dsh-relayhub-bridge"}
```

Send **either** `ticket` (equivalent to `/enroll`) **or** `code`. Sending both
is accepted; `ticket` wins.

`200` response (abridged):

```json
{
  "protocol": "toip",
  "version": 1,
  "client": "dsh",
  "display_name": "dsh-laptop",
  "inbound": "anthropic-messages",
  "endpoint": "/v1/messages",
  "base_url": "http://192.168.1.10:8799",
  "models": [{"model_id": "deepseek-v4-pro", "context_window": 1000000}],
  "station": {"id": "rst_…", "base_url": "http://192.168.1.10:8799"},
  "plugin": {
    "id": "dsh-relayhub-bridge",
    "version": "0.1.0",
    "join_path": "/v1/toip/join",
    "session_path": "/v1/toip/session",
    "headers": {
      "plugin_id": "X-DSH-Plugin-Id",
      "plugin_version": "X-DSH-Plugin-Version",
      "station_id": "X-Relayhub-Station-Id"
    }
  },
  "session": {"token": "rht_…", "token_hint": "…a1b2", "expires_at": 1798968048.9, "rotated": false},
  "dsh": {
    "provider": "relayhub",
    "baseURL": "http://192.168.1.10:8799/v1",
    "apiKey": "rht_…",
    "models": [{"id": "deepseek-v4-pro", "contextWindow": 1000000}]
  },
  "otp": {"algorithm": "SHA1", "digits": 6, "period": 30, "seconds_left": 21.4}
}
```

Client obligations:

1. Persist `session.token` as the API key. It is shown once; the server keeps
   only SHA-256.
2. Use `dsh.baseURL` **verbatim**. It already ends in `/v1`; the DeepSeek
   Messages adapter appends `/v1` only when the path does not already end with
   it, so this value is the only unambiguous spelling.
3. Send `X-DSH-Plugin-Id` (and `X-DSH-Plugin-Version` if known) on inference
   requests to be accounted per plugin. The token is already bound to the
   plugin, so logs work without the header — but the header disambiguates
   several plugins sharing one machine.
4. Never derive the code from anything in this response. The seed is not here.

`rotated` is `true` when the station revoked a previously issued session token
for this device and issued a new one. Both are normal; treat it as
informational.

## 5. `GET /v1/toip/session`

Authenticated with the session token (`X-Api-Key: rht_…` or
`Authorization: Bearer rht_…`).

```json
{
  "protocol": "toip", "version": 1,
  "station_id": "rst_…", "token_name": "dsh-laptop",
  "plugin_id": "dsh-relayhub-bridge",
  "expires_at": 1798968048.9, "expires_in": 7775999.9,
  "models": [],
  "usage": {"requests": 12, "ok": 12, "failed": 0, "tokens_in": 340, "tokens_out": 902}
}
```

Use it as a cheap liveness/identity check. `expires_in` of `0` with a non-zero
`expires_at` means expired — re-join with a fresh code.

## 6. Computing the code

RFC 6238 / RFC 4226 HOTP truncation:

```
counter = floor(unix_seconds / 30)
mac     = HMAC-SHA1(secret, counter as 8-byte big-endian)
offset  = mac[19] & 0x0F
code    = (mac[offset..offset+3] as uint32 & 0x7FFFFFFF) mod 10^6
```

The `secret` is provisioned by the operator (`hubrelay toip station` prints an
`otpauth://` URI; any TOTP app can read it, and the plugin can accept the same
base32 secret).

The server accepts the current window and ±1 window (`window: 1`), so clock
drift up to 30 s is tolerated. Drift beyond that fails — surface a
"check your clock" hint rather than a credentials error.

## 7. Errors

Errors use the OpenAI-shaped envelope:

```json
{"error": {"type": "permission_error", "message": "动态口令不正确或已过期（…）"}}
```

| Status | `type` | Meaning | Client action |
|---|---|---|---|
| `400` | `invalid_request_error` | Missing `plugin`, missing ticket for `/enroll`, or code expired | Fix the request; prompt for a fresh code |
| `403` | `permission_error` | Wrong/expired code, revoked or disabled ticket, plugin not on the ticket's allow-list, or too many attempts | Re-prompt; after a lockout wait ~5 min |
| `404` | `not_found_error` | TOIP not enabled on this station | Fall back to `POST /v1/pair` |
| `401` | `authentication_error` | `/session` called without/with a bad token | Re-join |

Rate limiting: **8 failed joins per source IP per 5 minutes**, then `403` until
the window rolls. Every rejection is recorded in the station audit log as
`toip.reject`.

## 8. Recommended client flow

```
1. If the user gave a URL   -> GET /v1/toip/station   (confirm enabled, learn params)
   else                     -> UDP v2 broadcast       (LAN discovery)
2. If no session token:
     a. If a ticket is configured  -> POST /v1/toip/enroll
     b. Else if a code is available -> POST /v1/toip/join  {code}
3. Persist session.token + dsh.baseURL + model list.
4. On every inference request, attach the plugin identity headers.
5. On 401 from the inference endpoint, clear the token and go to step 2b.
```

Keep the local join/scan attempts in a small client-side log. The server logs
the traffic, but "why did my plugin fail to join at 09:14" is only answerable
on the client side.

---

# TOIP 中文

TOIP 是本网关为了让**插件**只需要「一个站点地址 + 一枚滚动 6 位口令」就能接入
而定义的接入协议。它与老的配对流程（`POST /v1/pair`）刻意分开：后者按设计就是
手动、一次性的。

- 协议标识：`toip`，版本 `1`
- 凭证：RFC 6238 TOTP 口令（SHA-1、6 位、30 秒步长）
- 传输：HTTP/1.1，`application/json`，UTF-8
- 依赖：无（服务端只用 Python 标准库；客户端只需 `fetch` 与 HMAC-SHA1）

## 1. 发现（可选，仅局域网）

站点会在可配置端口（默认 `8795`）应答 UDP 广播探测。

| 探测报文（ASCII） | 应答是否含 `toip` 块 |
|---|---|
| `RELAYHUB-DISCOVER-v1` | 否 |
| `RELAYHUB-DISCOVER-v2` | 是 |

`v2` 应答（见上方英文部分的 JSON 示例）。规则：

- 应答**不含 host**：客户端必须用 UDP 来源地址，因为多网卡网关无法知道哪个
  地址对探测方可达。
- `toip` 里的路径相对 HTTP 根，请拼在 `http://<来源地址>:<port>` 之后。
- 发现只声明能力，**绝不含**种子、口令、令牌。`toip.enabled` 为 false 或缺字段时
  回退到 `POST /v1/pair`。
- 跨网段无法发现，请直接配置 base URL。

## 2. `GET /v1/toip/station`

公开能力探测，无需凭证。`200` 返回能力（含 `otp` 参数与端点表），未启用 TOIP
的站点返回 `404`。

客户端**不要**指望这里能拿到种子：`otp` 只说明「怎么算口令」，共享秘密由管理员
带外配置。

## 3. `POST /v1/toip/enroll`（首接）

需要**登记口令**（ticket，`hubrelay toip ticket` 打印的那串）。只有滚动口令
无法登记新插件。

`plugin` 必填，它是**日志分账标签**而不是凭证：允许小写字母、数字、`.`、`_`、`-`，
不能以 `.` 开头/结尾，也不能含 `..`（它会变成目录名）。

## 4. `POST /v1/toip/join`（重接 / 轮换）

发 `ticket`（等价于 `/enroll`）**或** `code` 之一；两个都发时 `ticket` 优先。

客户端义务：

1. 把 `session.token` 当 API Key 存下来——它只出现这一次，服务端只留 SHA-256。
2. `dsh.baseURL` **原样使用**：它已经以 `/v1` 结尾，DSH 的 Messages 适配器只在
   pathname 不以 `/v1` 结尾时才补 `/v1`，所以这个拼法是唯一无歧义的。
3. 推理请求带上 `X-DSH-Plugin-Id`（知道版本就再带 `X-DSH-Plugin-Version`）以便
   按插件分账。令牌本身已绑定插件，所以不带这个头也能分账；带上是为了一台机器上
   多个插件之间能区分。
4. 不要从响应里推导口令——种不在这里。

`rotated` 为 `true` 表示站点作废了该设备上一次的会话令牌并发新枚。两种都是正常
情况，当信息看即可。

## 5. `GET /v1/toip/session`

用会话令牌鉴权（`X-Api-Key: rht_…` 或 `Authorization: Bearer rht_…`），返回
身份、过期时间与用量。适合当廉价的存活/身份检查：`expires_at` 非 0 而
`expires_in` 为 `0` 表示已过期，需要用新口令重接。

## 6. 口令算法

按 RFC 6238 / RFC 4226 截断：`counter = floor(unix秒 / 30)`，
`mac = HMAC-SHA1(secret, counter 的 8 字节大端)`，`offset = mac[19] & 0x0F`，
`code = (mac[offset..offset+3] 当 uint32 & 0x7FFFFFFF) mod 10^6`。

服务端接受当前窗口与 ±1 个窗口（`window: 1`），所以能容忍 30 秒内的时钟漂移；
超出即失败。**此时要提示「检查时钟」，不要报成凭证错误。**

## 7. 错误

错误用 OpenAI 形状的信封（见英文部分）。状态码语义：

| 状态 | 含义 | 客户端动作 |
|---|---|---|
| `400` | 缺 `plugin`、`/enroll` 缺 ticket、口令已过期 | 修正请求；提示用户取新口令 |
| `403` | 口令错/过期、通行证吊销或停用、插件不在白名单、尝试次数过多 | 重新提示；被锁后等约 5 分钟 |
| `404` | 本站未启用 TOIP | 回退 `POST /v1/pair` |
| `401` | `/session` 无令牌或令牌无效 | 重新接入 |

限次：**每个来源 IP 5 分钟内 8 次失败**，超限后 `403` 直到窗口滚过。每次拒绝都
记入站点审计（事件名 `toip.reject`）。

## 8. 建议的客户端流程

```
1. 用户给了网址 -> GET /v1/toip/station（确认启用、读取参数）
   否则        -> UDP v2 广播（局域网发现）
2. 若没有会话令牌：
     a. 配置了 ticket -> POST /v1/toip/enroll
     b. 有口令        -> POST /v1/toip/join {code}
3. 存下 session.token + dsh.baseURL + 模型清单。
4. 每次推理请求附上插件身份头。
5. 推理端点返回 401 时，清掉令牌回到第 2b 步。
```

请在客户端本地留一份小小的接入/扫描尝试日志。服务端记的是流量账，而
「我的插件早上 9:14 为什么没接上」只有客户端答得出来。
