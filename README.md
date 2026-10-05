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
- **Admin console**: local web UI for channels / tokens / policies / request log /
  usage / audit — with an EN/中文 toggle in the header.
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
- **管理控制台** Admin console：本地网页，管理渠道/令牌/策略/请求明细/用量/审计。
- **一致性探测** Conformance probe：对着任意兼容网关跑合规探测，抓出不合规实现。
- **请求审计** Request audit：控制面操作审计与请求明细（脱敏）。

## Highlights (English)

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

More subcommands (`token` / `clients` / `pair` / `audit` / `check` / `scan` /
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

更多子命令（`token` / `clients` / `pair` / `audit` / `check` / `scan` / `requests` /
`usage`）见各自主命令的 `--help`。

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
- Suspected key leak? Revoke immediately (`token rm` / rotate upstream keys).

## 安全须知 Security Notes（中文）

- 上游 Key 以明文 JSON 存放在本地号池文件中（与常见客户端做法一致）；请自行做好
  文件权限与磁盘加密，**不要**把号池文件提交进版本库或分享给他人。
- 绑定非回环地址（公网/局域网）前，网关强制要求已配置凭证（master Key 或下游令牌），
  且所有流量都必须携带凭证。
- 管理控制台默认只监听回环地址；绑非回环地址必须显式提供 `--token`。
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
