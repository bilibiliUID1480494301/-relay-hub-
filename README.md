# relay-hub · 局域网/自托管大模型中转站

[![CI](https://github.com/bilibiliUID1480494301/relay-hub/actions/workflows/ci.yml/badge.svg)](https://github.com/bilibiliUID1480494301/relay-hub/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)
![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)

A self-hosted LLM relay/gateway for your LAN: multi-upstream key pool, downstream
tokens, usage accounting, circuit breaking, and conformance probing. Pure Python
standard library — no third-party runtime dependencies.

一个自托管的大模型中转站：把多家上游（官方 API Key、本地自托管推理服务）统一成一个
OpenAI/Anthropic 兼容入口，带号池调度、下游令牌、用量记账、分级熔断和一致性探测。
纯 Python 标准库实现，零第三方运行时依赖。

## 功能 Features

- **上游号池** Upstream key pool：多渠道轮询/最少失败/额度感知调度，优先级与权重，
  四档分级冷却（额度耗尽 / 限流 / 5xx / 鉴权失效），热加载。
- **下游令牌** Downstream tokens：per-device 令牌（对标 one-api 的「令牌」），模型白名单、
  RPM/每日限额、用量记账，明文只在发放时出现一次。
- **双协议入口** Dual protocol：`POST /v1/messages`（Anthropic）与
  `POST /v1/chat/completions`（OpenAI），同一令牌两种鉴权头都认。
- **配对发放** Pairing：带外配对码（成功即焚、限次）+ 可选的局域网免码配对。
- **管理控制台** Admin console：本地网页，管理渠道/令牌/策略/请求明细/用量/审计。
- **一致性探测** Conformance probe：对着任意兼容网关跑合规探测，抓出不合规实现。
- **请求审计** Request audit：控制面操作审计与请求明细（脱敏）。

## 特色 Highlights

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

## 快速开始 Quick Start

```bash
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
`usage`）见各自主命令的 `--help`。See each subcommand's `--help` for details.

## 运行环境 Requirements

- Python 3.10+（仅标准库）
- Windows / macOS / Linux

## 免责声明 Disclaimer

> **中文**：本项目仅供学习、研究与个人自托管用途。使用者应自行确保其使用行为符合
> 所在地区法律法规，以及其接入的上游服务的用户协议与服务条款。本项目按「现状」提供，
> 不附带任何明示或暗示的担保；作者不对任何人因使用本项目而产生的直接或间接损失负责。
> 请勿将本项目用于任何违反上游服务条款或损害第三方权益的用途，由此产生的一切风险与
> 责任由使用者自行承担。
>
> **English**: This project is provided for learning, research, and personal
> self-hosting purposes only. You are solely responsible for ensuring that your
> use complies with applicable laws and regulations in your jurisdiction as well
> as the terms of service of any upstream services you connect to. The software
> is provided "AS IS", without warranty of any kind. In no event shall the
> authors be liable for any claim, damages, or other liability arising from the
> use of this software. Any risk arising from use in violation of upstream terms
> of service rests solely with the user.

## 安全须知 Security Notes

- 上游 Key 以明文 JSON 存放在本地号池文件中（与常见客户端做法一致）；请自行做好
  文件权限与磁盘加密，**不要**把号池文件提交进版本库或分享给他人。
- 绑定非回环地址（公网/局域网）前，网关强制要求已配置凭证（master Key 或下游令牌），
  且所有流量都必须携带凭证。
- 管理控制台默认只监听回环地址；绑非回环地址必须显式提供 `--token`。
- 遇到疑似密钥泄露请立即吊销（`token rm` / 更换上游 Key）。

## 许可证 License

[MIT](./LICENSE)
