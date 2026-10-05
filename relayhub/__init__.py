"""relay-hub：局域网/自托管大模型中转站。

上游号池（多 Key 轮转、熔断冷却）+ 双协议适配（Anthropic/OpenAI）
+ HTTP 网关服务（鉴权、配对、TOIP 动态口令接入、用量记账）
+ 按插件分账的插件日志（pluginlogs/）。
"""

__version__ = "0.3.0"
