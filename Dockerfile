# relay-hub / hubrelay — self-hosted LLM relay gateway
# 中文：构建后 `docker compose up -d` 即起站；数据（号池/令牌/日志）全在 /data 卷。
# English: build & `docker compose up -d`; all state (pool/tokens/logs) lives in the /data volume.

FROM python:3.12-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    RELAYHUB_HOME=/data

COPY pyproject.toml README.md hubrelay.py ./
COPY relayhub ./relayhub
RUN pip install --no-cache-dir .

# 数据卷：号池 pool.json（含上游 Key 明文）、令牌 tokens.json、请求日志
VOLUME ["/data"]
EXPOSE 8799

# 安全闸保持服务端原样：--public 必须已配凭证（下游令牌/master key），否则拒绝启动。
# 建议先 `docker compose exec relay hubrelay token add my-phone` 发一枚令牌再对外。
ENTRYPOINT ["hubrelay"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8799", "--public"]
