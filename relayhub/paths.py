"""配置根目录定位。

中转站自身的配置/数据根（RELAYHUB_HOME）定位规则：
    RELAYHUB_HOME 非空 -> 就用它
    否则 LOCALAPPDATA 非空 -> <LOCALAPPDATA>/relay-hub
    否则 ~/.local/share/relay-hub
号池、令牌、日志等状态文件都挂在同一个根下，便于整目录备份。
"""

from __future__ import annotations

import os
from pathlib import Path

ENV_RELAYHUB_HOME = "RELAYHUB_HOME"




def relayhub_home() -> Path:
    """中转站自己的数据根。

    放 LOCALAPPDATA 下而不是仓库里：号池文件含上游 Key 明文，
    不该跟着版本库走。RELAYHUB_HOME 可覆盖（沙箱实测、测试用）。
    """
    override = os.environ.get(ENV_RELAYHUB_HOME, "").strip()
    if override:
        return Path(override).expanduser()
    base = os.environ.get("LOCALAPPDATA", "").strip()
    root = Path(base) if base else Path.home() / ".local" / "share"
    return root / "relay-hub"


def pool_path() -> Path:
    """上游号池文件。"""
    return relayhub_home() / "pool.json"


def tokens_path() -> Path:
    """下游令牌文件（发给各客户端的 per-device 凭证）。

    与号池分文件：号池存的是上游渠道密钥，这里存的是发给客户端的令牌，
    两者的轮换语义与暴露面不同（README「五」的术语区分），不该混在一个文件里。
    """
    return relayhub_home() / "tokens.json"


def pairing_path() -> Path:
    """配对窗口状态文件（`pair begin` 写、serve 兑换、单次成功后删除）。

    与令牌同理走文件而不是进程内状态：开窗在控制面进程、兑换在数据面进程，
    两个进程唯一可靠的共享物就是文件（与号池/令牌同一套架构约定）。
    """
    return relayhub_home() / "pairing.json"


def audit_path() -> Path:
    """控制面操作审计日志（JSONL，追加写）。"""
    return relayhub_home() / "audit.jsonl"


def toip_station_path() -> Path:
    """TOIP 站点身份（station id + 动态口令种子）。

    口令种子等价于「该站点全部接入能力」，所以它与号池（上游密钥）、
    令牌（下游凭证）分开成第三个文件：三者的轮换节奏与暴露面互不相同，
    混在一个文件里会让「轮换口令」这种纯运维动作有碰到密钥的风险。
    """
    return relayhub_home() / "toip.json"


def toip_tickets_path() -> Path:
    """TOIP 通行证文件（登记口令的哈希 + 插件白名单 + 绑定关系）。

    落盘只存 SHA-256 与尾 4 位提示（与 tokens.json 同纪律），明文只在
    `hubrelay toip ticket` 打印那一次。
    """
    return relayhub_home() / "toip_tickets.json"


def plugin_logs_root() -> Path:
    """插件日志根目录（<home>/pluginlogs/<plugin_id>/…）。

    与 requests.jsonl（全局、按令牌分账）分开的理由见 gateway/pluginlogs.py：
    插件是「一个整体」，它的接入事件与调用流水需要能一个目录读完。
    """
    return relayhub_home() / "pluginlogs"


def users_path() -> Path:
    """公网用户文件（用户/密码哈希/额度/计费规则）。"""
    return relayhub_home() / "users.json"


def policy_path() -> Path:
    """接入策略文件（IP/设备 拉黑与优先名单，后台管理与网关共享）。

    独立文件的理由：策略是「运行中随时改的管理动作」，令牌是「发放时定死的
    配置」——放一起会让两边的写盘互相踩。数据面每请求指纹热加载，
    后台管理改完下一请求即生效。
    """
    return relayhub_home() / "policy.json"


def redeem_codes_path() -> Path:
    """兑换码文件（一次性核销）。"""
    return relayhub_home() / "codes.json"


def accounts_path() -> Path:
    """平台账号文件（可选扩展能力：jobs 做任务用的账号凭证）。

    与号池分文件的理由同令牌：平台账号不参与推理选路，
    凭证来源与轮换节奏也和上游 Key 完全不同。
    """
    return relayhub_home() / "accounts.json"


def requests_log_path() -> Path:
    """请求明细日志（JSONL，一行一次推理请求，只记元数据不记对话内容）。"""
    return relayhub_home() / "requests.jsonl"




def backup_root() -> Path:
    """备份根目录，放在 LOCALAPPDATA 下，避免污染仓库。"""
    return relayhub_home() / "backups"



def launch_sandbox_dir() -> Path:
    """覆盖实测用的隔离目录：放仓库外，避免把 credentials 拷进版本库。"""
    return relayhub_home() / "sandbox"



