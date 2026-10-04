"""`hubrelay doctor` 命令行入口 / CLI entry for the doctor self-check."""

from __future__ import annotations

import argparse
import sys

from ..doctor import run_checks


def cmd_doctor(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="relayhub.gateway doctor",
        description="环境自检：Python / 数据目录 / 号池与令牌 / 本机推理服务 / 端口占用 / 防火墙提示\n"
        "Environment self-check: python, data root, pool & tokens, local inference, port, firewall hint.",
    )
    parser.add_argument("--port", type=int, default=8799, help="要检测的端口 / port to probe (default 8799)")
    parser.add_argument("--json", action="store_true", help="输出 JSON / emit JSON")
    args = parser.parse_args(argv)

    checks = run_checks(port=args.port)
    if args.json:
        import json

        print(json.dumps(checks, ensure_ascii=False, indent=1))
    else:
        mark = {True: "✓", False: "✗"}
        for c in checks:
            print(f"  {mark[bool(c['ok'])]} {c['name']:<16} {c['detail']}")
            if c["fix"] and not c["ok"]:
                print(f"      └─ 修复 / fix: {c['fix']}")
            elif c["fix"]:
                print(f"      └─ 提示 / hint: {c['fix']}")
        bad = [c for c in checks if not c["ok"]]
        print(f"\n{'✗ 有 ' + str(len(bad)) + ' 项未通过 / ' + str(len(bad)) + ' check(s) failed' if bad else '✓ 全部通过 / all checks passed'}")
    return 0 if all(c["ok"] for c in checks) else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(cmd_doctor(sys.argv[1:]))
