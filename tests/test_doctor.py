"""hubrelay doctor 环境自检测试 / tests for the doctor self-check."""

from __future__ import annotations

import relayhub.api as api


def test_doctor_checks_shape(tmp_path, monkeypatch):
    monkeypatch.setenv("RELAYHUB_HOME", str(tmp_path / "home"))
    checks = api.doctor(port=18999, scan_timeout=0.3)
    names = {c["name"] for c in checks}
    assert {"python", "data_root", "pool", "tokens", "local_inference",
            "port:18999", "firewall_hint"} <= names
    by_name = {c["name"]: c for c in checks}
    assert by_name["python"]["ok"] is True
    assert by_name["data_root"]["ok"] is True          # tmp_path 一定可写
    assert by_name["pool"]["detail"].startswith("empty")
    assert by_name["tokens"]["detail"].startswith("empty")


def test_doctor_port_conflict(tmp_path, monkeypatch):
    import socket

    monkeypatch.setenv("RELAYHUB_HOME", str(tmp_path / "home"))
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.listen(1)
    try:
        checks = api.doctor(port=port, scan_timeout=0.2)
        by_name = {c["name"]: c for c in checks}
        assert by_name[f"port:{port}"]["ok"] is False
        assert "fix" in by_name[f"port:{port}"]
    finally:
        s.close()


def test_doctor_cli(tmp_path, monkeypatch, capsys):
    from relayhub.gateway.doctor_api import cmd_doctor

    monkeypatch.setenv("RELAYHUB_HOME", str(tmp_path / "home"))
    rc = cmd_doctor(["--port", "18999", "--json"])
    assert rc == 0
    out = capsys.readouterr().out
    assert '"python"' in out
