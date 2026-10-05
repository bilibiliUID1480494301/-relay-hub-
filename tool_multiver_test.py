# -*- coding: utf-8 -*-
"""逐版本 PyPI 实测 0.2.8 ~ 0.2.11（子进程前台起站，父进程探测）。

每个版本干净 venv 安装，验证：
  - __version__ / --version 对得上
  - hubrelay serve --help 与 serve help 不崩（0.2.7 的 %LOCALAPPDATA% 回归）
  - 起站 → /healthz（0.2.8+）→ test 令牌 chat → embeddings（0.2.7+）→
    /v1/responses 非流式+流式（0.2.10+），按版本预期比对
"""
import json
import os
import subprocess
import sys
import urllib.request
from pathlib import Path

PY = sys.executable
TMP = Path(r"C:/Users/ws/AppData/Local/Temp/hubrelay_mtv")

CHILD = (
    "import sys, hubrelay\n"
    "home = sys.argv[1]\n"
    "st = hubrelay.Station(port=int(sys.argv[2]), home=home)\n"
    "t = st.create_token('mtv', scope='test')\n"
    "print('TOKEN', t.plaintext, flush=True)\n"
    "print('URL', st.serve(background=False), flush=True)\n"
)


def api_calls(url, token):
    out = {}
    try:
        with urllib.request.urlopen(url + "/healthz", timeout=5) as r:
            out["healthz"] = json.loads(r.read()).get("ok") is True
    except Exception:
        out["healthz"] = False

    def post(path, payload):
        req = urllib.request.Request(
            url + path, data=json.dumps(payload).encode(),
            headers={"Authorization": f"Bearer {token}",
                     "Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read())

    out["chat"] = post("/v1/chat/completions", {
        "model": "any", "messages": [{"role": "user", "content": "hi"}],
    })["choices"][0]["message"]["content"] != ""
    try:
        out["embeddings"] = post("/v1/embeddings",
                                 {"model": "any", "input": "hi"}).get("object") == "list"
    except urllib.error.HTTPError as exc:
        out["embeddings"] = exc.code != 404  # 404 = 该版本还没有此端点
    try:
        rs = post("/v1/responses", {"model": "any", "input": "hi"})
        out["responses"] = rs.get("object") == "response" and rs.get("output_text") != ""
    except urllib.error.HTTPError as exc:
        out["responses"] = exc.code != 404
    try:
        req = urllib.request.Request(
            url + "/v1/responses",
            data=json.dumps({"model": "any", "input": "hi", "stream": True}).encode(),
            headers={"Authorization": f"Bearer {token}",
                     "Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=20) as r:
            out["responses_stream"] = "response.completed" in r.read().decode("utf-8")
    except Exception:
        out["responses_stream"] = False
    return out


def test_version(ver, port):
    venv = TMP / f"v{ver.replace('.', '')}"
    if not (venv / "Scripts" / "python.exe").exists():
        assert subprocess.run([sys.executable, "-m", "venv", str(venv)]).returncode == 0
    pip = str(venv / "Scripts" / "pip.exe")
    py = str(venv / "Scripts" / "python.exe")
    exe = str(venv / "Scripts" / "hubrelay.exe")
    res = {}
    for attempt in range(4):
        if subprocess.run([pip, "install", "-q", "--no-cache-dir",
                           f"hubrelay=={ver}"]).returncode == 0:
            break
    else:
        res["install"] = False
        return res
    res["install"] = True

    r = subprocess.run([py, "-c", "import hubrelay;print(hubrelay.__version__)"],
                       capture_output=True, text=True)
    res["version_ok"] = r.stdout.strip() == ver
    res["serve_help"] = subprocess.run([exe, "serve", "--help"],
                                       capture_output=True, text=True).returncode == 0
    res["serve_help_word"] = "usage:" in subprocess.run(
        [exe, "serve", "help"], capture_output=True, text=True).stdout.lower()
    res["version_flag"] = ver in subprocess.run(
        [exe, "--version"], capture_output=True, text=True).stdout

    env = dict(os.environ)
    env["RELAYHUB_HOME"] = str(TMP / f"home-{ver}")
    child = subprocess.Popen([py, "-c", CHILD, str(TMP / f"home-{ver}"), str(port)],
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             text=True, env=env)
    try:
        token = url = None
        for _ in range(60):
            line = child.stdout.readline()
            if not line:
                break
            if line.startswith("TOKEN"):
                token = line.split()[1]
            elif line.startswith("URL"):
                url = line.split()[1]
                break
        if not url:
            res["serve"] = False
            return res
        res["serve"] = True
        res.update(api_calls(url, token))
    finally:
        child.kill()
    return res


if __name__ == "__main__":
    TMP.mkdir(exist_ok=True)
    versions = sys.argv[1:] or ["0.2.8", "0.2.9", "0.2.10", "0.2.11"]
    expected = {
        "0.2.8": {"chat": True, "healthz": True, "embeddings": True,
                  "responses": False, "responses_stream": False},
        "0.2.9": {"chat": True, "healthz": True, "embeddings": True,
                  "responses": False, "responses_stream": False},
        "0.2.10": {"chat": True, "healthz": True, "embeddings": True,
                   "responses": True, "responses_stream": True},
        "0.2.11": {"chat": True, "healthz": True, "embeddings": True,
                   "responses": True, "responses_stream": True},
    }
    all_ok = True
    for i, ver in enumerate(versions):
        res = test_version(ver, 18800 + i)
        problems = []
        for k in ("install", "version_ok", "serve_help", "serve_help_word",
                  "version_flag", "serve"):
            if res.get(k) is not True:
                problems.append(f"{k}={res.get(k)}")
        for k, want in expected.get(ver, {}).items():
            if res.get(k) != want:
                problems.append(f"{k}={res.get(k)} (want {want})")
        status = "PASS" if not problems else "FAIL"
        if status == "FAIL":
            all_ok = False
        print(f"[{status}] {ver}: " + ("; ".join(problems) if problems else "all good"),
              flush=True)
    print("VERDICT:", "ALL-PASS" if all_ok else "HAS-FAILURES")
