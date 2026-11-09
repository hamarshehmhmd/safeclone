import json
import os
import shutil
import sys

import pytest

from safeclone import cli, sandbox
from safeclone.supervise import parse_strace, plant, touched

needs_bwrap = pytest.mark.skipif(not sandbox.available() or os.system("bwrap --ro-bind / / --unshare-user --unshare-net true >/dev/null 2>&1") != 0,
                                 reason="bubblewrap with user namespaces not available")


def test_scan_cli_exit_codes(takehome, capsys, tmp_path, w):
    assert cli.main(["--color", "never", "scan", takehome]) == 1
    out = capsys.readouterr().out
    assert "verdict: CRITICAL" in out and ".vscode/tasks.json" in out
    clean = tmp_path / "clean"
    w(clean, "a.py", "print(1)\n")
    assert cli.main(["scan", str(clean)]) == 0
    assert cli.main(["scan", takehome, "--fail-on", "none"]) == 0


def test_scan_json_and_sarif(takehome, capsys, tmp_path):
    sar = tmp_path / "out.sarif"
    cli.main(["scan", takehome, "--json", "--sarif", str(sar)])
    data = json.loads(capsys.readouterr().out)
    assert data["verdict"] == "critical" and data["findings"][0]["severity"] == "critical"
    s = json.load(open(str(sar)))
    assert s["version"] == "2.1.0" and s["runs"][0]["results"]


def test_scan_ioc_file(tmp_path, w, capsys):
    w(tmp_path / "r", "x.js", "const k = 'evil-domain.example';\n")
    iocs = w(tmp_path, "iocs.txt", "# comment\nevil-domain.example\n")
    assert cli.main(["scan", str(tmp_path / "r"), "--ioc-file", iocs, "--json"]) == 1
    assert "ioc-string" in capsys.readouterr().out


def test_temp_cleanup(takehome, monkeypatch, tmp_path):
    import tempfile
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    cli.main(["scan", takehome, "--json"])
    assert [p for p in os.listdir(str(tmp_path)) if p.startswith("safeclone-")] == []


def test_open_cli(takehome, tmp_path, capsys):
    rc = cli.main(["--color", "never", "open", takehome, "--dest", str(tmp_path / "q")])
    assert rc == 0
    out = capsys.readouterr().out
    assert "defused" in out
    dest = tmp_path / "q" / "takehome"
    assert (dest / ".safeclone" / "quarantine" / ".vscode" / "tasks.json").exists()
    assert cli.main(["open", takehome, "--dest", str(tmp_path / "q")]) == 2
    assert cli.main(["open", takehome, "--dest", str(tmp_path / "q"), "--force"]) == 0


def test_bad_target(capsys):
    assert cli.main(["scan", "/definitely/not/here.bin"]) == 2


def test_canaries(tmp_path):
    home = str(tmp_path)
    st = plant(home)
    assert touched(home, st) == []
    open(os.path.join(home, ".ssh/id_rsa")).read()
    with open(os.path.join(home, ".aws/credentials"), "a") as fh:
        fh.write("x")
    os.remove(os.path.join(home, ".env"))
    got = {c["path"]: c["how"] for c in touched(home, st)}
    assert got == {"~/.ssh/id_rsa": "read", "~/.aws/credentials": "modified", "~/.env": "deleted"}


def test_parse_strace():
    text = ('101 execve("/usr/bin/curl", ["curl", "-s", "http://x"], 0x7ffd /* 9 vars */) = 0\n'
            '102 execve("/usr/local/bin/nope", ["nope"], 0x7 /* 1 var */) = -1 ENOENT (No such file or directory)\n'
            '101 connect(5, {sa_family=AF_INET, sin_port=htons(1224), sin_addr=inet_addr("203.0.113.7")}, 16) = -1 ENETUNREACH\n'
            '101 connect(5, {sa_family=AF_INET, sin_port=htons(41000), sin_addr=inet_addr("127.0.0.1")}, 16) = 0\n'
            '103 connect(4, {sa_family=AF_UNIX, sun_path="/run/user/1000/ssh-agent.sock"}, 110) = -1 ENOENT\n')
    execs, conns = parse_strace(text)
    assert execs[0]["path"] == "/usr/bin/curl" and execs[0]["ok"] and execs[0]["argv"][0] == "curl"
    assert execs[1]["ok"] is False
    assert {"family": "inet", "dest": "203.0.113.7:1224"} in conns
    assert {"family": "unix", "dest": "/run/user/1000/ssh-agent.sock"} in conns
    assert len(conns) == 2


def test_build_argv_isolation(tmp_path):
    argv = sandbox.build_argv(str(tmp_path), ["true"], 3)
    assert "--unshare-net" in argv and "--clearenv" in argv and "--new-session" in argv
    assert argv[argv.index("--tmpfs") + 1] == "/tmp"
    assert ["--tmpfs", "/home"] == argv[argv.index("/home") - 1: argv.index("/home") + 1]
    assert "--unshare-net" not in sandbox.build_argv(str(tmp_path), ["true"], 3, net=True)


def test_suspicious_classification():
    rep = {"canaries": [], "connects": [], "proxy_requests": [{"method": "CONNECT", "dest": "registry.npmjs.org:443"}]}
    assert not cli.suspicious(rep)
    rep["connects"] = [{"family": "unix", "dest": "/var/run/nscd/socket"}]
    assert not cli.suspicious(rep)
    rep["connects"].append({"family": "unix", "dest": "/tmp/ssh-XXXX/agent.123"})
    assert cli.suspicious(rep)
    rep["connects"] = []
    rep["proxy_requests"].append({"method": "GET", "dest": "http://203.0.113.7:1224/x"})
    assert cli.suspicious(rep)


def test_run_without_bwrap(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(sandbox, "available", lambda: False)
    assert cli.main(["run", str(tmp_path), "--", "true"]) == 2
    assert "bubblewrap" in capsys.readouterr().err


@needs_bwrap
def test_sandbox_catches_takehome(takehome, capsys):
    if not shutil.which("curl"):
        pytest.skip("curl not installed")
    rc = cli.main(["--color", "never", "run", takehome, "--fail-on-suspicious", "--", "sh", "scripts/setup.sh"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "~/.ssh/id_rsa" in out and "~/.aws/credentials" in out
    assert "203.0.113.7:1224" in out and "api.npoint.io:443" in out
    assert "verdict: SUSPICIOUS" in out


@needs_bwrap
def test_sandbox_json_stdout_is_pure(takehome, capfd):
    rc = cli.main(["run", takehome, "--json", "--trace", "off", "--", "sh", "scripts/setup.sh"])
    out = capfd.readouterr()
    rep = json.loads(out.out)
    assert rc == 0 and "setup ok" in out.err and rep["exit_code"] == 0


@needs_bwrap
def test_sandbox_hides_host_env_and_home(tmp_path, w, capsys, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_shouldnotleak")
    w(tmp_path, "probe.sh", 'env > env.txt; ls -a "$HOME" > home.txt; [ -e /home/box ] && echo yes > hostdir.txt; true\n')
    rep = sandbox.run(str(tmp_path), ["sh", "probe.sh"], keep=True, trace="off")
    work = rep["workdir"]
    env = open(os.path.join(work, "env.txt")).read()
    assert "ghp_shouldnotleak" not in env and "SSH_AUTH_SOCK" not in env and "SAFECLONE_SANDBOX=1" in env
    assert not os.path.exists(os.path.join(work, "hostdir.txt"))
    assert {"env.txt", "home.txt"} <= set(rep["files"]["created"])
    assert rep["exit_code"] == 0 and rep["canaries"] == []
    # the original repo is untouched
    assert not os.path.exists(str(tmp_path / "env.txt"))
    shutil.rmtree(os.path.dirname(work))


@needs_bwrap
def test_sandbox_report_survives_noisy_command(tmp_path):
    rep = sandbox.run(str(tmp_path), [sys.executable if sys.executable.startswith("/usr") else "sh", "-c", "exit 3"]
                      if not sys.executable.startswith("/usr") else ["sh", "-c", "exit 3"], trace="off")
    assert rep["exit_code"] == 3


@needs_bwrap
@pytest.mark.skipif(not shutil.which("strace"), reason="strace not installed")
def test_sandbox_strace(tmp_path, w):
    w(tmp_path, "t.sh", "echo hi > /dev/null; ls > /dev/null\n")
    rep = sandbox.run(str(tmp_path), ["sh", "t.sh"])
    if not rep.get("traced"):
        pytest.skip("strace not under /usr")
    names = {os.path.basename(e["path"]) for e in rep["execs"]}
    assert "ls" in names
