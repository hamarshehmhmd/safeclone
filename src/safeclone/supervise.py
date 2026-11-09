"""Runs INSIDE the sandbox: plants canary credentials, runs a proxy sinkhole, runs the command, reports.

The report goes out on an inherited pipe fd that the untrusted command never sees (close_fds).
"""
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time

CANARIES = {
    ".ssh/id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\nsafeclone-canary-ssh\n-----END OPENSSH PRIVATE KEY-----\n",
    ".ssh/id_ed25519": "-----BEGIN OPENSSH PRIVATE KEY-----\nsafeclone-canary-ed25519\n-----END OPENSSH PRIVATE KEY-----\n",
    ".aws/credentials": "[default]\naws_access_key_id = AKIASAFECLONECANARY0\naws_secret_access_key = safeclone-canary\n",
    ".config/gh/hosts.yml": "github.com:\n    oauth_token: gho_safeclonecanary000000000000000000\n    user: you\n",
    ".docker/config.json": '{"auths": {"https://index.docker.io/v1/": {"auth": "c2FmZWNsb25lOmNhbmFyeQ=="}}}\n',
    ".kube/config": "apiVersion: v1\nkind: Config\nusers: [{name: canary, user: {token: safeclone-canary}}]\n",
    ".git-credentials": "https://you:ghp_safeclonecanary@github.com\n",
    ".config/solana/id.json": "[1,2,3]\n",
    ".config/google-chrome/Default/Login Data": "canary",
    ".config/google-chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/000003.log": "canary",
    ".bash_history": "ssh prod-db\n",
    ".zsh_history": ": 1700000000:0;ssh prod-db\n",
    ".config/Exodus/exodus.wallet/seed.seco": "canary",
    ".electrum/wallets/default_wallet": "canary",
    ".env": "OPENAI_API_KEY=sk-safeclone-canary\n",
}
OLD = 946684800  # 2000-01-01: any read bumps atime past mtime (relatime)


def plant(home):
    stamps = {}
    for rel, body in CANARIES.items():
        p = os.path.join(home, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as fh:
            fh.write(body)
        os.chmod(p, 0o600)
        os.utime(p, (OLD, OLD + 10))
        stamps[rel] = os.stat(p).st_mtime
    return stamps


def touched(home, stamps):
    out = []
    for rel, mtime in stamps.items():
        p = os.path.join(home, rel)
        try:
            st = os.stat(p)
        except OSError:
            out.append({"path": "~/" + rel, "how": "deleted"})
            continue
        if st.st_mtime != mtime:
            out.append({"path": "~/" + rel, "how": "modified"})
        elif st.st_atime > OLD + 1:
            out.append({"path": "~/" + rel, "how": "read"})
    return out


class Sinkhole:
    """Tiny HTTP/HTTPS proxy that records where the command tried to go and answers 403."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(64)
        self.port = self.sock.getsockname()[1]
        self.seen = []
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(c,), daemon=True).start()

    def _one(self, c):
        try:
            c.settimeout(3)
            data = b""
            while b"\r\n\r\n" not in data and len(data) < 65536:
                chunk = c.recv(4096)
                if not chunk:
                    break
                data += chunk
            head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1")
            lines = head.split("\r\n")
            parts = lines[0].split(" ")
            if len(parts) >= 2:
                method, target = parts[0], parts[1]
                host = ""
                for ln in lines[1:]:
                    if ln.lower().startswith("host:"):
                        host = ln.split(":", 1)[1].strip()
                if method == "CONNECT":
                    dest = target
                else:
                    dest = target if target.startswith("http") else "http://%s%s" % (host, target)
                self.seen.append({"method": method, "dest": dest[:300], "t": round(time.time(), 3)})
            c.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        except OSError:
            pass
        finally:
            c.close()


STRACE_LINE = re.compile(r'^(?:\[pid\s+)?(\d+)\]?\s*(execve|connect)\((.*)')


def parse_strace(text):
    execs, conns = [], []
    for line in text.splitlines():
        m = re.match(r"^(\d+)\s+(execve|connect)\((.*)$", line)
        if not m:
            continue
        call, rest = m.group(2), m.group(3)
        if call == "execve":
            em = re.match(r'"([^"]*)",\s*\[(.*?)\]', rest)
            if em:
                argv = re.findall(r'"((?:[^"\\]|\\.)*)"', em.group(2))
                execs.append({"pid": int(m.group(1)), "path": em.group(1), "argv": argv[:12],
                              "ok": "= 0" in rest.rsplit(")", 1)[-1]})
        else:
            if "AF_UNIX" in rest:
                um = re.search(r'sun_path="([^"]*)"', rest)
                conns.append({"family": "unix", "dest": um.group(1) if um else "?"})
                continue
            ip = re.search(r'inet_(?:addr|pton)\((?:AF_INET6,\s*)?"([^"]+)"', rest)
            port = re.search(r"sin6?_port=htons\((\d+)\)", rest)
            if ip and port:
                dest = "%s:%s" % (ip.group(1), port.group(1))
                if not dest.startswith(("127.0.0.1", "::1")):
                    conns.append({"family": "inet", "dest": dest})
    return execs, conns


def _undumpable():
    """PR_SET_DUMPABLE=0: same-uid children can't ptrace us or open /proc/<pid>/fd/<report-fd>."""
    try:
        import ctypes
        ctypes.CDLL(None, use_errno=True).prctl(4, 0, 0, 0, 0)
    except Exception:
        pass


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--report-fd", type=int, required=True)
    ap.add_argument("--home", required=True)
    ap.add_argument("--net", action="store_true")
    ap.add_argument("--trace", default="")
    ap.add_argument("--timeout", type=float, default=300)
    ap.add_argument("--stdout-to-stderr", action="store_true")
    ap.add_argument("cmd", nargs=argparse.REMAINDER)
    a = ap.parse_args(argv)
    cmd = a.cmd[1:] if a.cmd and a.cmd[0] == "--" else a.cmd
    _undumpable()
    report_fh = os.fdopen(a.report_fd, "w")
    stamps = plant(a.home)
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": a.home, "LANG": "C.UTF-8", "TERM": os.environ.get("TERM", "xterm"),
           "USER": "dev", "SHELL": "/bin/sh", "TMPDIR": "/tmp", "CI": "", "SAFECLONE_SANDBOX": "1"}
    for k in ("PATH",):
        if os.environ.get("SAFECLONE_PATH"):
            env[k] = os.environ["SAFECLONE_PATH"]
    sink = None
    if not a.net:
        sink = Sinkhole()
        url = "http://127.0.0.1:%d" % sink.port
        for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy",
                  "npm_config_proxy", "npm_config_https_proxy"):
            env[k] = url
        env["GLOBAL_AGENT_HTTP_PROXY"] = url
        env["NODE_USE_ENV_PROXY"] = "1"
    run = list(cmd)
    trace_file = "/tmp/.safeclone-trace"
    if a.trace:
        run = [a.trace, "-f", "-qq", "-s", "200", "-e", "trace=execve,connect", "-o", trace_file] + run
    t0 = time.time()
    timed_out = False
    try:
        p = subprocess.Popen(run, env=env, close_fds=True, stdin=subprocess.DEVNULL,
                             stdout=2 if a.stdout_to_stderr else None)
        try:
            rc = p.wait(timeout=a.timeout)
        except subprocess.TimeoutExpired:
            p.kill()
            rc = p.wait()
            timed_out = True
    except FileNotFoundError as e:
        rc, err = 127, str(e)
    else:
        err = ""
    time.sleep(0.2)
    execs, conns = [], []
    if a.trace and os.path.exists(trace_file):
        with open(trace_file, errors="replace") as fh:
            execs, conns = parse_strace(fh.read())
    report = {"exit_code": rc, "error": err, "timed_out": timed_out, "seconds": round(time.time() - t0, 2),
              "canaries": touched(a.home, stamps), "proxy_requests": sink.seen if sink else [],
              "execs": execs, "connects": conns}
    report_fh.write(json.dumps(report))
    report_fh.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
