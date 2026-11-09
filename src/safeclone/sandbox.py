"""Run a command against a COPY of the repo in a credential-free bubblewrap sandbox (Linux)."""
import json
import os
import shutil
import subprocess
import sys
import tempfile

SYSTEM_RO = ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/lib32", "/opt"]
ETC_RO = ["/etc/ssl", "/etc/ca-certificates", "/etc/pki", "/etc/alternatives", "/etc/ld.so.cache",
          "/etc/ld.so.conf", "/etc/ld.so.conf.d", "/etc/localtime", "/etc/nsswitch.conf", "/etc/hosts",
          "/etc/resolv.conf", "/etc/passwd", "/etc/group", "/etc/os-release", "/etc/mime.types", "/etc/gitconfig"]
LEAK_ENV_HINTS = ("TOKEN", "SECRET", "KEY", "PASSWORD", "AUTH", "SSH_AUTH_SOCK", "AWS_", "GH_", "GITHUB_", "NPM_", "OPENAI", "ANTHROPIC")


class SandboxError(Exception):
    pass


def available():
    return sys.platform.startswith("linux") and shutil.which("bwrap") is not None


def _pkg_parent():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def build_argv(work, cmd, report_fd, net=False, trace=None, extra_ro=(), timeout=300, python=None):
    python = python or os.path.realpath(sys.executable)
    argv = ["bwrap", "--die-with-parent", "--new-session", "--unshare-user", "--unshare-ipc", "--unshare-pid",
            "--unshare-uts", "--unshare-cgroup-try", "--hostname", "sandbox", "--clearenv"]
    if not net:
        argv.append("--unshare-net")
    for p in SYSTEM_RO + ETC_RO:
        argv += ["--ro-bind-try", p, p]
    pyroots = {os.path.realpath(sys.prefix), os.path.realpath(sys.base_prefix), os.path.dirname(os.path.dirname(python))}
    for r in sorted(pyroots):
        if r not in ("/", "/usr") and not r.startswith("/usr/"):
            argv += ["--ro-bind-try", r, r]
    pkg = _pkg_parent()
    argv += ["--ro-bind", pkg, "/run/safeclone/lib"]
    for p in extra_ro:
        p = os.path.abspath(os.path.expanduser(p))
        argv += ["--ro-bind", p, p]
    argv += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--tmpfs", "/home", "--tmpfs", "/root",
             "--dir", "/home/dev", "--bind", work, "/work", "--chdir", "/work",
             "--setenv", "HOME", "/home/dev", "--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin",
             "--setenv", "PYTHONPATH", "/run/safeclone/lib", "--setenv", "PYTHONNOUSERSITE", "1",
             "--setenv", "PYTHONDONTWRITEBYTECODE", "1"]
    sup = [python, "-I", "-c",
           "import sys; sys.path.insert(0, '/run/safeclone/lib'); from safeclone.supervise import main; sys.exit(main())",
           "--report-fd", str(report_fd), "--home", "/home/dev", "--timeout", str(timeout)]
    if net:
        sup.append("--net")
    if trace:
        sup += ["--trace", trace]
    return argv + ["--"] + sup + ["--"] + list(cmd)


def copy_repo(src, dest):
    shutil.copytree(src, dest, symlinks=True, ignore=shutil.ignore_patterns(".safeclone"))
    return dest


def snapshot(root):
    out = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            out[os.path.relpath(p, root)] = (st.st_size, st.st_mtime_ns, st.st_mode)
    return out


def diff(before, after):
    created = sorted(set(after) - set(before))
    deleted = sorted(set(before) - set(after))
    changed = sorted(k for k in set(before) & set(after) if before[k][:2] != after[k][:2])
    return {"created": created, "modified": changed, "deleted": deleted}


def run(repo, cmd, net=False, trace="auto", extra_ro=(), timeout=300, keep=False):
    if not available():
        raise SandboxError("sandbox needs Linux + bubblewrap (apt install bubblewrap). "
                           "On macOS, run 'safeclone scan/open' and use a VM or devcontainer for execution.")
    if not cmd:
        raise SandboxError("no command given (use: safeclone run DIR -- npm install)")
    tmp = tempfile.mkdtemp(prefix="safeclone-run-")
    work = copy_repo(repo, os.path.join(tmp, "work"))
    before = snapshot(work)
    if trace == "auto":
        trace = shutil.which("strace")
        if trace and not os.path.realpath(trace).startswith(("/usr/", "/bin/")):
            trace = None
    elif trace in ("off", "", None):
        trace = None
    r, w = os.pipe()
    argv = build_argv(work, cmd, w, net=net, trace=trace, extra_ro=extra_ro, timeout=timeout)
    p = subprocess.Popen(argv, pass_fds=(w,), stdin=subprocess.DEVNULL)
    os.close(w)
    with os.fdopen(r) as fh:
        raw = fh.read()
    p.wait()
    try:
        report = json.loads(raw) if raw else None
    except ValueError:
        report = None
    if report is None:
        report = {"exit_code": None, "error": "sandbox supervisor produced no report (bwrap exit %s)" % p.returncode,
                  "canaries": [], "proxy_requests": [], "execs": [], "connects": []}
    report["files"] = diff(before, snapshot(work))
    report["network"] = "host network" if net else "none (loopback only; HTTP(S) proxy sinkhole)"
    report["traced"] = bool(trace)
    report["command"] = list(cmd)
    report["workdir"] = work if keep else None
    if not keep:
        shutil.rmtree(tmp, ignore_errors=True)
    return report


def leaked_env_names(env=None):
    env = os.environ if env is None else env
    return sorted(k for k in env if any(h in k.upper() for h in LEAK_ENV_HINTS))
