"""safeclone command line."""
import argparse
import json
import os
import shutil
import sys
import tempfile

from . import __version__
from .defuse import defuse
from .fetch import FetchError, fetch, kind_of
from .patterns import SEVERITIES, sev_rank
from .scan import Finding, scan
from . import sandbox
from .supervise import CANARIES

COLORS = {"critical": "1;31", "high": "31", "medium": "33", "low": "36", "info": "2", "clean": "32"}
BUILTIN_IOCS = ["jsonwebauth"]


class Out:
    def __init__(self, color):
        self.color = color

    def c(self, code, s):
        return "\x1b[%sm%s\x1b[0m" % (code, s) if self.color else s


def _color(mode):
    if mode == "always":
        return True
    if mode == "never" or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def load_iocs(paths):
    out = list(BUILTIN_IOCS)
    for p in paths or []:
        with open(p, encoding="utf-8") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip().strip(",").strip('"')
                if line:
                    out.append(line)
    return out


def render_scan(res, o, limit=40, title=None):
    lines = []
    v = res.verdict
    counts = res.counts()
    summ = ", ".join("%d %s" % (counts[s], s) for s in reversed(SEVERITIES) if counts.get(s))
    lines.append(o.c("1", title or "safeclone scan: %s" % res.root))
    lines.append("verdict: %s   %s   (%d files)" % (o.c(COLORS.get(v, "1"), v.upper()), summ or "no findings",
                                                     res.files_scanned))
    shown = res.sorted()
    for f in shown[:limit]:
        loc = f.path + (":%d" % f.line if f.line else "")
        lines.append("  %s %s  %s" % (o.c(COLORS[f.severity], "%-8s" % f.severity), o.c("1", loc), f.message))
        if f.snippet:
            lines.append("           " + o.c("2", f.snippet[:150]))
    if len(shown) > limit:
        lines.append("  … %d more (use --json for all)" % (len(shown) - limit))
    if res.truncated:
        lines.append(o.c("33", "  (stopped after the file limit; scan is partial)"))
    return "\n".join(lines)


def sarif(res):
    rules = sorted({f.rule for f in res.findings})
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "safeclone", "version": __version__,
                                "informationUri": "https://github.com/hamarshehmhmd/safeclone",
                                "rules": [{"id": r} for r in rules]}},
            "results": [{
                "ruleId": f.rule, "level": level[f.severity],
                "message": {"text": "[%s] %s" % (f.severity, f.message)},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.path},
                                                    "region": {"startLine": max(1, f.line)}}}],
            } for f in res.sorted()],
        }],
    }


def _acquire(target, workdir=None):
    """Return (path, kind, notes, tmp) where tmp is a temp dir to delete afterwards (or None)."""
    kind = kind_of(target)
    tmp = None
    if kind != "dir" and not workdir:
        tmp = workdir = tempfile.mkdtemp(prefix="safeclone-")
    path, kind, notes = fetch(target, workdir)
    return path, kind, notes, tmp


def _with_notes(res, notes):
    for sev, rule, name, msg in notes:
        res.findings.append(Finding(sev, rule, name, msg, surface="archive"))
    return res


def _fail(res, fail_on):
    if fail_on == "none":
        return 0
    return 1 if any(sev_rank(f.severity) >= sev_rank(fail_on) for f in res.findings) else 0


def cmd_scan(a, o):
    path, kind, notes, tmp = _acquire(a.target, a.workdir)
    res = _with_notes(scan(path, load_iocs(a.ioc_file)), notes)
    if tmp:
        shutil.rmtree(tmp, ignore_errors=True)
    if a.sarif:
        with open(a.sarif, "w", encoding="utf-8") as fh:
            json.dump(sarif(res), fh, indent=2)
    if a.json:
        print(json.dumps(res.to_dict(), indent=2))
    else:
        title = None if kind == "dir" else "safeclone scan: %s  (%s, fetched without running anything)" % (a.target, kind)
        print(render_scan(res, o, a.limit, title=title))
    return _fail(res, a.fail_on)


def cmd_open(a, o):
    base = os.path.abspath(os.path.expanduser(a.dest or os.path.join("~", "safeclone")))
    os.makedirs(base, exist_ok=True)
    stage = os.path.join(base, ".incoming")
    shutil.rmtree(stage, ignore_errors=True)
    path, kind, notes, _ = _acquire(a.target, stage)
    if kind in ("zip", "tar"):
        name = os.path.basename(a.target).split(".")[0] or "repo"
    else:
        name = os.path.basename(os.path.abspath(path).rstrip("/")) or "repo"
    dest = os.path.join(base, name)
    if os.path.exists(dest):
        if not a.force:
            raise FetchError("%s already exists (use --force to replace)" % dest)
        shutil.rmtree(dest)
    if kind == "dir":
        shutil.copytree(path, dest, symlinks=True)
    else:
        shutil.move(path, dest)
    shutil.rmtree(stage, ignore_errors=True)
    res = _with_notes(scan(dest, load_iocs(a.ioc_file)), notes)
    print(render_scan(res, o, a.limit, title="safeclone open: %s -> %s" % (a.target, dest)))
    actions = defuse(dest, res)
    print()
    print(o.c("1", "defused %d item(s):" % len(actions)))
    for act in actions:
        print("  %s %s  %s" % (o.c("32", "%-12s" % act["action"]), act["path"], o.c("2", act["why"])))
    print()
    print("Quarantined originals are in %s/.safeclone/quarantine/ (read them, don't run them)." % dest)
    if sandbox.available():
        print("Next: %s" % o.c("1", "safeclone run %s -- <install/test command>" % dest))
    return _fail(res, a.fail_on)


REGISTRIES = ("registry.npmjs.org", "registry.yarnpkg.com", "registry.npmmirror.com", "pypi.org",
              "files.pythonhosted.org", "crates.io", "static.crates.io", "index.crates.io", "proxy.golang.org",
              "sum.golang.org", "rubygems.org", "repo.packagist.org", "repo.maven.apache.org", "nodejs.org")


def _host(dest):
    d = dest.split("://", 1)[-1].split("/", 1)[0]
    return d.rsplit(":", 1)[0] if ":" in d and not d.startswith("[") else d


def split_requests(rep):
    expected, other = [], []
    for r in rep.get("proxy_requests", []):
        (expected if _host(r["dest"]) in REGISTRIES else other).append(r)
    return expected, other


def risky_connects(rep):
    """inet connects, plus unix sockets that would hand over credentials (agents, docker)."""
    out = []
    for c in rep.get("connects", []):
        if c["family"] != "unix" or any(k in c["dest"] for k in ("agent", "docker.sock", "keyring", "gpg")):
            out.append(c)
    return out


def suspicious(rep):
    _exp, other = split_requests(rep)
    return bool(rep.get("canaries") or other or risky_connects(rep))


def render_run(rep, o):
    lines = [o.c("1", "safeclone run: %s" % " ".join(rep["command"]))]
    lines.append("sandbox: no host HOME, no SSH agent, no tokens, network: %s%s" % (
        rep["network"], ", strace on" if rep.get("traced") else ""))
    if rep.get("error"):
        lines.append(o.c("31", "error: " + rep["error"]))
    lines.append("exit code: %s%s  (%.1fs)" % (rep.get("exit_code"), " (timed out)" if rep.get("timed_out") else "",
                                               rep.get("seconds") or 0))
    bad = False
    if rep["canaries"]:
        bad = True
        lines.append(o.c("1;31", "touched decoy credentials:"))
        for c in rep["canaries"]:
            lines.append("  %s %s" % (o.c("31", "%-9s" % c["how"]), c["path"]))
    else:
        lines.append(o.c("32", "decoy credentials: untouched (%d decoys)" % len(CANARIES)))
    expected, other = split_requests(rep)
    if other:
        bad = True
        lines.append(o.c("1;31", "tried to reach non-registry hosts (blocked by sinkhole):"))
        for r in other[:20]:
            lines.append("  %s %s" % (o.c("31", "%-7s" % r["method"]), r["dest"]))
    if expected:
        hosts = sorted({_host(r["dest"]) for r in expected})
        lines.append(o.c("2", "package registry requests (expected, blocked offline): %d to %s" % (len(expected), ", ".join(hosts))))
    risky = risky_connects(rep)
    if risky:
        bad = True
        lines.append(o.c("1;31", "direct connect() attempts (strace):"))
        for c in risky[:20]:
            lines.append("  %s %s" % (o.c("31", "%-7s" % c["family"]), c["dest"]))
    execs = rep.get("execs", [])
    if execs:
        progs = []
        for e in execs:
            n = os.path.basename(e["path"])
            if n not in progs:
                progs.append(n)
        lines.append("programs executed (%d execve): %s" % (len(execs), ", ".join(progs[:20])))
    f = rep["files"]
    lines.append("files: %d created, %d modified, %d deleted in the copy" % (len(f["created"]), len(f["modified"]), len(f["deleted"])))
    for k in ("created", "modified", "deleted"):
        for p in f[k][:8]:
            lines.append("  %s %s" % (o.c("2", "%-9s" % k), p))
    lines.append(o.c("1;31", "verdict: SUSPICIOUS") if bad else o.c("1;32", "verdict: nothing suspicious observed"))
    return "\n".join(lines), bad


def cmd_run(a, o):
    path, kind, notes, tmp = _acquire(a.target, None)
    cmd = a.cmd
    try:
        rep = sandbox.run(path, cmd, net=a.net, trace=a.trace, extra_ro=a.ro, timeout=a.timeout, keep=a.keep,
                          quiet_stdout=a.json)
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)
    if a.json:
        print(json.dumps(rep, indent=2))
        bad = suspicious(rep)
    else:
        text, bad = render_run(rep, o)
        print(text)
    if a.fail_on_suspicious and bad:
        return 1
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="safeclone", description="Open stranger repos without handing over your laptop.")
    ap.add_argument("--version", action="version", version="safeclone " + __version__)
    ap.add_argument("--color", choices=["auto", "always", "never"], default="auto")
    sub = ap.add_subparsers(dest="cmd_name", required=True)

    s = sub.add_parser("scan", help="statically list every auto-exec surface and IoC (runs nothing)")
    s.add_argument("target", help="git URL, .zip/.tar.gz or directory")
    s.add_argument("--json", action="store_true")
    s.add_argument("--sarif", metavar="FILE")
    s.add_argument("--fail-on", choices=SEVERITIES + ["none"], default="high")
    s.add_argument("--ioc-file", action="append", help="extra IoCs, one per line (package names, domains, strings)")
    s.add_argument("--limit", type=int, default=40)
    s.add_argument("--workdir", help="keep the fetched copy here")

    op = sub.add_parser("open", help="fetch into ~/safeclone/<name>, scan, and disarm it for your editor")
    op.add_argument("target")
    op.add_argument("--dest", help="parent folder (default ~/safeclone)")
    op.add_argument("--force", action="store_true")
    op.add_argument("--fail-on", choices=SEVERITIES + ["none"], default="none")
    op.add_argument("--ioc-file", action="append")
    op.add_argument("--limit", type=int, default=25)

    r = sub.add_parser("run", help="run a command on a copy of the repo in a credential-free sandbox (Linux, bwrap)",
                       usage="safeclone run TARGET [options] -- COMMAND [ARGS...]")
    r.add_argument("target")
    r.add_argument("--net", action="store_true", help="allow real network (default: none)")
    r.add_argument("--trace", default="auto", help="'auto' (use strace if installed), 'off', or a path to strace")
    r.add_argument("--ro", action="append", default=[], help="extra read-only path to expose (e.g. ~/.nvm)")
    r.add_argument("--timeout", type=float, default=300)
    r.add_argument("--keep", action="store_true", help="keep the sandbox copy for inspection")
    r.add_argument("--json", action="store_true")
    r.add_argument("--fail-on-suspicious", action="store_true")

    argv = list(sys.argv[1:] if argv is None else argv)
    tail = []
    if "--" in argv:
        i = argv.index("--")
        argv, tail = argv[:i], argv[i + 1:]
    a = ap.parse_args(argv)
    a.cmd = tail
    o = Out(_color(a.color))
    try:
        return {"scan": cmd_scan, "open": cmd_open, "run": cmd_run}[a.cmd_name](a, o)
    except (FetchError, sandbox.SandboxError, OSError) as e:
        print("safeclone: error: %s" % e, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
