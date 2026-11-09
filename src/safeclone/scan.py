"""Static scan of every place a repo can run code before you decide to run it."""
import json
import os
import re
import stat
from dataclasses import asdict, dataclass, field

from . import jsonc
from .patterns import scan_text, sev_rank, worst

SKIP_DIRS = {"node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache", "dist", "build", ".next", "target"}
MAX_FILE = 1_000_000
MAX_FILES = 8000
TEXT_EXT = {
    ".js", ".cjs", ".mjs", ".ts", ".tsx", ".jsx", ".json", ".jsonc", ".py", ".sh", ".bash", ".zsh",
    ".ps1", ".bat", ".cmd", ".rb", ".pl", ".php", ".go", ".rs", ".toml", ".yaml", ".yml", ".cfg",
    ".ini", ".mk", ".env", ".envrc", ".md", ".txt", ".html", ".vue", ".svelte", ".lua", ".java", ".kt",
}
TEXT_NAMES = {"Makefile", "makefile", "GNUmakefile", "justfile", "Justfile", "Taskfile.yml", "Dockerfile",
              ".envrc", ".npmrc", ".yarnrc", ".yarnrc.yml", "Rakefile", "Gemfile", "config", "pre-commit"}

GIT_DANGEROUS = [
    (r"^core\.hookspath$", "critical", "core.hooksPath points git at hooks shipped in the repo"),
    (r"^core\.fsmonitor$", "critical", "core.fsmonitor runs a program on every git status"),
    (r"^core\.sshcommand$", "critical", "core.sshCommand replaces ssh for every fetch/push"),
    (r"^core\.(pager|editor|askpass)$", "high", "git runs this program for you"),
    (r"^core\.gitproxy$", "high", "core.gitProxy runs a program for git:// URLs"),
    (r"^filter\..+\.(clean|smudge|process)$", "critical", "filter driver runs on checkout/add"),
    (r"^diff\..+\.(textconv|command)$", "high", "diff driver runs a program on git diff/log"),
    (r"^merge\..+\.driver$", "high", "merge driver runs a program on merge"),
    (r"^credential\..*helper$|^credential\.helper$", "critical", "credential helper receives your git credentials"),
    (r"^include(if\..+)?\.path$", "high", "includes another config file"),
    (r"^alias\..+$", "medium", "git alias (shell aliases start with '!')"),
    (r"^(sequence|gpg|ssh)\.(editor|program)$|^gpg\..+\.program$", "high", "git runs this program for you"),
    (r"^uploadpack\.packobjectshook$|^protocol\..+\.allow$", "high", "changes how git runs/transports"),
]

AUTO_TASK_KEYS = ("runOn",)
VSCODE_EXEC_SETTINGS = re.compile(
    r"^(terminal\.integrated\.(profiles|shell|shellArgs|env|automationProfile|defaultProfile)|"
    r"python\.(defaultInterpreterPath|pythonPath|venvPath)|git\.path|eslint\.(runtime|nodePath)|"
    r"npm\.packageManager|php\..*executablePath|go\.(alternateTools|goroot|toolsGopath)|rust-analyzer\.server\.path|"
    r".*\.(executablePath|serverPath|binaryPath|commandPath|interpreterPath|nodePath|pythonPath)|"
    r"jest\.jestCommandLine|deno\.path|julia\.executablePath|clangd\.path|"
    r"task\.allowAutomaticTasks|security\.workspace\.trust\..*|extensions\.ignoreRecommendations)$")
DEVCONTAINER_HOOKS = ["initializeCommand", "onCreateCommand", "updateContentCommand", "postCreateCommand",
                      "postStartCommand", "postAttachCommand"]
NPM_INSTALL_HOOKS = {"preinstall", "install", "postinstall", "prepublish", "preprepare", "prepare", "postprepare"}
NPM_RUN_HOOKS = {"predev", "prestart", "pretest", "prebuild", "postdev", "poststart"}


@dataclass
class Finding:
    severity: str
    rule: str
    path: str
    message: str
    line: int = 0
    snippet: str = ""
    surface: str = "content"

    def to_dict(self):
        return asdict(self)


@dataclass
class ScanResult:
    root: str
    findings: list = field(default_factory=list)
    surfaces: dict = field(default_factory=dict)
    files_scanned: int = 0
    truncated: bool = False

    @property
    def verdict(self):
        return worst((f.severity for f in self.findings), default="clean") if self.findings else "clean"

    def counts(self):
        out = {}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    def to_dict(self):
        return {
            "root": self.root, "verdict": self.verdict, "counts": self.counts(),
            "files_scanned": self.files_scanned, "truncated": self.truncated,
            "surfaces": self.surfaces, "findings": [f.to_dict() for f in self.sorted()],
        }

    def sorted(self):
        return sorted(self.findings, key=lambda f: (-sev_rank(f.severity), f.path, f.line))


def _read(path):
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_FILE + 1)
    except OSError:
        return None
    if b"\x00" in data[:8192]:
        return None
    return data[:MAX_FILE].decode("utf-8", "replace")


class Scanner:
    def __init__(self, root, iocs=()):
        self.root = os.path.realpath(root)
        self.res = ScanResult(root=self.root)
        self.iocs = [i for i in iocs if i]
        self._seen_content = set()

    def rel(self, p):
        return os.path.relpath(p, self.root).replace(os.sep, "/")

    def add(self, severity, rule, path, message, line=0, snippet="", surface="content"):
        rel = self.rel(path) if os.path.isabs(path) else path
        self.res.findings.append(Finding(severity, rule, rel, message, line, snippet, surface))
        self.res.surfaces.setdefault(surface, 0)
        self.res.surfaces[surface] += 1

    # ---- command strings that a tool will run for you -------------------------------------
    def check_command(self, cmd, path, surface, base_sev, what, line=0, snippet=None):
        cmd_s = cmd if isinstance(cmd, str) else " ".join(str(c) for c in (cmd or []))
        if isinstance(cmd, dict):
            cmd_s = " ; ".join(str(v) for v in cmd.values())
        sevs = [base_sev]
        extra = []
        for rid, sev, _no, _snip, msg in scan_text(cmd_s):
            sevs.append("critical" if sev_rank(sev) >= sev_rank("high") else sev)
            extra.append(msg)
        sev = worst(sevs)
        msg = what + (" — " + "; ".join(sorted(set(extra))) if extra else "")
        self.add(sev, surface + "-command", path, msg, line, (snippet if snippet is not None else cmd_s)[:200], surface)
        self._seen_content.add(os.path.abspath(path) if os.path.isabs(path) else os.path.join(self.root, path))

    # ---- surfaces ---------------------------------------------------------------------------
    def git(self):
        gitdir = os.path.join(self.root, ".git")
        if os.path.isfile(gitdir):
            self.add("medium", "git-file", gitdir, ".git is a file (gitdir: redirect); check where it points",
                     snippet=(_read(gitdir) or "").strip()[:120], surface="git")
            return
        if not os.path.isdir(gitdir):
            return
        hooks = os.path.join(gitdir, "hooks")
        if os.path.isdir(hooks):
            for name in sorted(os.listdir(hooks)):
                p = os.path.join(hooks, name)
                if name.endswith(".sample") or not os.path.isfile(p):
                    continue
                body = _read(p) or ""
                execu = bool(os.stat(p).st_mode & stat.S_IXUSR)
                last = [ln for ln in body.splitlines() if ln.strip() and not ln.startswith("#")]
                self.check_command(body, p, "git-hook",
                                   "critical" if execu else "high",
                                   "git hook '%s' shipped inside the repo%s — runs on your next git %s" % (
                                       name, "" if execu else " (not executable yet)", _hook_trigger(name)),
                                   snippet=last[-1] if last else "")
        cfg = os.path.join(gitdir, "config")
        if os.path.isfile(cfg):
            for key, value, line in _git_config_items(_read(cfg) or ""):
                for rx, sev, msg in GIT_DANGEROUS:
                    if re.match(rx, key):
                        if key.startswith("alias.") and not value.startswith("!"):
                            continue
                        self.check_command(value, cfg, "git-config", sev, "%s = … (%s)" % (key, msg), line)
                        break

    def vscode(self, d):
        tasks = os.path.join(d, ".vscode", "tasks.json")
        if os.path.isfile(tasks):
            data = jsonc.loads(_read(tasks) or "") or {}
            if not isinstance(data, dict):
                data = {}
            for t in data.get("tasks", []) or []:
                if not isinstance(t, dict):
                    continue
                run_on = (t.get("runOptions") or {}).get("runOn")
                pres = t.get("presentation") or {}
                hidden = pres.get("reveal") == "never" or pres.get("echo") is False or pres.get("close") is True
                cmd = " ".join(str(x) for x in [t.get("command", "")] + list(t.get("args", []) or []))
                for osk in ("linux", "osx", "windows"):
                    if isinstance(t.get(osk), dict) and t[osk].get("command"):
                        cmd += " ; " + str(t[osk]["command"])
                label = t.get("label", "?")
                if run_on == "folderOpen":
                    self.check_command(cmd, tasks, "vscode-task", "critical",
                                       "task '%s' runs automatically when the folder is opened%s" % (
                                           label, " with its output hidden" if hidden else ""))
                else:
                    self.check_command(cmd, tasks, "vscode-task", "low", "task '%s' (runs only when you start it)" % label)
        settings = os.path.join(d, ".vscode", "settings.json")
        if os.path.isfile(settings):
            data = jsonc.loads(_read(settings) or "") or {}
            for k, v in (data.items() if isinstance(data, dict) else []):
                if VSCODE_EXEC_SETTINGS.match(k):
                    sev = "high"
                    if k == "task.allowAutomaticTasks" and str(v).lower() == "on":
                        sev = "critical"
                        what = "task.allowAutomaticTasks=on lets folder-open tasks run without asking"
                    elif k.startswith("security.workspace.trust"):
                        what = "workspace setting tries to change Workspace Trust (%s)" % k
                    elif k == "extensions.ignoreRecommendations":
                        continue
                    else:
                        what = "workspace setting '%s' makes the editor run a program from here" % k
                    self.check_command(json.dumps(v), settings, "vscode-settings", sev, what)
        launch = os.path.join(d, ".vscode", "launch.json")
        if os.path.isfile(launch):
            data = jsonc.loads(_read(launch) or "") or {}
            for c in (data.get("configurations", []) if isinstance(data, dict) else []) or []:
                if isinstance(c, dict) and c.get("preLaunchTask"):
                    self.add("low", "vscode-prelaunch", launch,
                             "launch config '%s' runs task '%s' before debugging" % (c.get("name"), c["preLaunchTask"]),
                             surface="vscode-launch")

    def devcontainer(self, d):
        for p in (os.path.join(d, ".devcontainer", "devcontainer.json"), os.path.join(d, ".devcontainer.json")):
            if not os.path.isfile(p):
                continue
            data = jsonc.loads(_read(p) or "") or {}
            if not isinstance(data, dict):
                continue
            for hook in DEVCONTAINER_HOOKS:
                if data.get(hook):
                    if hook == "initializeCommand":
                        self.check_command(data[hook], p, "devcontainer", "critical",
                                           "initializeCommand runs on your HOST before the container starts")
                    else:
                        self.check_command(data[hook], p, "devcontainer", "medium",
                                           "%s runs inside the dev container (which gets your git creds/SSH agent by default)" % hook)
            text = json.dumps(data)
            if re.search(r"docker\.sock|\$\{localEnv:HOME\}|/\.ssh|/\.aws|source=/(,|\")|\"--privileged\"|\"privileged\":\s*true", text):
                self.add("high", "devcontainer-host-access", p,
                         "dev container mounts host secrets/docker socket or runs privileged", surface="devcontainer")

    def package_json(self, p):
        data = jsonc.loads(_read(p) or "") or {}
        if not isinstance(data, dict):
            return
        scripts = data.get("scripts") or {}
        if isinstance(scripts, dict):
            for name, cmd in scripts.items():
                if name in NPM_INSTALL_HOOKS:
                    self.check_command(cmd, p, "npm-lifecycle", "high", "'%s' script runs on npm install" % name)
                elif name in NPM_RUN_HOOKS:
                    self.check_command(cmd, p, "npm-lifecycle", "low", "'%s' script runs before '%s'" % (name, name[3:] if name.startswith("pre") else name[4:]))
                else:
                    hits = list(scan_text(str(cmd)))
                    if hits:
                        self.check_command(cmd, p, "npm-script", "medium", "script '%s'" % name)
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            deps = data.get(section) or {}
            if not isinstance(deps, dict):
                continue
            for name, spec in deps.items():
                s = str(spec)
                low = name.lower()
                for ioc in self.iocs:
                    if ioc.lower() == low:
                        self.add("critical", "ioc-package", p, "dependency '%s' is on the IoC list" % name,
                                 snippet="%s: %s" % (name, s), surface="ioc")
                if re.match(r"^(https?:|git(\+\w+)?:|github:|file:|[\w.-]+/[\w.-]+(#.*)?$)", s):
                    self.add("medium", "npm-url-dependency", p,
                             "%s '%s' is fetched from a URL/git ref, not the registry" % (section, name),
                             snippet="%s: %s" % (name, s), surface="npm-deps")

    def python(self, d):
        setup = os.path.join(d, "setup.py")
        if os.path.isfile(setup):
            self.add("medium", "setup-py", setup, "setup.py runs arbitrary Python on pip install / build",
                     surface="python-build")
        pyproject = os.path.join(d, "pyproject.toml")
        if os.path.isfile(pyproject):
            text = _read(pyproject) or ""
            m = re.search(r"(?m)^\s*backend-path\s*=\s*(.+)$", text)
            if m:
                self.add("high", "in-tree-build-backend", pyproject,
                         "build-system uses an in-tree build backend (repo code runs on pip install)",
                         snippet=m.group(0).strip(), surface="python-build")

    def walk(self):
        count = 0
        for dirpath, dirnames, filenames in os.walk(self.root, followlinks=False):
            rel = self.rel(dirpath)
            dirnames[:] = sorted(x for x in dirnames if x not in SKIP_DIRS and not (rel == "." and x == ".git"))
            for dn in list(dirnames):
                full = os.path.join(dirpath, dn)
                if os.path.islink(full):
                    self._symlink(full)
            if rel == "." or rel.count("/") < 4:
                self.vscode(dirpath)
                self.devcontainer(dirpath)
                self.python(dirpath)
            for fn in sorted(filenames):
                full = os.path.join(dirpath, fn)
                if os.path.islink(full):
                    self._symlink(full)
                    continue
                count += 1
                if count > MAX_FILES:
                    self.res.truncated = True
                    return
                self._file(full, fn)
        self.res.files_scanned = count

    def _symlink(self, p):
        target = os.readlink(p)
        real = os.path.realpath(p)
        if os.path.isabs(target) or not (real == self.root or real.startswith(self.root + os.sep)):
            self.add("high", "symlink-escape", p, "symlink points outside the repo", snippet="-> " + target,
                     surface="symlinks")

    def _file(self, full, fn):
        rel = self.rel(full)
        surface_files = {
            ".envrc": ("high", "direnv", ".envrc is executed by direnv when you cd into the folder (once allowed)"),
            ".pnpmfile.cjs": ("high", "pnpmfile", ".pnpmfile.cjs runs on every pnpm install"),
            ".mcp.json": ("high", "agent-mcp", "MCP servers defined here are launched by Claude Code/Cursor when you trust the folder"),
        }
        if fn in surface_files:
            sev, surface, msg = surface_files[fn]
            body = _read(full) or ""
            self.check_command(body[:4000], full, surface, sev, msg)
        elif fn == "package.json":
            self.package_json(full)
        elif fn in (".yarnrc.yml", ".yarnrc"):
            body = _read(full) or ""
            m = re.search(r"(?m)^\s*yarn-?[pP]ath\s*[:=]?\s*\"?([^\s\"]+)", body)
            if m:
                self.add("high", "yarn-path", full, "yarnPath makes yarn execute a JS file from the repo", snippet=m.group(0).strip(),
                         surface="package-manager")
        elif fn == ".npmrc":
            body = _read(full) or ""
            for m in re.finditer(r"(?m)^\s*(script-shell|node-options|onload-script|registry|@[\w-]+:registry)\s*=\s*(.+)$", body):
                sev = "medium" if "registry" in m.group(1) else "high"
                self.add(sev, "npmrc", full, ".npmrc sets %s" % m.group(1), snippet=m.group(0).strip(), surface="package-manager")
        elif fn.endswith(".pth") or fn in ("sitecustomize.py", "usercustomize.py"):
            self.add("high", "python-startup", full, "%s runs automatically whenever Python starts with this dir on the path" % fn,
                     surface="python-build")
        elif rel.startswith(".claude/") and fn.startswith("settings") and fn.endswith(".json"):
            data = jsonc.loads(_read(full) or "") or {}
            if isinstance(data, dict) and data.get("hooks"):
                self.check_command(json.dumps(data["hooks"])[:4000], full, "agent-hooks", "high",
                                   "Claude Code hooks run shell commands during your agent session")
        elif rel in (".cursor/hooks.json", ".gemini/settings.json", ".codex/config.toml"):
            self.check_command((_read(full) or "")[:4000], full, "agent-hooks", "medium",
                               "coding-agent config in the repo can register hooks/MCP servers")
        elif rel.startswith(".husky/") and "." not in fn and fn != "_":
            self.check_command((_read(full) or "").strip()[-400:], full, "git-hook", "medium",
                               "husky hook (installed by the 'prepare' script on npm install)")
        if os.path.isfile(full):
            try:
                with open(full, "rb") as fh:
                    magic = fh.read(4)
            except OSError:
                magic = b""
            if magic in (b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xfe\xed\xfa\xcf") or magic[:2] == b"MZ":
                self.add("medium", "native-binary", full, "prebuilt native executable/library in the repo", surface="binaries")
                return
        ext = os.path.splitext(fn)[1].lower()
        if ext in TEXT_EXT or fn in TEXT_NAMES or ".git/hooks" in rel:
            try:
                if os.path.getsize(full) > MAX_FILE:
                    return
            except OSError:
                return
            body = _read(full)
            if body is not None:
                self._content(full, body)

    def _content(self, full, body, boost=False):
        key = (full, boost)
        if key in self._seen_content:
            return
        self._seen_content.add(key)
        if full in self._seen_content and not boost:
            return
        for rid, sev, no, snip, msg in scan_text(body):
            if rid == "credential-paths" and os.path.basename(full).lower().startswith(("readme", "security", "changelog")):
                continue
            self.add(sev, rid, full, msg, no, snip, "content")
        low = body.lower()
        for ioc in self.iocs:
            if len(ioc) >= 6 and ioc.lower() in low:
                no = low[:low.find(ioc.lower())].count("\n") + 1
                self.add("critical", "ioc-string", full, "matches IoC '%s'" % ioc, no, ioc, "ioc")

    def run(self):
        self.git()
        self.walk()
        # de-duplicate exact repeats
        seen, uniq = set(), []
        for f in self.res.findings:
            k = (f.rule, f.path, f.line, f.message)
            if k not in seen:
                seen.add(k)
                uniq.append(f)
        self.res.findings = uniq
        return self.res


def _hook_trigger(name):
    return {"pre-commit": "commit", "commit-msg": "commit", "prepare-commit-msg": "commit", "post-commit": "commit",
            "post-checkout": "checkout/switch/clone", "post-merge": "pull/merge", "pre-push": "push",
            "pre-rebase": "rebase", "post-rewrite": "rebase/amend", "reference-transaction": "command that updates refs",
            "fsmonitor-watchman": "status"}.get(name, "operation")


def _git_config_items(text):
    section = ""
    for no, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line[0] in "#;":
            continue
        m = re.match(r'^\[\s*([A-Za-z0-9.-]+)(?:\s+"(.*)")?\s*\]\s*(.*)$', line)
        if m:
            section = m.group(1).lower() + ("." + m.group(2) if m.group(2) is not None else "")
            line = m.group(3).strip()
            if not line:
                continue
        if "=" in line:
            k, v = line.split("=", 1)
        else:
            k, v = line, "true"
        yield section + "." + k.strip().lower(), v.strip().strip('"'), no


def scan(root, iocs=()):
    return Scanner(root, iocs).run()
