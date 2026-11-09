"""Disarm a copy of the repo so it is safe to open in an editor: move auto-exec files to .safeclone/quarantine."""
import json
import os
import re
import shutil

from .scan import GIT_DANGEROUS, _git_config_items

QUARANTINE = os.path.join(".safeclone", "quarantine")

ALWAYS_MOVE = [".envrc", ".pnpmfile.cjs", ".mcp.json", ".cursor/hooks.json", ".devcontainer.json",
               ".devcontainer/devcontainer.json"]


def _move(root, rel, actions, why):
    src = os.path.join(root, rel)
    if not os.path.lexists(src):
        return
    dst = os.path.join(root, QUARANTINE, rel)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    if os.path.lexists(dst):
        os.remove(dst)
    shutil.move(src, dst)
    actions.append({"action": "quarantined", "path": rel.replace(os.sep, "/"), "why": why})


def _strip_git_config(root, actions):
    cfg = os.path.join(root, ".git", "config")
    if not os.path.isfile(cfg):
        return
    with open(cfg, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    bad_lines = set()
    for key, value, line in _git_config_items(text):
        for rx, _sev, _msg in GIT_DANGEROUS:
            if re.match(rx, key) and not (key.startswith("alias.") and not value.startswith("!")):
                bad_lines.add(line)
                actions.append({"action": "removed-git-config", "path": ".git/config", "why": key})
                break
    if not bad_lines:
        return
    backup = os.path.join(root, QUARANTINE, ".git-config.original")
    os.makedirs(os.path.dirname(backup), exist_ok=True)
    shutil.copyfile(cfg, backup)
    kept = []
    for no, raw in enumerate(text.splitlines(), 1):
        if no in bad_lines:
            m = re.match(r'^(\s*\[[^\]]*\])', raw)
            kept.append((m.group(1) + " " if m else "") + "# removed by safeclone")
        else:
            kept.append(raw)
    with open(cfg, "w", encoding="utf-8") as fh:
        fh.write("\n".join(kept) + "\n")


def defuse(root, result=None):
    """Disarm repo at root in place. Returns list of actions."""
    root = os.path.realpath(root)
    actions = []
    hooks = os.path.join(root, ".git", "hooks")
    if os.path.isdir(hooks):
        for name in sorted(os.listdir(hooks)):
            if not name.endswith(".sample"):
                _move(root, os.path.join(".git", "hooks", name), actions, "git hook shipped in the repo")
    _strip_git_config(root, actions)
    for rel in ALWAYS_MOVE:
        _move(root, rel, actions, "auto-runs when the folder is opened/trusted")
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)
        if rel_dir.startswith(".safeclone") or rel_dir.split(os.sep)[0] in ("node_modules", ".git"):
            dirnames[:] = []
            continue
        for fn in filenames + [d for d in dirnames if os.path.islink(os.path.join(dirpath, d))]:
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root)
            if os.path.islink(full):
                real = os.path.realpath(full)
                if os.path.isabs(os.readlink(full)) or not real.startswith(root + os.sep):
                    _move(root, rel, actions, "symlink points outside the repo -> " + os.readlink(full))
                continue
            if rel.replace(os.sep, "/") in (".vscode/tasks.json", ".vscode/settings.json") or \
                    (rel_dir.endswith(".vscode") and fn in ("tasks.json", "settings.json")):
                _move(root, rel, actions, "VS Code workspace file that can run commands")
            elif rel_dir.split(os.sep)[0] == ".claude" and fn.startswith("settings") and fn.endswith(".json"):
                _move(root, rel, actions, "Claude Code settings can register hooks")
            elif fn.endswith(".pth") or fn in ("sitecustomize.py", "usercustomize.py"):
                _move(root, rel, actions, "Python startup hook")
            elif fn in (".yarnrc.yml", ".yarnrc"):
                _move(root, rel, actions, "yarn config can point yarnPath at repo code")
    # neutralise package-manager install scripts for the next 'npm install'
    npmrc = os.path.join(root, ".npmrc")
    if os.path.exists(os.path.join(root, "package.json")):
        if os.path.exists(npmrc):
            _move(root, ".npmrc", actions, "replaced with ignore-scripts=true")
        with open(npmrc, "w", encoding="utf-8") as fh:
            fh.write("# written by safeclone: lifecycle scripts stay off until you have read them\nignore-scripts=true\n")
        actions.append({"action": "wrote", "path": ".npmrc", "why": "ignore-scripts=true"})
    vs = os.path.join(root, ".vscode")
    os.makedirs(vs, exist_ok=True)
    with open(os.path.join(vs, "settings.json"), "w", encoding="utf-8") as fh:
        json.dump({"task.allowAutomaticTasks": "off", "security.workspace.trust.enabled": True}, fh, indent=2)
    actions.append({"action": "wrote", "path": ".vscode/settings.json", "why": "task.allowAutomaticTasks=off"})
    meta = os.path.join(root, ".safeclone")
    os.makedirs(meta, exist_ok=True)
    with open(os.path.join(meta, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump({"actions": actions, "scan": result.to_dict() if result is not None else None}, fh, indent=2)
    return actions
