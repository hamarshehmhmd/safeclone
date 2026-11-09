import io
import os
import stat
import tarfile
import zipfile

import pytest

from safeclone.defuse import defuse
from safeclone.fetch import FetchError, clone, fetch, kind_of
from safeclone.scan import scan


def test_kind_of(tmp_path):
    assert kind_of("https://github.com/a/b") == "git"
    assert kind_of("git@github.com:a/b.git") == "git"
    assert kind_of(str(tmp_path)) == "dir"
    assert kind_of("x.zip") == "zip"
    assert kind_of("x.tar.gz") == "tar"
    with pytest.raises(FetchError):
        kind_of(str(tmp_path / "nope.bin"))


def test_zip_traversal_and_symlink(tmp_path):
    z = tmp_path / "a.zip"
    with zipfile.ZipFile(str(z), "w") as zf:
        zf.writestr("../evil.txt", "x")
        zf.writestr("/abs.txt", "x")
        info = zipfile.ZipInfo("repo/link")
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(info, "/etc/passwd")
        h = zipfile.ZipInfo("repo/run.sh")
        h.external_attr = (stat.S_IFREG | 0o755) << 16
        zf.writestr(h, "#!/bin/sh\n")
    path, kind, notes = fetch(str(z), str(tmp_path / "w"))
    assert kind == "zip"
    rules = sorted(n[1] for n in notes)
    assert rules == ["archive-path-traversal", "archive-path-traversal", "archive-symlink"]
    assert not os.path.exists(str(tmp_path / "evil.txt"))
    assert not os.path.lexists(os.path.join(path, "link"))
    assert os.access(os.path.join(path, "run.sh"), os.X_OK)


def test_tar(tmp_path):
    t = tmp_path / "a.tar.gz"
    with tarfile.open(str(t), "w:gz") as tf:
        data = b"hello"
        ti = tarfile.TarInfo("proj/a.txt")
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
        ln = tarfile.TarInfo("proj/l")
        ln.type = tarfile.SYMTYPE
        ln.linkname = "/root"
        tf.addfile(ln)
        bad = tarfile.TarInfo("../x")
        bad.size = 1
        tf.addfile(bad, io.BytesIO(b"x"))
    path, kind, notes = fetch(str(t), str(tmp_path / "w"))
    assert open(os.path.join(path, "a.txt")).read() == "hello"
    assert sorted(n[1] for n in notes) == ["archive-path-traversal", "archive-symlink"]


def test_clone_failure_is_clean_error(tmp_path):
    with pytest.raises(FetchError):
        clone("https://127.0.0.1:9/none.git", str(tmp_path / "c"))


def test_clone_refuses_ext_protocol(tmp_path):
    with pytest.raises(FetchError):
        clone("ext::sh -c touch% /tmp/pwned-safeclone", str(tmp_path / "c"))
    assert not os.path.exists("/tmp/pwned-safeclone")


def test_defuse_takehome(takehome, tmp_path):
    path, _, _ = fetch(takehome, str(tmp_path / "w"))
    res = scan(path)
    actions = defuse(path, res)
    done = {(a["action"], a["path"]) for a in actions}
    assert ("quarantined", ".git/hooks/post-checkout") in done
    assert ("quarantined", ".vscode/tasks.json") in done
    assert ("removed-git-config", ".git/config") in done
    assert ("wrote", ".npmrc") in done
    assert os.path.exists(os.path.join(path, ".git/hooks/pre-commit.sample"))
    cfg = open(os.path.join(path, ".git/config")).read()
    assert "fsmonitor" not in cfg and "repositoryformatversion" in cfg
    assert "ignore-scripts=true" in open(os.path.join(path, ".npmrc")).read()
    assert os.path.exists(os.path.join(path, ".safeclone/quarantine/.vscode/tasks.json"))
    assert os.path.exists(os.path.join(path, ".safeclone/manifest.json"))
    again = scan(path)
    surf = {f.rule for f in again.findings if not f.path.startswith(".safeclone")}
    assert "git-hook-command" not in surf and "git-config-command" not in surf and "vscode-task-command" not in surf


def test_defuse_symlink_and_envrc(tmp_path, w):
    w(tmp_path, ".envrc", "echo hi\n")
    w(tmp_path, ".claude/settings.json", {"hooks": {}})
    os.symlink("/etc", str(tmp_path / "out"))
    actions = defuse(str(tmp_path))
    paths = {a["path"] for a in actions if a["action"] == "quarantined"}
    assert {".envrc", "out", ".claude/settings.json"} <= paths
    assert not os.path.lexists(str(tmp_path / "out"))
