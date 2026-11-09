"""Get a stranger's repo onto disk without running anything: git URL, .zip, .tar(.gz) or a directory."""
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import zipfile

GIT_URL = re.compile(r"^(https?://|ssh://|git@[\w.-]+:|git://)")


class FetchError(Exception):
    pass


def kind_of(target):
    if GIT_URL.match(target):
        return "git"
    low = target.lower()
    if os.path.isdir(target):
        return "dir"
    if low.endswith(".zip"):
        return "zip"
    if low.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz")):
        return "tar"
    if os.path.isfile(target):
        if zipfile.is_zipfile(target):
            return "zip"
        if tarfile.is_tarfile(target):
            return "tar"
    raise FetchError("don't know how to open %r (want a git URL, .zip, .tar.gz or directory)" % target)


def safe_git_env():
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update({
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/bin/false" if os.name != "nt" else "echo",
        "GIT_LFS_SKIP_SMUDGE": "1",
        "GIT_ALLOW_PROTOCOL": "https:http:ssh:git",
    })
    env.pop("SSH_AUTH_SOCK", None)
    return env


def clone(url, dest, depth=1):
    cmd = ["git",
           "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "core.symlinks=false",
           "-c", "protocol.file.allow=never", "-c", "protocol.ext.allow=never",
           "-c", "credential.helper=", "-c", "submodule.recurse=false", "-c", "filter.lfs.smudge=",
           "-c", "filter.lfs.process=", "-c", "filter.lfs.required=false",
           "clone", "--no-recurse-submodules", "--quiet"]
    if depth:
        cmd += ["--depth", str(depth)]
    cmd += ["--", url, dest]
    p = subprocess.run(cmd, env=safe_git_env(), capture_output=True, text=True, stdin=subprocess.DEVNULL)
    if p.returncode:
        raise FetchError("git clone failed: " + (p.stderr.strip() or "exit %d" % p.returncode))


def _safe_member(name, dest):
    name = name.replace("\\", "/")
    if name.startswith("/") or re.match(r"^[A-Za-z]:", name) or ".." in name.split("/"):
        return None
    full = os.path.realpath(os.path.join(dest, name))
    root = os.path.realpath(dest)
    if full != root and not full.startswith(root + os.sep):
        return None
    return full


def extract_zip(path, dest, notes):
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            full = _safe_member(info.filename, dest)
            if full is None:
                notes.append(("critical", "archive-path-traversal", info.filename, "archive entry escapes the folder (skipped)"))
                continue
            mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                target = zf.read(info).decode("utf-8", "replace")
                notes.append(("high", "archive-symlink", info.filename, "archive contains a symlink -> %s (not created)" % target))
                continue
            if info.is_dir():
                os.makedirs(full, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with zf.open(info) as src, open(full, "wb") as out:
                shutil.copyfileobj(src, out)
            if mode & 0o111:
                os.chmod(full, 0o755)


def extract_tar(path, dest, notes):
    with tarfile.open(path) as tf:
        for m in tf.getmembers():
            full = _safe_member(m.name, dest)
            if full is None:
                notes.append(("critical", "archive-path-traversal", m.name, "archive entry escapes the folder (skipped)"))
                continue
            if m.issym() or m.islnk():
                notes.append(("high", "archive-symlink", m.name, "archive contains a link -> %s (not created)" % m.linkname))
                continue
            if m.isdir():
                os.makedirs(full, exist_ok=True)
            elif m.isfile():
                os.makedirs(os.path.dirname(full), exist_ok=True)
                src = tf.extractfile(m)
                with open(full, "wb") as out:
                    shutil.copyfileobj(src, out)
                os.chmod(full, 0o755 if m.mode & 0o111 else 0o644)
            else:
                notes.append(("medium", "archive-special-file", m.name, "device/fifo entry skipped"))


def _single_top(dest):
    entries = [e for e in os.listdir(dest) if e not in ("__MACOSX",)]
    if len(entries) == 1 and os.path.isdir(os.path.join(dest, entries[0])):
        return os.path.join(dest, entries[0])
    return dest


def fetch(target, workdir=None):
    """Return (path_to_repo, kind, notes). Never executes repo content."""
    kind = kind_of(target)
    notes = []
    if kind == "dir":
        return os.path.abspath(target), kind, notes
    workdir = workdir or tempfile.mkdtemp(prefix="safeclone-")
    os.makedirs(workdir, exist_ok=True)
    if kind == "git":
        name = re.sub(r"\.git$", "", target.rstrip("/").split("/")[-1].split(":")[-1]) or "repo"
        dest = os.path.join(workdir, name)
        clone(target, dest)
        return dest, kind, notes
    dest = os.path.join(workdir, "extracted")
    os.makedirs(dest, exist_ok=True)
    (extract_zip if kind == "zip" else extract_tar)(target, dest, notes)
    return _single_top(dest), kind, notes
