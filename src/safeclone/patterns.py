"""Content heuristics shared by every surface: pipe-to-shell, obfuscation, payload hosts, hidden code."""
import re

SEVERITIES = ["info", "low", "medium", "high", "critical"]


def sev_rank(s):
    return SEVERITIES.index(s)


# (id, severity, regex, message)
CONTENT_RULES = [
    ("pipe-to-shell", "critical",
     re.compile(r"\b(curl|wget|fetch)\b[^\n|;]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b"),
     "downloads a script and pipes it straight into a shell"),
    ("powershell-download-exec", "critical",
     re.compile(r"(?i)(iwr|invoke-webrequest|downloadstring|new-object\s+net\.webclient)[^\n]*\|\s*iex|powershell[^\n]*\s-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}"),
     "PowerShell download-and-execute"),
    ("base64-to-shell", "critical",
     re.compile(r"base64\s+(-d|--decode)[^\n]*\|\s*(ba|z)?sh\b|echo\s+[A-Za-z0-9+/=]{40,}\s*\|\s*base64"),
     "decodes base64 and runs it"),
    ("eval-decoded", "critical",
     re.compile(r"\beval\s*\(\s*(atob|Buffer\.from|unescape|decodeURIComponent|String\.fromCharCode)\b|\bexec\s*\(\s*(base64\.b64decode|zlib\.decompress|bytes\.fromhex)"),
     "evaluates decoded/obfuscated code"),
    ("function-constructor", "high",
     re.compile(r"new\s+Function\s*\([^)]*(atob|fromCharCode|Buffer\.from|require)"),
     "builds code at runtime with the Function constructor"),
    ("remote-eval", "high",
     re.compile(r"(axios|fetch|request|got|https?\.get)\s*\([^\n]{0,200}\)[^\n]{0,200}(\.then\s*\([^\n]{0,80}eval|new Function)|\beval\s*\(\s*(res|response|r)\.(data|body|text)"),
     "fetches remote content and evaluates it"),
    ("inline-interpreter-net", "high",
     re.compile(r"\b(node\s+-e|python3?\s+-c|perl\s+-e|ruby\s+-e)\b[^\n]*(https?://|require\(['\"](https?|net|child_process)['\"]\)|urllib|socket)"),
     "inline interpreter one-liner that touches the network"),
    ("paste-payload-host", "high",
     re.compile(r"(?i)\b(api\.)?(npoint\.io|jsonkeeper\.com|pastebin\.com/raw|paste\.ee/r|hastebin\.com/raw|rentry\.co/[^\s/]+/raw|gist\.githubusercontent\.com)\b"),
     "pulls data from a paste/JSON-bin host (used to stage payloads in fake-interview repos)"),
    ("raw-ip-url", "high",
     re.compile(r"https?://(?!127\.0\.0\.1|0\.0\.0\.0|localhost|10\.|192\.168\.)(\d{1,3}\.){3}\d{1,3}(:\d+)?"),
     "talks to a bare IP address"),
    ("credential-paths", "high",
     re.compile(r"(\.ssh/id_[a-z0-9]+|\.aws/credentials|\.config/gh/hosts\.yml|\.docker/config\.json|\.npmrc['\"]|Login Data|Local Extension Settings|nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa|\.config/solana|Library/Keychains|keychain-db|\.kube/config)"),
     "references credential, browser-profile or crypto-wallet locations"),
    ("env-exfil", "medium",
     re.compile(r"(JSON\.stringify\(\s*process\.env\s*\)|os\.environ\.copy\(\)\s*\)|\benv\s*\|\s*(curl|nc)\b|printenv\s*\|)"),
     "serialises the whole environment (common credential-exfil step)"),
    ("reverse-shell", "critical",
     re.compile(r"/dev/tcp/\d|\bnc\b[^\n]*\s-e\s|\bsocat\b[^\n]*exec:|bash\s+-i\s*>&"),
     "reverse-shell pattern"),
]

HIDDEN_UNICODE = re.compile("[\u202a-\u202e\u2066-\u2069\u200b-\u200d\u2060\u180e\ufe00-\ufe0f]|[\U000e0000-\U000e007f]|[\U000e0100-\U000e01ef]")
FAR_RIGHT = re.compile(r"\S[ \t]{150,}\S")
LONG_LINE = 4000


def scan_text(text, max_hits=20):
    """Yield (rule_id, severity, line_no, snippet, message)."""
    hits = 0
    for no, line in enumerate(text.splitlines(), 1):
        if len(line) > 20000:
            probe = line[:20000]
        else:
            probe = line
        for rid, sev, rx, msg in CONTENT_RULES:
            m = rx.search(probe)
            if m:
                yield rid, sev, no, _snip(probe, m.start()), msg
                hits += 1
        if FAR_RIGHT.search(probe):
            m = FAR_RIGHT.search(probe)
            yield ("hidden-far-right", "high", no, _snip(probe, m.end() - 1),
                   "code hidden far to the right after a run of whitespace (scroll-off trick)")
            hits += 1
        if HIDDEN_UNICODE.search(probe):
            m = HIDDEN_UNICODE.search(probe)
            yield ("hidden-unicode", "high", no, "U+%04X at column %d" % (ord(m.group()), m.start() + 1),
                   "invisible or bidi-control Unicode characters")
            hits += 1
        if len(line) > LONG_LINE and _looks_obfuscated(line):
            yield ("obfuscated-line", "medium", no, _snip(line, 0),
                   "very long dense line that looks minified or obfuscated (%d chars)" % len(line))
            hits += 1
        if hits >= max_hits:
            return


def _looks_obfuscated(line):
    sample = line[:6000]
    if not sample:
        return False
    hexes = len(re.findall(r"\\x[0-9a-fA-F]{2}|_0x[0-9a-f]{3,}", sample))
    spaces = sample.count(" ") / len(sample)
    return hexes > 20 or spaces < 0.02


def _snip(line, pos, width=110):
    start = max(0, pos - 40)
    s = line[start:start + width].strip()
    s = re.sub(r"\s{3,}", " … ", s)
    return ("…" if start else "") + s


def worst(sevs, default="info"):
    sevs = list(sevs)
    if not sevs:
        return default
    return max(sevs, key=sev_rank)
