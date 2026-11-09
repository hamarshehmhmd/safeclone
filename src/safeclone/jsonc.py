"""Tolerant JSON-with-comments parser (VS Code tasks/settings, devcontainer.json)."""
import json
import re


def strip_comments(text):
    out, i, n = [], 0, len(text)
    in_str = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


_TRAILING = re.compile(r",(\s*[}\]])")


def loads(text):
    """Parse JSONC. Returns None if it still is not valid JSON."""
    if text.startswith("\ufeff"):
        text = text[1:]
    cleaned = strip_comments(text)
    prev = None
    while prev != cleaned:
        prev, cleaned = cleaned, _TRAILING.sub(r"\1", cleaned)
    try:
        return json.loads(cleaned)
    except ValueError:
        return None
