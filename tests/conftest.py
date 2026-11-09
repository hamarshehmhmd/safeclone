import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, os.path.join(ROOT, "examples"))


def write(base, rel, body, mode=None):
    p = os.path.join(str(base), rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(body if isinstance(body, str) else json.dumps(body))
    if mode:
        os.chmod(p, mode)
    return p


@pytest.fixture
def w():
    return write


@pytest.fixture
def takehome(tmp_path):
    import make_takehome
    return make_takehome.build(str(tmp_path / "takehome.zip"))
