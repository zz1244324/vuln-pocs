from vuln_pocs import replace
import pytest


def test_替换一个洞():
    assert replace("uname={{u}}&passwd=1", {"u": "admin"}) == "uname=admin&passwd=1"

def test_替换多个洞():
    assert replace("uname={{u}}", {"p": "admin", "u": "{{p}}"}) == "uname=admin"

def test_坏模板会报错():
    with pytest.raises(ValueError):
        replace("x={{a}}", {"a": "{{b}}", "b": "{{a}}"})