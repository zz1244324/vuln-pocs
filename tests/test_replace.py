from vuln_pocs import replace
import pytest


def test_替换一个洞():
    assert replace("uname={{u}}&passwd=1", {"u": "admin"}) == "uname=admin&passwd=1"

def test_替换嵌套的洞():
    assert replace("uname={{u}}", {"p": "admin", "u": "{{p}}"}) == "uname=admin"

def test_坏模板会报错():
    with pytest.raises(ValueError):
        replace("x={{a}}", {"a": "{{b}}", "b": "{{a}}"})

def test_替换表达式():
    assert replace("a={{1+1}}", {}) == "a=2"

def test_变量与运算混写():
    assert replace("a={{n+1}}", {"n": 5}) == "a=6"

def test_未闭合的占位符会报错():
    with pytest.raises(ValueError, match="未闭合"):
        replace("a={{b", {})


