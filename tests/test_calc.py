import ast
import pytest
from vuln_pocs import calc,transform


def test_加法():
    assert transform("1+2*3", {}) == 7          # ← 纯数字，给空表 {}

def test_不支持的运算符会报错():
    with pytest.raises(ValueError):
        transform("1-1", {})                     # ← 补 {}

def test_非数字字面量会报错():
    with pytest.raises(ValueError):
        transform("1+'abc'", {})

def test_变量替换():
    assert transform("a+b*2", {"a": 1, "b": 2}) == 5

def test_name():
    with pytest.raises(ValueError):
        transform("a+b*2", {"a": 1})              # ← b 不存在

