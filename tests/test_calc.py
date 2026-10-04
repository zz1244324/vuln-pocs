import ast
import pytest
from vuln_pocs import calc

def test_加法():
    assert calc(ast.parse("1+2*3").body[0].value) == 7

def test_不支持的运算符会报错():
    with pytest.raises(ValueError):
        calc(ast.parse("1-1").body[0].value)