from vuln_pocs import raw



#1. 标准 GET，头后一个空行，没有 body
REQ_NO_BODY = """GET /a HTTP/1.1
Host: 127.0.0.1:8899"""

# 2. 标准 POST，头后一个空行 + 一行 body
REQ_POST = """POST /Less-11/ HTTP/1.1
Host: 127.0.0.1:8594
Content-Type: application/x-www-form-urlencoded

uname=admin' or 1=1 -- -&passwd=1"""

# 3. body 是多行
REQ_MULTI = """POST /Less-11/ HTTP/1.1
Host: 127.0.0.1:8594

uname=admin
passwd=1
submit=Submit"""

# 4. body 内部还有空行
REQ_INNER_BLANK = """POST /Less-11/ HTTP/1.1
Host: 127.0.0.1:8594

a=1

b=2"""

# 5. 头部值里带冒号（两个冒号，故意加重的）
REQ_COLON = """GET /a HTTP/1.1
Host: 127.0.0.1:8899
Referer: http://127.0.0.1:8594/Less-1/"""

# 6. 头部值前面有空格
REQ_SPACE = """GET /a HTTP/1.1
Host:     127.0.0.1:8899"""
def test_无body():
    m, p, h, b = raw(REQ_NO_BODY)
    assert m == "GET"
    assert p == "/a"
    assert h == {"Host": "127.0.0.1:8899"}
    assert b == ""

def test_有body():
    m, p, h, b = raw(REQ_POST)
    assert m == "POST"
    assert p == "/Less-11/"
    assert h == {"Host": "127.0.0.1:8594", "Content-Type": "application/x-www-form-urlencoded"}
    assert b == "uname=admin' or 1=1 -- -&passwd=1"

def test_多行body():
    m, p, h, b = raw(REQ_MULTI)
    assert m == "POST"
    assert p == "/Less-11/"
    assert h == {"Host": "127.0.0.1:8594"}
    assert b == "uname=admin\npasswd=1\nsubmit=Submit"

def test_body内部有空行():
    m, p, h, b = raw(REQ_INNER_BLANK)
    assert m == "POST"
    assert p == "/Less-11/"
    assert h == {"Host": "127.0.0.1:8594"}
    assert b == "a=1\n\nb=2"

def test_头部值里带冒号():
    m, p, h, b = raw(REQ_COLON)
    assert m == "GET"
    assert p == "/a"
    assert h == {"Host": "127.0.0.1:8899", "Referer": "http://127.0.0.1:8594/Less-1/"}

def test_头部值前面有空格():
    m, p, h, b = raw(REQ_SPACE)
    assert m == "GET"
    assert p == "/a"
    assert h == {"Host": "127.0.0.1:8899"}


