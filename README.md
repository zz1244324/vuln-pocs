## vuln-pocs:
```bash
  vuln-pocs是基于pocs引擎的漏洞扫描器
  框架参考nuclei
```
*该引擎是基于yaml模板,模板请放`src/vuln_pocs/templates/`文件夹中
### 快速开始

需要 Python 3.12 + uv

```bash
  uv sync                      # 装依赖
  uv run vuln-pocs <目标URL1> <目标URL2> #支持多url扫描
```

在sqli-lab中的代码演示图

```bash
[进度 1/14] joomla-unauth: clean
2026-11-01 19:28:24,461 - INFO - http://127.0.0.1:8594/api/index.php/v1/config/application?public=true 没发现漏洞,模板名:joomla-unauth,响应状态:404
[进度 2/14] bak-exposed: clean
2026-11-01 19:28:24,475 - INFO - http://127.0.0.1:8594/index.php.bak 没发现漏洞,模板名:bak-exposed,响应状态:404
[进度 3/14] less11-raw: hit
2026-11-01 19:28:26,548 - WARNING - http://127.0.0.1:8594/Less-11/ 命中漏洞,模板名:less11-raw:命中词:Your Login name
[进度 4/14] nginx-alias: clean
2026-11-01 19:28:26,551 - INFO - http://127.0.0.1:8594/files../etc/passwd 没发现漏洞,模板名:nginx-alias,响应状态:404
[进度 5/14] phpunit-rce: clean
2026-11-01 19:28:26,553 - INFO - http://127.0.0.1:8594/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php 没发现漏洞,模板名:phpunit-rce,响应状态:404
[进度 6/14] shiro-deser: clean
2026-11-01 19:28:26,557 - INFO - http://127.0.0.1:8594/ 没发现漏洞,模板名:shiro-deser,响应状态:200
[进度 7/14] less11-post-sqli: hit
2026-11-01 19:28:26,701 - WARNING - http://127.0.0.1:8594/Less-11/ 命中漏洞,模板名:less11-post-sqli:命中词:Your Login name
[进度 8/14] ssti: clean
2026-11-01 19:28:26,705 - INFO - http://127.0.0.1:8594/ 没发现漏洞,模板名:ssti,响应状态:200
[进度 9/14] thinkphp5-rce: clean
2026-11-01 19:28:26,709 - INFO - http://127.0.0.1:8594/index.php?s=/Index/%5Cthink%5Capp/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=-1 没发现漏洞,模板名:thinkphp5-rce,响应状态:404
[进度 10/14] tomcat-weak-pass: clean
2026-11-01 19:28:26,712 - INFO - http://127.0.0.1:8594/manager/html 没发现漏洞,模板名:tomcat-weak-pass,响应状态:404
[进度 11/14] weblogic-ssrf: clean
2026-11-01 19:28:26,717 - INFO - http://127.0.0.1:8594/uddiexplorer/SearchPublicRegistries.jsp 没发现漏洞,模板名:weblogic-ssrf,响应状态:404
[进度 12/14] sqli-error: hit
2026-11-01 19:28:28,616 - WARNING - http://127.0.0.1:8594/Less-1/ 命中漏洞,模板名:sqli-error:命中词:You have an error in your SQL syntax
[进度 13/14] xff-spoof: hit
2026-11-01 19:28:28,762 - WARNING - http://127.0.0.1:8594/Less-18/ 命中漏洞,模板名:xff-spoof:命中正则:<title>Less-18[^<]*</title>,匹配内容:<title>Less-18 Header Injectio...
[进度 14/14] less9-time-blind: hit
2026-11-01 19:28:33,804 - WARNING - http://127.0.0.1:8594/Less-9/ 命中漏洞,模板名:less9-time-blind:基线:2.25,payloadtime:7.07
```

![运行效果](docs/d_1.png)

```bash
  实测时间盲注,post型注入、报错注入、XFF头注入

```

### 模式
```bash
  uv run vuln-pocs <目标URL> --v #详细输出扫描日志
  uv run vuln-pocs <目标URL> --rate N ##每秒最多发 N 个请求
  uv run vuln-pocs <目标URL> --workers N #N为设置并发数(默认为3)

```


### 功能

```bash
  1.已是命令行参数：--workers N（默认 3）
  2.raw报文解析:见下图模板格式
  3.ast白名单:允许自己设置白名单,目前支持数字常量（int / float） · 变量名 · + · *
  4.探针:用去检查目标是否挂了,会在开始先测试一次可通性


```
### 模板格式
```bash
常规式:
  name: #模板名
  request:
    method: #请求方式
    path: #目录
    headers:
      #请求头(默认没有)
    param:
      #关键字:参数
    payload:
      #用去时间盲注的第二次请求
    timeout: #时间限制
  matcher:
    type: status / word / regex / size / time
    words: ["特征词"]
```
```bash
raw报文解析式:
  name: #模板名
  request:
   raw: |  #这个|必须要加
    #报文(注意空格.根据空格判断body)
  matcher:
    type: status / word / regex / size / time
    words: ["特征词"]
```
### matcher 字段

| type | 该填的字段名 | 说明 |
|---|---|---|
| `status` | `status` | 期望状态码 ⚠️ 仅协议级证据，勿单独作为判定 |
| `word` | `words` | 特征词列表，命中任一即算 |
| `regex` | `regex` | 正则列表 |
| `size` | `size` / `not_size` | 期望长度 / 排除长度 |
| `time` | `sleep` | 阈值秒数，第二发慢过它才算命中 |

### 引擎结构

| 函数 | 作用 | 说明 |
|---|---|---|
| `main` | 编排全流程 | CLI 参数 → 探针 → 并发派发 → 按序收集结果 |
| `probe` | 可达性探针 | 开跑前 + worker 撞连接错误时复用；绕代理，4xx/5xx 也算"活" |
| `scan_template` | 处理单个模板 | 并发单元：只算不打印，返回结果 dict |
| `load_template` | 导入 YAML 模板 | 解析失败时软跳过（不崩） |
| `raw` | 报文解析 | 首行 method + path，空行之后是 body |
| `data_check` | 模板字段校验 | 按必需字段表逐条核 |
| `build_url` | 构造 URL | 替换 `{{BaseURL}}`；相对路径则拼接 |
| `send_request` | 发送请求 | 每线程一个 Session，带超时 / 重试 |
| `replace` | `{{变量}}` 替换 | 支持嵌套 |
| `transform` | 文本转化节点 | 表达式 → 值（AST 入口） |
| `calc` | 白名单求值器 | `ast` 节点白名单，**禁用 `eval`** |
| `match_*` | 漏洞判断分派 | `status` / `word` / `regex` / `size` / `time` |
| `render` | 结果输出 | 主线程调用，保证日志顺序 |


### 输出文件

```bash
result.db —— SQLite 库，含每次入库记录
reports/json_report_<时间戳>.json —— JSON 报告


```
```bash
扫描结束后会在末尾输出入库数
```
![运行效果](docs/d_2.png)

### 注意事项
```bash
1.库里只记“真跑过并出结论”的——skip / unreachable 不入库
2.status 型只能证明服务器返回了该状态码，不能证明文件或漏洞存在，须配合 word / regex 内容判据使用

```


### 已知限制
```bash
  1.目前只支持post,get,raw三种请求方式
  2.目前只支持status,word,regex,size,time五种匹配方式
```