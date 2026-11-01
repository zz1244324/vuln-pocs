# 模板库速查（14 个模板 / 8 个漏洞家族）

> 从 `AGENTS.md` §3 拆出——**只在新增或修改模板时才需要读这份**。
> 写模板前先读 `AGENTS.md` §7（YAML 契约）与 §15（硬约定）。
> 双向验证是标配：真靶场要 hit，任意正常站要 clean。

## 速查表

| 模板 | 靶场 | 家族 | 判据（物证） |
|---|---|---|---|
| `bak-exposed` | 任意 | 配置错误 | 状态码 200 ⚠️ **证据弱，必误报（挂账 #12）** |
| `less9-time-blind` | phpstudy 8594 | SQL 注入 | 时间差（payload − 基线） |
| `less11-post-sqli` | phpstudy 8594 | SQL 注入 | `Your Login name` |
| `less11-raw` | phpstudy 8594 | SQL 注入 | `Your Login name` |
| `sqli-error` | phpstudy 8594 | SQL 注入 | `You have an error in your SQL syntax` |
| `xff-spoof` | phpstudy 8594 | 配置错误 | 正则 `<title>Less-18[^<]*</title>` |
| `thinkphp5-rce` | Kali 8080 | 代码执行 | `PHP Version` |
| `nginx-alias` | Kali 8091 | 配置错误（穿越） | `root:` |
| `tomcat-weak-pass` | Kali 8080 | 默认凭据 | `Tomcat Web Application Manager` |
| `phpunit-rce` | Kali 8080 | 遗留文件暴露 | `PHP Version` |
| `joomla-unauth` | Kali 8081 | 未授权访问 | `"password":"` |
| `weblogic-ssrf` | Kali 7001 | SSRF | `could not connect over HTTP to server:` |
| `SSTI.yaml`（name: `ssti`） | Kali 8000 | SSTI | `7777777` |
| `shiro-deser` | Kali 8080 | 反序列化 | `You have successfully logged in` |

**家族覆盖（8）**：代码漏洞 / 配置错误 / 默认凭据 / 开发遗留文件暴露 / 未授权访问 / SSRF / SSTI / 反序列化。
路线图红线：模板总数控制在 **15–20**，当前 14。

---

## weblogic-ssrf

Kali `weblogic/CVE-2014-4210`（7001，uddiexplorer 未授权）。常规式 GET `/uddiexplorer/SearchPublicRegistries.jsp`，param 复刻完整表单 + `operator: "http://127.0.0.1:1"`（必然连不通的地址），matcher word `could not connect over HTTP to server:`。

- **家族**：SSRF——失败回显即物证（只有"服务器自己去连过"才写得出这句话）。
- **坑**：响应原文里单引号是 HTML 实体 `&#39;`，判定词不能带引号——浏览器渲染成 `'` 会骗过你。**物证必须来自响应原文，不能来自浏览器渲染结果**（判定失败先 curl 抓原文对词）。
- **手动复现三分法**：连不上 → `could not connect`；连上且是 HTTP → `returned a 404`；连上非 HTTP（内网 Redis `172.23.0.2:6379`）→ `Response contained no data`——即内网端口扫描判据。

## SSTI.yaml（name: ssti）

Kali 自建 Flask 靶场（8000，gunicorn，`?name=` 回显点）。常规式 GET `/`，param `name: "{{7*'7'}}"`，matcher word `7777777`。

- **判据原理**：Jinja2 里数字×字符串 = 重复得 `7777777`，Twig 得 `49`——一发同时验"有无 SSTI"和"哪家引擎"。`7777777` 是**算出来的**不是回显的，天然物证，裸词误报率≈零。
- **坑**：payload 必须放 param 不能放 path——path 过 `replace()`（`{{}}` 会被自家引擎解释甚至报错 skip），param 值原样透传（与 §7.2"raw 只有第一行 path 被替换"同族原理：数据通道 vs 代码通道）。

> ✅ 2026-10-20 晚 `90ef0b7` 修：两模板内容曾对调，现已名实相符（`weblogic-ssrf.yaml` = weblogic 逻辑、`SSTI.yaml` = SSTI 逻辑），检测逻辑各自双向验证通过（7001 hit/clean、8000 hit/clean）。游离键+空行已于 `084730e` 清掉。
> ⚠️ 历史坑：**YAML 重复键静默覆盖**，两处值不同时会静默改道，不报错。

## shiro-deser

2026-10-22，第 8 家族「反序列化」，模板 13→14。Kali `shiro/CVE-2016-4437`（8080，demo 凭据 `admin/vulhub`）。常规式 GET `/` + `headers: Cookie: rememberMe=<预计算密文>`，matcher word `You have successfully logged in`。

- **检测分层**：L1 指纹（垃圾 cookie → `deleteMe` 自曝，只证明是 Shiro；裸访问不触发）→ L2 验 key（**沉默即物证**：合法密文发过去 `deleteMe` 消失；且此 demo 把"记住的我"渲染成登录态 → 升级为**正向物证**，只有 解密✓→反序列化✓→恢复身份✓ 全链路通过才可能出现）→ L3 RCE 不做（sleep 时间判据属 L3：送的是代码不是身份，越"只做证据"红线）。
- **L2 预计算链**：登录勾 RememberMe 抓服务器亲发密文 → 已知 key 解出明文（377 字节 `SimplePrincipalCollection`，头 `aced0005`）→ 固定 key+明文+IV(全零) ⇒ 密文确定，写死进 YAML，**引擎零新原语**。
- **坑**：Shiro 密文格式 = IV(16 字节) + AES-CBC(明文)，IV 必须拼在密文前再 base64（漏拼则全错位解成乱码→deleteMe，表现与 key 错一模一样）；**Cookie 是请求头、Set-Cookie 是响应头**，方向反了静默失效。
- **设计决策**：负向匹配降级为引擎通用能力挂账（`AGENTS.md` §16 #11）——deleteMe 在响应头（word matcher 只看 body）+ 纯负向证据必误报，本模板用正向物证规避。
- **待做**：作者 REPL 亲手复现加密链（教学目标）。

## thinkphp5-rce

raw 式，path 里的 `\` 必须写成 `%5C`（requests 会原样转发）；检测 payload 用 phpinfo 版（无害证据），matcher `word: ["PHP Version"]`。

- **坑**：ThinkPHP 报错页也返回 200 → 判定必须看内容不能看状态码；浏览器会把 URL 里的 `\` 换成 `/`（`%5C` 编码可过）。

## nginx-alias

Kali `nginx/insecure-configuration`（8091）。`location /files { alias /home/; }` 错位配置 → `/files../etc/passwd` 读任意文件；matcher `word: ["root:"]`。

- **家族**：配置错误（alias 拼接不归一化）。
- **判据选择**：读 passwd 比"Index of"列目录证据更强。
- **坑**：无扩展名文件 nginx 回 octet-stream，**浏览器会下载但 requests 照常拿 body**。

## tomcat-weak-pass

Kali `tomcat/tomcat8`（8080）。常规式 GET `/manager/html` + `headers: Authorization: "Basic base64(账号:密码)"`，matcher `word: ["Tomcat Web Application Manager"]`。

- **家族**：默认凭据。
- **坑**（2026-10-18 踩过）：键名写 `header` 引擎静默忽略 → 裸请求 401 → clean，全程无报错。

## phpunit-rce

Kali `phpunit/CVE-2017-9841`（8080，`php:apache` 镜像，根路径 403 属正常）。raw 式 POST 到 `/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`，body = `<?php phpinfo(); ?>`，matcher `word: ["PHP Version"]`。

- **家族**：开发遗留文件暴露——vendor 里的测试辅助文件把请求 body 直接 `eval`，"能访问到它 = 执行它"。
- **必须 raw 不能常规式**：param 是 dict 会被 urlencode，payload 是代码原文，任何一层编码都会毁掉它（`%3C%3Fphp` 不是合法 PHP）。
- **坑**：PHP 双分号 `;;` 是语法错误 → eval 失败空响应 → 静默 miss；路径大小写敏感（`Util/PHP`）。

## joomla-unauth

Kali `joomla/CVE-2023-23752`（8081）。常规式纯 GET `/api/index.php/v1/config/application?public=true`，无 headers 无 param，matcher `words: ['"password":"']`。

- **家族**：未授权访问——Joomla 4.x REST API 设计要求 Bearer token，但 `/config/application` 控制器没做 ACL 检查，无凭据 GET 直出数据库配置（user/password/host/db）。危害链第一环，扫描器只做证据。
- **判据选择**：用 JSON 键值形态 `"password":"` 而不是裸词 `password`——裸词在登录页遍地都是必误报；YAML 内外引号要换种（外单内双）。

## bak-exposed

backup 文件探测（`.bak` / `.sql` / `.zip`），status 型 matcher。

- ⚠️ **已知缺陷（挂账 #12）**：对"任意路径都回 200"的站点必误报（2026-10-22 Shiro 靶场实测：`/index.php.bak` 200 → hit）。status 型证据弱，修法是加 body 词/长度约束。
- 这个模板是练"证据强度"的现成教材：**能返回 200 ≠ 文件存在**。

## 靶场速记

- phpstudy（8590–8598）：8594 = sqli-labs（当前主要目标），完整端口表见 `AGENTS.md` §18。
- Kali Vulhub：`192.168.189.136`，`/root/vulhub` 158 个靶场，`docker compose up -d` 启动。
