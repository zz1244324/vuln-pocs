import logging
import requests
import argparse
import yaml
from pathlib import Path
import re
import time
import ast

#url构建
def build_url (base,path):
    path = replace(path, {"BaseURL": base})

    if path.startswith(("http://", "https://")):
        url = path
    else:
        url = base + path
    return url

#模板导入
def load_template(file_tpl,num,total):
    data=None
    try:
        data = yaml.safe_load(file_tpl.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
            logging.warning(f"[{num}/{total}] 加载失败: {file_tpl.name},...{e}")
    return data

#报文解析
def raw(http_request):
    lines = http_request.splitlines()
    headers={}
    body=len(lines)
    for i, line in enumerate(lines):
        if line=="":
            body=i
            break #第一个空行之后的就是body了
        if i==0:
            method= line.split(" ")[0]
            path= line.split(" ")[1]
        if i>0 and i<body:
            key=line.split(":")[0]
            value=line.split(":",1)[1].strip() #去除空格
            headers[key]=value

    param_str = '\n'.join(lines[body+1:])

    return method,path,headers,param_str

#嵌套替换
def replace(text, values):
    count = 0
    count_max = 1000  # 设置最大迭代次数以防止无限循环
    while "{{" in text: #不用顺序,自动排序
        for name, value in values.items():
            text = text.replace("{{" + name + "}}", value)
        count +=1
        if count >= count_max and "{{" in text:
            raise ValueError("模板替换迭代次数超过限制")
    return text

#白名单检测
def calc(node):
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.BinOp):
        left = calc(node.left)
        right = calc(node.right)
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Mult):
            return left * right
        raise ValueError("不支持该的表达式")


#结果判断
def render(status,num,total,url,name,detail,status_code,text):
    #击中
    if status=="hit":
        logging.warning(f"[{num}/{total}] {url} 命中漏洞,模板名:{name}{detail}")
    #错误
    elif status=="broken":
        logging.error(f"[{num}/{total}] {url} 规则无效,模板名:{name},原因:{detail}")
    #找不到规则
    elif status=="empty":
        logging.error(f"[{num}/{total}] {url} 规则为空,模板名:{name}")
    #没命中
    else:
        logging.info(f"[{num}/{total}] {url} 没发现漏洞,模板名:{name},响应状态:{status_code}")
        logging.debug(f"[{num}/{total}] 响应内容: {text}")

#发送请求
def send_request(method,url,headers,timeout,p):
    cost_time=None
    status_requ=None
    requ=None

    kwargs = {'params': p} if method == 'GET' else {'data': p}
    try:
        t_start = time.perf_counter()
        requ=requests.request(method,url,
                            headers=headers,
                            timeout=timeout,
                            proxies={'http': None, 'https': None},
                            **kwargs)
        cost_time= time.perf_counter() - t_start
    except requests.exceptions.ConnectionError:
        status_requ="break"
    except requests.exceptions.RequestException as e:
        logging.warning(f"请求失败: {e}")
        status_requ="continue"
    return cost_time,status_requ,requ

#模板检查
def data_check(required, data,num,total):
    for path in required:
        cur = data
        for key in path:
            if key not in cur:
                logging.warning(f"模板[{num}/{total}]缺少必要字段: {key},跳过此模板")
                return False
            cur = cur[key]
    return True


#状态判断
def match_status(m,requ,data,url,baseline_time):
    status="clean" 
    detail=""

    if requ.status_code == m.get('status'):
        status="hit"
    return  status, detail

#特征词判断
def match_word(m,requ,data,url,baseline_time):
    status="clean" 
    detail=""
    for word in m.get('words'):
        if word in requ.text:
            status="hit"
            break
    return  status, detail

#正则匹配判断
def match_regex(m,requ,data,url,baseline_time):
    status="clean" 
    detail=""
    bad=0

    if bad==len(m.get('regex')):
        status="empty"
    for pattern in m.get('regex'):
        if not isinstance(pattern, str):
            status="broken"
            detail+=f"第{bad+1}条正则规则类型错误,忽略该条"
            bad += 1
            continue
        try:
            if re.search(pattern, requ.text , re.I | re.S):
                status="hit"
                break
        except re.error as e:
            status="broken"
            detail+=f"第{bad+1}条正则语法类型错误,错误信息为: {e}忽略该条"
            bad+=1
    if bad==len(m.get('regex')) and bad>0:
        status="broken"
        detail+="正则匹配全部失败"

    return  status, detail

#长度判断
def match_size(m,requ,data,url,baseline_time):
    status="clean" 
    detail=""

    if 'not_size' in m:
        if abs(len(requ.content) - m['not_size']) > m.get('tolerance', 0):
            status="hit"
    elif 'size' in m:
        if len(requ.content) ==m.get('size'):
            status="hit"
    else:
        status="empty"
    return  status, detail

#时间判断
def match_time(m,requ,data,url,baseline_time):
    status="clean" 
    detail=""
    if not isinstance(data['request'].get('param', {}), dict) or not isinstance(data['request'].get('payload', {}), dict):
        status = "broken"
        detail = "该模板的param和payload必须要是字典类型"
        return status, detail
    method = data['request'].get('method', 'GET').upper()
    payload_params={**data['request'].get('param',{}),**data['request'].get('payload',{})}

    if 'timeout'in data["request"] and data["request"]["timeout"]<m['sleep']:
        status = "broken"
        detail=f"timeout({data['request']['timeout']})值必须大于 sleep({m['sleep']})"
    elif 'payload' not in data['request']:
        status = "broken"
        detail="payload模板不存在"
    else:
        payload_time,status_requ_payload,requ2=send_request(method,url,
                      data['request'].get('headers'),
                      data['request'].get('timeout', 5),
                      payload_params)

        if status_requ_payload:
            detail="request测试请求失败"
            status = "broken"
        else:
            if payload_time - baseline_time > m.get('tolerance', m['sleep'] / 2):
                status = "hit"
                detail=f",基线:{baseline_time:.2f},payloadtime:{payload_time:.2f}"
    return  status, detail

#模板表
required = [
('name',),
('request', 'path'),
('matcher', 'type'),
]

#专属表
matcher_required = {
    'word':   [('matcher', 'words')],
    'status': [('matcher', 'status')],
    'regex':  [('matcher', 'regex')],
    'time':   [('matcher', 'sleep')],
    'size':   [],
}


#分派表
matcher_table={
'status':match_status,
'word':match_word,
'regex':match_regex,
'size':match_size,
'time':match_time
}


def main() -> None:
    #参数设置
    p=argparse.ArgumentParser()
    p.add_argument("url", help="目标 URL :")
    p.add_argument("--v", action="store_true", help="详细输出debug信息")
    args = p.parse_args()

    #logging配置
    logging.basicConfig(level=logging.DEBUG if args.v else logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s'
                        )
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)

    #判断url是否合法
    if not args.url.startswith(("http://", "https://")):
        logging.error(f"URL 不合法: {args.url}")
        logging.error("必须以 http:// 或 https:// 开头")
        return
    base = args.url.rstrip("/")

    #加载模板
    tpl_dir = Path(__file__).parent / "templates"
    files = sorted(tpl_dir.glob("*.yaml"))
    total = len(files)

    for num,file_tpl in enumerate(files, start=1):
        try:
            data=load_template(file_tpl,num,total)
            if data is None:
                continue
            logging.debug(f"[{num}/{total}] 加载模板: {data.get('name')} path={data.get('request', {}).get('path')}")

            #模板raw写法解析
            if 'raw' in data['request']:
                m, p, h, param_str = raw(data['request']['raw'])
                data['request']['method']  = m
                data['request']['path']    = p
                data['request']['headers'] = h
                data['request']['param']   = param_str

            #模板格式检查
            check = data_check(required, data,num,total)
            if check is False:
                continue

            #专属检查
            check_matcher = data_check(matcher_required.get(data['matcher'].get('type')), data,num,total)
            if check_matcher is False:
                continue



        #请求发送
            name=data['name']
            method = data['request'].get('method', 'GET').upper()
            #判断请求类型
            if method not in ('GET', 'POST'):
                logging.warning(f"[{num}/{total}] {name} 不支持的请求方法: {method},跳过此模板")
                continue
            #发送请求
            url=build_url(base,data['request']['path'])
            baseline_time,status_requ,requ=send_request(
                method,url,
                data['request'].get('headers'),
                data['request'].get('timeout', 5),
                data['request'].get('param'),
                )
            if status_requ =="break":
                logging.error(f"目标不可达，终止扫描: {args.url},请检查网络或目标是否可达")
                logging.error(f"[{num}/{total}] 模板中断,还剩[{total-num}]个模板未跑")
                break

            if status_requ =="continue":
                logging.warning(f"网络问题,跳过[{num}/{total}] 模板")
                continue

            logging.debug(f"[{num}/{total}] 实际发出的头: {requ.request.headers}")

        #漏洞判断

            #初始话参数
            # status="clean"
            # detail=""
            m=data['matcher']
            text=requ.text[:200] #只打印请求前面的200个


            func= matcher_table.get(m.get('type'))
            #不支持该类型的模板
            if func is None:
                logging.warning(f"[{num}/{total}] {name} 不支持的匹配类型: {m['type']},跳过此模板")
                continue
            else:
                status, detail = func(m, requ, data, url, baseline_time)


            #输出结果
            render(status,num,total,args.url,name,detail,requ.status_code,text)

        #最后保护屏障
        except Exception as e:
                logging.error(f"[{num}/{total}] 模板处理异常,跳过,错误为: {e}")
                continue

if __name__ == "__main__":
    main()