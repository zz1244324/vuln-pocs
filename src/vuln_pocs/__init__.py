import logging
import requests
import argparse
import yaml
from pathlib import Path
import re
import time


def build_url (base,path):
    path = path.replace("{{BaseURL}}", base)

    if path.startswith(("http://", "https://")):
        url = path
    else:
        url = base + path
    return url

def load_template(file_tpl,num,total):
    data=None
    try:
        data = yaml.safe_load(file_tpl.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
            logging.warning(f"[{num}/{total}] 加载失败: {file_tpl.name},...")
    return(data)

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
    

def send_request(method,url,headers,timeout,p):
    cost_time=None
    status=None
    requ=None

    
    kwargs = {'params': p} if method == 'GET' else {'data': p}
    try:
        t_start = time.perf_counter()
        requ=requests.request(method,url,
                            headers=headers,
                            timeout=timeout,
                            **kwargs)
        cost_time= time.perf_counter() - t_start
    except requests.exceptions.ConnectionError:
        logging.error(f"目标不可达，终止扫描: {url}")
        status="break"
    except requests.exceptions.RequestException as e:
        logging.warning(f"请求失败: {e}")
        status="continue"
    return cost_time,status,requ


def match_status(type,status,requ_status):
    status="clean" 
    detail=""

    if requ_status == status:
        status="hit"
    return  status, detail

def match_word(type,word,requ_text):
    status="clean" 
    detail=""

    for word in word:
        if word in requ_text:
            status="hit"
    return  status, detail
            
def match_regex(regex,num,total,name,requ_text):
    status="clean" 
    detail=""

    if bad==len(regex):
        status="empty"
    for pattern in regex:
        if not isinstance(pattern, str):
            logging.warning(f"[{num}/{total}] {name} 的正则规则类型错误: {pattern!r},忽略该条")
            bad += 1
            continue
        try:
            if re.search(pattern, requ_text , re.I | re.S):
                status="hit"
                break
        except re.error as e:
            logging.warning(f"[{num}/{total}] {name} 的正则表达式无效: {pattern},错误信息为: {e}忽略该条")
            bad+=1
    if bad==len(regex) and bad>0:
        status="broken"
        detail="正则匹配全部失败"

    return  status, detail

def match_size(m,requ_content):
    status="clean" 
    detail=""

    if 'not_size' in m:
        if abs(len(requ_content) - m['not_size']) > m.get('tolerance', 0):
            status="hit"
    elif 'size' in m:
        if len(requ_content) ==m.get('size'):
            status="hit"
    else:
        status="empty"
    return  status, detail

def match_time(m,data,status_requ_payload,payload_time,baseline_time):
    status="clean" 
    detail=""

    if 'timeout'in data["request"] and data["request"]["timeout"]<m['sleep']:
        status = "broken"
        detail=f"timeout({data['request']['timeout']})值必须大于 sleep({m.get('sleep')})"
    elif 'payload' not in data['request']:
        status = "broken"
        detail="payload模板不存在"
    else:
        if status_requ_payload:
            detail=f"request测试请求失败"
            status = "broken"
        else:
            if payload_time - baseline_time > m.get('tolerance', m.get('sleep') / 2):
                status = "hit"
                detail=f",基线:{baseline_time:.2f},payloadtime:{payload_time:.2f}"
    return  status, detail

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
                break

            if status_requ =="continue":
                continue

            logging.debug(f"[{num}/{total}] 实际发出的头: {requ.request.headers}")

        #漏洞判断
            #初始数据

            m=data['matcher']
            bad=0
            status="clean"
            detail=""
            text=requ.text[:200] #只打印请求前面的200个
        
            #模板一

            status,detail=match_status(m['status'],requ.status_code)

            
            #模板二
        
            status,detail=match_word(m.get('words', []),requ.text)

            #模板三 正则判断 加 报错防御

            status,detail=match_regex(m.get('regex', []),num,total,name,requ.text)

           
            #模板四

            status,detail=match_size(m,requ.content)

            
            #模板五
            

                   
            payload_params={**data['request'].get('param',{}),**data['request'].get('payload',{})}
            payload_time,status_requ_payload,requ2=send_request(
                method,url,
                data['request'].get('headers'),
                data['request'].get('timeout', 5),
                payload_params,
                )
           
            status,detail=match_time(m,data,status_requ_payload,payload_time,baseline_time)

            matcher_table={
                'status':match_status,
                'word':match_word,
                'regex':match_regex,
                'size':match_size,
                'time':match_time:
            }

            
                #不支持该类型的模板
            func= matcher_table.get(m.get('type'))
            if func is None:
                logging.warning(f"[{num}/{total}] {name} 不支持的匹配类型: {m['type']},跳过此模板")
                continue

        #输出结果

            render(status,num,total,args.url,name,detail,requ.status_code,text)
            
        #最后保护屏障
        except Exception as e:
                logging.error(f"[{num}/{total}] 模板处理异常,跳过,错误为: {e}")
                continue

if __name__ == "__main__":
    main()