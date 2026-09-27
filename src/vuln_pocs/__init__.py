import logging
import requests
import argparse
import yaml
from pathlib import Path
import re
import time

#url构建
def build_url (base,path):
    path = path.replace("{{BaseURL}}", base)

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
            logging.warning(f"[{num}/{total}] 加载失败: {file_tpl.name},...")
    return data

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
                            **kwargs)
        cost_time= time.perf_counter() - t_start
    except requests.exceptions.ConnectionError:
        logging.error(f"目标不可达，终止扫描: {url}")
        status_requ="break"
    except requests.exceptions.RequestException as e:
        logging.warning(f"请求失败: {e}")
        status_requ="continue"
    return cost_time,status_requ,requ


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

     #分派表
    matcher_table={
    'status':match_status,
    'word':match_word,
    'regex':match_regex,
    'size':match_size,
    'time':match_time
    }


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