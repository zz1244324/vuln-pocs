import logging
import requests
import argparse
import yaml
from pathlib import Path
import re
import time


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
            try:
                data = yaml.safe_load(file_tpl.read_text(encoding="utf-8"))
            except yaml.YAMLError as e:
                logging.warning(f"[{num}/{total}] 加载失败: {file_tpl.name},错误信息:{type(e).__name__},跳过此模板")
                continue
            logging.debug(f"[{num}/{total}] 加载模板: {data.get('name')} path={data.get('request', {}).get('path')}")


        #请求发送
            name=data['name']
            method = data['request'].get('method', 'GET').upper()
            #判断请求类型
            if method not in ('GET', 'POST'):
                logging.warning(f"[{num}/{total}] {name} 不支持的请求方法: {method},跳过此模板")
                continue

            path = data['request']['path'].replace("{{BaseURL}}", base)

            if path.startswith(("http://", "https://")):
                url = path
            else:
                url = base + path
            payload=None
            if 'param' in data['request']:
                payload=data['request']['param']
            kwargs = {'params': payload} if method == 'GET' else {'data': payload}
            #发送请求
            try:
                t_start = time.perf_counter()
                requ=requests.request(method,url,
                                headers=data['request'].get('headers'),
                                timeout=data['request'].get('timeout', 5),
                                **kwargs)
                baseline_time = time.perf_counter() - t_start
            except requests.exceptions.ConnectionError:
                logging.error(f"目标不可达，终止扫描: {args.url}")
                break
            except requests.exceptions.RequestException as e:
                logging.warning(f"请求失败: {e}")
                continue
            logging.debug(f"[{num}/{total}] 实际发出的头: {requ.request.headers}")

        #漏洞判断
            #初始数据
            m=data['matcher']
            bad=0
            status="clean"
            detail=""
            #模板一
            if m['type'] == 'status':
                if requ.status_code == m['status']:
                    status="hit"
            #模板二
            elif m['type'] == 'word':
                for word in m.get('words', []):
                    if word in requ.text:
                        status="hit"
                        break
            #模板三 正则判断 加 报错防御
            elif m['type'] == 'regex':
                if bad==len(m.get('regex', [])):
                    status="empty"
                for pattern in m.get('regex', []):
                    if not isinstance(pattern, str):
                        logging.warning(f"[{num}/{total}] {name} 的正则规则类型错误: {pattern!r},忽略该条")
                        bad += 1
                        continue
                    try:
                        if re.search(pattern, requ.text , re.I | re.S):
                            status="hit"
                            break
                    except re.error as e:
                        logging.warning(f"[{num}/{total}] {name} 的正则表达式无效: {pattern},错误信息为: {e}忽略该条")
                        bad+=1
                if bad==len(m.get('regex', [])) and bad>0:
                    status="broken"
                    detail="正则匹配全部失败"
            #模板四
            elif m["type"]=="size":
                if 'not_size' in m:
                    if abs(len(requ.content) - m['not_size']) > m.get('tolerance', 0):
                        status="hit"
                elif 'size' in m:
                    if len(requ.content) ==m.get("size"):
                        status="hit"
                else:
                    status="empty"
            #模板五
            elif m['type']=="time":
                if 'timeout'in data["request"] and data["request"]["timeout"]<m['sleep']:
                    status = "broken"
                    detail=f"timeout({data['request']['timeout']})值必须大于 sleep({m['sleep']})"
                elif 'payload' not in data['request']:
                    status = "broken"
                    detail="payload模板不存在"
                else:

                    t_start = time.perf_counter()
                    payload_time={**data['request'].get('param',{}),**data['request'].get('payload',{})}
                    kwargs_time = {'params': payload_time} if method == 'GET' else {'data': payload_time}
                    try:
                        requ2 = requests.request(method,url,
                                            headers=data['request'].get('headers'),
                                            timeout=data['request'].get('timeout', 5),
                                            **kwargs_time
                                            )
                    except requests.exceptions.RequestException as e:
                        detail=f"request测试请求失败,{e}"

                        status = "broken"
    
                    else:
                        payload_time = time.perf_counter() - t_start
                        if payload_time - baseline_time > m.get('tolerance', m['sleep'] / 2):
                            status = "hit"
                            detail=f",基线:{baseline_time:.2f},payloadtime:{payload_time:.2f}"

            #不支持的模板
            else:
                logging.warning(f"[{num}/{total}] {name} 不支持的匹配类型: {m['type']},跳过此模板")
                continue


        #输出结果
            #击中
            if status=="hit":
                logging.warning(f"[{num}/{total}] {args.url} 命中漏洞,模板名:{name}{detail}")
            #错误
            elif status=="broken":
                logging.error(f"[{num}/{total}] {args.url} 规则无效,模板名:{name},原因:{detail}")
            #找不到规则
            elif status=="empty":
                logging.error(f"[{num}/{total}] {args.url} 规则为空,模板名:{name}")
            #没命中
            else:
                logging.info(f"[{num}/{total}] {args.url} 没发现漏洞,模板名:{name},响应状态:{requ.status_code}")
                logging.debug(f"[{num}/{total}] 响应内容: {requ.text[:200]}")  # 只打印前200个字符

        #最后保护屏障
        except Exception as e:
                logging.error(f"[{num}/{total}] 模板处理异常,跳过,错误为: {e}")
                continue

if __name__ == "__main__":
    main()