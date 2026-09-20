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
    for num,file_tpl in enumerate(tpl_dir.glob("*.yaml"), start=1):
        try:
            try:
                data = yaml.safe_load(file_tpl.read_text(encoding="utf-8"))
            except yaml.YAMLError as e:
                logging.warning(f"第{num}个模板加载失败: {file_tpl.name},错误信息:{type(e).__name__},跳过此模板")
                continue
            logging.debug(f"加载模板: {data.get('name')} path={data.get('request', {}).get('path')}")


        #请求发送
            path = data['request']['path'].replace("{{BaseURL}}", base)
            params=None

            if path.startswith(("http://", "https://")):
                url = path
            else:
                url = base + path

            if 'param' in data['request']:
                params={data['request']['param']: data['request']['value']}
            
            try:
                t_start = time.perf_counter()
                requ=requests.get(url=url,
                                params=params,
                                headers=data['request'].get('headers'),
                                timeout=data['request'].get('timeout', 5)
                                )
                baseline_time = time.perf_counter() - t_start
            except requests.exceptions.ConnectionError:
                logging.error(f"目标不可达，终止扫描: {args.url}")
                break
            except requests.exceptions.RequestException as e:
                logging.warning(f"请求失败: {e}")
                continue
            logging.debug(f"实际发出的头: {requ.request.headers}")

        #漏洞判断
            m=data['matcher']
            name=data['name']
            bad=0
            status="clean"
            if m['type'] == 'status':
                if requ.status_code == m['status']:
                    status="hit"

            elif m['type'] == 'word':
                for word in m.get('words', []):
                    if word in requ.text:
                        status="hit"
                        break
            #正则判断 加 报错防御
            elif m['type'] == 'regex':
                if bad==len(m.get('regex', [])):
                    status="empty"
                for pattern in m.get('regex', []):
                    if not isinstance(pattern, str):
                        logging.warning(f"第{num}个模板{name} 的正则规则类型错误: {pattern!r},忽略该条")
                        bad += 1
                        continue
                    try:
                        if re.search(pattern, requ.text , re.I | re.S):
                            status="hit"
                            break
                    except re.error as e:
                        logging.warning(f"第{num}个模板{name} 的正则表达式无效: {pattern},错误信息为: {e}忽略该条")
                        bad+=1
                if bad==len(m.get('regex', [])) and bad>0:
                    status="broken"

            elif m["type"]=="size":
                if 'not_size' in m:
                    if abs(len(requ.content) - m['not_size']) > m.get('tolerance', 0):
                        status="hit"
                elif 'size' in m:
                    if len(requ.content) ==m.get("size"):
                        status="hit"
                else:
                    status="empty"

            elif m['type']=="time":
                if 'timeout'in data["request"] and data["request"]["timeout"]<m['sleep']:
                    status = "broken"
                    logging.error(f"timeout({data["request"]["timeout"]})必须大于 sleep({m['sleep']}),模板{name}不可用")
                if 'payload_value' not in data['request']:
                    status = "broken"
                    logging.error(f"payload_value不存在,模板{name}不可用")
                else:

                    t_start = time.perf_counter()
                    try:
                        requ2 = requests.get(url=url,
                                    params={data['request']['param']: data['request']['payload_value']},
                                    headers=data['request'].get('headers'),
                                    timeout=data['request'].get('timeout', 5))
                    except requests.exceptions.RequestException as e:
                        logging.warning(f"{url}请求失败{e}")
                        status = "broken"
    
                    else:
                        payload_time = time.perf_counter() - t_start
                        if payload_time - baseline_time > m.get('tolerance', m['sleep'] / 2):
                            status = "hit"



            else:
                logging.warning(f"第{num}个模板{name} 不支持的匹配类型: {m['type']},跳过此模板")
                continue


            #输出结果
            if status=="hit":
                logging.warning(f"第{num}个模板{args.url} 命中漏洞,模板名:{name},响应状态:{requ.status_code} ")

            elif status=="broken":
                logging.error(f"第{num}个模板{args.url} 规则无效,模板名:{name}")
            elif status=="empty":
                logging.error(f"第{num}个模板{args.url} 规则为空,模板名:{name}")
            else:
                logging.info(f"第{num}个模板{args.url} 没发现漏洞,模板名:{name},响应状态:{requ.status_code}")
                logging.debug(f"响应内容: {requ.text[:200]}")  # 只打印前200个字符

        #最后保护屏障
        except Exception as e:
                logging.error(f"第{num}个模板处理异常,跳过,错误为: {e}")
                continue

if __name__ == "__main__":
    main()