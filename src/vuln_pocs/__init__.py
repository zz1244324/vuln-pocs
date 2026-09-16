import logging
import requests
import argparse
import yaml
from pathlib import Path



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
    #判断url是否合法
    if not args.url.startswith(("http://", "https://")):
        logging.error(f"URL 不合法: {args.url}")
        logging.error("必须以 http:// 或 https:// 开头")
        return
    #加载模板
    num=1
    tpl_dir = Path(__file__).parent / "templates"
    for file_tpl in tpl_dir.glob("*.yaml"):
        data = yaml.safe_load(file_tpl.read_text(encoding="utf-8"))
        logging.debug(f"加载模板: {data}")
    #请求发送
        path = data['request']['path']
        params=None
        if 'param' in data['request']:
            params={data['request']['param']: data['request']['value']}
        requ=requests.get(args.url + path,
                         params=params,
                         timeout=5
                         )
    #漏洞判断   
        m=data['matcher']
        name=data['name']
        if m['type'] == 'status':
            hit = (requ.status_code == m['status'])
        else:
            hit = False
            for word in m['words']:
                if word in requ.text:
                    hit = True
                    break    
        #输出结果
        if hit:
            logging.warning(f"第{num}个模板{args.url} 命中漏洞,类型:{name},响应状态:{requ.status_code} ")
        else:
            logging.info(f"第{num}个模板{args.url} 没发现漏洞,模板名:{name},响应状态:{requ.status_code}")
            logging.debug(f"响应内容: {requ.text[:200]}")  # 只打印前200个字符
        num+=1