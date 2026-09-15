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
    tpl_dir = Path(__file__).parent / "templates"
    for path in tpl_dir.glob("*.yaml"):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        logging.debug(f"加载模板: {data}")
    #请求发送
        requ=requests.get(args.url,
                         params={data['request']['param']: data['request']['value']},
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
        if hit:
            logging.warning(f"{args.url} 有漏洞,类型:{name} ")
        else:
            logging.info(f"{args.url} 没发现漏洞:{name}")
            logging.debug(f"响应内容: {requ.text[:200]}")  # 只打印前200个字符
 