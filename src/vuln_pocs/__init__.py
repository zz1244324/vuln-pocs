import logging
import requests
import argparse


def main() -> None:
    p=argparse.ArgumentParser()
    p.add_argument("url", help="目标 URL :")
    p.add_argument("--v", action="store_true", help="详细输出debug信息")
    args = p.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.v else logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s'
                        )

    requ=requests.get(args.url,
                      params={"id": "1'"},
                      timeout=5
                      )
    if "You have an error in your SQL syntax" in requ.text:
        logging.warning(f"{args.url} 有sql注入漏洞 ")
    else:
        logging.info(f"{args.url} 没有sql注入漏洞 ")

    
 