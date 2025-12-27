import requests
import base64
import re
import socket
import json
import yaml
from concurrent.futures import ThreadPoolExecutor

# 1. 订阅源列表
urls = [
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    
]

# 2. 终极版全球特征库
features = {
    # 亚洲 & 太平洋
    'hk|hkg|hongkong|香港|pccw|hkt': '香港',
    'tw|taiwan|tpe|hinet|cht|台湾|台北': '台湾',
    'jp|japan|tokyo|nrt|hnd|kix|osaka|日本|东京|大阪': '日本',
    'sg|singapore|sin|新加坡': '新加坡',
    'kr|korea|icn|seoul|sel|韩国|首尔': '韩国',
    'th|thailand|bkk|bangkok|泰国|曼谷': '泰国',
    'vn|vietnam|hanoi|sgn|越南|河内|胡志明': '越南',
    'my|malaysia|kul|马来西亚|吉隆坡': '马来西亚',
    'ph|philippines|mnl|manila|菲律宾|马尼拉': '菲律宾',
    'id|indonesia|cgk|jakarta|印尼|雅加达': '印尼',
    'in|india|bom|del|mumbai|印度|孟买': '印度',
    'au|australia|syd|mel|澳大利亚|悉尼|墨尔本': '澳大利亚',
    # 北美 & 南美
    'us|america|unitedstates|usa|lax|sfo|iad|ord|sea|美国|洛杉矶|纽约': '美国',
    'ca|canada|yvr|yyz|mtl|加拿大|温哥华|多伦多': '加拿大',
    'br|brazil|sao|brazil|巴西|圣保罗': '巴西',
    'mx|mexico|mex|墨西哥': '墨西哥',
    # 欧洲
    'de|germany|fra|frankfurt|德国|法兰克福': '德国',
    'uk|gb|london|lon|lhr|英国|伦敦': '英国',
    'fr|france|par|paris|法国|巴黎': '法国',
    'nl|netherlands|ams|amsterdam|荷兰|阿姆斯特丹': '荷兰',
    'ru|russia|moscow|mow|svo|俄罗斯|莫斯科': '俄罗斯',
    'tr|turkey|ist|istanbul|土耳其|伊斯坦布尔': '土耳其',
    'it|italy|mil|milano|意大利|米兰': '意大利',
    'es|spain|mad|madrid|西班牙|马德里': '西班牙',
    'ch|switzerland|zrh|zurich|瑞士|苏黎世': '瑞士',
    # 非洲
    'za|southafrica|jnb|南非': '南非',
    'eg|egypt|cai|埃及': '埃及'
}

def get_country(addr, old_name=""):
    # 1. API 识别
    try:
        res = requests.get(f"http://ip-api.com/json/{addr}?fields=country&lang=zh-CN", timeout=1.2).json()
        if res.get("country"): return res.get("country")
    except: pass
    
    # 2. 特征库识别
    search_str = f"{old_name} {addr}".lower()
    for pattern, name in features.items():
        if re.search(r'\b(' + pattern + r')\b', search_str) or re.search(pattern, search_str):
            return name
    return "优质"

def check_node(node):
    if not node.startswith("vmess://"): return None
    try:
        link_body = node.split("://")[1].split("#")[0]
        link_body += '=' * (-len(link_body) % 4)
        info = json.loads(base64.b64decode(link_body).decode('utf-8'))
        addr, port = info.get("add"), int(info.get("port"))
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            if s.connect_ex((addr, port)) == 0:
                country = get_country(addr, node.split("#")[1] if "#" in node else "")
                return {
                    "raw_link": node.split("#")[0],
                    "country": country,
                    "server": addr,
                    "port": port,
                    "uuid": info.get("id"),
                    "aid": int(info.get("aid", 0)),
                    "net": info.get("net", "tcp"),
                    "host": info.get("host", ""),
                    "path": info.get("path", ""),
                    "tls": True if info.get("tls") == "tls" else False
                }
    except: pass
    return None

def main():
    raw_list = []
    print("正在拉取远程节点...")
    for url in urls:
        try:
            res = requests.get(url, timeout=10).text
            try: raw_list.extend(base64.b64decode(res).decode('utf-8').splitlines())
            except: raw_list.extend(res.splitlines())
        except: continue

    raw_list = list(set(raw_list))
    print(f"总计原始节点: {len(raw_list)}，测活开始...")

    with ThreadPoolExecutor(max_workers=100) as executor:
        results = [r for r in executor.map(check_node, raw_list) if r is not None]

    # 按国家排序，确保相同国家挨在一起
    results.sort(key=lambda x: x['country'])

    clash_proxies = []
    plain_nodes = []

    for i, item in enumerate(results):
        # 统一干净的名称：[国家] 序号 @schpd
        clean_name = f"{item['country']} {i+1:03d} @schpd"
        
        # 1. YAML 格式对象
        proxy_obj = {
            "name": clean_name,
            "type": "vmess",
            "server": item["server"],
            "port": item["port"],
            "uuid": item["uuid"],
            "alterId": item["aid"],
            "cipher": "auto",
            "udp": True,
            "tls": item["tls"],
            "network": item["net"]
        }
        if item["net"] == "ws":
            proxy_obj["ws-opts"] = {"path": item["path"], "headers": {"Host": item["host"]}}
        clash_proxies.append(proxy_obj)
        
        # 2. 明文格式行
        plain_nodes.append(f"{item['raw_link']}#{clean_name}")

    # 保存 YAML
    config = {
        "proxies": clash_proxies,
        "proxy-groups": [{"name": "🚀 节点选择", "type": "select", "proxies": [p["name"] for p in clash_proxies]}],
        "rules": ["MATCH,🚀 节点选择"]
    }
    with open("config.yaml", "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False)

    # 保存明文
    with open("nodes_plain.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(plain_nodes))

    print(f"完成！YAML 节点数: {len(clash_proxies)}")

if __name__ == "__main__":
    main()
