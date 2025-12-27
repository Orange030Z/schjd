import requests
import base64
import re
import socket
import json
import yaml
from concurrent.futures import ThreadPoolExecutor

# 1. 订阅源
urls = [
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/vpei/free/master/v2ray",
    "https://raw.githubusercontent.com/tiamm/free-v2ray-nodes/master/v2ray.txt",
    "https://raw.githubusercontent.com/Pawpieee/Free-Vpn-Everyday/main/V2Ray",
    "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2ray",
    "https://raw.githubusercontent.com/ovsc/v2ray-free/main/v2ray.txt",
    "https://raw.githubusercontent.com/freefq/free/master/v2ray"
]

# 2. 国家特征库
features = {
    'hk|hkg|hongkong|香港': '香港',
    'tw|taiwan|tpe|台湾': '台湾',
    'jp|japan|tokyo|nrt|日本': '日本',
    'sg|singapore|sin|新加坡': '新加坡',
    'us|america|unitedstates|usa|lax|美国': '美国',
    'kr|korea|icn|seoul|韩国': '韩国',
    'de|germany|fra|德国': '德国',
    'uk|gb|london|lhr|英国': '英国',
    'nl|netherlands|ams|荷兰': '荷兰',
    'ru|russia|moscow|俄罗斯': '俄罗斯',
    'ca|canada|yvr|加拿大': '加拿大',
    'fr|france|par|法国': '法国'
}

def get_country(addr, old_name=""):
    try:
        res = requests.get(f"http://ip-api.com/json/{addr}?fields=country&lang=zh-CN", timeout=1.2).json()
        if res.get("country"): return res.get("country")
    except: pass
    search_str = f"{old_name} {addr}".lower()
    for pattern, name in features.items():
        if re.search(pattern, search_str): return name
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
    for url in urls:
        try:
            res = requests.get(url, timeout=10).text
            try:
                raw_list.extend(base64.b64decode(res).decode('utf-8').splitlines())
            except:
                raw_list.extend(res.splitlines())
        except: continue

    raw_list = list(set(raw_list))
    with ThreadPoolExecutor(max_workers=100) as executor:
        results = [r for r in executor.map(check_node, raw_list) if r is not None]

    # 按国家排序，方便重命名序号
    results.sort(key=lambda x: x['country'])

    clash_proxies = []
    plain_nodes = []

    for i, item in enumerate(results):
        # 统一干净的名称：[国家] 序号 @schpd
        clean_name = f"{item['country']} {i+1:03d} @schpd"
        
        # 1. 构造 Clash Proxy 对象
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
        
        # 2. 构造明文行
        plain_nodes.append(f"{item['raw_link']}#{clean_name}")

    # 写入 config.yaml
    config = {
        "proxies": clash_proxies,
        "proxy-groups": [{"name": "🚀 节点选择", "type": "select", "proxies": [p["name"] for p in clash_proxies]}],
        "rules": ["MATCH,🚀 节点选择"]
    }
    with open("config.yaml", "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False)

    # 写入 nodes_plain.txt
    with open("nodes_plain.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(plain_nodes))

    print(f"成功！YAML 和 明文已更新，节点总数: {len(results)}")

if __name__ == "__main__":
    main()
