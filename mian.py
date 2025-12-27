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
    "https://raw.githubusercontent.com/vpei/free/master/v2ray",
    "https://raw.githubusercontent.com/tiamm/free-v2ray-nodes/master/v2ray.txt",
    "https://raw.githubusercontent.com/Pawpieee/Free-Vpn-Everyday/main/V2Ray",
    "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2ray",
    "https://raw.githubusercontent.com/ovsc/v2ray-free/main/v2ray.txt",
    "https://raw.githubusercontent.com/freefq/free/master/v2ray"
]

# 2. 终极国家特征库
features = {
    'hk|hkg|hongkong|香港|pccw|hkt': '香港',
    'tw|taiwan|tpe|hinet|cht|台湾|台北': '台湾',
    'jp|japan|tokyo|nrt|hnd|kix|osaka|日本|东京|大阪': '日本',
    'sg|singapore|sin|新加坡': '新加坡',
    'us|america|unitedstates|usa|lax|sfo|iad|ord|美国|洛杉矶|纽约': '美国',
    'kr|korea|icn|seoul|韩国|首尔': '韩国',
    'de|germany|fra|frankfurt|德国|法兰克福': '德国',
    'uk|gb|london|lon|lhr|英国|伦敦': '英国',
    'fr|france|par|paris|法国|巴黎': '法国',
    'nl|netherlands|ams|amsterdam|荷兰|阿姆斯特丹': '荷兰',
    'ru|russia|moscow|mow|俄罗斯|莫斯科': '俄罗斯',
    'tr|turkey|ist|istanbul|土耳其|伊斯坦布尔': '土耳其',
    'ca|canada|yvr|yyz|加拿大|温哥华|多伦多': '加拿大',
    'au|australia|syd|mel|澳大利亚|悉尼|墨尔本': '澳大利亚',
    'th|thailand|bkk|泰国|曼谷': '泰国',
    'vn|vietnam|hanoi|sgn|越南|河内|胡志明': '越南',
    'my|malaysia|kul|马来西亚|吉隆坡': '马来西亚',
    'ph|philippines|mnl|菲律宾|马尼拉': '菲律宾',
    'in|india|bom|del|印度|孟买': '印度',
    'br|brazil|sao|巴西|圣保罗': '巴西'
}

def get_country(addr, old_name=""):
    # 优先调用地理位置接口
    try:
        res = requests.get(f"http://ip-api.com/json/{addr}?fields=country&lang=zh-CN", timeout=1.2).json()
        if res.get("country"): return res.get("country")
    except: pass
    
    # 关键词匹配
    search_str = f"{old_name} {addr}".lower()
    for pattern, name in features.items():
        if re.search(pattern, search_str): return name
    
    # 反向DNS解析
    try:
        hostname = socket.gethostbyaddr(addr)[0].lower()
        for pattern, name in features.items():
            if re.search(pattern, hostname): return name
    except: pass
    
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
                # 返回用于YAML的字典
                return {
                    "raw": node, # 保留原始链接用于明文输出
                    "country": country,
                    "proxy": {
                        "name": f"{country} {addr[:5]} @schpd",
                        "type": "vmess",
                        "server": addr,
                        "port": port,
                        "uuid": info.get("id"),
                        "alterId": int(info.get("aid", 0)),
                        "cipher": "auto",
                        "udp": True,
                        "tls": True if info.get("tls") == "tls" else False,
                        "network": info.get("net", "tcp"),
                        "ws-opts": {"path": info.get("path"), "headers": {"Host": info.get("host")}} if info.get("net") == "ws" else None
                    }
                }
    except: pass
    return None

def main():
    raw_list = []
    print("正在拉取源数据...")
    for url in urls:
        try:
            res = requests.get(url, timeout=10).text
            try:
                raw_list.extend(base64.b64decode(res).decode('utf-8').splitlines())
            except:
                raw_list.extend(res.splitlines())
        except: continue

    raw_list = list(set(raw_list))
    print(f"原始节点: {len(raw_list)}，开始测活...")

    with ThreadPoolExecutor(max_workers=100) as executor:
        results = [r for r in executor.map(check_node, raw_list) if r is not None]

    # 1. 生成 config.yaml (Clash 格式)
    proxies = [r["proxy"] for r in results]
    clash_config = {
        "proxies": proxies,
        "proxy-groups": [{"name": "🚀 节点选择", "type": "select", "proxies": [p["name"] for p in proxies]}],
        "rules": ["MATCH,🚀 节点选择"]
    }
    with open("config.yaml", "w", encoding="utf-8") as f:
        yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)

    # 2. 生成 nodes_plain.txt (明文格式)
    plain_nodes = []
    for index, r in enumerate(results):
        base_link = r["raw"].split("#")[0]
        plain_nodes.append(f"{base_link}#{r['country']} {index+1:03d} @schpd")
    
    with open("nodes_plain.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(plain_nodes))

    print(f"成功！YAML 和 明文文件已更新。有效节点: {len(results)}")

if __name__ == "__main__":
    main()
