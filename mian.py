import requests
import base64
import re
import socket
import json
import yaml
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, parse_qs, unquote, urlencode

# 1. 动态订阅源列表
def get_all_subs():
    urls = [
        "https://raw.githubusercontent.com/ripaojiedian/freenode/main/sub",
        "https://raw.githubusercontent.com/cook369/proxy-collect/main/dist/yudou/v2ray.txt",
        "https://raw.githubusercontent.com/cook369/proxy-collect/main/dist/jichangx/v2ray.txt",
        "https://raw.githubusercontent.com/cook369/proxy-collect/main/dist/oneclash/v2ray.txt",
        "https://raw.githubusercontent.com/go4sharing/sub/main/sub.yaml",
    ]
    return list(dict.fromkeys(urls))

# 2. 全球特征库
features = [
    ('hk|hkg|hongkong|香港|pccw|hkt', '香港'),
    ('tw|taiwan|tpe|hinet|cht|台湾', '台湾'),
    ('jp|japan|tokyo|nrt|日本', '日本'),
    ('sg|singapore|sin|新加坡', '新加坡'),
    ('kr|korea|icn|seoul|韩国', '韩国'),
    ('us|america|usa|lax|sfo|美国', '美国'),
    ('uk|gb|london|英国', '英国'),
    ('fr|france|paris|法国', '法国'),
    ('de|germany|frankfurt|德国', '德国'),
    ('ru|russia|moscow|俄罗斯', '俄罗斯'),
]

def get_region_name(text):
    for pattern, name in features:
        if re.search(pattern, str(text).lower()): return name
    return "优质"

# --- 核心辅助：将解析后的字典转回通用链接 (供 Base64 订阅使用) ---
def dict_to_link(node, name):
    try:
        t = node.get('type')
        if t == 'ss':
            user_info = base64.b64encode(f"{node['cipher']}:{node['password']}".encode()).decode()
            return f"ss://{user_info}@{node['server']}:{node['port']}#{unquote(name)}"
        elif t == 'vmess':
            v2_json = {
                "v": "2", "ps": name, "add": node['server'], "port": node['port'],
                "id": node.get('uuid') or node.get('id'), "aid": node.get('alterId', 0), 
                "net": node.get('network', 'tcp'), "type": "none",
                "host": node.get('ws-opts', {}).get('headers', {}).get('Host', ''),
                "path": node.get('ws-opts', {}).get('path', ''), "tls": "tls" if node.get('tls') else ""
            }
            return f"vmess://{base64.b64encode(json.dumps(v2_json).encode()).decode()}"
        elif t in ['vless', 'trojan']:
            uuid = node.get('uuid') or node.get('password')
            query = {"type": node.get('network', 'tcp'), "security": "tls" if node.get('tls') else "none"}
            return f"{t}://{uuid}@{node['server']}:{node['port']}?{urlencode(query)}#{unquote(name)}"
    except: return None

# 3. 核心解析逻辑：支持从 URL 和 字典(YAML) 两种方式解析
def parse_node(item):
    try:
        if isinstance(item, str):
            node_url = item.strip()
            if node_url.startswith("vmess://"):
                body = base64.b64decode(node_url.split("://")[1].split("#")[0] + "==").decode('utf-8')
                info = json.loads(body)
                res = {
                    "type": "vmess", "server": info['add'], "port": int(info['port']),
                    "uuid": info['id'], "alterId": int(info.get('aid', 0)), "cipher": "auto",
                    "tls": info.get('tls') == "tls", "network": info.get('net', 'tcp'),
                    "name_seed": info.get('ps', '')
                }
                if info.get('net') == 'ws':
                    res["ws-opts"] = {"path": info.get('path', '/'), "headers": {"Host": info.get('host', '')}}
                return res
            
            parsed = urlparse(node_url)
            scheme = parsed.scheme
            if scheme in ["vless", "trojan", "ss"]:
                user_info = unquote(parsed.netloc).split('@')
                addr = user_info[1].split(':')
                res = {"type": scheme, "server": addr[0], "port": int(addr[1]), "name_seed": unquote(parsed.fragment or "")}
                if scheme == "ss":
                    res["cipher"], res["password"] = user_info[0].split(':')
                else:
                    res["uuid" if scheme == "vless" else "password"] = user_info[0]
                    q = parse_qs(parsed.query)
                    res.update({"tls": q.get('security', [''])[0] == 'tls', "network": q.get('type', ['tcp'])[0]})
                return res
        
        elif isinstance(item, dict):
            node = item.copy()
            node['name_seed'] = node.get('name', 'node')
            return node
    except: return None

# 4. 万能提取函数
def fetch_and_extract(url):
    nodes = []
    try:
        res = requests.get(url, timeout=15).text
        if "proxies:" in res:
            try:
                data = yaml.safe_load(res)
                if data and 'proxies' in data: return data['proxies']
            except: pass
        
        try: text_to_scan = base64.b64decode(res).decode('utf-8')
        except: text_to_scan = res
            
        links = re.findall(r'(?:vmess|vless|trojan|ss)://[a-zA-Z0-9%?&=._/@#:+*-]+', text_to_scan)
        nodes.extend(links)
    except: pass
    return nodes

def main():
    target_urls = get_all_subs()
    all_raw_items = []
    
    print(f"开始抓取 {len(target_urls)} 个源...")
    for url in target_urls:
        items = fetch_and_extract(url)
        all_raw_items.extend(items)
        print(f"源 {url[:30]}... 提取到 {len(items)} 个节点")

    processed_nodes = []
    seen_fp = set()
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = list(executor.map(parse_node, all_raw_items))
        
    for node in results:
        if not node or not node.get('server'): continue
        fp = f"{node['type']}:{node['server']}:{node['port']}"
        if fp not in seen_fp:
            seen_fp.add(fp)
            region = get_region_name(node.get('name_seed', '') + node['server'])
            node['region'] = region
            processed_nodes.append(node)

    processed_nodes.sort(key=lambda x: x['region'])
    
    clash_proxies = []
    plain_links = []
    
    for i, node in enumerate(processed_nodes):
        name = f"{node['region']} {i+1:03d} @schpd_chat"
        
        # 生成通用链接用于 Base64 订阅
        link = dict_to_link(node, name)
        if link: plain_links.append(link)
        
        # 生成 Clash 格式
        node.pop('name_seed', None)
        node.pop('region', None)
        node['name'] = name
        clash_proxies.append(node)

    # 写入 Clash config.yaml
    config = {
        "port": 7890, "socks-port": 7891, "allow-lan": True, "mode": "rule",
        "proxies": clash_proxies,
        "proxy-groups": [
            {"name": "🚀 自动选择", "type": "url-test", "url": "http://www.gstatic.com/generate_204", "interval": 300, "proxies": [p["name"] for p in clash_proxies]},
            {"name": "🌍 代理工具", "type": "select", "proxies": ["🚀 自动选择"] + [p["name"] for p in clash_proxies]}
        ],
        "rules": ["MATCH,🌍 代理工具"]
    }
    with open("config.yaml", "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False)

    # 写入 Base64 my_sub.txt
    with open("my_sub.txt", "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(plain_links).encode()).decode())

    print(f"✨ 成功！config.yaml ({len(clash_proxies)}) 与 my_sub.txt ({len(plain_links)}) 已更新")

if __name__ == "__main__":
    main()
