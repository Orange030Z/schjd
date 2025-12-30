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

# 2. 终极版全球特征库（已替换）
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
    # 1. 优先使用 ip-api.com 快速查询国家（仅返回 country 字段，轻量快速）
    try:
        res = requests.get(
            f"http://ip-api.com/json/{addr}?fields=country&lang=zh-CN",
            timeout=1.2
        ).json()
        if res.get("country"):
            return res.get("country")
    except:
        pass
    
    # 2. 失败则回落至特征库匹配
    search_str = f"{old_name} {addr}".lower()
    for pattern, name in features.items():
        # 使用 \b 边界匹配更精确，避免误匹配（如 hk 误匹配 hkg2）
        if re.search(r'\b(' + pattern + r')\b', search_str) or re.search(pattern, search_str):
            return name
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
    except:
        return None

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
    except:
        return None

# 4. 万能提取函数
def fetch_and_extract(url):
    nodes = []
    try:
        res = requests.get(url, timeout=15).text
        if "proxies:" in res:
            try:
                data = yaml.safe_load(res)
                if data and 'proxies' in data:
                    return data['proxies']
            except:
                pass
        
        try:
            text_to_scan = base64.b64decode(res).decode('utf-8')
        except:
            text_to_scan = res
            
        links = re.findall(r'(?:vmess|vless|trojan|ss)://[a-zA-Z0-9%?&=._/@#:+*-]+', text_to_scan)
        nodes.extend(links)
    except:
        pass
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
        if not node or not node.get('server'):
            continue
        fp = f"{node['type']}:{node['server']}:{node['port']}"
        if fp not in seen_fp:
            seen_fp.add(fp)
            # 使用新函数识别国家/地区
            region = get_country(node['server'], node.get('name_seed', ''))
            node['region'] = region
            processed_nodes.append(node)

    # 按地区排序（中文地区名自然排序）
    processed_nodes.sort(key=lambda x: x['region'])
    
    clash_proxies = []
    plain_links = []
    
    for i, node in enumerate(processed_nodes):
        name = f"{node['region']} {i+1:03d} @schpd_chat"
        
        # 生成通用链接用于 Base64 订阅
        link = dict_to_link(node, name)
        if link:
            plain_links.append(link)
        
        # 生成 Clash 格式
        node.pop('name_seed', None)
        node.pop('region', None)
        node['name'] = name
        clash_proxies.append(node)

    # 写入 Clash config.yaml
    config = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": True,
        "mode": "rule",
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