import requests
import base64
import re
import socket
import json
import yaml
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, parse_qs, unquote

# 1. 动态获取 cmliu 订阅源列表
def get_all_subs():
    urls = ["https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray"]
    try:
        res = requests.get("https://raw.githubusercontent.com/cmliu/cmliu/main/SubsCheck-URLs", timeout=10).text
        urls.extend([l.strip() for l in res.splitlines() if l.startswith("http")])
    except: pass
    return list(set(urls))

# 2. 你提供的终极版全球特征库
features = {
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
    'us|america|unitedstates|usa|lax|sfo|iad|ord|sea|美国|洛杉矶|纽约': '美国',
    'ca|canada|yvr|yyz|mtl|加拿大|温哥华|多伦多': '加拿大',
    'br|brazil|sao|brazil|巴西|圣保罗': '巴西',
    'mx|mexico|mex|墨西哥': '墨西哥',
    'de|germany|fra|frankfurt|德国|法兰克福': '德国',
    'uk|gb|london|lon|lhr|英国|伦敦': '英国',
    'fr|france|par|paris|法国|巴黎': '法国',
    'nl|netherlands|ams|amsterdam|荷兰|阿姆斯特丹': '荷兰',
    'ru|russia|moscow|mow|svo|俄罗斯|莫斯科': '俄罗斯',
    'tr|turkey|ist|istanbul|土耳其|伊斯坦布尔': '土耳其',
    'it|italy|mil|milano|意大利|米兰': '意大利',
    'es|spain|mad|madrid|西班牙|马德里': '西班牙',
    'ch|switzerland|zrh|zurich|瑞士|苏黎世': '瑞士',
    'za|southafrica|jnb|南非': '南非',
    'eg|egypt|cai|埃及': '埃及'
}

def get_region_name(node_str):
    search_str = node_str.lower()
    for pattern, name in features.items():
        if re.search(pattern, search_str):
            return name
    return "优质"

# 3. 核心解析函数 (全协议支持)
def parse_node(node_url):
    try:
        if node_url.startswith("vmess://"):
            body = node_url.split("://")[1].split("#")[0]
            body += '=' * (-len(body) % 4)
            info = json.loads(base64.b64decode(body).decode('utf-8'))
            return {
                "type": "vmess", "server": info['add'], "port": int(info['port']),
                "uuid": info['id'], "alterId": int(info.get('aid', 0)), "cipher": "auto",
                "tls": info.get('tls') == "tls", "network": info.get('net', 'tcp'),
                "ws-opts": {"path": info['path'], "headers": {"Host": info['host']}} if info.get('net') == 'ws' else None
            }
        elif node_url.startswith(("vless://", "trojan://", "ss://")):
            parsed = urlparse(node_url)
            net_type = parsed.scheme
            user_info = unquote(parsed.netloc).split('@')
            address = user_info[1].split(':')
            node_dict = {"type": "ss" if net_type == "ss" else net_type, "server": address[0], "port": int(address[1])}
            if net_type == "ss":
                node_dict["cipher"], node_dict["password"] = user_info[0].split(':')
            else:
                node_dict["uuid" if net_type == "vless" else "password"] = user_info[0]
                query = parse_qs(parsed.query)
                node_dict.update({"udp": True, "tls": query.get('security', [''])[0] in ['tls', 'xtls'], "network": query.get('type', ['tcp'])[0]})
            return node_dict
    except: return None

# 4. 测活函数
def check_node(node):
    info = parse_node(node)
    if not info: return None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.2)
            if s.connect_ex((info['server'], info['port'])) == 0:
                info['region'] = get_region_name(node)
                info['raw_link'] = node.split("#")[0]
                return info
    except: pass
    return None

def main():
    target_urls = get_all_subs()
    raw_nodes = []
    for url in target_urls:
        try:
            res = requests.get(url, timeout=5).text
            try: raw_nodes.extend(base64.b64decode(res).decode('utf-8').splitlines())
            except: raw_nodes.extend(res.splitlines())
        except: continue

    print(f"正在全协议测活 {len(set(raw_nodes))} 个节点...")
    with ThreadPoolExecutor(max_workers=100) as executor:
        results = [r for r in executor.map(check_node, list(set(raw_nodes))) if r]

    results.sort(key=lambda x: x['region'])
    clash_proxies = []
    plain_nodes = []
    
    for i, item in enumerate(results):
        name = f"{item['region']} {i+1:03d} @schpd"
        raw_link = item.pop('raw_link', '')
        item.pop('region', None)
        item['name'] = name
        clash_proxies.append(item)
        plain_nodes.append(f"{raw_link}#{name}")

    # 生成原生的 Clash 配置文件
    config = {
        "port": 7890, "socks-port": 7891, "allow-lan": True, "mode": "rule",
        "proxies": clash_proxies,
        "proxy-groups": [
            {"name": "🚀 自动选择", "type": "url-test", "url": "http://www.gstatic.com/generate_204", "interval": 300, "proxies": [p["name"] for p in clash_proxies]},
            {"name": "🌍 代理工具", "type": "select", "proxies": ["🚀 自动选择"] + [p["name"] for p in clash_proxies]}
        ],
        "rules": ["GEOIP,CN,DIRECT", "MATCH,🌍 代理工具"]
    }

    with open("config.yaml", "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False)

    with open("my_sub.txt", "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(plain_nodes).encode()).decode())

    print(f"✅ 处理完成！已生成 config.yaml (Clash) 和 my_sub.txt (Base64)")

if __name__ == "__main__":
    main()
