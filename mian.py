import requests
import base64
import re
import json
import yaml
import time
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, unquote, urlencode


HEALTH_CHECK_URLS = [
    "http://cp.cloudflare.com/generate_204",    
    "http://www.gstatic.com/generate_204",       
]
HEALTH_CHECK_TIMEOUT = 5    
MAX_DELAY = 2000            
TCP_TIMEOUT = 3             

def check_tcp_connect(server, port):
    
    try:
        socket.setdefaulttimeout(TCP_TIMEOUT)
        s = socket.create_connection((server, port))
        s.close()
        return True
    except:
        return False

def test_ss_delay(node):
    
    if node.get('type') != 'ss' or 'cipher' not in node or 'password' not in node:
        return None
    try:
        auth = base64.b64encode(f"{node['cipher']}:{node['password']}".encode()).decode()
        proxies = {
            "http": f"ss://{auth}@{node['server']}:{node['port']}",
            "https": f"ss://{auth}@{node['server']}:{node['port']}"
        }
        for url in HEALTH_CHECK_URLS:
            start = time.time()
            r = requests.get(url, proxies=proxies, timeout=HEALTH_CHECK_TIMEOUT, verify=False)
            if r.status_code in [200, 204]:
                return int((time.time() - start) * 1000)
    except:
        pass
    return None

def is_node_alive(node):
    """判断节点是否相对可用"""
    # 所有节点必须 TCP 可达
    if not check_tcp_connect(node['server'], node['port']):
        return False
    # ss 节点额外要求延迟测试成功且在阈值内
    if node['type'] == 'ss':
        delay = test_ss_delay(node)
        return delay is not None and delay <= MAX_DELAY
    # vmess/vless/trojan 只需 TCP 通即可（GitHub Actions 限制）
    return True

# ==================== 订阅源 ====================
def get_all_subs():
    urls = [
        "https://raw.githubusercontent.com/ripaojiedian/freenode/main/sub",
        "https://raw.githubusercontent.com/cook369/proxy-collect/main/dist/yudou/v2ray.txt",
        "https://raw.githubusercontent.com/cook369/proxy-collect/main/dist/jichangx/v2ray.txt",
        "https://raw.githubusercontent.com/cook369/proxy-collect/main/dist/oneclash/v2ray.txt",
        "https://raw.githubusercontent.com/go4sharing/sub/main/sub.yaml",
    ]
    return list(dict.fromkeys(urls))  # 去重

# ==================== 全球特征库 ====================
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

# 自动生成排序顺序：严格按特征库出现顺序 + 优质最后
region_order = list(dict.fromkeys(features.values()))
region_order.append('优质')

def get_country(addr, old_name=""):
    """识别节点地区：优先 IP 查询，其次特征库"""
    try:
        res = requests.get(
            f"http://ip-api.com/json/{addr}?fields=country&lang=zh-CN",
            timeout=1.2
        ).json()
        if res.get("country"):
            return res.get("country")
    except:
        pass

    search_str = f"{old_name} {addr}".lower()
    for pattern, name in features.items():
        if re.search(r'\b(' + pattern + r')\b', search_str) or re.search(pattern, search_str):
            return name
    return "优质"

# ==================== 节点转通用链接 ====================
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

# ==================== 解析节点 ====================
def parse_node(item):
    try:
        if isinstance(item, str):
            node_url = item.strip()
            if node_url.startswith("vmess://"):
                body = base64.b64decode(node_url[8:].split("#")[0] + "==").decode('utf-8', errors='ignore')
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
                addr_port = user_info[1].split(':')
                res = {
                    "type": scheme, "server": addr_port[0], "port": int(addr_port[1]),
                    "name_seed": unquote(parsed.fragment or "")
                }
                if scheme == "ss":
                    res["cipher"], res["password"] = user_info[0].split(':')
                else:
                    res["uuid" if scheme == "vless" else "password"] = user_info[0]
                    q = parse_qs(parsed.query)
                    res["tls"] = q.get('security', [''])[0] == 'tls'
                    res["network"] = q.get('type', ['tcp'])[0]
                return res

        elif isinstance(item, dict):  # Clash YAML 格式
            node = item.copy()
            node['name_seed'] = node.get('name', 'node')
            return node
    except:
        return None

# ==================== 提取订阅内容 ====================
def fetch_and_extract(url):
    nodes = []
    try:
        res = requests.get(url, timeout=15).text
        # Clash YAML 格式
        if "proxies:" in res:
            try:
                data = yaml.safe_load(res)
                if data and 'proxies' in data:
                    return data['proxies']
            except:
                pass

        # Base64 编码
        try:
            text_to_scan = base64.b64decode(res).decode('utf-8', errors='ignore')
        except:
            text_to_scan = res

        # 提取所有链接
        links = re.findall(r'(vmess|vless|trojan|ss)://[A-Za-z0-9%?&=._/@#:+*-]+', text_to_scan)
        nodes.extend(links)
    except:
        pass
    return nodes

# ==================== 主函数 ====================
def main():
    target_urls = get_all_subs()
    all_raw_items = []

    print(f"开始抓取 {len(target_urls)} 个订阅源...")
    for url in target_urls:
        items = fetch_and_extract(url)
        all_raw_items.extend(items)
        print(f"  {url[:50]:50} → {len(items)} 个节点")

    # 解析节点
    parsed_nodes = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        parsed_nodes = list(filter(None, executor.map(parse_node, all_raw_items)))

    # 去重 + 地区识别
    processed_nodes = []
    seen_fp = set()
    for node in parsed_nodes:
        if not node or not node.get('server'):
            continue
        fp = f"{node['type']}:{node['server']}:{node['port']}"
        if fp in seen_fp:
            continue
        seen_fp.add(fp)
        node['region'] = get_country(node['server'], node.get('name_seed', ''))
        processed_nodes.append(node)

    print(f"解析去重后共 {len(processed_nodes)} 个节点")

    # ==================== 简单测活 ====================
    print("开始测活（TCP + ss 延迟测试）...")
    alive_nodes = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        future_to_node = {executor.submit(is_node_alive, node): node for node in processed_nodes}
        for future in as_completed(future_to_node):
            node = future_to_node[future]
            if future.result():
                alive_nodes.append(node)

    print(f"测活完成，保留 {len(alive_nodes)} 个相对可用节点")
    processed_nodes = alive_nodes if alive_nodes else processed_nodes

    # ==================== 排序 + 编号 ====================
    processed_with_key = []
    for i, node in enumerate(processed_nodes):
        region = node['region']
        order_key = region_order.index(region) if region in region_order else len(region_order)
        processed_with_key.append((order_key, i, node))

    processed_with_key.sort(key=lambda x: (x[0], x[1]))
    processed_nodes = [item[2] for item in processed_with_key]

    # 生成最终配置
    clash_proxies = []
    plain_links = []
    current_region = None
    region_counter = 0

    for node in processed_nodes:
        if node['region'] != current_region:
            current_region = node['region']
            region_counter = 1
        else:
            region_counter += 1

        name = f"{current_region} {region_counter:03d} @schpd_chat"
        link = dict_to_link(node, name)
        if link:
            plain_links.append(link)

        node.pop('name_seed', None)
        node.pop('region', None)
        node['name'] = name
        clash_proxies.append(node)

    # ==================== 写入文件 ====================
    config = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "proxies": clash_proxies,
        "proxy-groups": [
            {
                "name": "🚀 自动选择",
                "type": "url-test",
                "url": "http://cp.cloudflare.com/generate_204",
                "interval": 300,
                "tolerance": 50,
                "proxies": [p["name"] for p in clash_proxies]
            },
            {
                "name": "🌍 代理工具",
                "type": "select",
                "proxies": ["🚀 自动选择"] + [p["name"] for p in clash_proxies]
            }
        ],
        "rules": ["MATCH,🌍 代理工具"]
    }

    with open("config.yaml", "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False)

    with open("my_sub.txt", "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(plain_links).encode()).decode())

    print(f"✨ 成功生成！共 {len(clash_proxies)} 个节点")
    print("   config.yaml 和 my_sub.txt 已更新")

if __name__ == "__main__":
    main()