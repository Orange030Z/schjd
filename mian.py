import requests
import base64
import re
import json
import yaml
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, parse_qs, unquote, urlencode

# ==================== 只保留 iosDG001 的订阅源 ====================
def get_all_subs():
    urls = [
        "https://raw.githubusercontent.com/iosDG001/_/refs/heads/main/SS",
        "https://raw.githubusercontent.com/iosDG001/_/refs/heads/main/SLVPN",
    ]
    return urls  # 无需去重，只有2个

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
    'us|america|unitedstates|usa|lax|sfo|iad|ord|sea|美国|洛杉矶|纽约': '美国',
    'ca|canada|yvr|yyz|mtl|加拿大|温哥华|多伦多': '加拿大',
    'de|germany|fra|frankfurt|德国|法兰克福': '德国',
    'uk|gb|london|lon|lhr|英国|伦敦': '英国',
    'fr|france|par|paris|法国|巴黎': '法国',
}

region_order = list(dict.fromkeys(features.values()))
region_order.append('优质')

def get_country(addr, old_name=""):
    try:
        res = requests.get(f"http://ip-api.com/json/{addr}?fields=country&lang=zh-CN", timeout=1.2).json()
        if res.get("country"):
            return res.get("country")
    except:
        pass

    search_str = f"{old_name} {addr}".lower()
    for pattern, name in features.items():
        if re.search(pattern, search_str):
            return name
    return "优质"

# ==================== 节点转通用链接 ====================
def dict_to_link(node, name):
    try:
        t = node.get('type')
        if t == 'ss':
            user_info = base64.b64encode(f"{node['cipher']}:{node['password']}".encode()).decode()
            return f"ss://{user_info}@{node['server']}:{node['port']}#{unquote(name)}"
        elif t in ['trojan']:
            uuid = node.get('password')
            query = {"type": node.get('network', 'tcp'), "security": "tls" if node.get('tls') else "none"}
            return f"trojan://{uuid}@{node['server']}:{node['port']}?{urlencode(query)}#{unquote(name)}"
    except:
        return None

# ==================== 解析节点 ====================
def parse_node(item):
    try:
        if isinstance(item, str):
            node_url = item.strip()
            parsed = urlparse(node_url)
            scheme = parsed.scheme
            if scheme in ["trojan", "ss"]:
                user_info = unquote(parsed.netloc).split('@')
                addr_port = user_info[1].split(':')
                res = {
                    "type": scheme, "server": addr_port[0], "port": int(addr_port[1]),
                    "name_seed": unquote(parsed.fragment or "")
                }
                if scheme == "ss":
                    res["cipher"], res["password"] = user_info[0].split(':')
                else:
                    res["password"] = user_info[0]
                    q = parse_qs(parsed.query)
                    res["tls"] = q.get('security', [''])[0] == 'tls' or 'allowInsecure' not in q
                    res["network"] = q.get('type', ['tcp'])[0]
                return res
    except:
        return None

# ==================== 提取订阅内容（专治 iosDG001 格式） ====================
def fetch_and_extract(url):
    nodes = []
    try:
        res = requests.get(url, timeout=15).text.strip()
        lines = [line.strip() for line in res.splitlines() if line.strip()]
        for line in lines:
            # 直接是标准链接 (SLVPN 全是这个)
            if re.match(r'(trojan|ss)://', line, re.IGNORECASE):
                nodes.append(line)
                continue
            # SS 特有：每行 base64 编码的完整链接
            try:
                decoded = base64.b64decode(line + '===').decode('utf-8', errors='ignore').strip()
                if re.match(r'(ss|trojan)://', decoded, re.IGNORECASE):
                    nodes.append(decoded)
            except:
                pass
    except Exception as e:
        print(f"提取失败 {url}: {e}")
    return nodes

# ==================== 主函数 ====================
def main():
    target_urls = get_all_subs()
    all_raw_items = []

    print(f"开始抓取 {len(target_urls)} 个 iosDG001 订阅源...")
    for url in target_urls:
        items = fetch_and_extract(url)
        all_raw_items.extend(items)
        print(f"  {url.split('/')[-1]:10} → {len(items)} 个节点")

    if not all_raw_items:
        print("警告：未提取到节点，请检查网络")
        return

    # 解析 + 去重 + 地区识别
    parsed_nodes = list(filter(None, map(parse_node, all_raw_items)))

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

    # 排序
    processed_nodes.sort(key=lambda n: (region_order.index(n['region']) if n['region'] in region_order else len(region_order), n['name_seed']))

    # 生成配置
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

    # 写入文件
    config = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "proxies": clash_proxies,
        "proxy-groups": [
            {"name": "🚀 自动选择", "type": "url-test", "url": "http://cp.cloudflare.com/generate_204", "interval": 300, "tolerance": 50, "proxies": [p["name"] for p in clash_proxies]},
            {"name": "🌍 代理工具", "type": "select", "proxies": ["🚀 自动选择"] + [p["name"] for p in clash_proxies]}
        ],
        "rules": ["MATCH,🌍 代理工具"]
    }

    with open("config.yaml", "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False)

    with open("my_sub.txt", "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(plain_links).encode()).decode())

    print(f"✨ 成功生成！共 {len(clash_proxies)} 个 iosDG001 节点")
    print("   config.yaml 和 my_sub.txt 已更新")

if __name__ == "__main__":
    main()