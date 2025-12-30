import requests
import base64
import re
import yaml
import time
from urllib.parse import urlparse, parse_qs, unquote, urlencode

# ==================== 配置区 ====================
def get_all_subs():
    return [
        "https://raw.githubusercontent.com/iosDG001/_/refs/heads/main/SS",
        "https://raw.githubusercontent.com/iosDG001/_/refs/heads/main/SLVPN",
    ]

# ==================== 完整特征库 ====================
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

# 排序优先级定义
region_order = list(dict.fromkeys(features.values()))
region_order.append('优质')

def get_country(addr, old_name=""):
    """识别节点地区"""
    search_str = f"{old_name} {addr}".lower()
    for pattern, name in features.items():
        if re.search(pattern, search_str):
            return name
    return "优质"

def parse_node(item):
    """解析 ss:// 和 trojan:// 链接"""
    try:
        parsed = urlparse(item.strip())
        if parsed.scheme not in ["ss", "trojan"]: return None
        
        netloc = unquote(parsed.netloc)
        user_info, addr_port = netloc.split('@', 1) if '@' in netloc else ("", netloc)
        
        # 针对 SS 可能存在的二次 Base64 编码 user_info 处理
        if parsed.scheme == "ss" and ":" not in user_info:
            try:
                user_info = base64.b64decode(user_info + '===').decode()
            except: pass

        server_port = addr_port.split(':')
        res = {
            "type": parsed.scheme,
            "server": server_port[0],
            "port": int(server_port[1]),
            "name_seed": unquote(parsed.fragment or "")
        }
        
        if parsed.scheme == "ss":
            res["cipher"], res["password"] = user_info.split(':', 1)
        else:
            res["password"] = user_info
            q = parse_qs(parsed.query)
            res.update({
                "tls": q.get('security', [''])[0] == 'tls',
                "network": q.get('type', ['tcp'])[0],
                "allowInsecure": True
            })
        return res
    except: return None

def fetch_and_extract(url):
    """抓取并全文解码"""
    nodes = []
    try:
        headers = {'User-Agent': 'ClashforWindows/0.20.39'}
        res = requests.get(url, timeout=15, headers=headers).text.strip()
        
        # 自动补齐 Base64 填充并解码
        try:
            missing_padding = len(res) % 4
            if missing_padding: res += '=' * (4 - missing_padding)
            decoded = base64.b64decode(res).decode('utf-8', errors='ignore')
            lines = decoded.splitlines()
        except:
            lines = res.splitlines()

        for line in lines:
            line = line.strip()
            if line.startswith(('ss://', 'trojan://')):
                nodes.append(line)
    except Exception as e:
        print(f"抓取失败 {url}: {e}")
    return nodes

def main():
    all_raw = []
    print("🚀 开始同步订阅源...")
    for url in get_all_subs():
        items = fetch_and_extract(url)
        all_raw.extend(items)
        print(f"✅ 源 {url[-5:]}：提取到 {len(items)} 个节点")

    if not all_raw:
        print("❌ 未发现任何有效节点，任务结束。")
        return

    # 去重处理
    parsed_nodes = []
    seen = set()
    for raw in all_raw:
        node = parse_node(raw)
        if not node: continue
        fp = f"{node['server']}:{node['port']}"
        if fp in seen: continue
        seen.add(fp)
        node['region'] = get_country(node['server'], node['name_seed'])
        parsed_nodes.append(node)

    # 排序
    parsed_nodes.sort(key=lambda n: region_order.index(n['region']) if n['region'] in region_order else 999)

    clash_proxies = []
    sub_links = []
    for i, node in enumerate(parsed_nodes):
        name = f"{node['region']} {i+1:03d} @schpd_chat"
        
        # Clash 格式
        c = node.copy()
        c.update({"name": name})
        c.pop('region'); c.pop('name_seed')
        clash_proxies.append(c)
        
        # 通用链接格式 (用于生成 my_sub.txt)
        if node['type'] == 'ss':
            ui = base64.b64encode(f"{node['cipher']}:{node['password']}".encode()).decode()
            sub_links.append(f"ss://{ui}@{node['server']}:{node['port']}#{name}")
        elif node['type'] == 'trojan':
            sub_links.append(f"trojan://{node['password']}@{node['server']}:{node['port']}?security=tls&type={node['network']}#{name}")

    # 保存 Clash 配置
    config = {
        "port": 7890, "socks-port": 7891, "allow-lan": True, "mode": "rule", "log-level": "info",
        "proxies": clash_proxies,
        "proxy-groups": [
            {
                "name": "🚀 自动选择", 
                "type": "url-test", 
                "proxies": [p["name"] for p in clash_proxies], 
                "url": "http://cp.cloudflare.com/generate_204", 
                "interval": 300, 
                "tolerance": 50
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
        f.write(base64.b64encode("\n".join(sub_links).encode()).decode())

    print(f"✨ 处理完成！共生成 {len(clash_proxies)} 个节点。")

if __name__ == "__main__":
    main()
