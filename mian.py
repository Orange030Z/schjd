import requests
import base64
import re
import json
import yaml
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, unquote

# --- 严格配置 ---
TCP_TIMEOUT = 1.5    # GitHub 环境下 1.5s 不通的节点，国内基本无法使用
MAX_WORKERS = 100    # 并发扫描线程数

def get_all_subs():
    return [
        "https://schpd.pages.dev/0b91f093-98cd-442e-a6eb-1eb7fc101676", # 新增源
        "https://cf-workers-sub-43i.pages.dev/sub?token=guest",
        "https://dyzh.zhangyucheng0720.workers.dev/c/NxZGc03",#  https://peige.dpkj.qzz.io/dapei      
        "https://dyzh.zhangyucheng0720.workers.dev/c/APHPvMC",
        "https://dyzh.zhangyucheng0720.workers.dev/c/Ic4EKr9",#https://raw.githubusercontent.com/ripaojiedian/freenode/main/sub
        "https://raw.githubusercontent.com/ggborr/FREEE-VPN/refs/heads/main/11clash",

"https://rss.zyfx6.xyz/clash/",
        "https://raw.githubusercontent.com/go4sharing/sub/main/sub.yaml",   
    ]

# 严格的 IP 黑名单：屏蔽在机房环境极速但在国内 Timeout 的 Cloudflare 公共段
IP_BLACK_LIST = [
    '127.0.0.1', 'localhost', '0.0.0.0', 
    '104.21.', '104.28.', '172.67.', '104.25.'
]

# 完整特征库
FEATURES = {
    'hk|hkg|hongkong|香港|pccw|hkt': '香港',
    'tw|taiwan|tpe|hinet|cht|台湾|台北': '台湾',
    'jp|japan|tokyo|nrt|hnd|kix|osaka|日本|东京|大阪': '日本',
    'sg|singapore|sin|新加坡': '新加坡',
    'kr|korea|icn|seoul|sel|韩国|首尔': '韩国',
    'mo|macau|macao|澳门': '澳门',
    'th|thailand|bkk|bangkok|泰国|曼谷': '泰国',
    'vn|vietnam|hanoi|sgn|越南|河内|胡志明': '越南',
    'my|malaysia|kul|马来西亚|吉隆坡': '马来西亚',
    'ph|philippines|mnl|manila|菲律宾|马尼拉': '菲律宾',
    'id|indonesia|cgk|jakarta|印尼|雅加达': '印尼',
    'in|india|bom|del|mumbai|印度|孟买': '印度',
    'au|australia|syd|mel|澳大利亚|悉尼|墨尔本': '澳大利亚',
    'nz|newzealand|akl|新西兰': '新西兰',
    'us|america|unitedstates|usa|lax|sfo|iad|ord|sea|美国|洛杉矶|纽约': '美国',
    'ca|canada|yvr|yyz|mtl|加拿大|温哥华|多伦多': '加拿大',
    'mx|mexico|mex|墨西哥': '墨西哥',
    'br|brazil|sao|brazil|巴西|圣保罗': '巴西',
    'de|germany|fra|frankfurt|德国|法兰克福': '德国',
    'uk|gb|london|lon|lhr|英国|伦敦': '英国',
    'fr|france|par|paris|法国|巴黎': '法国',
    'nl|netherlands|ams|amsterdam|荷兰|阿姆斯特丹': '荷兰',
    'ru|russia|moscow|mow|svo|俄罗斯|莫斯科': '俄罗斯',
    'tr|turkey|ist|istanbul|土耳其|伊斯坦布尔': '土耳其',
    'it|italy|mil|milano|意大利|米兰': '意大利',
    'es|spain|mad|madrid|西班牙|马德里': '西班牙',
    'ch|switzerland|zrh|zurich|瑞士|苏黎世': '瑞士',
    'ae|uae|dubai|dxb|迪拜|阿联酋': '阿联酋',
    'za|southafrica|jnb|南非': '南非',
    'eg|egypt|cai|埃及': '埃及'
}

# 完整国旗库
FLAGS = {
    '香港': '🇭🇰', '台湾': '🇹🇼', '日本': '🇯🇵', '新加坡': '🇸🇬', '韩国': '🇰🇷',
    '澳门': '🇲🇴', '泰国': '🇹🇭', '越南': '🇻🇳', '马来西亚': '🇲🇾', '菲律宾': '🇵🇭',
    '印尼': '🇮🇩', '印度': '🇮🇳', '澳大利亚': '🇦🇺', '新西兰': '🇳🇿', '美国': '🇺🇸', 
    '加拿大': '🇨🇦', '墨西哥': '🇲🇽', '巴西': '🇧🇷', '德国': '🇩🇪', '英国': '🇬🇧', 
    '法国': '🇫🇷', '荷兰': '🇳🇱', '俄罗斯': '🇷🇺', '土耳其': '🇹🇷', '意大利': '🇮🇹', 
    '西班牙': '🇪🇸', '瑞士': '🇨🇭', '阿联酋': '🇦🇪', '南非': '🇿🇦', '埃及': '🇪🇬', '优质': '✨'
}

def is_ip_allowed(server):
    for black_ip in IP_BLACK_LIST:
        if server.startswith(black_ip): return False
    return True

def check_tcp_port(server, port):
    if not is_ip_allowed(server): return False
    try:
        ip = socket.gethostbyname(server)
        if not is_ip_allowed(ip): return False
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TCP_TIMEOUT)
            return s.connect_ex((ip, int(port))) == 0
    except: return False

def fetch_and_extract(url):
    headers = {'User-Agent': 'v2rayNG/1.8.12'}
    try:
        resp = requests.get(url, headers=headers, timeout=12)
        if resp.status_code != 200: return []
        text = resp.text.strip()
        if not any(p in text for p in ['://', 'proxies:']):
            try: text = base64.b64decode(text + '===').decode('utf-8', errors='ignore')
            except: pass
        if "proxies:" in text:
            try: return yaml.safe_load(text).get('proxies', [])
            except: pass
        return re.findall(r'(vmess|vless|trojan|ss)://[^\s"\'<>]+', text, re.IGNORECASE)
    except: return []

def parse_node(item):
    try:
        if isinstance(item, dict): return item
        url = item.strip()
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        if scheme == "vmess":
            v2_json = json.loads(base64.b64decode(url[8:].split('#')[0] + '===').decode('utf-8'))
            return {"type": "vmess", "server": v2_json['add'], "port": int(v2_json['port']), "uuid": v2_json['id'], "tls": v2_json.get('tls') == "tls", "network": v2_json.get('net', 'tcp'), "name": v2_json.get('ps', 'Node')}
        elif scheme in ["ss", "trojan", "vless"]:
            netloc = unquote(parsed.netloc)
            user_info, addr_port = netloc.split('@') if '@' in netloc else ("", netloc)
            addr, port = addr_port.split(':')
            node = {"type": scheme, "server": addr, "port": int(port), "name": unquote(parsed.fragment or "Node")}
            if scheme == "ss": node["cipher"], node["password"] = user_info.split(':')
            else: node["password"] = user_info
            return node
    except: return None

def dict_to_link(node):
    try:
        t, name = node['type'], node.get('name', 'Node')
        if t == 'ss':
            auth = base64.b64encode(f"{node['cipher']}:{node['password']}".encode()).decode()
            return f"ss://{auth}@{node['server']}:{node['port']}#{name}"
        elif t == 'vmess':
            vj = {"v": "2", "ps": name, "add": node['server'], "port": node['port'], "id": node['uuid'], "aid": 0, "net": node.get('network', 'tcp'), "type": "none", "tls": "tls" if node.get('tls') else ""}
            return f"vmess://{base64.b64encode(json.dumps(vj).encode()).decode()}"
        elif t in ['vless', 'trojan']:
            pw = node.get('uuid') or node.get('password')
            return f"{t}://{pw}@{node['server']}:{node['port']}#{name}"
    except: return None

def main():
    print("--- 启动节点自动化处理 (严格过滤版) ---")
    all_raw = []
    for url in get_all_subs():
        items = fetch_and_extract(url)
        all_raw.extend(items)
        print(f"提取源: {url[:40]}... 成功抓取: {len(items)}")

    unique_nodes = {}
    for item in all_raw:
        n = parse_node(item)
        if n and n.get('server'):
            unique_nodes[f"{n['server']}:{n['port']}"] = n

    print(f"去重后 {len(unique_nodes)} 个，正在进行严格 TCP 筛选...")
    alive = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as exe:
        tasks = {exe.submit(check_tcp_port, n['server'], n['port']): n for n in unique_nodes.values()}
        for f in as_completed(tasks):
            if f.result(): alive.append(tasks[f])

    clash_nodes, links = [], []
    region_counters = {}

    for n in alive:
        region = "优质"
        match_str = f"{n.get('name', '')} {n.get('server', '')}".lower()
        for pattern, r_name in FEATURES.items():
            if re.search(pattern, match_str):
                region = r_name
                break
        
        region_counters[region] = region_counters.get(region, 0) + 1
        count = region_counters[region]
        flag = FLAGS.get(region, '🌐')
        
        # --- 修改点：在末尾增加后缀 ---
        n['name'] = f"{flag} {region} {count:02d} @schpd_chat"
        clash_nodes.append(n)

    clash_nodes.sort(key=lambda x: x['name'])
    final_links = [dict_to_link(n) for n in clash_nodes if dict_to_link(n)]

    # 保存文件
    conf = {
        "proxies": clash_nodes,
        "proxy-groups": [
            {"name": "🚀 自动选择", "type": "url-test", "proxies": [x["name"] for x in clash_nodes], "url": "http://www.gstatic.com/generate_204", "interval": 300},
            {"name": "🌍 代理工具", "type": "select", "proxies": ["🚀 自动选择"] + [x["name"] for x in clash_nodes]}
        ],
        "rules": ["MATCH,🌍 代理工具"]
    }
    with open("config.yaml", "w", encoding="utf-8") as f:
        yaml.dump(conf, f, allow_unicode=True, sort_keys=False)

    with open("my_sub.txt", "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(final_links).encode()).decode())

    print(f"✅ 执行完毕！最终保留存活节点: {len(clash_nodes)}")

if __name__ == "__main__":
    main()
