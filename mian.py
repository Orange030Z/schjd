import requests
import base64
import re
import json
import yaml
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, unquote

# --- 配置 ---
TIMEOUT = 3
MAX_WORKERS = 100

def get_all_subs():
    return [
        "https://peige.dpkj.qzz.io/dapei",
        "https://raw.githubusercontent.com/iosDG001/_/refs/heads/main/SS",
        "https://raw.githubusercontent.com/iosDG001/_/refs/heads/main/SLVPN",
        "https://raw.githubusercontent.com/ripaojiedian/freenode/main/sub",
        "https://raw.githubusercontent.com/cook369/proxy-collect/main/dist/jichangx/v2ray.txt",
        "https://raw.githubusercontent.com/go4sharing/sub/main/sub.yaml",   
    ]

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
def check_tcp_port(server, port):
    try:
        ip = socket.gethostbyname(server)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            return s.connect_ex((ip, int(port))) == 0
    except:
        return False

def fetch_and_extract(url):
    nodes = []
    headers = {'User-Agent': 'v2rayNG/1.8.12'}
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code != 200: return []
        text = resp.text.strip()
        
        # 尝试解码 Base64 订阅格式
        if not any(p in text for p in ['://', 'proxies:']):
            try:
                text = base64.b64decode(text + '===').decode('utf-8', errors='ignore')
            except: pass
            
        # 尝试 YAML
        if "proxies:" in text:
            try:
                data = yaml.safe_load(text)
                return data.get('proxies', [])
            except: pass

        # 正则提取
        links = re.findall(r'(vmess|vless|trojan|ss)://[^\s"\'<>]+', text, re.IGNORECASE)
        nodes.extend(links)
    except: pass
    return nodes

def parse_node(item):
    try:
        if isinstance(item, dict): return item
        url = item.strip()
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        
        if scheme == "vmess":
            v2_json = json.loads(base64.b64decode(url[8:].split('#')[0] + '===').decode('utf-8'))
            return {
                "type": "vmess", "server": v2_json['add'], "port": int(v2_json['port']),
                "uuid": v2_json['id'], "alterId": 0, "cipher": "auto",
                "tls": v2_json.get('tls') == "tls", "network": v2_json.get('net', 'tcp'),
                "name": v2_json.get('ps', 'Node'), "ws-opts": {"path": v2_json.get('path', '')}
            }
        elif scheme in ["ss", "trojan", "vless"]:
            netloc = unquote(parsed.netloc)
            user_info, addr_port = netloc.split('@') if '@' in netloc else ("", netloc)
            addr, port = addr_port.split(':')
            node = {"type": scheme, "server": addr, "port": int(port), "name": unquote(parsed.fragment or "Node")}
            if scheme == "ss":
                node["cipher"], node["password"] = user_info.split(':')
            else:
                node["password"] = user_info
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
    print("--- 正在提取节点 ---")
    all_raw = []
    for url in get_all_subs():
        items = fetch_and_extract(url)
        all_raw.extend(items)
        print(f"源 {url[:40]}... -> {len(items)} 个")

    unique_nodes = {}
    for item in all_raw:
        n = parse_node(item)
        if n and n.get('server'):
            unique_nodes[f"{n['server']}:{n['port']}"] = n

    print(f"去重后 {len(unique_nodes)} 个，开始 TCP 扫描...")
    alive = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as exe:
        tasks = {exe.submit(check_tcp_port, n['server'], n['port']): n for n in unique_nodes.values()}
        for f in as_completed(tasks):
            if f.result(): alive.append(tasks[f])

    clash_nodes, links = [], []
    for i, n in enumerate(alive):
        region = "优质"
        for p, r in FEATURES.items():
            if re.search(p, n['name'].lower()): region = r; break
        n['name'] = f"{region}-{i+1:03d}"
        clash_nodes.append(n)
        link = dict_to_link(n)
        if link: links.append(link)

    # 保存 Clash
    conf = {
        "proxies": clash_nodes,
        "proxy-groups": [{"name": "🚀 自动选择", "type": "url-test", "proxies": [x["name"] for x in clash_nodes], "url": "http://www.gstatic.com/generate_204", "interval": 300},
                         {"name": "🌍 代理工具", "type": "select", "proxies": ["🚀 自动选择"] + [x["name"] for x in clash_nodes]}],
        "rules": ["MATCH,🌍 代理工具"]
    }
    with open("config.yaml", "w", encoding="utf-8") as f:
        yaml.dump(conf, f, allow_unicode=True, sort_keys=False)

    # 保存 Base64
    with open("my_sub.txt", "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(links).encode()).decode())

    print(f"✅ 完成！存活: {len(clash_nodes)}")

if __name__ == "__main__":
    main()
