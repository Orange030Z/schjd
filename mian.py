import requests
import base64
import re
import socket
import json
import yaml
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, parse_qs, unquote

# 1. 动态订阅源列表
def get_all_subs():
    urls = [
        "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
        "https://raw.githubusercontent.com/anaer/Sub/main/clash.yaml",
        "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/clash.yml",
        "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2",
        "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity.yml",
        "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/sub/sub_merge_yaml.yml",
        "https://raw.githubusercontent.com/mfuu/v2ray/master/clash.yaml",
        "https://raw.githubusercontent.com/MrMohebi/xray-proxy-grabber-telegram/master/collected-proxies/clash-meta/all.yaml",
        "https://raw.githubusercontent.com/go4sharing/sub/main/sub.yaml",
    ]
    """
    # 动态爬取代码
    try:
        res = requests.get("https://raw.githubusercontent.com/cmliu/cmliu/main/SubsCheck-URLs", timeout=10).text
        urls.extend([l.strip() for l in res.splitlines() if l.startswith("http")])
    except: pass
    """
    return list(dict.fromkeys(urls))

# 2. 全球特征库
features = [
    ('hk|hkg|hongkong|香港|pccw|hkt|宽频|九仓', '香港'),
    ('tw|taiwan|tpe|hinet|cht|台湾|台北|彰化|新北', '台湾'),
    ('jp|japan|tokyo|nrt|hnd|kix|osaka|日本|东京|大阪|埼玉', '日本'),
    ('sg|singapore|sin|新加坡|狮城', '新加坡'),
    ('kr|korea|icn|seoul|sel|韩国|首尔|春川', '韩国'),
    ('us|america|unitedstates|usa|lax|sfo|iad|ord|sea|美国|洛杉矶|纽约|圣何塞|波特兰|西雅图', '美国'),
    ('uk|gb|london|lon|lhr|英国|伦敦', '英国'),
    ('fr|france|par|paris|法国|巴黎', '法国'),
    ('de|germany|fra|frankfurt|德国|法兰克福', '德国'),
    ('nl|netherlands|ams|amsterdam|荷兰|阿姆斯特丹', '荷兰'),
    ('ru|russia|moscow|mow|svo|俄罗斯|莫斯科|伯力|圣彼得堡', '俄罗斯'),
    ('ca|canada|yvr|yyz|mtl|加拿大|温哥华|多伦多|蒙特利尔', '加拿大'),
    ('au|australia|syd|mel|澳大利亚|悉尼|墨尔本', '澳大利亚'),
    ('th|thailand|bkk|bangkok|泰国|曼谷', '泰国'),
    ('vn|vietnam|hanoi|sgn|越南|河内|胡志明', '越南'),
    ('my|malaysia|kul|马来西亚|吉隆坡', '马来西亚'),
    ('ph|philippines|mnl|manila|菲律宾|马尼拉', '菲律宾'),
    ('in|india|bom|del|mumbai|印度|孟买', '印度'),
    ('tr|turkey|ist|istanbul|土耳其|伊斯坦布尔', '土耳其'),
    ('br|brazil|sao|巴西|圣保罗', '巴西'),
    ('za|southafrica|jnb|南非', '南非')
]

def get_region_name(node_str):
    decoded_str = unquote(node_str).lower()
    clean_str = re.sub(r'(cn2|gia|iplc|bgp|移动|联通|电信|直连|中转|专线)', '', decoded_str)
    for pattern, name in features:
        if re.search(pattern, clean_str):
            return name
    return "优质"

# 3. 核心解析逻辑 (全协议补完版)
def parse_node(node_url):
    try:
        node_url = node_url.strip()
        if node_url.startswith("vmess://"):
            body = node_url.split("://")[1].split("#")[0]
            body = body.replace('-', '+').replace('_', '/')
            body += '=' * (-len(body) % 4)
            info = json.loads(base64.b64decode(body).decode('utf-8'))
            return {
                "type": "vmess", "server": info['add'], "port": int(info['port']),
                "uuid": info['id'], "alterId": int(info.get('aid', 0)), "cipher": "auto",
                "tls": info.get('tls') in ["tls", True], "network": info.get('net', 'tcp'),
                "ws-opts": {"path": info['path'], "headers": {"Host": info['host']}} if info.get('net') == 'ws' else None,
                "grpc-opts": {"grpc-service-name": info.get('path', '')} if info.get('net') == 'grpc' else None
            }
        
        elif node_url.startswith(("vless://", "trojan://", "ss://")):
            parsed = urlparse(node_url)
            scheme = parsed.scheme
            # 处理 SS 的 Base64 格式 (ss://BASE64@host:port)
            if '@' not in parsed.netloc and scheme == 'ss':
                raw_ss = base64.b64decode(parsed.netloc + "==").decode('utf-8')
                user_info, server_part = raw_ss.split('@')
                server_addr = server_part.split(':')
            else:
                user_info, server_part = unquote(parsed.netloc).split('@')
                server_addr = server_part.split(':')

            node_dict = {"type": "ss" if scheme == "ss" else scheme, "server": server_addr[0], "port": int(server_addr[1])}
            
            if scheme == "ss":
                if ':' in user_info:
                    node_dict["cipher"], node_dict["password"] = user_info.split(':')
                else: # 某些旧版单端口 Base64
                    decoded_ui = base64.b64decode(user_info + "==").decode('utf-8')
                    node_dict["cipher"], node_dict["password"] = decoded_ui.split(':')
            else:
                node_dict["uuid" if scheme == "vless" else "password"] = user_info
                q = parse_qs(parsed.query)
                node_dict.update({
                    "tls": q.get('security', [''])[0] in ['tls', 'xtls'],
                    "network": q.get('type', ['tcp'])[0],
                    "udp": True
                })
                if q.get('sni'): node_dict['sni'] = q['sni'][0]
                if node_dict['network'] == 'ws':
                    node_dict['ws-opts'] = {'path': q.get('path', ['/'])[0], 'headers': {'Host': q.get('host', [''])[0]}}
            return node_dict
    except: return None

# 4. 节点提取器 (解决 YAML/文本 混合问题)
def extract_links(text):
    # 正则匹配所有主流协议链接
    pattern = r'(vmess|vless|trojan|ss)://[a-zA-Z0-9%?&=._/@#:+*-]+'
    return re.findall(pattern, text)

def process_node(node):
    info = parse_node(node)
    if not info: return None
    info['region'] = get_region_name(node)
    info['raw_link'] = node.split("#")[0]
    info['fp'] = f"{info['type']}:{info['server']}:{info['port']}"
    return info

# 5. 主程序
def main():
    target_urls = get_all_subs()
    all_raw_links = []
    
    print(f"正在抓取 {len(target_urls)} 个源...")
    for url in target_urls:
        try:
            res = requests.get(url, timeout=10).text
            # 策略：先尝试 Base64 解码，解不开就当普通文本，然后用正则提取所有链接
            try:
                content = base64.b64decode(res).decode('utf-8')
                all_raw_links.extend(extract_links(content))
            except:
                all_raw_links.extend(extract_links(res))
        except: continue

    unique_links = list(dict.fromkeys(all_raw_links))
    print(f"🔍 提取到链接: {len(unique_links)} 条，正在转换格式...")

    with ThreadPoolExecutor(max_workers=50) as executor:
        results = [r for r in executor.map(process_node, unique_links) if r]

    unique_results = []
    seen_fp = set()
    for r in results:
        if r['fp'] not in seen_fp:
            seen_fp.add(r['fp'])
            unique_results.append(r)

    unique_results.sort(key=lambda x: x['region'])
    
    clash_proxies = []
    plain_nodes = []
    
    for i, item in enumerate(unique_results):
        name = f"{item['region']} {i+1:03d} @schpd_chat"
        raw_link = item.pop('raw_link', '')
        item.pop('fp', None); item.pop('region', None)
        item['name'] = name
        clash_proxies.append(item)
        plain_nodes.append(f"{raw_link}#{name}")

    # 生成配置
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

    with open("my_sub.txt", "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(plain_nodes).encode()).decode())

    print(f"✨ 处理完成！获取节点: {len(unique_results)} 个")

if __name__ == "__main__":
    main()
