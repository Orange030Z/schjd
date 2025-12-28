import requests
import base64
import re
import socket
import json
import yaml
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, parse_qs, unquote

# 1. 动态获取 cmliu 订阅源列表
def get_all_subs():
    urls = ["https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray"]
    try:
        # 爬取 cmliu 仓库中的订阅列表
        res = requests.get("https://raw.githubusercontent.com/cmliu/cmliu/main/SubsCheck-URLs", timeout=10).text
        urls.extend([l.strip() for l in res.splitlines() if l.startswith("http")])
    except: pass
    return list(set(urls))

# 2. 增强版全球特征库（带优先级顺序的列表）
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
    # 1. 解码处理
    decoded_str = unquote(node_str).lower()
    # 2. 清洗干扰词
    clean_str = re.sub(r'(cn2|gia|iplc|bgp|移动|联通|电信|直连|中转|专线)', '', decoded_str)
    
    # 3. 匹配特征库
    for pattern, name in features:
        if re.search(pattern, clean_str):
            return name
            
    # 4. 备选逻辑：根据域名后缀识别
    server_match = re.search(r'([a-z]{2})\d*\.', clean_str)
    if server_match:
        code_map = {'hk': '香港', 'jp': '日本', 'sg': '新加坡', 'us': '美国', 'tw': '台湾', 'kr': '韩国'}
        short_code = server_match.group(1)
        if short_code in code_map:
            return code_map[short_code]
            
    return "优质"

# 3. 核心解析逻辑 (支持多协议)
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

# 4. 严苛测活逻辑 (0.5s 超时 + 过滤内网)
def check_node(node):
    info = parse_node(node)
    if not info: return None
    try:
        # 排除内网 IP
        if re.match(r'^(127\.|10\.|192\.168\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.)', info['server']): return None
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5) # 极低超时门槛
            start_time = time.time()
            if s.connect_ex((info['server'], info['port'])) == 0:
                if (time.time() - start_time) > 0.5: return None
                info['region'] = get_region_name(node)
                info['raw_link'] = node.split("#")[0]
                # 指纹去重：协议+地址+端口
                info['fp'] = f"{info['type']}:{info['server']}:{info['port']}"
                return info
    except: pass
    return None

def main():
    target_urls = get_all_subs()
    raw_nodes = []
    
    print(f"开始抓取 {len(target_urls)} 个源...")
    for url in target_urls:
        try:
            res = requests.get(url, timeout=5).text
            try: 
                content = base64.b64decode(res).decode('utf-8')
                raw_nodes.extend(content.splitlines())
            except: 
                raw_nodes.extend(res.splitlines())
        except: continue

    raw_nodes = list(set(raw_nodes))
    print(f"🔍 原始节点: {len(raw_nodes)}，开始极速测活...")

    with ThreadPoolExecutor(max_workers=100) as executor:
        results = [r for r in executor.map(check_node, raw_nodes) if r]

    # 去重处理
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

    # 5. 生成 Clash 原生配置文件
    config = {
        "port": 7890, "socks-port": 7891, "allow-lan": True, "mode": "rule",
        "proxies": clash_proxies,
        "proxy-groups": [
            {"name": "🚀 自动选择", "type": "url-test", "url": "http://www.gstatic.com/generate_204", "interval": 300, "proxies": [p["name"] for p in clash_proxies]},
            {"name": "🌍 代理工具", "type": "select", "proxies": ["🚀 自动选择"] + [p["name"] for p in clash_proxies]}
        ],
        "rules": [
            "DOMAIN-SUFFIX,google.com,🌍 代理工具",
            "GEOIP,CN,DIRECT",
            "MATCH,🌍 代理工具"
        ]
    }

    with open("config.yaml", "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False)

    with open("my_sub.txt", "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(plain_nodes).encode()).decode())

    print(f"✨ 处理完成！保留高质量节点: {len(unique_results)} 个")

if __name__ == "__main__":
    main()
