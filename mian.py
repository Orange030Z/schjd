import requests
import base64
import re
import socket
import json
from concurrent.futures import ThreadPoolExecutor

# 订阅源列表
urls = [
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt"
]

def get_region_free(addr):
    """
    免 API 识别地区逻辑：
    1. 尝试通过域名关键字识别
    2. 尝试反向 DNS 解析识别
    3. 兜底使用一个极简公共接口
    """
    # 常见机场/服务器节点特征库
    features = {
        'hk|hkg|hongkong': '香港',
        'tw|taiwan|tpe': '台湾',
        'jp|japan|tokyo|nrt|hnd': '日本',
        'sg|singapore|sin': '新加坡',
        'us|america|unitedstates|lax|sfo|iad': '美国',
        'kr|korea|icn|seoul': '韩国',
        'de|germany|fra': '德国',
        'uk|london|gb': '英国'
    }

    # 1. 直接检查地址字符串（如果是域名）
    addr_lower = addr.lower()
    for pattern, name in features.items():
        if re.search(pattern, addr_lower):
            return name

    # 2. 尝试反向 DNS 解析（不需要网络请求 API）
    try:
        hostname = socket.gethostbyaddr(addr)[0].lower()
        for pattern, name in features.items():
            if re.search(pattern, hostname):
                return name
    except:
        pass

    # 3. 兜底：使用一个不需要注册、几乎无限制的公共查询接口 (ip-api.com 极速版)
    try:
        # 这个接口在低频调用下完全免费，且不需要任何 API Key
        res = requests.get(f"http://ip-api.com/json/{addr}?fields=country&lang=zh-CN", timeout=2).json()
        return res.get("country", "优质")
    except:
        return "优质"

def check_node(node):
    if not node.startswith("vmess://"):
        return None
    try:
        link_body = node.split("://")[1].split("#")[0]
        link_body += '=' * (-len(link_body) % 4)
        info = json.loads(base64.b64decode(link_body).decode('utf-8'))
        
        addr, port = info.get("add"), int(info.get("port"))
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            if s.connect_ex((addr, port)) == 0:
                # 测活成功后识别地区
                region = get_region_free(addr)
                return {"node": node, "region": region}
    except:
        pass
    return None

def clean_and_rename():
    raw_list = []
    print("正在获取原始节点...")
    for url in urls:
        try:
            res = requests.get(url, timeout=10).text
            try:
                raw_list.extend(base64.b64decode(res).decode('utf-8').splitlines())
            except:
                raw_list.extend(res.splitlines())
        except: continue

    raw_list = list(set(raw_list))
    print(f"正在分析 {len(raw_list)} 个节点...")

    alive_results = []
    with ThreadPoolExecutor(max_workers=30) as executor:
        results = list(executor.map(check_node, raw_list))
        alive_results = [r for r in results if r is not None]
    
    processed_nodes = []
    for index, item in enumerate(alive_results):
        base_part = item["node"].split("#")[0]
        region = item["region"]
        new_name = f"{region} 优选 {index+1:02d} @schpd"
        processed_nodes.append(f"{base_part}#{new_name}")

    if processed_nodes:
        # --- 这里依然采用明文输出，解决你的报错问题见下文 ---
        final_text = "\n".join(processed_nodes)
        with open("my_sub.txt", "w", encoding="utf-8") as f:
            f.write(final_text)
        print("my_sub.txt 更新成功！")

if __name__ == "__main__":
    clean_and_rename()
