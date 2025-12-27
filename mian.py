import requests
import base64
import re
import socket
import json
from concurrent.futures import ThreadPoolExecutor

# 1. 海量订阅源
urls = [
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/vpei/free/master/v2ray",
    "https://raw.githubusercontent.com/tiamm/free-v2ray-nodes/master/v2ray.txt",
    "https://raw.githubusercontent.com/Pawpieee/Free-Vpn-Everyday/main/V2Ray",
    "https://raw.githubusercontent.com/aiboboxx/v2rayfree/main/v2ray",
    "https://raw.githubusercontent.com/ovsc/v2ray-free/main/v2ray.txt",
    "https://raw.githubusercontent.com/freefq/free/master/v2ray"
]

# 2. 全球国家特征库
features = {
    'hk|hkg|hongkong|香港': '香港',
    'tw|taiwan|tpe|台湾': '台湾',
    'jp|japan|tokyo|nrt|日本': '日本',
    'sg|singapore|sin|新加坡': '新加坡',
    'us|america|unitedstates|usa|lax|美国': '美国',
    'kr|korea|icn|seoul|韩国': '韩国',
    'de|germany|fra|德国': '德国',
    'uk|gb|london|lhr|英国': '英国',
    'fr|france|par|paris|法国': '法国',
    'nl|netherlands|ams|荷兰': '荷兰',
    'ru|russia|moscow|俄罗斯': '俄罗斯',
    'tr|turkey|ist|土耳其': '土耳其',
    'ca|canada|yvr|加拿大': '加拿大',
    'in|india|bom|印度': '印度',
    'th|thailand|bkk|泰国': '泰国',
    'vn|vietnam|sgn|越南': '越南',
    'my|malaysia|kul|马来西亚': '马来西亚',
    'au|australia|syd|澳大利亚': '澳大利亚'
}

def get_country(addr, old_name=""):
    """通过 IP 接口和特征库确认国家"""
    # A. 优先调用免 API 接口 (中文)
    try:
        res = requests.get(f"http://ip-api.com/json/{addr}?fields=country&lang=zh-CN", timeout=1.2).json()
        if res.get("country"):
            return res.get("country")
    except: pass

    # B. 特征库模糊匹配
    search_str = f"{old_name} {addr}".lower()
    for pattern, name in features.items():
        if re.search(pattern, search_str):
            return name
            
    # C. 反向 DNS 识别
    try:
        hostname = socket.gethostbyaddr(addr)[0].lower()
        for pattern, name in features.items():
            if re.search(pattern, hostname):
                return name
    except: pass
    
    return "优质"

def check_node(node):
    if not node.startswith("vmess://"): return None
    try:
        link_body = node.split("://")[1].split("#")[0]
        link_body += '=' * (-len(link_body) % 4)
        info = json.loads(base64.b64decode(link_body).decode('utf-8'))
        addr, port = info.get("add"), int(info.get("port"))
        
        # TCP 端口探测
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            if s.connect_ex((addr, port)) == 0:
                country = get_country(addr, node.split("#")[1] if "#" in node else "")
                return {"node": node, "country": country}
    except: pass
    return None

def main():
    raw_list = []
    print("正在拉取源数据...")
    for url in urls:
        try:
            res = requests.get(url, timeout=10).text
            try:
                raw_list.extend(base64.b64decode(res).decode('utf-8').splitlines())
            except:
                raw_list.extend(res.splitlines())
        except: continue

    raw_list = list(set(raw_list))
    print(f"开始分析 {len(raw_list)} 个节点...")

    alive_results = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        results = list(executor.map(check_node, raw_list))
        alive_results = [r for r in results if r is not None]
    
    alive_results.sort(key=lambda x: x['country'])

    processed_nodes = []
    for index, item in enumerate(alive_results):
        base_part = item["node"].split("#")[0]
        # 格式：[国家] 序号 @schpd_chat
        new_name = f"{item['country']} {index+1:03d} @schpd_chat"
        processed_nodes.append(f"{base_part}#{new_name}")

    if processed_nodes:
        # 准备两个版本的内容
        plain_content = "\n".join(processed_nodes)
        b64_content = base64.b64encode(plain_content.encode('utf-8')).decode('utf-8')
        
        # 保存明文文件
        with open("nodes_plain.txt", "w", encoding="utf-8") as f:
            f.write(plain_content)
        # 保存 Base64 文件 (适配 FlClash)
        with open("nodes_b64.txt", "w", encoding="utf-8") as f:
            f.write(b64_content)
            
        print(f"更新成功！有效节点: {len(processed_nodes)}")

if __name__ == "__main__":
    main()
