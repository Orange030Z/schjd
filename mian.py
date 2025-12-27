import requests
import base64
import re
import socket
import json
from concurrent.futures import ThreadPoolExecutor

# 订阅源列表（建议增加一些源以保证数量）
urls = [
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/vpei/free/master/v2ray",
    "https://raw.githubusercontent.com/tiamm/free-v2ray-nodes/master/v2ray.txt"
]

def get_region_free(addr):
    features = {
        # --- 亚洲 & 太平洋 ---
        'hk|hkg|hongkong|香港|pccw|hkt': '香港',
        'tw|taiwan|tpe|hinet|cht|台湾|台北': '台湾',
        'jp|japan|tokyo|nrt|hnd|kix|osaka|日本|东京|大阪|埼玉': '日本',
        'sg|singapore|sin|新加坡': '新加坡',
        'kr|korea|icn|seoul|sel|韩国|首尔|春川': '韩国',
        'th|thailand|bkk|bangkok|泰国|曼谷': '泰国',
        'vn|vietnam|hanoi|sgn|越南|河内|胡志明': '越南',
        'my|malaysia|kul|吉隆坡|马来西亚': '马来西亚',
        'ph|philippines|mnl|manila|菲律宾|马尼拉': '菲律宾',
        'id|indonesia|cgk|jakarta|印尼|雅加达': '印尼',
        'in|india|bom|del|mumbai|印度|孟买': '印度',
        'ae|uae|dubai|dxb|迪拜|阿联酋': '阿联酋',
        'au|australia|syd|mel|bne|澳大利亚|悉尼|墨尔本|布里斯班': '澳大利亚',
        'nz|newzealand|akl|新西兰|奥克兰': '新西兰',
        # --- 北美 & 南美 ---
        'us|america|unitedstates|usa|lax|sfo|iad|ord|sea|美国|洛杉矶|圣何塞|西雅图|纽约|芝加哥': '美国',
        'ca|canada|yvr|yyz|mtl|加拿大|温哥华|多伦多|蒙特利尔': '加拿大',
        'br|brazil|sao|brazil|巴西|圣保罗': '巴西',
        # --- 欧洲 ---
        'de|germany|fra|frankfurt|德国|法兰克福': '德国',
        'uk|gb|london|lon|lhr|英国|伦敦': '英国',
        'fr|france|par|paris|法国|巴黎': '法国',
        'nl|netherlands|ams|amsterdam|荷兰|阿姆斯特丹': '荷兰',
        'ru|russia|moscow|mow|svo|俄罗斯|莫斯科|新西伯利亚': '俄罗斯',
        'tr|turkey|ist|istanbul|土耳其|伊斯坦布尔': '土耳其'
    }

    addr_lower = addr.lower()
    for pattern, name in features.items():
        if re.search(pattern, addr_lower):
            return name

    try:
        hostname = socket.gethostbyaddr(addr)[0].lower()
        for pattern, name in features.items():
            if re.search(pattern, hostname):
                return name
    except:
        pass

    try:
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
                region = get_region_free(addr)
                return {"node": node, "region": region}
    except:
        pass
    return None

def clean_and_rename():
    raw_list = []
    print("正在拉取原始节点数据...")
    for url in urls:
        try:
            res = requests.get(url, timeout=10).text
            try:
                raw_list.extend(base64.b64decode(res).decode('utf-8').splitlines())
            except:
                raw_list.extend(res.splitlines())
        except: continue

    raw_list = list(set(raw_list))
    print(f"原始节点总数: {len(raw_list)}，开始多线程分析...")

    alive_results = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = list(executor.map(check_node, raw_list))
        alive_results = [r for r in results if r is not None]
    
    processed_nodes = []
    for index, item in enumerate(alive_results):
        base_part = item["node"].split("#")[0]
        region = item["region"]
        # 统一命名格式
        new_name = f"{region} {index+1:03d} @schpd_chat"
        processed_nodes.append(f"{base_part}#{new_name}")

    if processed_nodes:
        # 1. 准备明文内容
        final_plain_text = "\n".join(processed_nodes)
        
        # 2. 准备 Base64 内容
        final_b64_text = base64.b64encode(final_plain_text.encode('utf-8')).decode('utf-8')
        
        # 保存明文文件
        with open("nodes_plain.txt", "w", encoding="utf-8") as f:
            f.write(final_plain_text)
            
        # 保存 Base64 文件 (用于 FlClash 订阅)
        with open("nodes_b64.txt", "w", encoding="utf-8") as f:
            f.write(final_b64_text)
            
        print("-" * 30)
        print(f"分析完成！有效节点: {len(processed_nodes)}")
        print("1. 明文文件已保存: nodes_plain.txt")
        print("2. 订阅文件已保存: nodes_b64.txt (请用此文件的 Raw 链接导入客户端)")
        print("-" * 30)

if __name__ == "__main__":
    clean_and_rename()
