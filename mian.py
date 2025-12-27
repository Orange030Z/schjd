import requests
import base64
import re
import socket
import json
from concurrent.futures import ThreadPoolExecutor

# 1. 订阅源列表
urls = [
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt"
]

def check_port(node):
    """TCP 端口测活：过滤掉无法连接的死节点"""
    if not node.startswith("vmess://"):
        return None
    try:
        link_body = node.split("://")[1].split("#")[0]
        link_body += '=' * (-len(link_body) % 4)
        info = json.loads(base64.b64decode(link_body).decode('utf-8'))
        
        addr = info.get("add")
        port = int(info.get("port"))
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            if s.connect_ex((addr, port)) == 0:
                return node
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
                decoded = base64.b64decode(res).decode('utf-8')
                raw_list.extend(decoded.splitlines())
            except:
                raw_list.extend(res.splitlines())
        except:
            continue

    raw_list = list(set(raw_list))

    print(f"共获取到 {len(raw_list)} 个节点，开始测活...")
    alive_nodes = []
    with ThreadPoolExecutor(max_workers=30) as executor:
        results = list(executor.map(check_port, raw_list))
        alive_nodes = [r for r in results if r is not None]
    
    print(f"测活完成，有效节点: {len(alive_nodes)}")

    # 2. 重命名并整理
    processed_nodes = []
    for index, node in enumerate(alive_nodes):
        base_part = node.split("#")[0] if "#" in node else node
        old_name = node.split("#")[1] if "#" in node else ""
            
        # 提取 Emoji
        emojis = "".join(re.findall(r'[\U00010000-\U0010ffff]', old_name))
        # 提取地区关键词
        region_match = re.search(r'(香港|美国|日本|新加坡|英国|德国|韩国|台湾|加拿大|土耳其|俄罗斯|法国)', old_name)
        region = region_match.group(1) if region_match else "优质"
        
        # 组合：地区 + 优选 + 编号
        new_name = f"{emojis} {region} 优选 {index+1:02d} @schpd".strip()
        processed_nodes.append(f"{base_part}#{new_name}")

    # 3. 保存为明文 (取消 Base64)
    if processed_nodes:
        final_text = "\n".join(processed_nodes)
        with open("my_sub.txt", "w", encoding="utf-8") as f:
            f.write(final_text)
        print("my_sub.txt (地区保留+优选命名) 更新成功！")

if __name__ == "__main__":
    clean_and_rename()
