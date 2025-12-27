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
    """TCP 端口测活"""
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
                return node
    except: pass
    return None

def clean_and_rename():
    raw_list = []
    print("正在获取原始节点...")
    for url in urls:
        try:
            res = requests.get(url, timeout=10).text
            try:
                # 尝试解码订阅源
                decoded = base64.b64decode(res).decode('utf-8')
                raw_list.extend(decoded.splitlines())
            except:
                raw_list.extend(res.splitlines())
        except: continue

    raw_list = list(set(raw_list))
    print(f"共获取到 {len(raw_list)} 个节点，开始测活...")
    
    with ThreadPoolExecutor(max_workers=30) as executor:
        results = list(executor.map(check_port, raw_list))
        alive_nodes = [r for r in results if r is not None]
    
    print(f"测活完成，有效节点: {len(alive_nodes)}")

    processed_nodes = []
    for index, node in enumerate(alive_nodes):
        base_part = node.split("#")[0] if "#" in node else node
        old_name = node.split("#")[1] if "#" in node else ""
            
        # 提取 Emoji
        emojis = "".join(re.findall(r'[\U00010000-\U0010ffff]', old_name))
        
        # --- 增强版地区匹配 ---
        # 增加了常见地区名及其缩写
        region_map = {
            '香港|HK|Hong Kong|HongKong': '香港',
            '美国|US|United States|USA': '美国',
            '日本|JP|Japan|Tokyo': '日本',
            '新加坡|SG|Singapore': '新加坡',
            '台湾|TW|Taiwan': '台湾',
            '韩国|KR|Korea|Seoul': '韩国',
            '德国|DE|Germany': '德国',
            '英国|UK|United Kingdom|London': '英国'
        }
        
        region = "优质"
        for pattern, name in region_map.items():
            if re.search(pattern, old_name, re.IGNORECASE):
                region = name
                break
        
        # 组合新名称
        new_name = f"{emojis} {region} 优选 {index+1:02d} @schpd".strip()
        processed_nodes.append(f"{base_part}#{new_name}")

    # 3. 保存文件
    if processed_nodes:
        final_text = "\n".join(processed_nodes)
        # --- 关键修改：重新进行 Base64 编码以适配 FlClash ---
        final_b64 = base64.b64encode(final_text.encode('utf-8')).decode('utf-8')
        with open("my_sub.txt", "w", encoding="utf-8") as f:
            f.write(final_b64)
        print("my_sub.txt 更新成功！已自动转换为 Base64 编码以适配导入。")

if __name__ == "__main__":
    clean_and_rename()