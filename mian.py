import requests
import base64
import re
import socket
from concurrent.futures import ThreadPoolExecutor

# 1. 订阅源列表 (你可以继续添加)
urls = [
    
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt"
]

def check_port(node):
    """TCP 端口测活：过滤掉无法连接的死节点"""
    try:
        # 提取 vmess:// 后的内容
        link_body = node.split("://")[1].split("#")[0]
        # 自动补齐 base64 填充
        link_body += '=' * (-len(link_body) % 4)
        
        import json
        info = json.loads(base64.b64decode(link_body).decode('utf-8'))
        
        # 获取地址和端口
        addr = info.get("add")
        port = int(info.get("port"))
        
        # 尝试连接端口，超时设为 2 秒
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
                # 尝试 Base64 解码整个订阅
                decoded = base64.b64decode(res).decode('utf-8')
                raw_list.extend(decoded.splitlines())
            except:
                raw_list.extend(res.splitlines())
        except:
            continue

    # 去重处理
    raw_list = list(set(raw_list))

    # 1. 多线程测活 (开启 30 个线程提升速度)
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
            
        # 提取 Emoji 和 地区
        emojis = "".join(re.findall(r'[\U00010000-\U0010ffff]', old_name))
        region_match = re.search(r'(香港|美国|日本|新加坡|英国|德国|韩国|台湾|加拿大)', old_name)
        region = region_match.group(1) if region_match else "优质"
        
        # 重新编号并添加后缀
        new_name = f"{emojis} {region} {index+1:02d} @schpd"
        processed_nodes.append(f"{base_part}#{new_name}")

    # 3. 保存到你指定的 my_sub.txt
    if processed_nodes:
        final_text = "\n".join(processed_nodes)
        final_b64 = base64.b64encode(final_text.encode('utf-8')).decode('utf-8')
        with open("my_sub.txt", "w", encoding="utf-8") as f:
            f.write(final_b64)
        print("my_sub.txt 更新成功！")

if __name__ == "__main__":
    clean_and_rename()
