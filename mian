import requests
import base64
import re

# 1. 你搜集的原始订阅列表（可以继续添加更多源）
urls = [
    "https://raw.githubusercontent.com/Pawpiee/Free-Node/main/sub/v2ray.txt",
    "https://raw.githubusercontent.com/vfarid/v2ray-share/main/all_v2ray.txt",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt"
]

def clean_and_rename():
    all_nodes = []
    for url in urls:
        try:
            res = requests.get(url, timeout=10).text
            # 尝试 Base64 解码，如果失败则按原样处理
            try:
                decoded = base64.b64decode(res).decode('utf-8')
                all_nodes.extend(decoded.splitlines())
            except:
                all_nodes.extend(res.splitlines())
        except:
            print(f"无法获取源: {url}")
            continue

    processed_nodes = []
    for index, node in enumerate(all_nodes):
        if "#" in node:
            # 分割链接和原始名称
            base_part, old_name = node.split("#", 1)
            
            # --- 核心修改部分 ---
            # 1. 提取国旗 Emoji (如果有)
            emojis = "".join(re.findall(r'[\U00010000-\U0010ffff]', old_name))
            
            # 2. 提取地区关键字（匹配常见地区名）
            region_match = re.search(r'(香港|美国|日本|新加坡|英国|德国|韩国|台湾|加拿大)', old_name)
            region = region_match.group(1) if region_match else "节点"
            
            # 3. 拼接成你的专属格式：[Emoji] 地区 [编号] @schpd
            # 例如：🇭🇰 香港 01 @schpd
            new_name = f"{emojis} {region} {index:02d} @schpd"
            
            processed_nodes.append(f"{base_part}#{new_name}")
            
    # 重新编码成 Base64 格式
    if processed_nodes:
        final_content = base64.b64encode("\n".join(processed_nodes).encode('utf-8')).decode('utf-8')
        with open("my_sub.txt", "w", encoding="utf-8") as f:
            f.write(final_content)
        print("订阅更新成功！")

if __name__ == "__main__":
    clean_and_rename()
