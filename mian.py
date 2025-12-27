import requests
import base64
import urllib.parse

# 1. 原始订阅源
urls = [
    "https://raw.githubusercontent.com/Pawpiee/Free-Node/main/sub/v2ray.txt",
    "https://raw.githubusercontent.com/vfarid/v2ray-share/main/all_v2ray.txt"
]

# 你的订阅转换器基础地址
SUB_CONVERTER_BASE = "https://dyzh.zhangyucheng0720.workers.dev/sub?"

def clean_and_rename():
    all_nodes = []
    # ... (这里保留你之前的抓取和重命名逻辑，生成 processed_nodes 列表) ...
    # 假设处理后的节点内容为 v2ray_raw_text
    
    # 将重命名后的内容先存为 v2ray_sub.txt (供转换器读取)
    v2ray_content = base64.b64encode(v2ray_raw_text.encode('utf-8')).decode('utf-8')
    with open("v2ray_sub.txt", "w", encoding="utf-8") as f:
        f.write(v2ray_content)

    # --- 自动转换逻辑 ---
    # 你的 Raw 文件地址 (请根据你的用户名修改)
    my_raw_url = "https://raw.githubusercontent.com/Orange030Z/schjd/main/v2ray_sub.txt"
    encoded_raw_url = urllib.parse.quote(my_raw_url)

    # 自动获取 Clash 格式
    clash_api = f"{SUB_CONVERTER_BASE}target=clash&url={encoded_raw_url}"
    try:
        clash_res = requests.get(clash_api, timeout=15).text
        with open("clash_config.yaml", "w", encoding="utf-8") as f:
            f.write(clash_res)
    except:
        print("Clash 转换失败")

if __name__ == "__main__":
    clean_and_rename()