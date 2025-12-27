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
       # 终极扩充版特征库：覆盖全球主流及小众国家、核心城市、机场代码
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
        'kh|cambodia|phnompenh|柬埔寨|金边': '柬埔寨',
        'pk|pakistan|khi|巴基斯坦': '巴基斯坦',
        'kz|kazakhstan|ala|哈萨克斯坦': '哈萨克斯坦',
        
        # --- 北美 & 南美 ---
        'us|america|unitedstates|usa|lax|sfo|iad|ord|sea|美国|洛杉矶|圣何塞|西雅图|纽约|芝加哥': '美国',
        'ca|canada|yvr|yyz|mtl|加拿大|温哥华|多伦多|蒙特利尔': '加拿大',
        'br|brazil|sao|brazil|巴西|圣保罗': '巴西',
        'mx|mexico|mex|墨西哥': '墨西哥',
        'ar|argentina|bue|阿根廷': '阿根廷',
        'cl|chile|scl|智利': '智利',
        'co|colombia|bog|哥伦比亚': '哥伦比亚',
        
        # --- 欧洲 ---
        'de|germany|fra|frankfurt|德国|法兰克福': '德国',
        'uk|gb|london|lon|lhr|英国|伦敦': '英国',
        'fr|france|par|paris|法国|巴黎': '法国',
        'nl|netherlands|ams|amsterdam|荷兰|阿姆斯特丹': '荷兰',
        'ru|russia|moscow|mow|svo|俄罗斯|莫斯科|新西伯利亚': '俄罗斯',
        'tr|turkey|ist|istanbul|土耳其|伊斯坦布尔': '土耳其',
        'it|italy|mil|milano|意大利|米兰': '意大利',
        'es|spain|mad|madrid|西班牙|马德里': '西班牙',
        'ch|switzerland|zrh|zurich|瑞士|苏黎世': '瑞士',
        'se|sweden|sto|stockholm|瑞典|斯德哥尔摩': '瑞典',
        'at|austria|vie|vienna|奥地利|维也纳': '奥地利',
        'pl|poland|waw|warsaw|波兰|华沙': '波兰',
        'no|norway|osl|oslo|挪威|奥斯陆': '挪威',
        'fi|finland|hel|helsinki|芬兰|赫尔辛基': '芬兰',
        'ie|ireland|dub|dublin|爱尔兰|都柏林': '爱尔兰',
        'ua|ukraine|kiev|iev|乌克兰|基辅': '乌克兰',
        'gr|greece|ath|athens|希腊|雅典': '希腊',
        'pt|portugal|lis|lisbon|葡萄牙|里斯本': '葡萄牙',
        
        # --- 非洲 ---
        'za|southafrica|jnb|johannesburg|南非': '南非',
        'eg|egypt|cai|cairo|埃及|开罗': '埃及',
        'ng|nigeria|los|尼日利亚': '尼日利亚',
        'ma|morocco|cas|摩洛哥': '摩洛哥'
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
        new_name = f"{region} | {index+1:02d} @schpd"
        processed_nodes.append(f"{base_part}#{new_name}")

    if processed_nodes:
        # --- 这里依然采用明文输出，解决你的报错问题见下文 ---
        final_text = "\n".join(processed_nodes)
        with open("my_sub.txt", "w", encoding="utf-8") as f:
            f.write(final_text)
        print("my_sub.txt 更新成功！")

if __name__ == "__main__":
    clean_and_rename()
