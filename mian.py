import requests, base64, re, socket, json, yaml
from concurrent.futures import ThreadPoolExecutor

# 1. 订阅源（增加了一些稳定的源）
urls = [
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/vpei/free/master/v2ray",
    "https://raw.githubusercontent.com/tiamm/free-v2ray-nodes/master/v2ray.txt"
]

def get_country(addr):
    try:
        res = requests.get(f"http://ip-api.com/json/{addr}?fields=country&lang=zh-CN", timeout=1.5).json()
        return res.get("country", "未知")
    except: return "优质"

def check_node(node):
    if not node.startswith("vmess://"): return None
    try:
        link_body = node.split("://")[1].split("#")[0]
        link_body += '=' * (-len(link_body) % 4)
        info = json.loads(base64.b64decode(link_body).decode('utf-8'))
        addr, port = info.get("add"), int(info.get("port"))
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            if s.connect_ex((addr, port)) == 0:
                country = get_country(addr)
                # 返回符合 Clash 标准的字典
                return {
                    "name": f"{country}_{addr[-4:]}_{port}", # 城市+末尾4位IP+端口，确保绝对不重复
                    "type": "vmess",
                    "server": addr,
                    "port": port,
                    "uuid": info.get("id"),
                    "alterId": int(info.get("aid", 0)),
                    "cipher": "auto",
                    "udp": True,
                    "tls": True if info.get("tls") == "tls" else False,
                    "network": info.get("net", "tcp"),
                    "ws-opts": {"path": info.get("path"), "headers": {"Host": info.get("host")}} if info.get("net") == "ws" else None
                }
    except: pass
    return None

def main():
    raw_nodes = []
    for url in urls:
        try:
            res = requests.get(url, timeout=10).text
            try: raw_nodes.extend(base64.b64decode(res).decode('utf-8').splitlines())
            except: raw_nodes.extend(res.splitlines())
        except: continue

    raw_nodes = list(set(raw_nodes))
    with ThreadPoolExecutor(max_workers=100) as executor:
        proxies = [r for r in executor.map(check_node, raw_nodes) if r is not None]

    # 构造 Clash 标准 YAML 结构
    clash_config = {
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": "🚀 节点选择",
                "type": "select",
                "proxies": ["自动选择"] + [p["name"] for p in proxies]
            },
            {
                "name": "自动选择",
                "type": "url-test",
                "proxies": [p["name"] for p in proxies],
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300
            }
        ],
        "rules": ["MATCH,🚀 节点选择"]
    }

    # 1. 保存为 config.yaml (FlClash 专用)
    with open("config.yaml", "w", encoding="utf-8") as f:
        yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)

    # 2. 保存为 nodes_plain.txt (明文版)
    plain_list = [f"{n.split('#')[0]}#{p['name']}" for n, p in zip(raw_nodes, proxies)]
    with open("nodes_plain.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(plain_list))

if __name__ == "__main__":
    main()
