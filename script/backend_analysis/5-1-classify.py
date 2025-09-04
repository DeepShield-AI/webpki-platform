
import json
import ipaddress
import re

# 文件路径
input_file = "5-ca_out.json"

# 加载 JSON
with open(input_file, "r", encoding="utf-8") as f:
    ca_dict = json.load(f)

# 结果分类
pretend_legit = {}   # 1. 冒充合法 CA
private_ca = {}      # 2. 私有 CA
self_signed = {}     # 3. 自签名（域名或 IP）
iot_related = {}     # 4. IoT 相关

# IoT 关键字列表
iot_keywords = [
    # 网络设备厂商
    "Vigor Router", "DrayTek", "Teltonika", "MikroTik", "Ubiquiti", "UBNT", "EdgeRouter",
    "TP-Link", "D-Link", "Netgear", "Linksys", "Cisco", "Juniper", "Zyxel", "Fortinet", "FortiGate",
    "Huawei", "H3C", "Ruijie", "Aruba", "Cambium", "Allied Telesis",

    # 工业物联网/网关
    "Siemens", "S7 PLC", "Rockwell", "Allen-Bradley", "Schneider Electric", "Moxa", "Advantech",
    "Lantronix", "ProSoft", "Phoenix Contact", "InHand", "Weidmüller", "Red Lion",

    # 云与内网基础设施
    "Kubernetes Ingress Controller Fake Certificate", "K8s Ingress", "Opnsense", "pfSense",
    "OpenWrt", "VyOS", "DD-WRT",

    # 媒体与家用设备
    "Netflix Internal", "Chromecast", "Apple TV", "Roku", "Sonos", "Philips Hue", "Ring Doorbell",

    # 电信与ISP设备
    "ZTE", "FiberHome", "Technicolor", "Arris", "Sagemcom", "Hitron", "Calix",

    # 其他 IoT 设备
    "SmartThings", "Home Assistant", "ESP8266", "ESP32", "Arduino", "Raspberry Pi", "BeagleBone"
]

# 域名匹配（简单正则）
domain_pattern = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")

for key, value in ca_dict.items():
    key_lower = key.lower()

    # 1. 冒充合法 CA（示例逻辑：包含 DV TLS / Secure Server / Let's Encrypt / DigiCert 等）
    if any(ca_name in key for ca_name in [
        "DV TLS CA", "Secure Server", "Let's Encrypt", "DigiCert", "GlobalSign", "Sectigo", "Go Daddy", "Entrust"
    ]):
        pretend_legit[key] = value

    # 2. 私有 CA（示例逻辑：名字中包含 "CA" 但不是知名 CA）
    if "ca" in key_lower and key not in pretend_legit:
        private_ca[key] = value

    # 3. 自签名：名字是域名或 IP
    try:
        # 判断是否是 IP
        ipaddress.ip_address(key)
        self_signed[key] = value
    except ValueError:
        # 如果是域名
        if domain_pattern.match(key):
            self_signed[key] = value

    # 4. IoT
    if any(k.lower() in key_lower for k in [kw.lower() for kw in iot_keywords]):
        iot_related[key] = value

def print_sorted(title, data_dict):
    print(f"\n=== {title} ===")
    for k, v in sorted(data_dict.items(), key=lambda x: x[1], reverse=True):
        print(f"{k}: {v}")

print_sorted("Pretend Legitimate CAs", pretend_legit)
print_sorted("Private CAs", private_ca)
print_sorted("Self-signed Certificates", self_signed)
print_sorted("IoT Related Certificates", iot_related)

# 计算总和
total_all = sum(ca_dict.values())
total_pretend_legit = sum(pretend_legit.values())
total_private_ca = sum(private_ca.values())
total_self_signed = sum(self_signed.values())
total_iot = sum(iot_related.values())

# 打印结果
print(f"=== Total Sum (All) === {total_all}")
print(f"=== Total Sum (Pretend Legitimate CAs) === {total_pretend_legit}")
print(f"=== Total Sum (Private CAs) === {total_private_ca}")
print(f"=== Total Sum (Self-signed Certificates) === {total_self_signed}")
print(f"=== Total Sum (IoT Related Certificates) === {total_iot}")
