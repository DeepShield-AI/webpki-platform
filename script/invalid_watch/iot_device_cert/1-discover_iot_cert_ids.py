
iot_seed_keywords = [
    # 网络设备厂商
    "Vigor Router", "DrayTek", "Teltonika", "MikroTik", "Ubiquiti", "UBNT", "EdgeRouter",
    "TP-Link", "D-Link", "Netgear", "Linksys", "Cisco", "Juniper", "Zyxel",
    "Fortinet", "FortiGate", "Huawei", "H3C", "Ruijie", "Aruba", "Cambium",
    "Allied Telesis", "UniFi", "Huawei Home Gateway", "Router", "CPE",

    # 工控与设备
    "Siemens", "S7 PLC", "Rockwell", "Allen-Bradley", "Schneider", "Schneider Electric",
    "Moxa", "Advantech", "Lantronix", "ProSoft", "Phoenix Contact", "InHand",
    "Weidmüller", "Red Lion", "Honeywell", "Bosch", "ABB", "Industrial",
    "Endress",   # Endress+Hauser

    # 网络操作系统 & 防火墙
    "Kubernetes", "Opnsense", "pfSense", "OpenWrt", "VyOS", "DD-WRT",
    "Traefik", "Sophos", "SonicWALL",

    # 消费电子 / 智能家居
    "Netflix Internal", "Chromecast", "Apple TV", "Roku", "Sonos",
    "Philips Hue", "Ring Doorbell", "SmartThings", "Home Assistant",
    "HomeAssistant", "Arduino", "Raspberry Pi", "BeagleBone",

    # IoT / 模组 & 开发板
    "ESP8266", "ESP32", "Espressif", "Tuya", "SmartHome", "IoT", "Thing",
    "Gizwits", "BroadLink", "Shelly", "Yeelight", "Sonoff",

    # 安防监控设备
    "Hikvision", "Dahua", "XM", "DVR", "NVR", "IPC", "Camera",
    "NetSurveillance", "AVTech", "GeoVision",

    # 家用网关 / 光猫
    "ZTE", "FiberHome", "Technicolor", "Arris", "Sagemcom", "Hitron", "Calix",

    # 通信模组
    "Quectel", "Sierra Wireless", "Telit", "NB-IoT", "eMTC", "LoRa", "Module", "Gateway",

    # 其他新增
    "NetElastic", "VMware", "Crestron", "Plesk", "3CX", "Azure VPN"
]

import re
import json
from backend.analyzer.utils import stream_by_id
from backend.celery.celery_db_pool import engine_cert

def is_device_cert(subject: dict, keywords=iot_seed_keywords):
    fields = " ".join(str(subject.get(k, "")).lower() for k in subject)

    # 关键词匹配
    for kw in keywords:
        if kw.lower() in fields:
            return True

    # 规则匹配
    if any(word in fields for word in ["vpn", "fw", "apiserver", "controller", "management"]):
        return True
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", str(subject.get("common_name", ""))):  # CN 是 IP
        return True

    return False

out = open("13-id_seed.txt", "w")
new_conn = engine_cert.raw_connection()
for row in stream_by_id(engine_cert.raw_connection(), "cert_search"):
    id = row[0]
    subject = json.loads(row[4])
    if not isinstance(subject, dict) : continue
    type = row[-1]
    if int(type) != 0: continue

    with new_conn.cursor() as cursor:
        query = """
            SELECT * from cert_trust
            WHERE id = %s
        """
        cursor.execute(query, (id,))
        row = cursor.fetchone()

    if row:
        trust = row[-1]
        if int(trust) != 0:
            if is_device_cert(subject):
                out.write(str(id))
                out.write('\n')
