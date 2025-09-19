
import csv
import json
import tldextract

from backend.scanner.celery_scan_task import _do_ssl_handshake
from backend.utils.network import resolve_host_dns
from backend.config.scan_config import InputScanConfig
from backend.utils.cert import get_sha256_hex_from_bytes

out = open("12-mitm.txt", "w")

with open("12-forged_details.csv", newline="", encoding="utf-8") as f:
    reader = csv.reader(f)
    for row in reader:
        try:
            record_id, leaf_sha256, subject_json, issuer_json, extra = row

            # 解析 JSON（注意 CSV 中的转义双引号）
            subject = json.loads(subject_json.replace('""', '"'))
            issuer = json.loads(issuer_json.replace('""', '"'))

            # 提取 Subject CN
            if "common_name" in subject:
                cn = subject["common_name"].lstrip("*.")  # 去掉泛域名前缀
                ext = tldextract.extract(cn)
                domain = ".".join(part for part in [ext.subdomain, ext.domain, ext.suffix] if part)

                # 解析 DNS 记录
                ipv4_list, ipv6_list = resolve_host_dns(
                    domain,
                    dns_servers=[
                        "8.8.8.8",
                        "1.1.1.1",
                        "114.114.114.114",
                        "223.5.5.5",
                    ],
                )

                # 尝试对解析到的 IPv4 地址进行 TLS 握手
                for ip in ipv4_list:
                    ssl_result = _do_ssl_handshake(domain, ip, InputScanConfig())
                    if ssl_result.get("peer_certs"):
                        # 计算握手证书的 SHA256
                        leaf_der_sha256 = get_sha256_hex_from_bytes(
                            ssl_result["peer_certs"][0]
                        )

                        # 与伪造证书对比
                        if leaf_der_sha256 == leaf_sha256:
                            print("[!] Potential MITM detected")
                            print(f"Domain: {domain}, IP: {ip}, Cert SHA256: {leaf_der_sha256}")
                            out.write(f"{domain}, {ip}, {leaf_der_sha256}")
                            out.write('\n')

        except Exception as e:
            print(f"[-] Error processing row {row}: {e}")
