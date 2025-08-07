
import sys
import json
from collections import defaultdict
from backend.analyzer.utils import stream_by_id
from backend.celery.celery_db_pool import engine_cert
from backend.utils.cert import get_sha256_hex_from_str

common_ca = [
"Let's Encrypt Authority X3",
"R3",
"R10",
"R11",
"DigiCert SHA2 Secure Server CA",
"DigiCert TLS RSA SHA256 2020 CA1",
"DigiCert Global G2 TLS RSA SHA256 2020 CA1",
"DigiCert Secure Site CA G2",
"DigiCert Global G3 TLS ECC SHA384 2020 CA1",
"DigiCert G5 TLS RSA4096 SHA384 2021 CA1",
"DigiCert SHA2 High Assurance Server CA",
"DigiCert EV RSA CA G2",
"DigiCert Global CA G2",
"DigiCert Basic RSA CN CA G2",
"DigiCert CN RSA CA G1",

"Sectigo RSA Organization Validation Secure Server CA",
"Sectigo RSA Domain Validation Secure Server CA",
"Sectigo ECC Organization Validation Secure Server CA",
"Sectigo ECC Domain Validation Secure Server CA",
"Sectigo Public Server Authentication CA DV R36",
"Sectigo Public Server Authentication CA OV R36",
"Sectigo RSA Extended Validation Secure Server CA",
"Sectigo Qualified Website Authentication CA R35",

"COMODO RSA Organization Validation Secure Server CA",
"COMODO RSA Domain Validation Secure Server CA",
"COMODO RSA Extended Validation Secure Server CA",
"COMODO ECC Domain Validation Secure Server CA 2",
"COMODO High-Assurance Secure Server CA",

"USERTrust RSA Organization Validation Secure Server CA",
"USERTrust RSA Domain Validation Secure Server CA",
"USERTrust RSA Certification Authority",
"USERTrust ECC Certification Authority",

"GeoTrust RSA CA 2018",
"GeoTrust DV SSL CA",
"GeoTrust EV RSA CA G2",
"GeoTrust TLS RSA CA G1",
"GeoTrust TLS DV RSA Mixed SHA256 2020 CA-1",
"GeoTrust CN RSA CA G1",
"GeoTrust RSA CN CA G2",
"GeoTrust Global TLS RSA4096 SHA256 2022 CA1",
"GeoTrust DV SSL CA - G3",
"GeoTrust G2 TLS CN RSA4096 SHA256 2022 CA1",
"GeoTrust TLS ECC CA G1",
"GeoTrust SSL CA - G3",
"GeoTrust Global TLS RSA4096 SHA256 2022 CA1",

"GlobalSign GCC R6 AlphaSSL CA 2023",
"GlobalSign GCC R6 AlphaSSL CA 2025",
"GlobalSign GCC R3 DV TLS CA 2020",
"GlobalSign GCC R3 OV TLS CA 2024",
"GlobalSign RSA OV SSL CA 2018",
"GlobalSign Domain Validation CA - SHA256 - G2",
"GlobalSign Organization Validation CA - SHA256 - G2",
"GlobalSign Organization Validation CA - SHA256 - G3",
"GlobalSign Extended Validation CA - SHA256 - G3",
"GlobalSign Root CA",
"GlobalSign",

"Go Daddy Secure Certificate Authority - G2",
"Go Daddy Secure Certification Authority",
"Starfield Secure Certificate Authority - G2",

"TrustAsia DV SSL CA - G5",
"TrustAsia RSA DV TLS CA G2",
"TrustAsia RSA DV TLS CA G3",
"TrustAsia ECC DV TLS CA G2",
"TrustAsia ECC DV TLS CA G3",
"TrustAsia DV TLS ECC CA 2025",
"TrustAsia DV TLS RSA CA 2025",
"TrustAsia TLS ECC CA",
"TrustAsia TLS RSA CA",

"Amazon RSA 2048 M01",
"Amazon RSA 2048 M02",
"Amazon RSA 2048 M03",
"Amazon RSA 2048 M04",
"Amazon ECDSA 256 M02",
"Amazon ECDSA 256 M03",
"Amazon ECDSA 256 M04",
"Amazon ECDSA 384 M02",
"Amazon ECDSA 384 M03",
"Amazon ECDSA 384 M04",
"Amazon Internal Butternut RSA 2k G1 01",
"Amazon Internal Butternut RSA 2k G1 02",
"Amazon Internal Butternut RSA 2k G1 03",
"Amazon Internal Butternut RSA 2k G1 04",
"Amazon Internal Butternut ECC 384 G1 01",
"Amazon Internal Butternut ECC 384 G1 02",
"Amazon Internal Butternut ECC 384 G1 03",

"GTS CA 1D2",
"GTS CA 1D4",
"GTS CA 1P5",

"RapidSSL TLS RSA CA G1",
"RapidSSL Global TLS RSA4096 SHA256 2022 CA1",
"RapidSSL RSA CA 2018",
"RapidSSL SHA256 CA",
"RapidSSL SHA256 CA - G3",
"RapidSSL SHA256 CA - G4",
"RapidSSL CA",
"RapidSSL TLS ECC CA G1",

"Thawte TLS RSA CA G1",
"Thawte RSA CA 2018",
"Thawte EV RSA CA 2018",
"Thawte EV RSA CA G2",
"Thawte DV SSL CA",
"thawte DV SSL SHA256 CA",
"Thawte G5 TLS RSA4096 SHA384 2022 CA1",
"thawte SSL CA - G2",
"Thawte Server CA",

"Entrust Certification Authority - L1K",
"Entrust Certification Authority - L1M",
"Entrust Certification Authority - L1F",
"Entrust OV TLS Issuing RSA CA 1",
"Entrust OV TLS Issuing RSA CA 2",
"Entrust EV TLS Issuing RSA CA 1",
"Entrust OV TLS Issuing ECC CA 1",
"Entrust EV TLS Issuing ECC CA 1",
"InCommon RSA Server CA 2",
"InCommon ECC Server CA 2",

"ZeroSSL RSA Domain Secure Site CA",
"ZeroSSL ECC Domain Secure Site CA",

"cPanel, Inc. Certification Authority",
"cPanel ECC Domain Validation Secure Server CA 3",

"Gandi RSA Domain Validation Secure Server CA 3",
"Gandi Standard SSL CA 2",

"Actalis Domain Validation Server CA G3",
"Actalis Organization Validated Server CA G3",

"Certum Domain Validation CA SHA2",
"Certum Organization Validation CA SHA2",
"Certum Extended Validation CA SHA2",

"SwissSign RSA TLS OV ICA 2022 - 1",
"SwissSign RSA TLS DV ICA 2022 - 1",
"SwissSign RSA TLS DV ICA 2021 - 1",
"SwissSign Server Silver CA 2014 - G22",
"SwissSign RSA TLS EV ICA 2022 - 1",

"Buypass Class 3 CA 2",
"Buypass Class 2 CA 2",
"Buypass Class 2 CA 5",

"WoTrus DV Server CA  [Run by the Issuer]",
"WoTrus OV Server CA  [Run by the Issuer]",
"Xcc Trust DV SSL CA",
"Xcc Trust OV SSL CA",

"SSL.com RSA SSL subCA",
"SSL.com DV CA",

"Trustico RSA DV SSL CA",
"Trustico RSA DV SSL CA 2",

"TrustCor DV SSL CA - G2 - RSA",

]

# 读取 fp_out.json 文件
with open("fp_out.json", "r", encoding="utf-8") as f:
    data = json.load(f)

# 提取需要检查的 fingerprint（SHA256 形式）
need_to_check_set = set()
need_to_check = defaultdict(list)

for k, v in data.items():
    if k not in common_ca:
        continue
    print(k, len(v.keys()))
    if isinstance(v, dict) and len(v.keys()) > 10:
        # print(k)
        for sub_k, sub_v in v.items():
            if sub_v == 1:
                need_to_check[k].append(sub_k)
                need_to_check_set.add(sub_k)

sys.exit(0)

# 根据数据库中的指纹匹配出需要检查的 ID
id_need_to_check = []

for row in stream_by_id(engine_cert.raw_connection(), "cert_fp"):
    cert_id = row[0]
    fp = row[1]
    fp_sha256 = get_sha256_hex_from_str(fp)

    if fp_sha256 in need_to_check_set:
        id_need_to_check.append(cert_id)

final = []
new_conn = engine_cert.raw_connection()
for id in id_need_to_check:
    with new_conn.cursor() as cursor:
        query = """
            SELECT issuer from cert_search
            WHERE id = %s
        """

        cursor.execute(query, (id,))
        row = cursor.fetchone()

    if row:
        issuer = json.loads(row[0])
        print(issuer.get("common_name"))
        if issuer.get("common_name") in common_ca:
            final.append(id)

# 保存到文件
output_path = "id_need_to_check.json"
with open(output_path, "w", encoding="utf-8") as f:
    json.dump(final, f, indent=2)

print(f"Saved {len(final)} IDs to {output_path}")
