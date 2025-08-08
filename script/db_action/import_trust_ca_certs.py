
import csv
import pymysql
from backend.parser.asn1_parser import ASN1Parser
from backend.utils.cert import get_sha256_hex_from_bytes, read_multiple_pem_certs_from_file

BATCH_SIZE = 5000

conn = pymysql.connect(
    host='localhost',
    user='tianyu',
    password='123456',
    database='cert',
    port=3306,
    charset='utf8mb4'
)
cursor = conn.cursor()
batch = []

with open('/home/tianyuz23/data/pki-internet-platform/data/ca_certs/IncludedRootsDistrustTLSSSLPEM.csv', newline='', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    count = 0

    for row in reader:
        try:
            pem = row["PEM"].strip()[1:-1]
            der = ASN1Parser.pem2der(pem)
            sha256 = get_sha256_hex_from_bytes(der)
            batch.append((sha256, der))
            count += 1

            if len(batch) >= BATCH_SIZE:
                cursor.executemany(
                    "INSERT IGNORE INTO cert (sha256, cert_der) VALUES (%s, %s)",
                    batch
                )
                conn.commit()

                cursor.executemany(
                    "INSERT IGNORE INTO ca_cert (sha256, cert_der) VALUES (%s, %s)",
                    batch
                )
                conn.commit()
                print(f"✅ 插入 {count} 行")
                batch.clear()

        except Exception as e:
            print(f"[错误] 第 {count} 行: {e}")


pem_ca_certs = read_multiple_pem_certs_from_file('/home/tianyuz23/data/pki-internet-platform/data/ca_certs/unique_ca_certs')
for pem in pem_ca_certs:
    try:
        der = ASN1Parser.pem2der(pem)
        sha256 = get_sha256_hex_from_bytes(der)
        batch.append((sha256, der))
        count += 1

        if len(batch) >= BATCH_SIZE:
            cursor.executemany(
                "INSERT IGNORE INTO cert (sha256, cert_der) VALUES (%s, %s)",
                batch
            )
            conn.commit()

            cursor.executemany(
                "INSERT IGNORE INTO ca_cert (sha256, cert_der) VALUES (%s, %s)",
                batch
            )
            conn.commit()

            print(f"✅ 插入 {count} 行")
            batch.clear()

    except Exception as e:
        print(f"[错误] 第 {count} 行: {e}")

# 插入剩余
if batch:
    cursor.executemany(
        "INSERT IGNORE INTO cert (sha256, cert_der) VALUES (%s, %s)",
        batch
    )
    conn.commit()

    cursor.executemany(
        "INSERT IGNORE INTO ca_cert (sha256, cert_der) VALUES (%s, %s)",
        batch
    )
    conn.commit()
    print(f"✅ 插入剩余 {len(batch)} 行")

cursor.close()
conn.close()
print(f"🎉 插入完成，共计 {count} 行")
