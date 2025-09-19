
import json
from backend.analyzer.utils import stream_by_id
from backend.celery.celery_db_pool import engine_tls, engine_cert
from collections import defaultdict

# /8 网段统计
count_by_slash8 = defaultdict(int)

# /16 网段统计
count_by_slash16 = defaultdict(int)

cert_conn = engine_cert.raw_connection()
tls_conn = engine_tls.raw_connection()
cert_cursor = cert_conn.cursor()
tls_cursor = tls_conn.cursor()
with open("13-matched_ids.txt", "r") as input:
    for id in input:

        query = """
            SELECT * FROM cert
            WHERE id = %s
        """
        cert_cursor.execute(query, (id,))
        row = cert_cursor.fetchone()

        sha256 = row[1]

        query = """
            SELECT * FROM tlshandshake
            WHERE leaf_sha256 = %s
        """
        tls_cursor.execute(query, (sha256,))
        rows = tls_cursor.fetchall()

        if rows:
            for row in rows:
                ip = row[2]
                if not ip:
                    continue
                parts = ip.split('.')
                if len(parts) != 4:
                    continue  # 跳过非法 IP

                with open("13-vul_ip.txt", "a") as ip_out:
                    ip_out.write(ip)
                    ip_out.write('\n')

                # 取 /8 网段（IP 第一个八位）
                first_octet = ip.split('.')[0]
                count_by_slash8[first_octet] += 1

                # 取 /16 网段（IP 前两个八位）
                slash16 = f"{parts[0]}.{parts[1]}"
                count_by_slash16[slash16] += 1

tls_cursor.close()
tls_conn.close()
cert_cursor.close()
cert_conn.close()

# 打印 /8 统计结果
print("\n/8 网段统计：")
for slash8, count in sorted(count_by_slash8.items(), key=lambda x: int(x[0])):
    print(f"{slash8}.x.x.x\t{count}")

# 如果需要保存为 JSON
with open("13-slash8_count-vul.json", "w", encoding="utf-8") as out:
    json.dump(count_by_slash8, out, ensure_ascii=False, indent=2)

# 打印 /16 统计结果
print("\n/16 网段统计：")
for slash16, count in sorted(count_by_slash16.items(), key=lambda x: (int(x[0].split('.')[0]), int(x[0].split('.')[1]))):
    print(f"{slash16}.x.x\t{count}")

# 保存为 JSON
with open("13-slash16_count-vul.json", "w", encoding="utf-8") as out:
    json.dump(count_by_slash16, out, ensure_ascii=False, indent=2)
