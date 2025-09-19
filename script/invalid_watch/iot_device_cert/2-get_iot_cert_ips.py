
import json
from backend.analyzer.utils import stream_by_id
from backend.celery.celery_db_pool import engine_tls, engine_cert
from collections import defaultdict

# /8 网段统计
count_by_slash8 = defaultdict(int)

# /16 网段统计
count_by_slash16 = defaultdict(int)

device_ids = []
with open("13-id_seed.txt", "r") as input:
    for id in input:
        device_ids.append(int(id.strip()))

cert_conn = engine_cert.raw_connection()
cursor = cert_conn.cursor()

out = open("13-iot_ip.txt", "w")

for row in stream_by_id(engine_tls.raw_connection(), "tlshandshake", start_id=2065672):
    ip = row[2]
    leaf_sha256 = row[-3]

    if not ip:
        continue

    parts = ip.split('.')
    if len(parts) != 4:
        continue  # 跳过非法 IP

    query = """
        SELECT * FROM cert_search
        WHERE sha256 = %s
    """
    cursor.execute(query, (leaf_sha256,))
    row = cursor.fetchone()

    if row:
        if int(row[0]) in device_ids:
            out.write(ip)
            out.write('\n')

cursor.close()
cert_conn.close()

out.close()
