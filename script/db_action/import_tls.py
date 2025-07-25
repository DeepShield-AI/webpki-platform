
import csv
import json
import pymysql

BATCH_SIZE = 5000

# === MySQL 连接 ===
conn = pymysql.connect(
    host='localhost',
    user='tianyu',
    password='123456',
    database='tls',
    port=3306,
    charset='utf8mb4'
)
cursor = conn.cursor()

def normalize(value):
    if value in ('N', 'None', '', '\\N'):
        return None
    return value

def parse_json_list(value):
    try:
        if normalize(value) is None:
            return json.dumps([])  # 空列表
        return json.dumps(json.loads(value))  # 正确转义的 JSON 字符串
    except Exception as e:
        print(f"[!] JSON parse error: {value}")
        return json.dumps([])

# === 批量插入 ===
batch = []
count = 0

with open('/home/tianyuz23/data/tls_rewritten.csv', newline='', encoding='utf-8') as f:
    # reader = csv.reader(f)
    reader = csv.reader(f, delimiter=',', quotechar='"', escapechar='\\')

    for row in reader:
        try:
            destination_host = normalize(row[1])
            destination_ip   = normalize(row[2])
            scan_time        = normalize(row[3])
            jarm             = normalize(row[4])
            jarm_hash        = normalize(row[5])
            tls_version      = normalize(row[6])
            tls_cipher       = normalize(row[7])
            cert_list_json   = parse_json_list(row[8])
            error_msg        = normalize(row[9])

            batch.append((
                destination_host, destination_ip, scan_time,
                jarm, jarm_hash, tls_version, tls_cipher,
                cert_list_json, error_msg
            ))

            count += 1
            if len(batch) >= BATCH_SIZE:
                cursor.executemany("""
                    INSERT INTO tlshandshake (
                        destination_host, destination_ip, scan_time,
                        jarm, jarm_hash, tls_version, tls_cipher,
                        cert_sha256_list, error
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, batch)
                conn.commit()
                print(f"✅ 插入 {count} 行")
                batch.clear()

        except Exception as e:
            print(f"[❌错误] 第 {count+1} 行: {e}")
            continue

# 插入剩余数据
if batch:
    cursor.executemany("""
        INSERT INTO tlshandshake (
            destination_host, destination_ip, scan_time,
            jarm, jarm_hash, tls_version, tls_cipher,
            cert_sha256_list, error
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, batch)
    conn.commit()
    print(f"✅ 插入剩余 {len(batch)} 行")

cursor.close()
conn.close()
print(f"🎉 总计导入 {count} 行")
