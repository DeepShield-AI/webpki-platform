
import csv
import base64
import pymysql

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

with open('/home/tianyuz23/data/converted.csv', newline='', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    count = 0

    for row in reader:
        try:
            sha256 = row['new_cert_hash']
            # print(row['cert_der_base64'])
            der_bytes = base64.b64decode(row['cert_der_base64'])

            batch.append((sha256, der_bytes))
            count += 1

            if len(batch) >= BATCH_SIZE:
                cursor.executemany(
                    "INSERT IGNORE INTO cert (sha256, cert_der) VALUES (%s, %s)",
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
        "INSERT INTO cert (sha256, cert_der) VALUES (%s, %s)",
        batch
    )
    conn.commit()
    print(f"✅ 插入剩余 {len(batch)} 行")

cursor.close()
conn.close()
print(f"🎉 插入完成，共计 {count} 行")
