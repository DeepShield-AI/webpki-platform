
import sqlite3
import csv

conn = sqlite3.connect('/var/lib/mysql-files/hash_map.db')
cursor = conn.cursor()
cursor.execute("DROP TABLE IF EXISTS hash_map")
cursor.execute("CREATE TABLE hash_map (old_hash TEXT PRIMARY KEY, new_hash TEXT)")
conn.commit()

# ⚠️ 关键改动：只取前两列
batch = []
batch_size = 10000  # 分批插入，防止内存暴涨

with open('/var/lib/mysql-files/converted.csv', newline='', encoding='utf-8') as f:
    reader = csv.reader(f)
    for row in reader:
        if len(row) >= 2:
            batch.append((row[0], row[1]))
        if len(batch) >= batch_size:
            cursor.executemany("INSERT INTO hash_map (old_hash, new_hash) VALUES (?, ?)", batch)
            conn.commit()
            batch = []
    if batch:
        cursor.executemany("INSERT INTO hash_map (old_hash, new_hash) VALUES (?, ?)", batch)
        conn.commit()

conn.close()
