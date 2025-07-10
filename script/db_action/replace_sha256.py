
import sqlite3
import json, time
import csv

conn = sqlite3.connect('/var/lib/mysql-files/hash_map.db')
cursor = conn.cursor()

with open('/var/lib/mysql-files/tls.csv', newline='', encoding='utf-8') as fin, \
     open('/var/lib/mysql-files/tls_rewritten.csv', 'w', newline='', encoding='utf-8') as fout:

    reader = csv.reader(fin, delimiter=',', quotechar='"', escapechar='\\')
    writer = csv.writer(fout)

    for row in reader:
        try:
            cert_hash_list_col = row[8]
            # print(cert_hash_list_col)
            # time.sleep(1)
            if cert_hash_list_col != '[]' and cert_hash_list_col != '\\N':
                old_list = json.loads(cert_hash_list_col)
                new_list = []
                for h in old_list:
                    cursor.execute("SELECT new_hash FROM hash_map WHERE old_hash = ?", (h,))
                    result = cursor.fetchone()
                    new_list.append(result[0] if result else h)
                row[8] = json.dumps(new_list)
        except Exception as e:
            print(f"错误行 {row[0]}: {e}")
        writer.writerow(row)
