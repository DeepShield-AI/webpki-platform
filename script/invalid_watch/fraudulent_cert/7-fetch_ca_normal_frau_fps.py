
import json
from backend.analyzer.utils import stream_by_id
from backend.celery.celery_db_pool import engine_cert

NORMAL = 0
FORGED = 1

fp_data = {}

trust_ca_names = []
new_conn = engine_cert.raw_connection()
with open("12-out.txt", "r", encoding="utf-8") as f:
    for line in f.readlines():
        print(line)
        trust_ca_names.append(line.strip())
        fp_data[line.strip()] = {
            NORMAL : set(),
            FORGED : set()
        }

for row in stream_by_id(engine_cert.raw_connection(), "cert_search"):
    id = row[0]
    subject = row[4]
    issuer = row[5]
    type = row[-1]

    if issuer not in trust_ca_names: continue
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
                # fraudulent cert
                type = FORGED
            else:
                # normal cert
                type = NORMAL

    with new_conn.cursor() as cursor:
        query = """
            SELECT * from cert_fp
            WHERE id = %s
        """
        cursor.execute(query, (id,))
        row = cursor.fetchone()

        if row:
            fp_sha256 = row[2]
            fp_data[issuer][type].add(fp_sha256)

for k, v in fp_data.items():
    v[NORMAL] = list(v[NORMAL])
    v[FORGED] = list(v[FORGED])

with open("12-fp.json", "w") as out:
    json.dump(fp_data, out)
