
import json
from collections import defaultdict
from backend.analyzer.utils import stream_by_id
from backend.celery.celery_db_pool import engine_cert
from backend.utils.cert import get_sha256_hex_from_str

fp_group = defaultdict(int)
new_conn = engine_cert.raw_connection()

for row in stream_by_id(engine_cert.raw_connection(), "cert_trust"):
    trust = row[2]
    if int(trust) == 0: continue

    with new_conn.cursor() as cursor:
        query = """
            SELECT * from cert_fp
            WHERE id = %s
        """
        cursor.execute(query, (row[0],))
        row = cursor.fetchone()

    if row:
        id = row[0]
        fp = row[1]
        fp_sha256 = row[2]
        fp_group[fp_sha256] += 1

new_conn.close()

with open("9-fp_group.json", "w") as f:
    json.dump(fp_group, f, indent=2)
