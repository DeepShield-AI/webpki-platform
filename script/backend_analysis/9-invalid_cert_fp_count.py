
import json
from collections import defaultdict
from backend.analyzer.utils import stream_by_id
from backend.celery.celery_db_pool import engine_cert
from backend.utils.cert import get_sha256_hex_from_str

ca_fp = defaultdict(dict)
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

        with new_conn.cursor() as cursor:
            query = """
                SELECT issuer from cert_search
                WHERE id = %s
            """
            cursor.execute(query, (id,))
            row = cursor.fetchone()

        if row:
            issuer = row[0]
            if issuer:
                if fp_sha256 not in ca_fp[issuer]:
                    ca_fp[issuer][fp_sha256] = 0
                ca_fp[issuer][fp_sha256] += 1

new_conn.close()

with open("9-fp_out.json", "w") as f:
    json.dump(ca_fp, f, indent=2)
