
import json
from collections import defaultdict
from backend.analyzer.utils import stream_by_id
from backend.celery.celery_db_pool import engine_cert
from backend.utils.cert import get_sha256_hex_from_str

ca_fp = defaultdict(dict)
new_conn = engine_cert.raw_connection()

common_ca = []
with open("trust_ca_common_name.txt", "r") as f:
    for line in f:
        common_ca.append(line.strip())

for row in stream_by_id(engine_cert.raw_connection(), "cert_search"):

    issuer = json.loads(row[5])
    if issuer:
        common_name = issuer.get("common_name")
        if common_name in common_ca:

            with new_conn.cursor() as cursor:
                query = """
                    SELECT * from cert_fp
                    WHERE id = %s
                """
                cursor.execute(query, (row[0],))
                row = cursor.fetchone()

            if row:
                id = row[0]
                fp_sha256 = row[2]

                if fp_sha256 not in ca_fp[common_name]:
                    ca_fp[common_name][fp_sha256] = 0
                ca_fp[common_name][fp_sha256] += 1

new_conn.close()

with open("8-fp_out.json", "w") as f:
    json.dump(ca_fp, f, indent=2)
