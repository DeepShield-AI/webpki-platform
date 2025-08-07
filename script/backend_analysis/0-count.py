
import json
from collections import defaultdict
from backend.analyzer.utils import stream_by_id
from backend.celery.celery_db_pool import engine_cert
from backend.utils.cert import get_sha256_hex_from_str

ca_fp = defaultdict(dict)
new_conn = engine_cert.raw_connection()

for row in stream_by_id(engine_cert.raw_connection(), "cert_fp"):
    id = row[0]
    fp = row[1]

    fp_sha256 = get_sha256_hex_from_str(fp)

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
            issuer = json.loads(issuer)
            if isinstance(issuer, dict):
                cn = issuer.get("common_name")

                if fp_sha256 not in ca_fp[str(cn)]:
                    ca_fp[str(cn)][fp_sha256] = 0
                ca_fp[str(cn)][fp_sha256] += 1

new_conn.close()

with open("fp_out.json", "w") as f:
    json.dump(ca_fp, f, indent=2)
