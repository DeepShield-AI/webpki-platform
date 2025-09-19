
import json
from collections import defaultdict
from backend.analyzer.utils import stream_by_id
from backend.celery.celery_db_pool import engine_cert

tot_num = 0
spki_sha256_dict = defaultdict(list)
new_conn = engine_cert.raw_connection()

with open("13-id_seed.txt", "r") as input:
    for id in input:
        with new_conn.cursor() as cursor:
            query = """
                SELECT * from cert_search
                WHERE id = %s
            """
            cursor.execute(query, (id,))
            row = cursor.fetchone()

        if row:
            spki_sha256 = row[6]
            if spki_sha256:
                if isinstance(spki_sha256, str):
                    spki_sha256_dict[spki_sha256].append(id)

with open("13-spki_collision.json", "w") as f:
    json.dump(spki_sha256_dict, f, indent=2)

print(len(spki_sha256_dict.keys()))
for v in spki_sha256_dict.values():
    print(len(v))
    